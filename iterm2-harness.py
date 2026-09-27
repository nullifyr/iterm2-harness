#!/usr/bin/env python3
"""
iterm2-harness — HTTP API for remote-controlling iTerm2 with auth and audit.

Endpoints:
  POST /api/v1/auth/request                      - request authorization (shows alert)
  GET  /api/v1/auth/whoami                       - validate current token
  GET  /api/v1/health                            - health check (no auth)
  POST /api/v1/reload                            - reload (restart) this script
  GET  /api/v1/windows                           - list windows / tabs / sessions
  GET  /api/v1/sessions                          - flat list of sessions (filterable)
  GET  /api/v1/sessions/{id}/screen              - read screen contents
  GET  /api/v1/sessions/{id}/metadata            - session metadata
  POST /api/v1/sessions/{id}/send-text           - send text
  POST /api/v1/sessions/{id}/send-key            - send key
  POST /api/v1/sessions/{id}/set-title           - set session title
  GET    /api/v1/files?path=...                  - read a file
  POST   /api/v1/files?path=...                  - write a file (json or multipart)
  DELETE /api/v1/files?path=...                  - delete a file
  GET    /api/v1/files/list?path=...             - list a directory

Auth:    every request except /health and /auth/request needs Authorization: Bearer <token>
Storage: ~/.iterm2-harness/tokens.json
Audit:   ~/.iterm2-harness/logs/YYYY-MM-DD.log
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import iterm2

VERSION = "2.0.0"

# Protocol and resource budgets. Keep these finite: this process shares iTerm2's
# bundled Python environment and should never let a client turn an API request
# into unbounded memory/CPU work.
MAX_BODY_SIZE = 32 * 1024 * 1024
MAX_REQUEST_LINE = 8 * 1024
MAX_HEADER_LINE = 8 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_COUNT = 64
MAX_SCREEN_LINES = 5000
MAX_FILE_READ_BYTES = 16 * 1024 * 1024
MAX_LIST_ENTRIES = 2000
MAX_REGEX_LENGTH = 1024

ALL_SCOPES = {
    "terminal.read",
    "terminal.write",
    "files.read",
    "files.write",
    "files.delete",
    "service.reload",
    "auth.manage",
}
DEFAULT_TOKEN_SCOPES = ["terminal.read", "terminal.write"]

# realpath() so that when this script is installed as a symlink under iTerm2's
# AutoLaunch folder, config.json is still read from the actual source dir
# (the brew prefix or the cloned repo), not from AutoLaunch itself.
SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))
CONFIG_FILE = SCRIPT_DIR / "config.json"

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 6770,
    "file_access": {
        "enabled": False,
        "allowed_paths": [],
    },
    "auth_prompt_timeout": 60,
}


HOME_DIR = Path(os.path.expanduser("~/.iterm2-harness"))
TOKENS_FILE = HOME_DIR / "tokens.json"
LOGS_DIR = HOME_DIR / "logs"


def load_config():
    """Load config.json, fall back to defaults; create the file if missing."""
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text("utf-8")))
        except Exception:
            pass
    else:
        try:
            CONFIG_FILE.write_text(
                json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2), "utf-8")
        except Exception:
            pass
    # Env vars take precedence for ad-hoc overrides.
    host = os.environ.get("ITERM2_HARNESS_HOST", cfg.get("host", DEFAULT_CONFIG["host"]))
    port = int(os.environ.get("ITERM2_HARNESS_PORT", cfg.get("port", DEFAULT_CONFIG["port"])))
    file_access = cfg.get("file_access") or {}
    try:
        auth_timeout = int(os.environ.get(
            "ITERM2_HARNESS_AUTH_TIMEOUT",
            cfg.get("auth_prompt_timeout", DEFAULT_CONFIG["auth_prompt_timeout"])))
    except (TypeError, ValueError):
        auth_timeout = DEFAULT_CONFIG["auth_prompt_timeout"]
    # 0 or negative disables the countdown (wait forever, old behaviour).
    return host, port, file_access, max(0, auth_timeout)


HOST, PORT, FILE_ACCESS, AUTH_PROMPT_TIMEOUT = load_config()

KEY_MAP = {
    "enter": "\r", "return": "\r",
    "ctrl+c": "\x03", "ctrl+d": "\x04", "ctrl+z": "\x1a", "ctrl+l": "\x0c",
    "ctrl+a": "\x01", "ctrl+e": "\x05", "ctrl+k": "\x0b", "ctrl+u": "\x15",
    "ctrl+w": "\x17", "ctrl+r": "\x12", "ctrl+p": "\x10", "ctrl+n": "\x0e",
    "tab": "\t", "escape": "\x1b", "esc": "\x1b",
    "up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
    "home": "\x1b[H", "end": "\x1b[F",
    "backspace": "\x7f", "delete": "\x1b[3~", "space": " ",
}

_connection = None
_auth_lock = asyncio.Lock()
_auth_attempts = {}
AUTH_RATE_WINDOW_SECONDS = 60
AUTH_RATE_MAX_ATTEMPTS = 5


# ─── Storage and audit ─────────────────────────────────────

def _ensure_dirs():
    HOME_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HOME_DIR, 0o700)
    except Exception:
        pass


def _token_hash(token):
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _normalize_scopes(scopes):
    if scopes is None:
        return list(DEFAULT_TOKEN_SCOPES)
    if not isinstance(scopes, list):
        return None
    normalized = []
    for scope in scopes:
        if not isinstance(scope, str) or scope not in ALL_SCOPES:
            return None
        if scope not in normalized:
            normalized.append(scope)
    return normalized


def _load_tokens():
    if not TOKENS_FILE.exists():
        return {}
    try:
        data = json.loads(TOKENS_FILE.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_tokens(tokens):
    _ensure_dirs()
    tmp = TOKENS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(tokens, ensure_ascii=False, indent=2), "utf-8")
    os.replace(tmp, TOKENS_FILE)
    try:
        os.chmod(TOKENS_FILE, 0o600)
    except Exception:
        pass


def _lookup_token(token):
    """Return token metadata, accepting legacy v1 plaintext entries read-only."""
    if not token:
        return None
    tokens = _load_tokens()
    info = tokens.get(_token_hash(token))
    if info:
        return info
    # v1 stored bearer secrets as dictionary keys. Keep them usable during the
    # v2 transition, but all newly issued credentials are hash-only.
    legacy = tokens.get(token)
    if legacy:
        legacy = dict(legacy)
        legacy.setdefault("scopes", sorted(ALL_SCOPES))
        legacy["legacy_plaintext"] = True
        return legacy
    return None


def _token_has_scope(token_info, required):
    if required is None:
        return True
    scopes = set((token_info or {}).get("scopes") or [])
    return required in scopes


def _legacy_token_id(storage_key):
    return "legacy-" + hashlib.sha256(storage_key.encode("utf-8")).hexdigest()[:16]


def _auth_rate_allowed(client_addr, now=None):
    """Bound unauthenticated approval prompts per client address."""
    now = time.monotonic() if now is None else now
    key = (client_addr or "?").rsplit(":", 1)[0]
    cutoff = now - AUTH_RATE_WINDOW_SECONDS
    recent = [t for t in _auth_attempts.get(key, []) if t >= cutoff]
    if len(recent) >= AUTH_RATE_MAX_ATTEMPTS:
        _auth_attempts[key] = recent
        return False
    recent.append(now)
    _auth_attempts[key] = recent
    return True


def audit(event, **fields):
    """Append a JSON line to today's audit log."""
    _ensure_dirs()
    today = datetime.now().strftime("%Y-%m-%d")
    log_file = LOGS_DIR / f"{today}.log"
    record = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "event": event,
        **fields,
    }
    line = json.dumps(record, ensure_ascii=False)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ─── HTTP protocol ─────────────────────────────────────────

class HTTPRequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


async def _readline_limited(reader, limit, what):
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=30)
    except asyncio.TimeoutError:
        raise HTTPRequestError(408, "Request timed out")
    except ValueError:
        raise HTTPRequestError(431 if what == "header" else 414,
                               f"{what.capitalize()} too large")
    if len(line) > limit:
        raise HTTPRequestError(431 if what == "header" else 414,
                               f"{what.capitalize()} too large")
    return line


async def read_http_request(reader):
    request_line = await _readline_limited(reader, MAX_REQUEST_LINE, "request line")
    if not request_line:
        return None
    try:
        decoded = request_line.decode("ascii")
    except UnicodeDecodeError:
        raise HTTPRequestError(400, "Request line must be ASCII")
    parts = decoded.rstrip("\r\n").split(" ")
    if len(parts) != 3:
        raise HTTPRequestError(400, "Malformed request line")
    method, target, http_version = parts
    method = method.upper()
    if http_version not in ("HTTP/1.0", "HTTP/1.1"):
        raise HTTPRequestError(505, "Unsupported HTTP version")
    if any(ord(c) < 0x20 for c in target):
        raise HTTPRequestError(400, "Invalid request target")
    parsed = urllib.parse.urlparse(target)
    path = parsed.path
    query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    headers = {}
    total_header_bytes = 0
    count = 0
    while True:
        raw = await _readline_limited(reader, MAX_HEADER_LINE, "header")
        total_header_bytes += len(raw)
        if total_header_bytes > MAX_HEADER_BYTES:
            raise HTTPRequestError(431, "Request headers too large")
        if raw in (b"\r\n", b"\n", b""):
            break
        count += 1
        if count > MAX_HEADER_COUNT:
            raise HTTPRequestError(431, "Too many request headers")
        try:
            line = raw.decode("iso-8859-1").rstrip("\r\n")
        except UnicodeDecodeError:
            raise HTTPRequestError(400, "Malformed request header")
        if ":" not in line:
            raise HTTPRequestError(400, "Malformed request header")
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in headers:
            if k == "content-length":
                raise HTTPRequestError(400, "Duplicate Content-Length")
            headers[k] = headers[k] + ", " + v
        else:
            headers[k] = v

    if "transfer-encoding" in headers:
        raise HTTPRequestError(400, "Transfer-Encoding is not supported")

    body = b""
    raw_length = headers.get("content-length", "0")
    try:
        content_length = int(raw_length)
    except (TypeError, ValueError):
        raise HTTPRequestError(400, "Invalid Content-Length")
    if content_length < 0:
        raise HTTPRequestError(400, "Invalid Content-Length")
    if content_length > MAX_BODY_SIZE:
        raise HTTPRequestError(413, "Request body too large")
    if content_length:
        try:
            body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=30)
        except asyncio.TimeoutError:
            raise HTTPRequestError(408, "Request body timed out")
        except asyncio.IncompleteReadError:
            raise HTTPRequestError(400, "Request body shorter than Content-Length")

    return method, path, query_params, headers, body


def make_response(status_code, data):
    data["_version"] = VERSION
    status_text = {
        200: "OK", 201: "Created", 204: "No Content",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
        409: "Conflict", 413: "Payload Too Large", 414: "URI Too Long",
        415: "Unsupported Media Type", 429: "Too Many Requests",
        431: "Request Header Fields Too Large", 500: "Internal Server Error",
        505: "HTTP Version Not Supported",
    }
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    header = (
        f"HTTP/1.1 {status_code} {status_text.get(status_code, 'Unknown')}\r\n"
        f"Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"Cache-Control: no-store\r\n\r\n"
    )
    return header.encode("utf-8") + body


# ─── API description (for progressive disclosure) ──────────

API_ENDPOINTS = [
    {
        "method": "GET", "path": "/api/v1/health",
        "auth": False,
        "summary": "Health check; returns service status.",
    },
    {
        "method": "POST", "path": "/api/v1/auth/request",
        "auth": False,
        "summary": "Request authorization for a new device. A confirmation alert is shown; on approval a token is returned.",
        "body": {
            "device_name": "string, client device name",
            "scopes": "optional list of capabilities; defaults to terminal.read + terminal.write",
        },
        "example": {"device_name": "my-laptop", "scopes": ["terminal.read"]},
        "response": {"token": "auth token", "token_id": "revocation id", "device_name": "string", "scopes": "granted capabilities"},
        "errors": {
            "403": "User pressed Deny.",
            "408": "Prompt closed with no answer (auth_prompt_timeout, default 60s).",
        },
    },
    {
        "method": "POST", "path": "/api/v1/reload",
        "auth": True,
        "summary": "Reload (restart) this script. The server disconnects and re-launches itself.",
    },
    {
        "method": "GET", "path": "/api/v1/auth/whoami",
        "auth": True,
        "summary": "Validate the current token and return the owning device info.",
    },
    {
        "method": "GET", "path": "/api/v1/auth/tokens",
        "auth": True,
        "summary": "List authorized devices/tokens without exposing bearer secrets. Requires auth.manage.",
    },
    {
        "method": "DELETE", "path": "/api/v1/auth/tokens/{token_id}",
        "auth": True,
        "summary": "Revoke an authorized token by token_id. Requires auth.manage.",
    },
    {
        "method": "GET", "path": "/api/v1/windows",
        "auth": True,
        "summary": "Hierarchical listing of windows -> tabs -> sessions.",
    },
    {
        "method": "GET", "path": "/api/v1/sessions",
        "auth": True,
        "summary": "Flat list of sessions (with parent window_id / tab_id) — always including path / job_name / command_line. Enumerates visible, minimized, and buried sessions. Filterable by name, job, command, path.",
        "query": {
            "name": "Case-insensitive keyword matched against each '/'-separated component of the session name (e.g. name=android matches 'Claude/Minis/Android (...)').",
            "job": "Case-insensitive keyword matched against each '/'-separated component of jobName. Note: some tools rename their process (e.g. claude reports its version like '2.1.132').",
            "command": "Case-insensitive keyword matched against each '/'-separated component of commandLine; falls back to whole-string substring match when no '/' is present. Recommended for stable matching, e.g. command=claude.",
            "path": "Case-insensitive keyword matched against each folder name of the working directory (e.g. path=minisapp matches '/Users/me/Src/.../MinisApp').",
            "regex": "When true, treat each query as a Python regex applied to the FULL string (component splitting is skipped).",
        },
    },
    {
        "method": "GET", "path": "/api/v1/sessions/{session_id}/screen",
        "auth": True,
        "summary": "Read terminal screen contents (including scrollback).",
        "query": {
            "limit": "Number of lines to return (from the bottom). Default 500.",
            "offset": "Skip this many lines from the bottom before taking limit; use to page through history. Default 0.",
            "strip": "When true, collapse runs of horizontal whitespace (spaces/tabs) into a single space and drop empty lines; line breaks are preserved. Default false.",
        },
    },
    {
        "method": "GET", "path": "/api/v1/sessions/{session_id}/metadata",
        "auth": True,
        "summary": "Get session metadata (working directory, command line, job name, grid size).",
    },
    {
        "method": "POST", "path": "/api/v1/sessions/{session_id}/send-text",
        "auth": True,
        "summary": "Send raw text to a session. Set enter=true to also press Enter after the text.",
        "body": {
            "text": "string, raw text to send",
            "enter": "bool, press Enter after the text (default false). Sent as a SEPARATE write to avoid TUI line editors swallowing it as part of the same input batch.",
            "enter_delay_ms": "int, milliseconds to wait between the text write and the Enter write. Default 30. Set to 0 for legacy single-write behavior.",
        },
        "example": {"text": "ls -la", "enter": True},
        "notes": "If the text already ends with \\r or \\n, no additional Enter is appended (avoids double-submit).",
    },
    {
        "method": "POST", "path": "/api/v1/sessions/{session_id}/set-title",
        "auth": True,
        "summary": "Set the session title (shown in the tab/window). Pass an empty string to reset to the default.",
        "body": {"title": "string, the new session title"},
        "example": {"title": "My Build Job"},
    },
    {
        "method": "POST", "path": "/api/v1/sessions/{session_id}/send-key",
        "auth": True,
        "summary": "Send a special key or key combination.",
        "body": {"key": "enter|tab|escape|up|down|left|right|home|end|backspace|delete|space|ctrl+{a-z}"},
        "example": {"key": "ctrl+c"},
    },
    {
        "method": "GET", "path": "/api/v1/files",
        "auth": True,
        "summary": "Read a file with optional slicing, tailing, line numbers, and grep. Gated by file_access in config.json.",
        "query": {
            "path": "Absolute path of the file to read.",
            "base64": "When true, return base64-encoded bytes instead of utf-8 text. Default false. Disables all line-mode params below.",
            "lines": "Return at most N lines. Default: all.",
            "offset": "1-based start line (combines with lines). Default 1. Mutually exclusive with tail.",
            "tail": "Return the LAST N lines (like `tail -n`). If both tail and offset are given, tail wins.",
            "line_numbers": "When true, prefix each returned line with its 1-based line number. Default false. Always implied when grep is active.",
            "grep": "Substring to filter lines by (case-insensitive). Output is always line-numbered, with `--` separators between match groups.",
            "grep_regex": "When true, treat grep as a Python regex. Default false (substring).",
            "grep_context": "Include N lines of context before and after each grep match (like `grep -C N`). Default 0.",
        },
        "response": {
            "path": "resolved absolute path",
            "size": "file size in bytes",
            "total_lines": "total number of lines in the file",
            "returned_lines": "number of lines in `content` (excluding `--` separators in grep mode)",
            "offset": "1-based start line of the first returned line (omitted in grep mode)",
            "has_more": "true if more lines exist after the returned slice (omitted in grep mode)",
            "encoding": "utf-8 or base64",
            "content": "file content (plain text, line-numbered, or base64)",
        },
        "errors": {
            "403": "file_access disabled or path outside allowed_paths",
            "404": "file not found",
            "415": "file is binary; retry with base64=true",
        },
    },
    {
        "method": "POST", "path": "/api/v1/files",
        "auth": True,
        "summary": "Write a file. Two modes: JSON body or multipart upload.",
        "query": {"path": "Absolute path of the file to write."},
        "body": {
            "content": "string, the content to write (required for JSON mode)",
            "encoding": "utf-8 (default) or base64",
            "mkdir": "bool, create missing parent directories (default false)",
            "append": "bool, append instead of overwrite (default false)",
        },
        "example": {"content": "hello\n", "mkdir": True},
        "notes": "Or send Content-Type: multipart/form-data with a 'file' field for raw bytes; "
                 "additional 'mkdir' / 'append' form fields are accepted.",
    },
    {
        "method": "DELETE", "path": "/api/v1/files",
        "auth": True,
        "summary": "Delete a file (not a directory).",
        "query": {"path": "Absolute path of the file to delete."},
    },
    {
        "method": "GET", "path": "/api/v1/files/list",
        "auth": True,
        "summary": "List directory contents.",
        "query": {
            "path": "Absolute path of the directory.",
            "recursive": "When true, walk the directory tree. Default false.",
        },
    },
]


def api_directory():
    """Return the full API directory used for error hints and discovery."""
    return {
        "service": "iterm2-harness",
        "version": VERSION,
        "listen": {"host": HOST, "port": PORT},
        "auth": {
            "scheme": "Bearer token in Authorization header",
            "obtain_token": "POST /api/v1/auth/request  (iTerm2 will show a confirmation alert)",
            "header_example": "Authorization: Bearer <token>",
            "capabilities": sorted(ALL_SCOPES),
            "default_scopes": DEFAULT_TOKEN_SCOPES,
        },
        "endpoints": API_ENDPOINTS,
    }


def error_payload(error_msg, hint=None, **extra):
    """Standard error payload with a hint and the full API directory for discovery."""
    payload = {"error": error_msg}
    if hint:
        payload["hint"] = hint
    payload.update(extra)
    payload["api"] = api_directory()
    return payload


# ─── Auth ──────────────────────────────────────────────────

PUBLIC_PATHS = {"/api/v1/health", "/api/v1/auth/request", "/", "/api", "/api/v1"}

HANDLER_SCOPES = {
    "handle_reload": "service.reload",
    "handle_whoami": None,
    "handle_list_tokens": "auth.manage",
    "handle_revoke_token": "auth.manage",
    "handle_list_windows": "terminal.read",
    "handle_list_sessions": "terminal.read",
    "handle_get_screen": "terminal.read",
    "handle_get_metadata": "terminal.read",
    "handle_send_text": "terminal.write",
    "handle_send_key": "terminal.write",
    "handle_set_title": "terminal.write",
    "handle_file_read": "files.read",
    "handle_file_write": "files.write",
    "handle_file_delete": "files.delete",
    "handle_file_list": "files.read",
}


def _extract_token(headers):
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _check_token(token):
    return _lookup_token(token)


class PromptUnavailable(Exception):
    """Raised when the PyObjC alert cannot be shown; caller falls back."""


# Decision constants for the authorization prompt.
AUTH_ALLOW, AUTH_DENY, AUTH_TIMEOUT = "allow", "deny", "timeout"

_ALERT_TITLE = "iterm2-harness authorization request"


def _alert_body(device_name, client_addr, scopes=None):
    scope_lines = "\n".join(f"  • {scope}" for scope in (scopes or []))
    return (f"Device: {device_name}\n"
            f"Origin: {client_addr}\n\n"
            f"Requested capabilities:\n{scope_lines or '  • none'}\n\n"
            f"Allow this device to control iTerm2?")


def _walk_subviews(view):
    """Yield every descendant of *view*, depth-first."""
    for sub in (view.subviews() or []):
        yield sub
        yield from _walk_subviews(sub)


# AppKit constants the prompt needs, each with its pre-10.12/10.13 SDK spelling
# as a fallback. iTerm2's bundled Python runtime varies by iTerm2 release, and
# an older PyObjC may only know the old names.
_APPKIT_CONSTS = {
    "accessory": ("NSApplicationActivationPolicyAccessory",),
    "warning": ("NSAlertStyleWarning", "NSWarningAlertStyle"),
    "floating": ("NSFloatingWindowLevel",),
    "event_mask_any": ("NSEventMaskAny", "NSAnyEventMask"),
    "default_mode": ("NSDefaultRunLoopMode",),
    "state_on": ("NSControlStateValueOn", "NSOnState"),
}


def _resolve_appkit_consts(AppKit):
    """Look up every constant up front, before any window exists.

    A name missing mid-prompt would surface as an AttributeError after the
    panel is already on screen — a 500 instead of the iterm2.Alert fallback.

    :raises PromptUnavailable: if any constant is unknown under every name.
    """
    consts = {}
    for key, names in _APPKIT_CONSTS.items():
        found = next((getattr(AppKit, n) for n in names if hasattr(AppKit, n)),
                     None)
        if found is None:
            raise PromptUnavailable(f"AppKit lacks {names[0]}")
        consts[key] = found
    return consts


def _drain_events(app, k):
    """Dispatch every queued AppKit event without ever blocking.

    distantPast means "return nil immediately if nothing is ready".
    """
    import AppKit
    while True:
        event = app.nextEventMatchingMask_untilDate_inMode_dequeue_(
            k["event_mask_any"], AppKit.NSDate.distantPast(),
            k["default_mode"], True)
        if event is None:
            return
        app.sendEvent_(event)


def _build_pyobjc_alert(device_name, client_addr, scopes):
    """Create the NSAlert and show it as a non-modal floating panel.

    AppKit requires NSWindow to be built on the main thread, so this must be
    called from the asyncio loop's own (main) thread. It deliberately does NOT
    call runModal(): a modal session would spin a nested runloop and starve
    asyncio. Instead the panel is ordered front and driven by _prompt_pyobjc().

    :returns: (alert, window, consts) — hand all three to _prompt_pyobjc.
    :raises PromptUnavailable: if PyObjC or the window server is unusable.
    """
    try:
        import AppKit
    except Exception as e:
        raise PromptUnavailable(f"PyObjC unavailable: {e}") from e

    k = _resolve_appkit_consts(AppKit)

    try:
        app = AppKit.NSApplication.sharedApplication()
        # Accessory: we get a window server connection and can show/focus a
        # panel, without ever appearing in the Dock or stealing the menu bar.
        app.setActivationPolicy_(k["accessory"])

        alert = AppKit.NSAlert.alloc().init()
        alert.setMessageText_(_ALERT_TITLE)
        alert.setInformativeText_(_alert_body(device_name, client_addr, scopes))
        alert.addButtonWithTitle_("Allow")
        alert.addButtonWithTitle_("Deny")
        alert.setAlertStyle_(k["warning"])
        alert.setShowsSuppressionButton_(False)

        # runModal() would normally lay the alert out before showing it. We
        # never call it (it spins a nested runloop that starves asyncio), so
        # lay out explicitly — otherwise AppKit's lazily-built placeholder
        # views leak onto the screen: an untitled third button between Allow
        # and Deny, and a stray "<Do not show this message again>" checkbox.
        alert.layout()

        window = alert.window()
        for view in _walk_subviews(window.contentView()):
            if not isinstance(view, AppKit.NSButton):
                continue
            title = str(view.title())
            # Placeholders are the empty-titled buttons and the suppression
            # checkbox; the real ones carry the titles we set above.
            if title in ("", "<Do not show this message again>"):
                view.setHidden_(True)

        window.setLevel_(k["floating"])
        window.makeKeyAndOrderFront_(None)
        app.activateIgnoringOtherApps_(True)
        return alert, window, k
    except PromptUnavailable:
        raise
    except Exception as e:
        raise PromptUnavailable(f"NSAlert failed: {e}") from e


async def _prompt_pyobjc(device_name, client_addr, timeout, scopes):
    """Show the auth panel and await the click, without blocking asyncio.

    The panel lives in this process, so iTerm2's main thread — and therefore
    its UI and its API server — are never touched. We poll the AppKit event
    queue in short non-blocking slices and `await asyncio.sleep(0)` between
    them, so every other harness request keeps being served while the panel
    is up. When the deadline passes we tear the panel down ourselves.
    """
    import AppKit

    # Build first, then start the clock: AppKit's first-use initialisation can
    # take a noticeable moment, and it should not eat into the user's time.
    alert, window, k = _build_pyobjc_alert(device_name, client_addr, scopes)
    app = AppKit.NSApplication.sharedApplication()
    base_text = _alert_body(device_name, client_addr, scopes)
    deadline = time.monotonic() + timeout if timeout > 0 else None

    buttons = alert.buttons()
    allow_btn, deny_btn = buttons.objectAtIndex_(0), buttons.objectAtIndex_(1)

    try:
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return AUTH_TIMEOUT
                alert.setInformativeText_(
                    f"{base_text}\n\n"
                    f"Auto-denied in {int(remaining) + 1}s if unanswered.")

            _drain_events(app, k)

            if allow_btn.state() == k["state_on"]:
                return AUTH_ALLOW
            if deny_btn.state() == k["state_on"]:
                return AUTH_DENY
            if not window.isVisible():
                # User closed the panel some other way — treat as refusal.
                return AUTH_DENY

            await asyncio.sleep(0.05)
    finally:
        # orderOut_ alone can leave the panel on screen: it only unmaps the
        # window, and with no modal session to unwind AppKit may never redraw.
        # close() releases it, and pumping once more lets the window server
        # process the teardown before we return.
        try:
            window.orderOut_(None)
            window.close()
            _drain_events(app, k)
        except Exception as e:
            audit("auth.prompt_teardown_failed", error=str(e))


async def _prompt_iterm2_alert(device_name, client_addr, scopes):
    """Fallback: iTerm2's own modal alert.

    This blocks iTerm2's main thread (and thus its whole UI) until answered,
    and cannot time out — only used when the PyObjC path is unavailable.
    """
    alert = iterm2.Alert(_ALERT_TITLE, _alert_body(device_name, client_addr, scopes))
    alert.add_button("Allow")
    alert.add_button("Deny")
    selection = await alert.async_run(_connection)
    # First add_button -> 1000, second -> 1001.
    return AUTH_ALLOW if selection == 1000 else AUTH_DENY


async def _prompt_user_authorize(device_name, client_addr, timeout, scopes):
    """Ask the user to approve a device, preferring the non-blocking prompt."""
    try:
        return await _prompt_pyobjc(device_name, client_addr, timeout, scopes)
    except PromptUnavailable as e:
        audit("auth.prompt_fallback", device_name=device_name, reason=str(e))
        return await _prompt_iterm2_alert(device_name, client_addr, scopes)


# ─── Routes ────────────────────────────────────────────────

ROUTES = [
    ("GET",  r"/$",                                         "handle_index"),
    ("GET",  r"/api$",                                      "handle_index"),
    ("GET",  r"/api/v1$",                                   "handle_index"),
    ("GET",  r"/api/v1/health$",                            "handle_health"),
    ("POST", r"/api/v1/reload$",                            "handle_reload"),
    ("POST", r"/api/v1/auth/request$",                      "handle_auth_request"),
    ("GET",  r"/api/v1/auth/whoami$",                       "handle_whoami"),
    ("GET",  r"/api/v1/auth/tokens$",                       "handle_list_tokens"),
    ("DELETE", r"/api/v1/auth/tokens/(?P<token_id>[^/]+)$", "handle_revoke_token"),
    ("GET",  r"/api/v1/windows$",                           "handle_list_windows"),
    ("GET",  r"/api/v1/sessions$",                          "handle_list_sessions"),
    ("GET",  r"/api/v1/sessions/(?P<sid>[^/]+)/screen$",    "handle_get_screen"),
    ("GET",  r"/api/v1/sessions/(?P<sid>[^/]+)/metadata$",  "handle_get_metadata"),
    ("POST", r"/api/v1/sessions/(?P<sid>[^/]+)/send-text$", "handle_send_text"),
    ("POST", r"/api/v1/sessions/(?P<sid>[^/]+)/send-key$",  "handle_send_key"),
    ("POST", r"/api/v1/sessions/(?P<sid>[^/]+)/set-title$", "handle_set_title"),
    ("GET",  r"/api/v1/files$",                             "handle_file_read"),
    ("POST", r"/api/v1/files$",                             "handle_file_write"),
    ("DELETE", r"/api/v1/files$",                           "handle_file_delete"),
    ("GET",  r"/api/v1/files/list$",                        "handle_file_list"),
]


def match_route(method, path):
    for route_method, pattern, handler_name in ROUTES:
        if method != route_method:
            continue
        m = re.match(pattern, path)
        if m:
            return handler_name, m.groupdict()
    return None, None


# ─── Handlers ──────────────────────────────────────────────

async def _get_app():
    return await iterm2.async_get_app(_connection)


async def _find_session(sid):
    app = await _get_app()
    return app.get_session_by_id(sid)


async def handle_index(**_):
    d = api_directory()
    d["status"] = "ok"
    d["hint"] = "iterm2-harness API directory. All endpoints except health and auth/request require a Bearer token."
    return 200, d


async def handle_health(**_):
    return 200, {"status": "ok", "server": "iterm2-harness",
                 "host": HOST, "port": PORT}


async def handle_reload(**_):
    """Trigger a restart asynchronously: respond first, then exec self."""
    audit("server.reload")

    async def _do_restart():
        # Give the HTTP response a moment to flush.
        await asyncio.sleep(0.3)
        import sys
        script = os.path.abspath(__file__)
        # iTerm2 Python scripts run as standalone processes; exec replaces us.
        os.execv(sys.executable, [sys.executable, script])

    asyncio.create_task(_do_restart())
    return 200, {"ok": True, "message": "Reloading script…"}


async def handle_auth_request(body=None, client_addr=None, **_):
    body = body or {}
    if not _auth_rate_allowed(client_addr):
        audit("auth.rate_limited", client=client_addr)
        return 429, {
            "error": "Too many authorization requests",
            "retry_after_seconds": AUTH_RATE_WINDOW_SECONDS,
        }
    device_name = (body.get("device_name") or "").strip() or "unknown-device"
    scopes = _normalize_scopes(body.get("scopes"))
    if scopes is None:
        return 400, error_payload(
            "Invalid scopes",
            hint=f"scopes must be a list containing only: {', '.join(sorted(ALL_SCOPES))}",
        )

    async with _auth_lock:
        audit("auth.request", device_name=device_name, client=client_addr,
              scopes=scopes)
        decision = await _prompt_user_authorize(
            device_name, client_addr or "?", AUTH_PROMPT_TIMEOUT, scopes)

        if decision == AUTH_TIMEOUT:
            audit("auth.timeout", device_name=device_name, client=client_addr,
                  timeout_seconds=AUTH_PROMPT_TIMEOUT)
            return 408, {
                "error": "No response from user",
                "hint": ("The authorization prompt closed after "
                         f"{AUTH_PROMPT_TIMEOUT}s with no answer. "
                         "Retry when you are at the machine."),
                "timeout_seconds": AUTH_PROMPT_TIMEOUT,
            }

        if decision != AUTH_ALLOW:
            audit("auth.denied", device_name=device_name, client=client_addr)
            return 403, {"error": "Authorization denied by user"}

        token = secrets.token_urlsafe(32)
        token_id = secrets.token_hex(8)
        tokens = _load_tokens()
        tokens[_token_hash(token)] = {
            "token_id": token_id,
            "device_name": device_name,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "client_addr": client_addr or "",
            "scopes": scopes,
        }
        _save_tokens(tokens)
        audit("auth.granted", device_name=device_name, client=client_addr,
              token_id=token_id, scopes=scopes)
        return 201, {
            "token": token,
            "token_id": token_id,
            "device_name": device_name,
            "scopes": scopes,
        }


async def handle_list_tokens(**_):
    items = []
    for key, info in _load_tokens().items():
        safe = dict(info)
        is_legacy = not key.startswith("sha256:")
        safe.pop("legacy_plaintext", None)
        safe["legacy_plaintext"] = is_legacy
        if is_legacy:
            safe.setdefault("token_id", _legacy_token_id(key))
            safe.setdefault("scopes", sorted(ALL_SCOPES))
        items.append(safe)
    items.sort(key=lambda x: x.get("created_at", ""))
    return 200, {"tokens": items}


async def handle_revoke_token(token_id, **_):
    tokens = _load_tokens()
    for key, info in list(tokens.items()):
        stored_id = info.get("token_id")
        if stored_id is None and not key.startswith("sha256:"):
            stored_id = _legacy_token_id(key)
        if stored_id == token_id:
            del tokens[key]
            _save_tokens(tokens)
            audit("auth.revoked", token_id=token_id,
                  device_name=info.get("device_name"))
            return 200, {"revoked": True, "token_id": token_id}
    return 404, {"error": f"Token id '{token_id}' not found"}


async def handle_whoami(token_info=None, **_):
    return 200, {
        "token_id": token_info.get("token_id"),
        "device_name": token_info.get("device_name"),
        "created_at": token_info.get("created_at"),
        "scopes": token_info.get("scopes", []),
        "legacy_plaintext": bool(token_info.get("legacy_plaintext")),
    }


async def handle_list_windows(**_):
    app = await _get_app()
    windows = []
    for window in app.windows:
        tabs = []
        for tab in window.tabs:
            sessions = []
            for s in tab.sessions:
                sessions.append({
                    "session_id": s.session_id, "name": s.name,
                    "columns": s.grid_size.width, "rows": s.grid_size.height,
                })
            tabs.append({"tab_id": tab.tab_id, "sessions": sessions})
        windows.append({"window_id": window.window_id, "tabs": tabs})
    return 200, {"windows": windows}


async def handle_list_sessions(query_params=None, **_):
    """Filters (all AND'd; omit for full list):
        name=<keyword>       any '/' component of the name contains keyword (case-insensitive)
        job=<keyword>        any '/' component of jobName matches
        command=<keyword>    any '/' component of commandLine matches
        path=<keyword>       any '/' component of working dir matches
                             (e.g. ?path=minisapp matches /…/OpenMinis/MinisApp)
        regex=true           treat the above as a regex against the FULL string
                             (component splitting is skipped in regex mode)

    The response always includes path / job_name / command_line for every
    session, whether filters are present or not. Buried (window-level
    minimized) and split-pane minimized sessions are also enumerated.
    """
    app = await _get_app()
    params = query_params or {}
    name_q = params.get("name", "")
    job_q = params.get("job", "")
    cmd_q = params.get("command", "")
    path_q = params.get("path", "")
    use_regex = params.get("regex", "false").lower() == "true"

    def matches(haystack, needle):
        if not needle:
            return True
        if not haystack:
            return False
        if use_regex:
            if len(needle) > MAX_REGEX_LENGTH:
                return False
            try:
                return re.search(needle, haystack) is not None
            except re.error:
                return False
        # Substring match against each '/' component (folder name / process
        # segment), case-insensitively. Falls back to whole-string match so
        # callers can still write `?command=claude --resume` against a flat
        # value with no separators.
        nl = needle.lower()
        hl = haystack.lower()
        for component in hl.split("/"):
            if component and nl in component:
                return True
        return nl in hl

    async def _v(s, name):
        try:
            return (await s.async_get_variable(name)) or ""
        except Exception:
            return ""

    async def _describe(s, window_id, tab_id):
        job = await _v(s, "jobName")
        command = await _v(s, "commandLine")
        path = await _v(s, "path")
        grid = getattr(s, "grid_size", None)
        columns = grid.width if grid else 0
        rows = grid.height if grid else 0
        return {
            "session_id": s.session_id, "name": s.name,
            "window_id": window_id, "tab_id": tab_id,
            "columns": columns, "rows": rows,
            "job_name": job, "command_line": command, "path": path,
        }

    # Enumerate every visible / minimized / buried session so callers don't
    # silently miss any.
    candidates = []  # list of (session, window_id, tab_id)
    for window in app.windows:
        for tab in window.tabs:
            for s in tab.all_sessions:
                candidates.append((s, window.window_id, tab.tab_id))
    for s in getattr(app, "buried_sessions", []) or []:
        candidates.append((s, None, None))

    sessions = []
    for s, wid, tid in candidates:
        if not matches(s.name, name_q):
            continue
        entry = await _describe(s, wid, tid)
        if not matches(entry["job_name"], job_q):
            continue
        if not matches(entry["command_line"], cmd_q):
            continue
        if not matches(entry["path"], path_q):
            continue
        if wid is None:
            entry["buried"] = True
        sessions.append(entry)

    return 200, {
        "sessions": sessions,
        "filter": {"name": name_q, "job": job_q, "command": cmd_q,
                   "path": path_q, "regex": use_regex},
    }


def _bounded_int(params, key, default, minimum=0, maximum=None):
    raw = params.get(key, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be an integer")
    if value < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{key} must be <= {maximum}")
    return value


async def handle_get_screen(sid, query_params=None, **_):
    session = await _find_session(sid)
    if not session:
        return 404, {
            "error": f"Session '{sid}' not found",
            "hint": "Call GET /api/v1/sessions to list current session_ids.",
        }

    params = query_params or {}
    try:
        limit = _bounded_int(params, "limit", 500, 1, MAX_SCREEN_LINES)
        offset = _bounded_int(params, "offset", 0, 0, MAX_SCREEN_LINES * 20)
    except ValueError as e:
        return 400, error_payload(str(e))
    strip = params.get("strip", "false").lower() == "true"

    # Public iTerm2 API only. The transaction keeps line geometry and content
    # consistent while the terminal is actively changing.
    async with iterm2.Transaction(_connection):
        info = await session.async_get_line_info()
        total = info.scrollback_buffer_height + info.mutable_area_height
        fetch_count = min(total, limit + offset)
        first_line = info.overflow + max(0, total - fetch_count)
        contents = await session.async_get_contents(first_line, fetch_count)

    all_lines = [line.string.replace("\x00", " ") for line in contents]
    if offset:
        lines = all_lines[:-offset] if offset < len(all_lines) else []
    else:
        lines = all_lines
    if len(lines) > limit:
        lines = lines[-limit:]
    if strip:
        lines = [re.sub(r"[ \t]+", " ", line).strip(" \t") for line in lines]
        lines = [line for line in lines if line]

    return 200, {
        "session_id": sid,
        "lines": lines,
        "fetched_lines": len(all_lines),
        "returned_lines": len(lines),
        "offset": offset,
        "has_more": (offset + limit) < total,
        "available_lines": total,
        "overflow": info.overflow,
    }


async def handle_get_metadata(sid, **_):
    session = await _find_session(sid)
    if not session:
        return 404, {
            "error": f"Session '{sid}' not found",
            "hint": "Call GET /api/v1/sessions to list current session_ids.",
        }

    async def safe(name):
        try:
            return (await session.async_get_variable(name)) or ""
        except Exception:
            return ""

    return 200, {
        "session_id": sid, "name": session.name,
        "columns": session.grid_size.width, "rows": session.grid_size.height,
        "path": await safe("path"),
        "command_line": await safe("commandLine"),
        "job_name": await safe("jobName"),
        # Extra title-related variables for diagnosing which one matches the
        # tab/pane label the user actually sees.
        "auto_name": await safe("autoName"),
        "terminal_icon_name": await safe("terminalIconName"),
        "terminal_window_name": await safe("terminalWindowName"),
        "user_name": await safe("name"),
        "session_name": await safe("session.name"),
        "tab_title_override": await safe("tab.titleOverride"),
    }


async def handle_send_text(sid, body=None, **_):
    if not body:
        return 400, {
            "error": "Missing request body",
            "hint": "Send a JSON body, e.g. {\"text\": \"ls -la\\r\"}. Use \\r for Enter.",
        }
    session = await _find_session(sid)
    if not session:
        return 404, {
            "error": f"Session '{sid}' not found",
            "hint": "Call GET /api/v1/sessions to list current session_ids.",
        }
    text = body.get("text", "")
    if not text:
        return 400, {
            "error": "Missing 'text' field",
            "hint": "Example: {\"text\": \"ls -la\", \"enter\": true}",
        }
    enter = bool(body.get("enter", False))
    # Send text and Enter as two SEPARATE writes when enter=true.
    #
    # Combining them into one send_text buffer looks like a single read() to
    # the target program. Many TUIs (Claude Code, Codex, some REPLs) do
    # keystroke coalescing / debounce inside their line editor: when the
    # trailing '\r' arrives glued to the last character in the same batch it
    # gets swallowed as part of an "insert" event, and the submit never
    # fires. Sending Enter as a separate RPC lets the target's event loop
    # observe the input's final state first, then react to the Return key.
    #
    # `enter_delay_ms` (default 30) is the pause between the two writes.
    # Set it to 0 to force the legacy combined-write behavior if you need
    # bit-for-bit compatibility with an old script.
    enter_delay_ms = body.get("enter_delay_ms")
    try:
        enter_delay_ms = int(enter_delay_ms) if enter_delay_ms is not None else 30
    except (TypeError, ValueError):
        enter_delay_ms = 30
    enter_delay_ms = max(0, min(5000, enter_delay_ms))

    # If the caller already put a CR/LF at the end of the text, don't stack a
    # second one on top of it — just honor whatever they sent. This preserves
    # the original {"text":"ls\r"} idiom without doubling the newline.
    trailing = text.endswith(("\r", "\n"))
    if enter and not trailing and enter_delay_ms == 0:
        # Legacy path: single write, text+CR.
        payload = text + "\r"
        await session.async_send_text(payload)
        return 200, {"ok": True, "sent": payload, "enter": enter,
                     "enter_delay_ms": 0, "split": False}

    await session.async_send_text(text)
    if enter and not trailing:
        if enter_delay_ms > 0:
            await asyncio.sleep(enter_delay_ms / 1000.0)
        await session.async_send_text("\r")

    return 200, {
        "ok": True,
        "sent": text + ("\r" if enter and not trailing else ""),
        "enter": enter,
        "enter_delay_ms": enter_delay_ms,
        "split": enter and not trailing,
        "trailing_newline_in_text": trailing,
    }


async def handle_set_title(sid, body=None, **_):
    if body is None:
        return 400, {
            "error": "Missing request body",
            "hint": "Send a JSON body, e.g. {\"title\": \"My Build\"}.",
        }
    session = await _find_session(sid)
    if not session:
        return 404, {
            "error": f"Session '{sid}' not found",
            "hint": "Call GET /api/v1/sessions to list current session_ids.",
        }
    if "title" not in body:
        return 400, {
            "error": "Missing 'title' field",
            "hint": "Example: {\"title\": \"My Build\"}. Use an empty string to reset.",
        }
    title = str(body["title"])
    await session.async_set_name(title)
    return 200, {"ok": True, "session_id": sid, "title": title}


async def handle_send_key(sid, body=None, **_):
    if not body:
        return 400, {
            "error": "Missing request body",
            "hint": "Send a JSON body, e.g. {\"key\": \"ctrl+c\"}.",
            "available_keys": sorted(KEY_MAP.keys()) + ["ctrl+{a-z}"],
        }
    session = await _find_session(sid)
    if not session:
        return 404, {
            "error": f"Session '{sid}' not found",
            "hint": "Call GET /api/v1/sessions to list current session_ids.",
        }
    key = body.get("key", "").lower().strip()
    if not key:
        return 400, {
            "error": "Missing 'key' field",
            "hint": "Example: {\"key\": \"enter\"} or {\"key\": \"ctrl+c\"}",
            "available_keys": sorted(KEY_MAP.keys()) + ["ctrl+{a-z}"],
        }

    sequence = KEY_MAP.get(key)
    if not sequence:
        m = re.match(r"^ctrl\+([a-z])$", key)
        if m:
            sequence = chr(ord(m.group(1)) - ord("a") + 1)
        else:
            return 400, {
                "error": f"Unknown key: '{key}'",
                "hint": "See available_keys, or use ctrl+{a-z} form.",
                "available_keys": sorted(KEY_MAP.keys()) + ["ctrl+{a-z}"],
            }
    await session.async_send_text(sequence)
    return 200, {"ok": True, "key": key}


# ─── File access ───────────────────────────────────────────

def _file_access_check(abs_path):
    """Return (ok, status, payload) for an absolute path under the access policy.

    On success returns (True, 0, resolved_real_path). On failure returns
    (False, status_code, error_body_dict).
    """
    if not FILE_ACCESS.get("enabled", False):
        return False, 403, {
            "error": "File access is disabled",
            "hint": "Set file_access.enabled=true in config.json next to the script, "
                    "then POST /api/v1/reload.",
        }
    if not abs_path:
        return False, 400, {
            "error": "Missing 'path' query parameter",
            "hint": "Provide an absolute path, e.g. ?path=/Users/me/notes.txt",
        }
    if not os.path.isabs(abs_path):
        return False, 400, {
            "error": "Path must be absolute",
            "hint": f"Got {abs_path!r}; pass a path starting with '/'.",
        }
    real = os.path.realpath(abs_path)
    allowed = FILE_ACCESS.get("allowed_paths") or []
    if allowed:
        # A request path is permitted if its realpath sits under any allowed
        # prefix (also realpath'd to handle symlinks in the policy itself).
        ok = False
        for prefix in allowed:
            p = os.path.realpath(os.path.expanduser(prefix))
            try:
                if os.path.commonpath([real, p]) == p:
                    ok = True
                    break
            except ValueError:
                continue
        if not ok:
            return False, 403, {
                "error": "Path is outside allowed_paths",
                "hint": "Edit file_access.allowed_paths in config.json to grant access.",
                "resolved_path": real,
                "allowed_paths": allowed,
            }
    return True, 0, real


def _is_probably_binary(data):
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


async def handle_file_read(query_params, body, raw_body, headers, client_addr, token_info, **_):
    """GET /api/v1/files — bounded read with optional slice/tail/grep."""
    import base64 as _b64
    path_str = query_params.get("path", "").strip()
    ok, status, info = _file_access_check(path_str)
    if not ok:
        return status, error_payload(info.get("error", "File access denied"),
                                     hint=info.get("hint"),
                                     **{k: v for k, v in info.items()
                                        if k not in ("error", "hint")})
    real = info

    if not os.path.exists(real):
        return 404, error_payload(f"File not found: {real}")
    if os.path.isdir(real):
        return 400, error_payload("Path is a directory; use GET /api/v1/files/list instead")

    try:
        size = os.path.getsize(real)
    except OSError as e:
        return 500, error_payload(f"Unable to stat file: {e}")
    if size > MAX_FILE_READ_BYTES:
        return 413, error_payload(
            f"File exceeds the {MAX_FILE_READ_BYTES} byte read limit",
            hint="Use a narrower allowed file, rotate large logs, or access it through a purpose-built tool.")

    use_base64 = query_params.get("base64", "false").lower() == "true"
    try:
        with open(real, "rb") as fh:
            raw = fh.read(MAX_FILE_READ_BYTES + 1)
    except PermissionError:
        return 403, error_payload("Permission denied")
    except OSError as e:
        return 500, error_payload(f"Read failed: {e}")

    if use_base64:
        return 200, {
            "path": real, "size": len(raw), "encoding": "base64",
            "content": _b64.b64encode(raw).decode("ascii"),
        }

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return 415, error_payload(
            "File appears to be binary",
            hint="Add ?base64=true to retrieve binary content as base64.")

    all_lines = text.splitlines(keepends=True)
    total_lines = len(all_lines)

    def _int(key, default=None):
        v = query_params.get(key)
        if v is None:
            return default
        try:
            n = int(v)
        except ValueError:
            raise ValueError(f"{key} must be an integer")
        if n < 0:
            raise ValueError(f"{key} must be >= 0")
        return n

    try:
        lines_n = _int("lines")
        offset_n = _int("offset", 1)
        tail_n = _int("tail")
        grep_ctx = _int("grep_context", 0)
    except ValueError as e:
        return 400, error_payload(str(e))

    line_numbers = query_params.get("line_numbers", "false").lower() == "true"
    grep_pat = query_params.get("grep", "")
    grep_regex = query_params.get("grep_regex", "false").lower() == "true"
    if len(grep_pat) > MAX_REGEX_LENGTH:
        return 400, error_payload("grep pattern is too long")

    if grep_pat:
        try:
            if grep_regex:
                pat = re.compile(grep_pat, re.IGNORECASE)
                match_fn = lambda value: bool(pat.search(value))
            else:
                lp = grep_pat.lower()
                match_fn = lambda value: lp in value.lower()
        except re.error as e:
            return 400, error_payload(f"Invalid regex: {e}")

        hit_indices = [i for i, line in enumerate(all_lines)
                       if match_fn(line.rstrip("\n\r"))]
        included = set()
        for hi in hit_indices:
            for ci in range(max(0, hi - grep_ctx),
                            min(total_lines, hi + grep_ctx + 1)):
                included.add(ci)

        out_lines = []
        prev = None
        for ci in sorted(included):
            if prev is not None and ci > prev + 1:
                out_lines.append("--\n")
            out_lines.append(f"{ci + 1:>6}: {all_lines[ci]}")
            prev = ci

        if lines_n is not None:
            filtered, count = [], 0
            for line in out_lines:
                filtered.append(line)
                if line != "--\n":
                    count += 1
                    if count >= lines_n:
                        break
            out_lines = filtered

        return 200, {
            "path": real, "size": len(raw), "total_lines": total_lines,
            "returned_lines": sum(1 for line in out_lines if line != "--\n"),
            "encoding": "utf-8", "content": "".join(out_lines),
        }

    if tail_n is not None:
        start = max(0, total_lines - tail_n)
        sliced = all_lines[start:]
        first_lno = start + 1
    else:
        start = max(0, (offset_n or 1) - 1)
        sliced = all_lines[start:start + lines_n] if lines_n is not None else all_lines[start:]
        first_lno = start + 1

    has_more = (first_lno + len(sliced) - 1) < total_lines
    content = ("".join(f"{first_lno + i:>6}: {line}"
                       for i, line in enumerate(sliced))
               if line_numbers else "".join(sliced))
    return 200, {
        "path": real, "size": len(raw), "total_lines": total_lines,
        "returned_lines": len(sliced), "offset": first_lno,
        "has_more": has_more, "encoding": "utf-8", "content": content,
    }


async def handle_file_write(query_params=None, body=None, raw_body=None, headers=None, **_):
    params = query_params or {}
    path = params.get("path", "")
    ok, status, info = _file_access_check(path)
    if not ok:
        return status, info
    real = info

    content_type = (headers or {}).get("content-type", "")
    data = None
    mkdir = False
    append = False

    if content_type.startswith("multipart/form-data"):
        parts = _parse_multipart(raw_body or b"", content_type)
        if not parts or "file" not in parts:
            return 400, {
                "error": "Missing 'file' field in multipart body",
                "hint": "Use a form field named 'file' to upload raw bytes.",
            }
        data = parts["file"]
        mkdir = parts.get("mkdir", b"").decode("utf-8", "replace").lower() == "true"
        append = parts.get("append", b"").decode("utf-8", "replace").lower() == "true"
    else:
        if body is None:
            return 400, {
                "error": "Missing JSON body",
                "hint": "Send {\"content\": \"...\", \"encoding\": \"utf-8\"} or use multipart upload.",
            }
        mkdir = bool(body.get("mkdir", False))
        append = bool(body.get("append", False))
        content = body.get("content", None)
        if content is None:
            return 400, {
                "error": "Missing 'content' field",
                "hint": "Provide the string to write, e.g. {\"content\": \"hello\"}",
            }
        encoding = (body.get("encoding") or "utf-8").lower()
        if encoding == "base64":
            import base64
            try:
                data = base64.b64decode(content, validate=True)
            except Exception as e:
                return 400, {"error": f"Invalid base64 content: {e}"}
        elif encoding == "utf-8":
            if not isinstance(content, str):
                return 400, {"error": "utf-8 content must be a string"}
            data = content.encode("utf-8")
        else:
            return 400, {"error": "encoding must be 'utf-8' or 'base64'"}

    parent = os.path.dirname(real)
    existed = os.path.exists(real)
    if parent and not os.path.isdir(parent):
        if mkdir:
            try:
                os.makedirs(parent, exist_ok=True)
            except OSError as e:
                return 500, {"error": f"mkdir failed: {e}"}
        else:
            return 409, {
                "error": f"Parent directory does not exist: {parent}",
                "hint": "Pass mkdir=true to create it automatically.",
            }

    mode = "ab" if append else "wb"
    try:
        with open(real, mode) as f:
            f.write(data)
    except OSError as e:
        return 500, {"error": f"Write failed: {e}"}

    audit("file.write", path=real, size=len(data),
          append=append, created=(not existed))
    return 200, {
        "path": real, "size": len(data),
        "created": not existed, "append": append,
    }


async def handle_file_delete(query_params=None, **_):
    params = query_params or {}
    path = params.get("path", "")
    ok, status, info = _file_access_check(path)
    if not ok:
        return status, info
    real = info

    if not os.path.exists(real):
        return 404, {"error": f"File not found: {real}"}
    if os.path.isdir(real):
        return 400, {
            "error": f"Path is a directory: {real}",
            "hint": "Directory deletion is not supported by this endpoint.",
        }
    try:
        os.remove(real)
    except OSError as e:
        return 500, {"error": f"Delete failed: {e}"}
    audit("file.delete", path=real)
    return 200, {"path": real, "deleted": True}


async def handle_file_list(query_params=None, **_):
    params = query_params or {}
    path = params.get("path", "")
    recursive = params.get("recursive", "false").lower() == "true"
    ok, status, info = _file_access_check(path)
    if not ok:
        return status, info
    real = info

    if not os.path.exists(real):
        return 404, {"error": f"Directory not found: {real}"}
    if not os.path.isdir(real):
        return 400, {
            "error": f"Path is not a directory: {real}",
            "hint": "Use GET /api/v1/files?path=... to read a file.",
        }

    entries = []
    truncated = False

    def add_entry(full):
        nonlocal truncated
        if len(entries) >= MAX_LIST_ENTRIES:
            truncated = True
            return False
        entries.append(_describe_entry(full, real))
        return True

    try:
        if recursive:
            stop = False
            for root, dirs, files in os.walk(real):
                for name in dirs:
                    if not add_entry(os.path.join(root, name)):
                        stop = True
                        break
                if stop:
                    break
                for name in files:
                    if not add_entry(os.path.join(root, name)):
                        stop = True
                        break
                if stop:
                    break
        else:
            for name in sorted(os.listdir(real)):
                if not add_entry(os.path.join(real, name)):
                    break
    except OSError as e:
        return 500, {"error": f"List failed: {e}"}

    return 200, {
        "path": real, "recursive": recursive, "entries": entries,
        "truncated": truncated, "limit": MAX_LIST_ENTRIES,
    }


def _describe_entry(full, root):
    try:
        st = os.lstat(full)
    except OSError:
        return {"name": os.path.relpath(full, root), "type": "unknown"}
    if os.path.isdir(full):
        typ = "dir"
    elif os.path.islink(full):
        typ = "link"
    else:
        typ = "file"
    return {
        "name": os.path.relpath(full, root),
        "type": typ,
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
    }


HANDLERS = {
    "handle_index": handle_index,
    "handle_health": handle_health,
    "handle_reload": handle_reload,
    "handle_auth_request": handle_auth_request,
    "handle_whoami": handle_whoami,
    "handle_list_tokens": handle_list_tokens,
    "handle_revoke_token": handle_revoke_token,
    "handle_list_windows": handle_list_windows,
    "handle_list_sessions": handle_list_sessions,
    "handle_get_screen": handle_get_screen,
    "handle_get_metadata": handle_get_metadata,
    "handle_send_text": handle_send_text,
    "handle_send_key": handle_send_key,
    "handle_set_title": handle_set_title,
    "handle_file_read": handle_file_read,
    "handle_file_write": handle_file_write,
    "handle_file_delete": handle_file_delete,
    "handle_file_list": handle_file_list,
}


# ─── Request handling ──────────────────────────────────────

async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    client_addr = f"{peer[0]}:{peer[1]}" if peer else "?"
    method = path = "-"
    status = 0
    try:
        req = await read_http_request(reader)
        if not req:
            writer.close()
            return
        method, path, query_params, headers, raw_body = req

        body = None
        ctype = (headers or {}).get("content-type", "").lower()
        if raw_body and not ctype.startswith("multipart/"):
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                status = 400
                writer.write(make_response(400, error_payload(
                    "Invalid JSON body",
                    hint="Request body must be valid JSON. See endpoints[].example for the expected fields."
                )))
                await writer.drain()
                return
            if not isinstance(body, dict):
                status = 400
                writer.write(make_response(400, error_payload(
                    "JSON body must be an object"
                )))
                await writer.drain()
                return

        handler_name, path_params = match_route(method, path)
        if not handler_name:
            allowed_methods = []
            for rm, pattern, _ in ROUTES:
                if re.match(pattern, path):
                    allowed_methods.append(rm)
            if allowed_methods:
                status = 405
                writer.write(make_response(405, error_payload(
                    f"Method {method} not allowed for {path}",
                    hint=f"Allowed methods on this path: {', '.join(sorted(set(allowed_methods)))}",
                    allowed_methods=sorted(set(allowed_methods)),
                )))
                await writer.drain()
                return
            status = 404
            writer.write(make_response(404, error_payload(
                f"Not found: {method} {path}",
                hint="Unknown path. See api.endpoints below for all available endpoints. "
                     "Hint: GET / or GET /api/v1 also returns this directory.",
            )))
            await writer.drain()
            return

        # Authentication and capability authorization.
        token_info = None
        if path not in PUBLIC_PATHS:
            token = _extract_token(headers)
            token_info = _check_token(token)
            if not token_info:
                status = 401
                audit("auth.reject", method=method, path=path, client=client_addr)
                writer.write(make_response(401, error_payload(
                    "Missing or invalid token",
                    hint="Call POST /api/v1/auth/request first, then pass the returned token as a Bearer token.",
                )))
                await writer.drain()
                return
            required_scope = HANDLER_SCOPES.get(handler_name)
            if not _token_has_scope(token_info, required_scope):
                status = 403
                audit("auth.scope_denied", method=method, path=path,
                      client=client_addr, required_scope=required_scope,
                      token_id=token_info.get("token_id"))
                writer.write(make_response(403, error_payload(
                    "Token lacks required capability",
                    required_scope=required_scope,
                    granted_scopes=token_info.get("scopes", []),
                )))
                await writer.drain()
                return

        handler = HANDLERS[handler_name]
        status, data = await handler(
            **path_params,
            query_params=query_params,
            body=body,
            raw_body=raw_body,
            headers=headers,
            client_addr=client_addr,
            token_info=token_info,
        )

        # Audit everything except health.
        if path != "/api/v1/health":
            audit(
                "request",
                method=method, path=path, status=status,
                client=client_addr,
                device=(token_info or {}).get("device_name"),
                params=query_params or None,
            )

        writer.write(make_response(status, data))
        await writer.drain()

    except HTTPRequestError as e:
        status = e.status
        audit("request.reject", method=method, path=path, client=client_addr,
              status=e.status, error=e.message)
        try:
            writer.write(make_response(e.status, error_payload(e.message)))
            await writer.drain()
        except Exception:
            pass
    except Exception as e:
        audit("error", method=method, path=path, client=client_addr, error=str(e))
        try:
            writer.write(make_response(500, {"error": str(e)}))
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ─── Entry point ───────────────────────────────────────────

PORT_FALLBACK_RANGE = 50  # Maximum number of port offsets to try.


async def _start_server_with_fallback(host, start_port, max_tries=PORT_FALLBACK_RANGE):
    """Start the server, incrementing the port if it's busy. Returns (server, port)."""
    last_err = None
    for offset in range(max_tries):
        port = start_port + offset
        try:
            server = await asyncio.start_server(
                handle_client, host, port,
                limit=max(MAX_REQUEST_LINE, MAX_HEADER_LINE) + 1024)
            if offset > 0:
                audit("server.port_fallback",
                      requested=start_port, actual=port, offset=offset)
            return server, port
        except OSError as e:
            last_err = e
            audit("server.port_busy", host=host, port=port, error=str(e))
            continue
    raise RuntimeError(
        f"No free port in {host}:{start_port}..{start_port + max_tries - 1}: {last_err}"
    )


def notify_user(title, message):
    """Push a non-blocking macOS notification-center toast via osascript."""
    def _esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')
    script = f'display notification "{_esc(message)}" with title "{_esc(title)}"'
    try:
        import subprocess
        subprocess.Popen(
            ["osascript", "-e", script],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        audit("notify.failed", error=str(e))


async def main(connection):
    global _connection, PORT
    _connection = connection
    _ensure_dirs()

    server, actual_port = await _start_server_with_fallback(HOST, PORT)
    PORT = actual_port
    audit("server.start", host=HOST, port=actual_port, version=VERSION)
    notify_user(
        "iterm2-harness started",
        f"v{VERSION} listening on {HOST}:{actual_port}",
    )

    # iTerm2's documented daemon lifecycle owns process termination. Keeping
    # serve_forever in a background task avoids depending on private websocket
    # attributes while still leaving the HTTP listener active.
    asyncio.create_task(server.serve_forever())

iterm2.run_forever(main)
