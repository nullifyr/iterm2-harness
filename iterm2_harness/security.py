"""Fail-closed configuration, credential migration, and per-session authority.

These controls constrain this API, NOT the OS authority of a writable terminal.
"""
import hashlib
import ipaddress
import json
import math
import re
import os
import secrets
import stat
import tempfile
import time
from pathlib import Path

from .common import APIError, boolean, identifier, integer, strict_json, text, utcnow

LEGACY_SCOPES = frozenset({"terminal.read", "terminal.write", "files.read", "files.write",
                           "files.delete", "service.reload", "auth.manage"})
SCOPES = LEGACY_SCOPES | {"session.create", "session.close", "layout.write", "status.write",
                          "variables.write"}
DEFAULT_SCOPES = ["terminal.read", "terminal.write"]
DEFAULT_CONFIG = {"host": "127.0.0.1", "port": 6770, "allow_remote": False,
                  "file_access": {"enabled": False, "allowed_paths": []},
                  "auth_prompt_timeout": 60, "require_input_approval": False,
                  "protect_focused_session": True, "allowed_profiles": []}


def load_config(root, env=None):
    env = os.environ if env is None else env
    home = Path(env.get("ITERM2_HARNESS_HOME", str(Path.home() / ".iterm2-harness"))).expanduser()
    explicit = env.get("ITERM2_HARNESS_CONFIG")
    path = Path(explicit).expanduser() if explicit else home / "config.json"
    if not explicit and not path.exists():
        path = Path(root) / "config.json"
    cfg = dict(DEFAULT_CONFIG)
    if path.exists():
        cfg.update(strict_json(path.read_bytes()))
    elif explicit:
        raise APIError(400, "config_missing", "Explicit configuration does not exist")
    cfg["host"] = env.get("ITERM2_HARNESS_HOST", cfg["host"])
    cfg["port"] = integer(env.get("ITERM2_HARNESS_PORT", cfg["port"]), "port", 1, 65535)
    cfg["auth_prompt_timeout"] = integer(env.get("ITERM2_HARNESS_AUTH_TIMEOUT", cfg["auth_prompt_timeout"]),
                                         "auth_prompt_timeout", 10, 120)
    for key in ("allow_remote", "require_input_approval", "protect_focused_session"):
        boolean(cfg[key], key)
    try:
        address = ipaddress.ip_address(cfg["host"])
    except ValueError:
        raise APIError(400, "invalid_bind", "Bind host must be a literal IP address")
    if not address.is_loopback and not cfg["allow_remote"]:
        raise APIError(400, "remote_not_enabled", "Non-loopback bind requires allow_remote=true; use a secure tunnel")
    fa = cfg["file_access"]
    if not isinstance(fa, dict):
        raise APIError(400, "invalid_file_policy", "file_access must be an object")
    boolean(fa.get("enabled", False), "file_access.enabled")
    roots = fa.get("allowed_paths", [])
    if not isinstance(roots, list) or any(not isinstance(p, str) or not p for p in roots):
        raise APIError(400, "invalid_file_policy", "allowed_paths must contain absolute paths")
    roots = [os.path.expanduser(p) for p in roots]
    if any(not os.path.isabs(p) for p in roots):
        raise APIError(400, "invalid_file_policy", "allowed_paths must be absolute")
    cfg["file_access"] = {"enabled": fa.get("enabled", False),
                          "allowed_paths": [os.path.realpath(p) for p in roots]}
    if not isinstance(cfg["allowed_profiles"], list) or any(not isinstance(p, str) for p in cfg["allowed_profiles"]):
        raise APIError(400, "invalid_profiles", "allowed_profiles must be a list of names")
    cfg["home"] = home
    cfg["config_path"] = path
    return cfg


def token_hash(token):
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()


def allowed_session(info, sid):
    targets = info.get("session_ids")
    return targets is None or sid in targets


def authorize(info, scope, sid=None):
    if not info:
        raise APIError(401, "unauthorized", "Missing, revoked, or expired credential")
    if scope and scope not in info.get("scopes", []):
        raise APIError(403, "scope_denied", "Required capability: " + scope)
    if sid is not None and not allowed_session(info, sid):
        raise APIError(403, "session_denied", "Credential is not authorized for that session")


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=".tokens-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class TokenStore:
    """Single-event-loop owner. Raw legacy keys are migrated, never looked up."""
    def __init__(self, path):
        self.path = Path(path)
        self.data = {}
        self.persisted_use = {}
        if self.path.exists():
            if self.path.is_symlink() or self.path.stat().st_size > 1024 * 1024:
                raise APIError(500, "invalid_token_store", "Unsafe credential store")
            self.data = strict_json(self.path.read_bytes())
        changed = False
        normalized = {}
        for key, record in self.data.items():
            if not isinstance(record, dict):
                raise APIError(500, "invalid_token_store", "Invalid credential record")
            record = dict(record)
            if not key.startswith("sha256:"):
                key = token_hash(key)
                record.setdefault("scopes", sorted(LEGACY_SCOPES))
                record["migrated_from_v1"] = True
                changed = True
            if not isinstance(record.get("scopes"), list) or any(s not in SCOPES for s in record["scopes"]):
                raise APIError(500, "invalid_token_store", "Invalid stored capabilities")
            # Fixed legacy privileges: adding a capability must never widen old grants.
            if record.get("migrated_from_v1"):
                record["scopes"] = sorted(set(record["scopes"]) & LEGACY_SCOPES)
            if "token_id" not in record:
                record["token_id"] = "legacy-" + hashlib.sha256(key.encode()).hexdigest()[:16]
                changed = True
            record.setdefault("session_ids", None)
            targets = record["session_ids"]
            if targets is not None:
                if not isinstance(targets, list) or not targets:
                    raise APIError(500, "invalid_token_store", "Invalid stored session targets")
                for target in targets:
                    identifier(target)
            expiry = record.get("expires_at")
            if expiry is not None and (type(expiry) not in (int, float) or not math.isfinite(expiry)):
                raise APIError(500, "invalid_token_store", "Invalid stored expiry")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", key) or key in normalized:
                raise APIError(500, "invalid_token_store", "Invalid or colliding credential hash")
            normalized[key] = record
        self.data = normalized
        if changed:
            self.save()

    def save(self):
        atomic_json(self.path, self.data)

    def lookup(self, token, now=None):
        if not isinstance(token, str) or not 1 <= len(token) <= 512:
            return None
        now = time.time() if now is None else now
        key = token_hash(token)  # NEVER fall back to data.get(token): that accepts hashes as passwords.
        item = self.data.get(key)
        if not item or (item.get("expires_at") is not None and now >= item["expires_at"]):
            return None
        item["last_used_at"] = utcnow()
        if now - self.persisted_use.get(key, 0) >= 60:
            self.save()
            self.persisted_use[key] = now
        return dict(item)

    def issue(self, name, scopes, session_ids, expires_in):
        if len(self.data) >= 1024:
            raise APIError(503, "token_capacity", "Revoke unused credentials first")
        token = secrets.token_urlsafe(32)
        record = {"token_id": secrets.token_hex(16), "device_name": name,
                  "scopes": scopes, "session_ids": session_ids,
                  "created_at": utcnow(), "last_used_at": None,
                  "expires_at": time.time() + expires_in}
        self.data[token_hash(token)] = record
        self.save()
        return dict(record, token=token)

    def inventory(self):
        fields = ("token_id", "device_name", "scopes", "session_ids", "created_at",
                  "last_used_at", "expires_at", "migrated_from_v1")
        return [{k: item.get(k) for k in fields} for item in self.data.values()]

    def revoke(self, token_id):
        for key, record in list(self.data.items()):
            if record["token_id"] == token_id:
                del self.data[key]
                self.save()
                return True
        return False


def grant_request(body):
    name = text(body.get("device_name", "unknown-device"), "device_name", 128)
    scopes = body.get("scopes", DEFAULT_SCOPES)
    if not isinstance(scopes, list) or any(not isinstance(s, str) or s not in SCOPES for s in scopes):
        raise APIError(400, "invalid_scopes", "Request documented capabilities only")
    scopes = sorted(set(scopes))
    targets = body.get("session_ids")
    if targets is not None:
        if not isinstance(targets, list) or not 1 <= len(targets) <= 256:
            raise APIError(400, "invalid_targets", "session_ids must be null or a nonempty list")
        targets = sorted(set(identifier(s) for s in targets))
    expiry = integer(body.get("expires_in", 86400), "expires_in", 60, 2592000)
    return name, scopes, targets, expiry


class Audit:
    """Bounded ordinary audit, not a tamper-proof compliance ledger."""
    def __init__(self, home):
        self.directory = Path(home) / "logs"

    def __call__(self, event, **fields):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory.parent, 0o700)
        path = self.directory / (utcnow()[:10] + ".log")
        if path.exists() and path.stat().st_size >= 8 * 1024 * 1024:
            os.replace(path, path.with_suffix(".previous.log"))
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(ts=utcnow(), event=event, **fields), ensure_ascii=True) + "\n")
