"""Canonical route, scope, and discovery table. v1 aliases are explicit."""
import re

# method, suffix, capability, operation, mutating, v1-compatible
ROUTES = [
    ("GET", "/health", None, "health", False, True),
    ("GET", "/openapi.json", None, "openapi", False, False),
    ("GET", "/capabilities", None, "capabilities", False, False),
    ("POST", "/auth/request", None, "grant", False, True),
    ("GET", "/auth/whoami", None, "whoami", False, True),
    ("GET", "/auth/tokens", "auth.manage", "tokens", False, True),
    ("DELETE", "/auth/tokens/{token_id}", "auth.manage", "revoke", True, True),
    ("POST", "/reload", "service.reload", "reload", True, True),
    ("GET", "/sessions", "terminal.read", "sessions", False, True),
    ("GET", "/windows", "terminal.read", "windows", False, True),
    ("GET", "/snapshot", "terminal.read", "snapshot", False, False),
    ("GET", "/focus", "terminal.read", "focus", False, False),
    ("GET", "/events", "terminal.read", "events", False, False),
    ("GET", "/actions/{action_id}", None, "receipt", False, False),
    ("GET", "/sessions/{sid}/screen", "terminal.read", "screen", False, True),
    ("GET", "/sessions/{sid}/metadata", "terminal.read", "metadata", False, True),
    ("GET", "/sessions/{sid}/status", "terminal.read", "status", False, False),
    ("PUT", "/sessions/{sid}/status", "status.write", "report", True, False),
    ("GET", "/sessions/{sid}/commands", "terminal.read", "commands", False, False),
    ("GET", "/sessions/{sid}/commands/{command_id}", "terminal.read", "command", False, False),
    ("POST", "/sessions/{sid}/lease", "terminal.write", "lease", True, False),
    ("DELETE", "/sessions/{sid}/lease", "terminal.write", "release", True, False),
    ("POST", "/sessions/{sid}/send-text", "terminal.write", "text", True, True),
    ("POST", "/sessions/{sid}/send-key", "terminal.write", "key", True, True),
    ("POST", "/sessions/{sid}/set-title", "terminal.write", "title", True, True),
    ("POST", "/sessions/{sid}/activate", "layout.write", "activate", True, False),
    ("POST", "/sessions/{sid}/split", "session.create", "split", True, False),
    ("DELETE", "/sessions/{sid}", "session.close", "close", True, False),
    ("POST", "/windows", "session.create", "window", True, False),
    ("POST", "/windows/{wid}/tabs", "session.create", "tab", True, False),
    ("GET", "/sessions/{sid}/variables/{name}", "terminal.read", "get_variable", False, False),
    ("PUT", "/sessions/{sid}/variables/{name}", "variables.write", "set_variable", True, False),
    ("GET", "/files", "files.read", "file_read", False, True),
    ("POST", "/files", "files.write", "file_write", True, True),
    ("DELETE", "/files", "files.delete", "file_delete", True, True),
    ("GET", "/files/list", "files.read", "file_list", False, True),
]
PUBLIC = {"health", "grant", "index"}


def resolve(method, path):
    if method == "GET" and path in ("/", "/api", "/api/v1", "/api/v2"):
        return (method, "", None, "index", False, True), {}, False
    legacy = path.startswith("/api/v1/")
    prefix = "/api/v1" if legacy else "/api/v2"
    if not path.startswith(prefix + "/"):
        return None, {}, legacy
    suffix = path[len(prefix):]
    for route in ROUTES:
        rm, template, _, _, _, compatible = route
        if rm != method or (legacy and not compatible):
            continue
        pattern = re.sub(r"\{([a-z_]+)\}", r"(?P<\1>[^/]+)", template)
        match = re.fullmatch(pattern, suffix)
        if match:
            return route, match.groupdict(), legacy
    return None, {}, legacy


def directory():
    return [{"method": method, "path": "/api/v2" + path, "scope": scope,
             "auth": operation not in PUBLIC, "mutating": mutating,
             "idempotency_required": mutating, "v1_alias": "/api/v1" + path if legacy else None}
            for method, path, scope, operation, mutating, legacy in ROUTES]


def openapi():
    from . import __version__
    paths = {}
    for method, path, scope, operation, mutating, legacy in ROUTES:
        entry = {"operationId": operation, "summary": operation.replace("_", " "),
                 "security": [] if operation in PUBLIC else [{"bearerAuth": []}],
                 "x-harness-capability": scope,
                 "responses": {"200": {"description": "Success; inspect receipt for mutations"},
                               "400": {"description": "Invalid input"},
                               "403": {"description": "Not authorized"},
                               "409": {"description": "Stale context, lease, cursor, or epoch"}}}
        parameters = [{"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
                      for name in re.findall(r"\{([a-z_]+)\}", path)]
        if mutating:
            parameters += [{"name": name, "in": "header", "required": True, "schema": {"type": "string"}}
                           for name in ("X-Harness-Epoch", "Idempotency-Key")]
        if parameters:
            entry["parameters"] = parameters
        if method in ("POST", "PUT", "DELETE"):
            entry["requestBody"] = {"required": False, "content": {"application/json": {
                "schema": {"type": "object"}}}}
        paths.setdefault("/api/v2" + path, {})[method.lower()] = entry
    return {"openapi": "3.1.0", "info": {"title": "iTerm2 Harness", "version": __version__,
            "description": "Route/security discovery. See docs/API.md for operation payloads and constraints."},
            "paths": paths, "components": {"securitySchemes": {"bearerAuth": {
                "type": "http", "scheme": "bearer"}}}}
