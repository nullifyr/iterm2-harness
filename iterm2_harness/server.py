"""HTTP admission, authorization, observations, and mutation policy composition."""
import asyncio
import functools
import json
import secrets
import time
from collections import OrderedDict, deque

from . import __version__
from .common import APIError, boolean, digest, identifier, integer, text, utcnow
from .filesystem import Files
from .protocol import MAX_BODY, SMALL_BODY, check_origin, flush, read_body, read_head, response
from .routes import PUBLIC, directory, resolve, openapi
from .security import SCOPES, Audit, TokenStore, allowed_session, authorize, grant_request
from .state import Actions


class Server:
    def __init__(self, config, adapter, events, observations, consent, root):
        self.config, self.adapter = config, adapter
        self.events, self.observations = events, observations
        self.consent = consent
        self.tokens = TokenStore(config["home"] / "tokens.json")
        self.audit = Audit(config["home"])
        self.files = Files(config["file_access"], protected=(config["home"], root))
        self.actions = Actions(events.epoch)
        self.stop = asyncio.Event()
        self.reload_requested = False
        self.clients, self.by_ip = set(), {}
        self.stream_count = 0
        self.auth_attempts = OrderedDict()
        self.auth_pending = False

    def authenticate(self, headers):
        value = headers.get("authorization", "")
        if not value.lower().startswith("bearer "):
            raise APIError(401, "unauthorized", "Use Authorization: Bearer <token>")
        token = value[7:].strip()
        info = self.tokens.lookup(token)
        authorize(info, None)
        return token, info

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip = peer[0]
        if len(self.clients) >= 64 or self.by_ip.get(ip, 0) >= 16:
            try:
                # Do not allocate another drain waiter for a rejected connection.
                writer.write(response(429, {"error": "connection_limit"}))
            finally:
                writer.close()
            return
        task = asyncio.current_task()
        self.clients.add((task, writer))
        self.by_ip[ip] = self.by_ip.get(ip, 0) + 1
        streamed = False
        request_id = secrets.token_hex(12)
        method, path, operation = "?", "?", "?"
        try:
            method, path, query, headers, length = await read_head(reader)
            check_origin(headers, self.config)
            route, params, legacy = resolve(method, path)
            if route is None:
                raise APIError(404, "route_missing", "See GET / for the API directory")
            _, _, scope, operation, mutating, _ = route
            token, info = None, None
            if operation not in PUBLIC:
                token, info = self.authenticate(headers)
                authorize(info, scope, params.get("sid"))
            if "sid" in params:
                self.adapter.session(params["sid"])  # Concrete, live ID; never "all"/"active".
            if method == "GET" and length:
                raise APIError(400, "get_body", "GET request bodies are not supported")
            body = await read_body(reader, headers, length, MAX_BODY if operation == "file_write" else SMALL_BODY)
            if operation == "events":
                if self.stream_count >= 8:
                    raise APIError(429, "stream_limit", "At most eight event streams may be open")
                if "session_id" in query:
                    authorize(info, "terminal.read", identifier(query["session_id"]))
                cursor = headers.get("last-event-id", query.get("since"))
                sequence = self.events.position(cursor)
                self.stream_count += 1
                streamed = True
                try:
                    await self.stream(writer, token, sequence, query)
                finally:
                    self.stream_count -= 1
                return
            if operation == "grant":
                status, data = await self.grant(body, ip)
            elif mutating:
                status, data = await self.mutate(route, params, body, query, headers, token, info, legacy)
            else:
                status, data = 200, await self.read(operation, params, query, info)
            if operation != "openapi":
                data["request_id"] = request_id
            self.audit("request", request_id=request_id, operation=operation, status=status,
                       actor_id=(info or {}).get("token_id"))
            await flush(writer, response(status, data, self.events.epoch, decorate=operation != "openapi"))
        except APIError as error:
            if not streamed:
                await self.error_response(writer, error, request_id)
        except asyncio.CancelledError:
            raise
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception as error:
            # No raw exceptions, tokens, commands, or query strings in logs/responses.
            try:
                self.audit("internal_error", request_id=request_id, exception_type=type(error).__name__)
            except Exception:
                pass
            if not streamed:
                await self.error_response(writer, APIError(500, "internal_error", "Request failed; consult the local audit"), request_id)
        finally:
            writer.close()
            self.clients.discard((task, writer))
            self.by_ip[ip] -= 1
            if not self.by_ip[ip]:
                del self.by_ip[ip]
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (Exception, asyncio.CancelledError):
                pass

    async def error_response(self, writer, error, request_id):
        try:
            await flush(writer, response(error.status, dict(error.payload(), request_id=request_id), self.events.epoch))
        except (Exception, asyncio.CancelledError):
            pass

    async def grant(self, body, ip):
        now = time.monotonic()
        recent = [t for t in self.auth_attempts.get(ip, []) if now-t < 60]
        self.auth_attempts[ip] = recent
        self.auth_attempts.move_to_end(ip)
        while len(self.auth_attempts) > 128:
            self.auth_attempts.popitem(last=False)
        if len(recent) >= 5 or self.auth_pending:
            raise APIError(429, "approval_rate_limit", "Approval busy or request rate exceeded")
        recent.append(now)
        name, scopes, targets, expiry = grant_request(body)
        if targets:
            for sid in targets:
                self.adapter.session(sid)
        message = ("Device (unverified name): %s\nNetwork peer: %s\nCapabilities: %s\n"
                   "Sessions: %s\nExpires in: %d seconds\n\n"
                   "Terminal input and profile creation may execute code with your user privileges. "
                   "This is not an OS sandbox.") % (name, ip, ", ".join(scopes), ", ".join(targets or ["ALL sessions"]), expiry)
        self.auth_pending = True
        try:
            allowed = await self.consent(message, self.config["auth_prompt_timeout"])
        finally:
            self.auth_pending = False
        if not allowed:
            self.audit("auth.denied", device_name=name)
            raise APIError(403, "authorization_denied", "Local authorization was denied or timed out")
        self.audit("auth.granted", device_name=name, scopes=scopes, session_ids=targets)
        return 201, self.tokens.issue(name, scopes, targets, expiry)

    def filtered_states(self, info):
        return [state for sid, state in self.observations.sessions.items() if allowed_session(info, sid)]

    async def read(self, operation, params, query, info):
        sid = params.get("sid")
        if operation == "index":
            return {"service": "iterm2-harness", "version": __version__, "endpoints": directory()}
        if operation == "health":
            if not self.adapter.alive:
                raise APIError(503, "not_ready", "iTerm2 is not connected")
            return {"status": "ok", "server": "iterm2-harness", "host": self.config["host"],
                    "port": self.config["port"], "last_backend_probe": self.adapter.last_probe}
        if operation == "openapi":
            return openapi()
        if operation == "capabilities":
            return {"features": self.adapter.capabilities(), "capabilities": sorted(SCOPES),
                    "events": {"replay_capacity": self.events.events.maxlen, "cursor": self.events.cursor,
                               "delivery": "bounded_replay_with_explicit_resync", "persistent": False},
                    "mutations": {"epoch_required": True, "idempotency_required": True,
                                  "receipts_persist_across_restart": False,
                                  "session_lease_required": ["send-text", "send-key", "set-title", "close"]}}
        if operation == "whoami":
            return dict(info)
        if operation == "tokens":
            return {"tokens": self.tokens.inventory()}
        if operation == "receipt":
            for (actor, _), record in self.actions.receipts.items():
                if actor == info["token_id"] and record["action_id"] == params["action_id"]:
                    return self.actions.reply(record)[1]
            raise APIError(404, "receipt_missing", "Receipt not found for this credential/epoch")
        if operation == "focus":
            result = self.adapter.focus()
            if result["session_id"] and not allowed_session(info, result["session_id"]):
                for key in ("session_id", "tab_id", "window_id"):
                    result[key] = None
            return result
        if operation == "snapshot":
            return {"cursor": self.events.cursor, "observed_at": utcnow(),
                    "sessions": [dict(state["metadata"], status=self.observations.status(state["session_id"]))
                                 for state in self.filtered_states(info)],
                    "coverage_started_at": self.observations.started_at,
                    "observation_limit": self.observations.max_sessions, "native_snapshot_atomic": False}
        if operation == "sessions":
            if query.get("regex", "false").lower() == "true":
                raise APIError(400, "regex_disabled", "Use bounded substring filters")
            semaphore = asyncio.Semaphore(8)

            async def describe(state):
                async with semaphore:
                    try:
                        return await self.adapter.metadata(state["session_id"])
                    except APIError as error:
                        if error.status == 404:
                            return None
                        raise
            items = await asyncio.gather(*(describe(s) for s in self.filtered_states(info)))
            mapping = {"name": "name", "job": "job_name", "command": "command_line", "path": "path"}
            items = [item for item in items if item and all(query.get(k, "").lower() in item.get(v, "").lower()
                                                            for k, v in mapping.items())]
            return {"sessions": items, "filter": query, "observation_limit": self.observations.max_sessions}
        if operation == "windows":
            windows = {}
            for state in self.filtered_states(info):
                meta = state["metadata"]
                if meta["window_id"] is None:
                    continue
                tabs = windows.setdefault(meta["window_id"], {})
                tabs.setdefault(meta["tab_id"], []).append(dict(meta))
            return {"windows": [{"window_id": wid, "tabs": [{"tab_id": tid, "sessions": sessions}
                                for tid, sessions in tabs.items()]} for wid, tabs in windows.items()]}
        if operation == "screen":
            return await self.adapter.screen(sid, query)
        if operation == "metadata":
            return await self.adapter.metadata(sid)
        if operation == "status":
            return self.observations.status(sid)
        if operation in ("commands", "command"):
            result = self.observations.history(sid)
            if operation == "commands":
                return result
            for command in result["commands"]:
                if command["command_id"] == params["command_id"]:
                    return dict(command)
            raise APIError(404, "command_not_observed", "Command is not in retained observation history")
        if operation == "get_variable":
            name = self.variable_name(params["name"])
            value = await self.adapter.rpc(self.adapter.session(sid).async_get_variable(name))
            value = str(value or "")
            return {"name": name, "value": value[:4096], "truncated": len(value) > 4096,
                    "trusted_instructions": False}
        if operation in ("file_read", "file_list"):
            function = self.files.read if operation == "file_read" else self.files.list
            return await asyncio.get_running_loop().run_in_executor(None, function, query)
        raise APIError(501, "not_implemented", "Operation not implemented")

    @staticmethod
    def variable_name(name):
        text(name, "variable_name", 128)
        if not name.startswith("user.harness.") or not all(c.isalnum() or c in "_." for c in name):
            raise APIError(403, "variable_namespace", "Only user.harness.* is exposed")
        return name

    async def mutate(self, route, params, body, query, headers, token, info, legacy):
        method, template, scope, operation, _, _ = route
        epoch = headers.get("x-harness-epoch", self.events.epoch if legacy else None)
        key = headers.get("idempotency-key", secrets.token_hex(16) if legacy else None)
        record, fresh = self.actions.begin(info["token_id"], key,
                                           [method, template, params, body, query], epoch)
        if not fresh:
            return self.actions.reply(record, True)
        sid = params.get("sid")
        lock_key = sid or ("files:" + query.get("path", "") if operation.startswith("file_") else "workspace")
        entered_effect = False
        try:
            async with self.actions.lock(lock_key):
                context_guard = operation in ("text", "key", "title", "close")
                expected_context = body.get("expected_context")
                if context_guard:
                    if not legacy:
                        text(expected_context, "expected_context", 64)
                    elif expected_context is None:
                        expected_context = (await self.adapter.metadata(sid))["context_id"]
                focus_approved = False

                async def recheck():
                    current = self.tokens.lookup(token)
                    authorize(current, scope, sid)
                    if sid:
                        self.adapter.session(sid)
                    if operation in ("text", "key", "title", "close"):
                        self.actions.check_lease(sid, current["token_id"], body.get("lease_id"), required=not legacy)
                    if context_guard:
                        observed = await self.adapter.metadata(sid)
                        if observed["context_id"] != expected_context:
                            raise APIError(409, "context_changed", "Session job/host/path changed; inspect and approve a new request")
                    if operation in ("text", "key") and self.config["protect_focused_session"] and not focus_approved:
                        # The initial check is allowed to reach local consent; the
                        # dispatch/second-write check must refuse newly focused input.
                        if dispatch_check and self.adapter.focus()["session_id"] == sid:
                            raise APIError(409, "focus_changed", "Target became focused; local consent is required")
                    return current

                dispatch_check = False
                await recheck()
                if operation in ("window", "tab", "split"):
                    if info.get("session_ids") is not None:
                        raise APIError(403, "global_grant_required", "Creation requires an explicit all-session grant")
                    profile = body.get("profile")
                    if profile is not None and profile not in self.config["allowed_profiles"]:
                        raise APIError(403, "profile_denied", "Profile is not in allowed_profiles")
                # A report-only token cannot auto-approve or turn agent output into policy.
                focused = sid and self.adapter.focus()["session_id"] == sid
                needs_approval = operation in ("window", "tab", "split", "close", "reload") or (
                    operation in ("text", "key") and (self.config["require_input_approval"] or
                    (focused and self.config["protect_focused_session"])))
                if needs_approval:
                    description = json.dumps({"operation": operation, "target": sid or params.get("wid"),
                                              "payload": {k: v for k, v in body.items() if k != "lease_id"}},
                                             ensure_ascii=True)
                    if len(description) > 8000:
                        raise APIError(413, "approval_payload_too_large", "Split the request; approval must show its complete payload")
                    if not await self.consent("Approve this exact action?\n" + description, self.config["auth_prompt_timeout"]):
                        raise APIError(403, "action_denied", "Local approval denied or timed out")
                    focus_approved = True
                dispatch_check = True
                await recheck()  # Revalidate context and authority after consent, and again before Enter.
                self.audit("action.dispatch", action_id=record["action_id"], actor_id=info["token_id"],
                           operation=operation, session_id=sid, payload_hash=record["fingerprint"])
                entered_effect = True
                result = await self.effect(operation, params, body, query, info, recheck)
                self.actions.finish(record, 200, result)
                self.audit("action.acknowledged", action_id=record["action_id"], operation=operation)
        except APIError as error:
            self.actions.finish(record, error.status, error.payload(), "unknown" if entered_effect else "rejected")
        except asyncio.CancelledError:
            self.actions.finish(record, 503, {"error": "interrupted", "message": "Outcome unknown; inspect target before any retry"}, "unknown")
            raise
        except Exception:
            self.actions.finish(record, 503, {"error": "outcome_unknown", "message": "Inspect target before any retry"}, "unknown")
        return self.actions.reply(record)

    async def effect(self, operation, params, body, query, info, recheck):
        sid, actor = params.get("sid"), info["token_id"]
        if operation == "lease":
            return self.actions.acquire(sid, actor, integer(body.get("ttl_seconds", 60), "ttl_seconds", 5, 120))
        if operation == "release":
            return self.actions.release(sid, actor, body.get("lease_id"))
        if operation == "report":
            return self.observations.report_agent(sid, body, actor)
        if operation in ("text", "key"):
            return await self.adapter.input(sid, body, key=operation == "key", recheck=recheck)
        if operation == "title":
            title = text(body.get("title"), "title", 1024, empty=True)
            await self.adapter.rpc(self.adapter.session(sid).async_set_name(title))
            return {"session_id": sid, "title": title}
        if operation == "activate":
            await self.adapter.rpc(self.adapter.session(sid).async_activate())
            return {"session_id": sid, "activated": True}
        if operation == "close":
            # The broker already obtained fresh, exact-target LOCAL approval and
            # rechecked the lease. Avoid a second, unbounded iTerm2 modal dialog.
            await self.adapter.rpc(self.adapter.session(sid).async_close(force=True))
            self.actions.leases.pop(sid, None)
            return {"session_id": sid, "close_acknowledged": True, "process_exit_verified": False}
        if operation in ("window", "tab", "split"):
            return await self.adapter.create(operation, sid or params.get("wid"), body)
        if operation == "set_variable":
            name = self.variable_name(params["name"])
            value = text(body.get("value"), "value", 4096, empty=True)
            await self.adapter.rpc(self.adapter.session(sid).async_set_variable(name, value))
            return {"name": name, "updated": True}
        if operation == "revoke":
            return {"revoked": self.tokens.revoke(params["token_id"])}
        if operation == "reload":
            self.reload_requested = True
            asyncio.get_running_loop().call_later(0.5, self.stop.set)
            return {"reload_scheduled": True}
        if operation in ("file_write", "file_delete"):
            function = functools.partial(self.files.write, query, body) if operation == "file_write" else functools.partial(self.files.delete, query)
            return await asyncio.get_running_loop().run_in_executor(None, function)
        raise APIError(501, "not_implemented", "Operation not implemented")

    async def stream(self, writer, token, sequence, query):
        if "session_id" in query:
            authorize(self.tokens.lookup(token), "terminal.read", identifier(query["session_id"]))
        await flush(writer, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
                            b"Connection: close\r\nX-Accel-Buffering: no\r\n\r\n")
        while not self.stop.is_set():
            info = self.tokens.lookup(token)
            if not info or "terminal.read" not in info.get("scopes", []):
                return
            self.events.changed.clear()
            try:
                items, sequence = self.events.read(sequence, info)
            except APIError:
                payload = {"reason": "history_gap", "current_cursor": self.events.cursor}
                await flush(writer, ("event: resync_required\ndata: " + json.dumps(payload) + "\n\n").encode())
                return
            for event in items:
                current = self.tokens.lookup(token)
                if not current or "terminal.read" not in current.get("scopes", []):
                    return
                if event["session_id"] and not allowed_session(current, event["session_id"]):
                    continue
                if query.get("session_id") and event["session_id"] not in (None, query["session_id"]):
                    continue
                frame = "id: %s\nevent: %s\ndata: %s\n\n" % (event["id"], event["event"], json.dumps(event, ensure_ascii=True))
                await flush(writer, frame.encode())
            try:
                await asyncio.wait_for(self.events.changed.wait(), 5)
            except asyncio.TimeoutError:
                # Reauthorization precedes heartbeat delivery too.
                if not self.tokens.lookup(token):
                    return
                await flush(writer, b": heartbeat\n\n")

    async def close_clients(self):
        clients = list(self.clients)
        for task, writer in clients:
            writer.close()
            task.cancel()
        await asyncio.gather(*(task for task, _ in clients), return_exceptions=True)
