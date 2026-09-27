"""Only documented iTerm2 APIs live here; monitors are explicitly supervised."""
import asyncio
import inspect
import time

from .common import APIError, boolean, identifier, integer, text, utcnow, digest

KEYS = {"enter": "\r", "return": "\r", "tab": "\t", "escape": "\x1b", "esc": "\x1b",
        "space": " ", "backspace": "\x7f", "delete": "\x1b[3~", "up": "\x1b[A",
        "down": "\x1b[B", "left": "\x1b[D", "right": "\x1b[C", "home": "\x1b[H", "end": "\x1b[F"}
KEYS.update({"ctrl+" + chr(c): chr(c-96) for c in range(97, 123)})


class Adapter:
    def __init__(self, connection, events, observations, sdk=None):
        if sdk is None:
            import iterm2 as sdk
        self.sdk, self.connection = sdk, connection
        self.events, self.observations = events, observations
        self.app = None
        self.alive = False
        self.jobs = {}
        self.global_jobs = []
        self.application_active = None
        self.transaction_lock = asyncio.Lock()
        self.last_probe = None

    async def rpc(self, awaitable):
        try:
            return await asyncio.wait_for(awaitable, 5)
        except asyncio.TimeoutError:
            raise APIError(503, "iterm_timeout", "iTerm2 did not acknowledge; mutation outcome may be unknown")
        except APIError:
            raise
        except Exception:
            raise APIError(503, "iterm_error", "iTerm2 RPC failed; do not blindly retry a mutation")

    async def start(self):
        self.app = await self.rpc(self.sdk.async_get_app(self.connection))
        self.alive = True
        await self.reconcile()
        if hasattr(self.sdk, "FocusMonitor"):
            self.global_jobs.append(asyncio.create_task(self.watch_focus()))
        for cls in ("NewSessionMonitor", "SessionTerminationMonitor", "LayoutChangeMonitor"):
            if hasattr(self.sdk, cls):
                self.global_jobs.append(asyncio.create_task(self.watch_layout(cls)))

    def all_sessions(self):
        result = {}
        for window in self.app.windows:
            for tab in window.tabs:
                for session in getattr(tab, "all_sessions", tab.sessions):
                    result[session.session_id] = (session, window.window_id, tab.tab_id)
        for session in getattr(self.app, "buried_sessions", []):
            result.setdefault(session.session_id, (session, None, None))
        return result

    def session(self, sid):
        identifier(sid)
        if not self.alive:
            raise APIError(503, "iterm_disconnected", "iTerm2 connection is not ready")
        item = self.all_sessions().get(sid)
        if not item:
            raise APIError(404, "session_missing", "Session is not currently available")
        return item[0]

    async def reconcile(self):
        sessions = self.all_sessions()
        for sid in set(self.observations.sessions) - set(sessions):
            for task in self.jobs.pop(sid, []):
                task.cancel()
            self.observations.remove(sid)
        for sid, (session, wid, tid) in list(sessions.items())[:self.observations.max_sessions]:
            fresh = sid not in self.observations.sessions
            state = self.observations.ensure(sid)
            grid = getattr(session, "grid_size", None)
            state["metadata"] = {"session_id": sid, "name": str(session.name)[:1024],
                                 "window_id": wid, "tab_id": tid, "buried": wid is None,
                                 "columns": getattr(grid, "width", 0), "rows": getattr(grid, "height", 0)}
            if fresh:
                self.events.publish("session.created", sid, **state["metadata"])
                jobs = []
                if hasattr(self.sdk, "PromptMonitor"):
                    jobs.append(asyncio.create_task(self.watch_prompt(sid)))
                else:
                    state["prompt_monitor"] = "unsupported"
                if hasattr(session, "get_screen_streamer"):
                    jobs.append(asyncio.create_task(self.watch_screen(sid)))
                self.jobs[sid] = jobs

    async def supervise(self, stop):
        """A public, bounded RPC probes connection health; run_forever alone does not."""
        while not stop.is_set():
            await self.rpc(self.app.async_get_variable("pid"))
            self.last_probe = utcnow()
            await self.reconcile()
            try:
                await asyncio.wait_for(stop.wait(), 2)
            except asyncio.TimeoutError:
                pass

    async def close(self):
        self.alive = False
        tasks = self.global_jobs + [t for group in self.jobs.values() for t in group]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for sid in list(self.observations.sessions):
            self.observations.monitor_failed(sid, "backend_disconnected")

    async def watch_prompt(self, sid):
        try:
            modes = self.sdk.PromptMonitor.Mode
            async with self.sdk.PromptMonitor(self.connection, sid,
                    modes=[modes.PROMPT, modes.COMMAND_START, modes.COMMAND_END]) as monitor:
                self.observations.ensure(sid)["prompt_monitor"] = "subscribed"
                include_id = "include_id" in inspect.signature(monitor.async_get).parameters
                while True:
                    item = await (monitor.async_get(include_id=True) if include_id else monitor.async_get())
                    if not isinstance(item, tuple) or len(item) not in (2, 3):
                        raise ValueError("unsupported prompt shape")
                    mode, value = item[:2]
                    native_id = item[2] if len(item) == 3 else None
                    kind = {modes.PROMPT: "prompt.ready", modes.COMMAND_START: "command.started",
                            modes.COMMAND_END: "command.finished"}.get(mode)
                    if kind:
                        self.observations.prompt_event(sid, kind, value, native_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            if sid in self.observations.sessions:
                self.observations.monitor_failed(sid, "unsupported_or_failed_prompt_monitor")

    async def watch_screen(self, sid):
        pending = None

        async def publish_later():
            await asyncio.sleep(0.5)
            self.events.publish("screen.invalidated", sid)

        try:
            async with self.session(sid).get_screen_streamer(want_contents=False) as monitor:
                while True:
                    await monitor.async_get()
                    # Drain the SDK continuously. At most one trailing-edge
                    # invalidation task exists, even during a screen flood.
                    if pending is None or pending.done():
                        pending = asyncio.create_task(publish_later())
        except asyncio.CancelledError:
            raise
        except Exception:
            self.events.publish("observation.gap", sid, source="screen", reason="monitor_unavailable")
        finally:
            if pending is not None:
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)

    async def watch_layout(self, class_name):
        try:
            async with getattr(self.sdk, class_name)(self.connection) as monitor:
                while True:
                    sid = await monitor.async_get()
                    if class_name == "SessionTerminationMonitor" and isinstance(sid, str):
                        self.events.publish("session.terminated", sid)
                    await self.reconcile()
                    self.events.publish("layout.invalidated")
        except asyncio.CancelledError:
            raise
        except Exception:
            self.events.publish("observation.gap", source="layout", reason="monitor_unavailable")

    async def watch_focus(self):
        try:
            async with self.sdk.FocusMonitor(self.connection) as monitor:
                while True:
                    update = await monitor.async_get_next_update()
                    if update.application_active is not None:
                        self.application_active = update.application_active.application_active
                    self.events.publish("focus.invalidated")
        except asyncio.CancelledError:
            raise
        except Exception:
            self.application_active = None
            self.events.publish("observation.gap", source="focus", reason="monitor_unavailable")

    def focus(self):
        window = getattr(self.app, "current_window", None)
        if window is None:
            window = getattr(self.app, "current_terminal_window", None)
        tab = getattr(window, "current_tab", None)
        session = getattr(tab, "current_session", None)
        return {"session_id": getattr(session, "session_id", None),
                "tab_id": getattr(tab, "tab_id", None), "window_id": getattr(window, "window_id", None),
                "application_active": self.application_active, "observed_at": utcnow(),
                "warning": "Focus is advisory; native AI and human input are not excluded"}

    async def metadata(self, sid):
        session = self.session(sid)
        base = dict(self.observations.ensure(sid)["metadata"])
        for field, variable in (("path", "path"), ("job_name", "jobName"), ("command_line", "commandLine"),
                                ("hostname", "hostname"), ("username", "username"), ("tmux_role", "tmuxRole")):
            value = await self.rpc(session.async_get_variable(variable))
            base[field] = str(value or "")[:4096]
        base["context_id"] = digest([sid, base["path"], base["hostname"], base["job_name"], base["command_line"]])
        base.update(evidence_source="iterm2_variables", integrity="unverified_terminal_report")
        return base

    async def screen(self, sid, query):
        limit = integer(query.get("limit", 500), "limit", 1, 1000)
        offset = integer(query.get("offset", 0), "offset", 0, 1000000)
        session = self.session(sid)
        if not hasattr(session, "async_get_line_info") or not hasattr(session, "async_get_contents"):
            raise APIError(501, "screen_api_unsupported", "Install an iTerm2 runtime with public line APIs")

        async def capture():
            async with self.transaction_lock, self.sdk.Transaction(self.connection):
                info = await session.async_get_line_info()
                total = info.scrollback_buffer_height + info.mutable_area_height
                end = max(0, total-offset)
                count = min(limit, end)
                first = info.overflow + end-count
                lines = await session.async_get_contents(first, count) if count else []
                overflow = info.overflow
                columns = session.grid_size.width
            return total, first, overflow, columns, lines

        total, first, overflow, columns, contents = await self.rpc(capture())
        lines, budget, truncated = [], 256 * 1024, False
        for line in contents:
            value = line.string.replace("\x00", " ")
            raw = value.encode("utf-8")
            if len(raw) > budget:
                truncated = True
                break
            budget -= len(raw)
            if query.get("strip", "false").lower() == "true":
                value = " ".join(value.split())
                if not value:
                    continue
            lines.append(value)
        return {"session_id": sid, "lines": lines, "first_line": first, "columns": columns,
                "overflow": overflow, "fetched_lines": len(contents), "returned_lines": len(lines),
                "offset": offset, "available_lines": total, "has_more": offset+limit < total,
                "truncated": truncated, "observed_at": utcnow(), "source": "terminal_grid",
                "trusted_instructions": False, "raw_stdout": False}

    async def input(self, sid, body, key=False, recheck=None):
        session = self.session(sid)
        if "suppress_broadcast" not in inspect.signature(session.async_send_text).parameters:
            raise APIError(501, "targeted_input_unsupported", "Runtime cannot guarantee broadcast suppression")
        if key:
            name = text(body.get("key"), "key", 32).lower()
            if name not in KEYS:
                raise APIError(400, "unknown_key", "Unsupported key name")
            value, enter, delay = KEYS[name], False, 0
        else:
            value = text(body.get("text"), "text", 32768, controls=True)
            enter = boolean(body.get("enter", False), "enter")
            delay = integer(body.get("enter_delay_ms", 30), "enter_delay_ms", 0, 1000)
        if recheck:
            await recheck()
        await self.rpc(session.async_send_text(value, suppress_broadcast=True))
        if enter and not value.endswith(("\r", "\n")):
            await asyncio.sleep(delay/1000)
            if recheck:
                try:
                    await recheck()
                except APIError:
                    raise APIError(409, "partial_input", "Text was delivered but Enter was withheld; inspect the session")
            await self.rpc(self.session(sid).async_send_text("\r", suppress_broadcast=True))
        return {"ok": True, "delivery": "acknowledged_by_iterm2", "execution_verified": False,
                "broadcast_suppressed": True, "bytes": len(value.encode("utf-8")),
                "warning": "PTY delivery is not command completion"}

    async def create(self, kind, sid, body):
        profile = body.get("profile")
        if profile is not None:
            text(profile, "profile", 256)
        if "command" in body or "profile_customizations" in body:
            raise APIError(400, "command_override_disabled", "Only approved profile startup commands are supported")
        if kind == "split":
            session = await self.rpc(self.session(sid).async_split_pane(
                vertical=boolean(body.get("vertical", False), "vertical"),
                before=boolean(body.get("before", False), "before"), profile=profile))
            result = {"session_id": session.session_id}
        elif kind == "tab":
            window = self.app.get_window_by_id(sid)
            if window is None:
                raise APIError(404, "window_missing", "Window not found")
            if "select" not in inspect.signature(window.async_create_tab).parameters:
                raise APIError(501, "background_tab_unsupported", "Runtime cannot create a background tab")
            tab = await self.rpc(window.async_create_tab(profile=profile, select=False))
            result = {"tab_id": getattr(tab, "tab_id", None)}
        else:
            window = await self.rpc(self.sdk.Window.async_create(self.connection, profile=profile))
            result = {"window_id": getattr(window, "window_id", None)}
        await self.reconcile()
        return dict(result, startup_command_may_run=True)

    def capabilities(self):
        session_class = getattr(self.sdk, "Session", object)
        return {"shell_history": {"implemented": True, "requires_shell_integration": True,
                                  "monitor_api_present": hasattr(self.sdk, "PromptMonitor"),
                                  "coverage": "observed_since_process_start", "command_output_capture": False},
                "workspace": {"implemented": True, "session_api_present": hasattr(self.sdk, "Session")},
                "targeted_input": {"implemented": True, "broadcast_suppression_required": True},
                "agent_status": {"implemented": True, "source": "explicit_authenticated_reports", "has_ttl": True},
                "native_session_status": {"implemented": False, "reason": "No verified native read adapter in this release"},
                "native_workgroups": {"implemented": False, "reason": "UI features are not assumed to have equivalent Python APIs"},
                "native_ai_chat": {"implemented": False, "reason": "Independent permission system; harness never inherits its grants"},
                "browser_automation": {"implemented": False, "reason": "No verified browser-control adapter"},
                "structured_execution": {"implemented": False, "reason": "PTY writes cannot prove actor-to-command attribution"},
                "mcp": {"implemented": False, "reason": "Transport adapter deferred; must reuse this authorization layer"},
                "annotations": {"implemented": False}, "selection": {"implemented": False},
                "user_variables": {"implemented": hasattr(session_class, "async_set_variable")}}
