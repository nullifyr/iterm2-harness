"""Bounded, explicitly lossy observations; leased, idempotent mutations.

No inference of agent success from silence, no exactly-once claim about a PTY.
"""
import asyncio
import copy
import secrets
import time
from collections import OrderedDict, deque

from .common import APIError, digest, integer, text, utcnow
from .security import allowed_session


class EventLog:
    def __init__(self, capacity=512, epoch=None):
        self.epoch = epoch or secrets.token_hex(16)
        self.sequence = 0
        self.events = deque(maxlen=capacity)
        self.changed = asyncio.Event()

    @property
    def cursor(self):
        return "%s:%d" % (self.epoch, self.sequence)

    def publish(self, kind, sid=None, **data):
        self.sequence += 1
        event = {"id": self.cursor, "sequence": self.sequence, "event": kind,
                 "session_id": sid, "observed_at": utcnow(), "data": copy.deepcopy(data)}
        self.events.append(event)
        self.changed.set()
        return event

    def position(self, cursor):
        if cursor is None:
            return self.sequence
        try:
            epoch, number = cursor.rsplit(":", 1)
            sequence = int(number)
        except (AttributeError, ValueError):
            raise APIError(400, "invalid_cursor", "Expected epoch:sequence")
        if epoch != self.epoch:
            raise APIError(409, "resync_required", "Server restarted; fetch a fresh snapshot")
        oldest = self.events[0]["sequence"] if self.events else self.sequence + 1
        if sequence < oldest - 1 or sequence > self.sequence:
            raise APIError(409, "resync_required", "Event history gap; fetch a fresh snapshot")
        return sequence

    def read(self, sequence, info):
        self.position("%s:%d" % (self.epoch, sequence))
        result = []
        for item in self.events:
            if item["sequence"] <= sequence:
                continue
            if item["session_id"] is None or allowed_session(info, item["session_id"]):
                result.append(copy.deepcopy(item))
        return result, self.sequence


class Observations:
    def __init__(self, events, max_sessions=256, history_limit=100):
        self.events = events
        self.sessions = OrderedDict()
        self.max_sessions, self.history_limit = max_sessions, history_limit
        self.started_at = utcnow()

    def ensure(self, sid):
        if sid not in self.sessions:
            if len(self.sessions) >= self.max_sessions:
                raise APIError(503, "session_capacity", "Observation capacity reached")
            self.sessions[sid] = {"session_id": sid, "shell_state": "unknown",
                                  "prompt_monitor": "starting", "active": None,
                                  "history": deque(maxlen=self.history_limit), "history_evicted": 0,
                                  "agent": None, "metadata": {}}
        return self.sessions[sid]

    def remove(self, sid):
        if self.sessions.pop(sid, None) is not None:
            self.events.publish("session.unavailable", sid)

    def _append(self, state, record):
        if len(state["history"]) == self.history_limit:
            state["history_evicted"] += 1
        state["history"].append(record)

    def prompt_event(self, sid, kind, value, native_id=None):
        state = self.ensure(sid)
        now = utcnow()
        if kind == "command.started":
            if state["active"] and native_id and state["active"]["prompt_id"] == native_id:
                return  # Duplicate delivery, not a second command.
            if state["active"]:
                state["active"]["outcome"] = "unknown_missing_end"
            record = {"command_id": secrets.token_hex(16), "prompt_id": native_id,
                      "command": str(value)[:4096], "start_observed": True,
                      "started_at": now, "finished_at": None, "exit_status": None,
                      "outcome": "running", "_started_mono": time.monotonic()}
            self._append(state, record)
            state["active"] = record
            state["shell_state"] = "running"
        elif kind == "command.finished":
            active = state["active"]
            # Only attach a completion to a start with the SAME native prompt ID.
            # Without IDs, temporal proximity is not sufficient proof of identity.
            matched = bool(active and native_id and active["prompt_id"] == native_id)
            if not matched:
                if native_id and any(r["prompt_id"] == native_id and r["finished_at"] for r in state["history"]):
                    return
                record = {"command_id": secrets.token_hex(16), "prompt_id": native_id,
                          "command": None, "start_observed": False, "started_at": None}
                self._append(state, record)
            else:
                record = active
            record.update(finished_at=now, exit_status=value if type(value) is int else None,
                          outcome="completed" if matched else "unmatched_completion")
            record["duration_ms"] = (round((time.monotonic() - record["_started_mono"]) * 1000)
                                     if matched else None)
            if matched:
                state["active"] = None
                state["shell_state"] = "finished"
            else:
                state["shell_state"] = "unknown"
        elif kind == "prompt.ready":
            if state["active"]:
                state["active"]["outcome"] = "unknown_missing_end"
                state["active"] = None
            state["shell_state"] = "prompt"
            self.events.publish(kind, sid, prompt_id=native_id,
                                evidence_source="shell_integration", integrity="unverified_terminal_report")
            return
        else:
            return
        state["observed_at"] = now
        self.events.publish(kind, sid, **self.public_record(record),
                            evidence_source="shell_integration", integrity="unverified_terminal_report")

    @staticmethod
    def public_record(record):
        return {k: v for k, v in record.items() if not k.startswith("_")}

    def monitor_failed(self, sid, reason):
        state = self.ensure(sid)
        state["prompt_monitor"] = "unavailable"
        state["shell_state"] = "unknown"
        if state["active"]:
            state["active"]["outcome"] = "unknown_monitor_gap"
            state["active"] = None
        self.events.publish("observation.gap", sid, source="prompt", reason=reason)

    def report_agent(self, sid, body, actor, now=None):
        now = time.monotonic() if now is None else now
        state = self.ensure(sid)
        status = body.get("state")
        if status not in ("working", "waiting", "idle", "unknown"):
            raise APIError(400, "invalid_agent_state", "Use working, waiting, idle, or unknown")
        sequence = integer(body.get("sequence"), "sequence", 1, 2**53 - 1)
        ttl = integer(body.get("ttl_seconds", 60), "ttl_seconds", 5, 300)
        old = state["agent"]
        if old and now < old["_expires_mono"]:
            if old["actor_id"] != actor:
                raise APIError(409, "reporter_conflict", "Another reporter currently owns this session status")
            if sequence <= old["sequence"]:
                raise APIError(409, "stale_report", "Reporter sequence must increase")
        provider = text(body.get("provider", "unspecified"), "provider", 128)
        detail = text(body.get("detail", ""), "detail", 2048, empty=True)
        state["agent"] = {"state": status, "provider": provider, "detail": detail,
                          "sequence": sequence, "actor_id": actor, "observed_at": utcnow(),
                          "ttl_seconds": ttl, "_expires_mono": now + ttl,
                          "source": "authenticated_reporter", "native_iterm_status": False}
        self.events.publish("agent.status", sid, **self.agent_status(sid, now))
        return self.agent_status(sid, now)

    def agent_status(self, sid, now=None):
        now = time.monotonic() if now is None else now
        agent = self.ensure(sid)["agent"]
        if not agent:
            return {"state": "unknown", "source": "unavailable", "stale": True}
        public = self.public_record(agent)
        public["stale"] = now >= agent["_expires_mono"]
        if public["stale"]:
            public["last_reported_state"] = public["state"]
            public["state"] = "unknown"
        return public

    def status(self, sid):
        state = self.ensure(sid)
        return {"session_id": sid, "shell_state": state["shell_state"],
                "prompt_monitor": state["prompt_monitor"], "agent": self.agent_status(sid),
                "shell_evidence": "unverified_terminal_report", "observed_at": state.get("observed_at")}

    def history(self, sid):
        state = self.ensure(sid)
        return {"commands": [self.public_record(r) for r in state["history"]],
                "coverage_started_at": self.started_at, "history_complete": False,
                "evicted": state["history_evicted"], "source": "observed_shell_integration",
                "warning": "Completion is not proof that a particular agent action caused the command"}


class Actions:
    """One owner per session; receipts remain for the whole server epoch.

At capacity, fail closed rather than evict a key and possibly execute it again.
"""
    def __init__(self, epoch, capacity=2048):
        self.epoch, self.capacity = epoch, capacity
        self.receipts = {}
        self.leases = {}
        self.locks = {}

    def lock(self, sid):
        if sid not in self.locks:
            if len(self.locks) >= 1024:
                raise APIError(503, "lock_capacity", "Restart to start a new action epoch")
            self.locks[sid] = asyncio.Lock()
        return self.locks[sid]

    def acquire(self, sid, actor, ttl=60, now=None):
        now = time.monotonic() if now is None else now
        old = self.leases.get(sid)
        if old and now < old["expires"]:
            if old["actor"] != actor:
                raise APIError(409, "session_leased", "Another credential holds the session")
            old["expires"] = now + ttl
        else:
            if len(self.leases) >= 256:
                self.leases = {k: v for k, v in self.leases.items() if v["expires"] > now}
                if len(self.leases) >= 256:
                    raise APIError(503, "lease_capacity", "Too many active leases")
            old = {"actor": actor, "id": secrets.token_hex(16), "expires": now + ttl}
            self.leases[sid] = old
        return {"lease_id": old["id"], "ttl_seconds": ttl, "epoch": self.epoch,
                "warning": "Lease coordinates harness clients only, not humans or native AI"}

    def check_lease(self, sid, actor, lease_id=None, required=True, now=None):
        now = time.monotonic() if now is None else now
        old = self.leases.get(sid)
        if not old or now >= old["expires"]:
            if required:
                raise APIError(409, "lease_required", "Acquire a current session lease")
            return
        if old["actor"] != actor or (required and lease_id != old["id"]):
            raise APIError(409, "lease_conflict", "Session lease does not match")

    def release(self, sid, actor, lease_id):
        self.check_lease(sid, actor, lease_id)
        del self.leases[sid]
        return {"released": True}

    def begin(self, actor, key, request, epoch):
        if epoch != self.epoch:
            raise APIError(409, "epoch_mismatch", "Fetch capabilities/snapshot before mutating")
        text(key, "Idempotency-Key", 128)
        address = (actor, key)
        fingerprint = digest(request)
        old = self.receipts.get(address)
        if old:
            if old["fingerprint"] != fingerprint:
                raise APIError(409, "idempotency_conflict", "Key was already used for a different request")
            return old, False
        if len(self.receipts) >= self.capacity:
            raise APIError(503, "receipt_capacity", "Receipt capacity reached; explicit new epoch required")
        record = {"action_id": secrets.token_hex(16), "fingerprint": fingerprint,
                  "state": "pending", "created_at": utcnow(), "result": None, "status": 202}
        self.receipts[address] = record
        return record, True

    def finish(self, record, status, result, state="completed"):
        record.update(status=status, result=copy.deepcopy(result), state=state, finished_at=utcnow())

    def reply(self, record, replayed=False):
        result = copy.deepcopy(record["result"] or {"pending": True})
        result["receipt"] = {k: v for k, v in record.items() if k not in ("result", "status")}
        result["receipt"].update(epoch=self.epoch, replayed=replayed)
        return record["status"], result
