# Second-pass review and implementation: 2.1.0

Baseline: `224797c75e86bf0c41202ec67b61f7961ae859b0`.

## Corrections to the earlier proposal

1. **Capability names are not an OS sandbox.** Splitting `command.execute` from
   raw terminal input would describe intent, not remove the latter's ability to
   execute commands. Profile creation also has execution authority. The code now
   documents this and uses target-scoped grants plus local consent where needed.
2. **Native GUI features do not imply public API parity.** Native Workgroups,
   browser automation, AI Chat permissions and native Session Status are not
   advertised as implemented. The capability matrix explicitly marks absent
   adapters. Agent status reports are separate and labeled as such.
3. **Events need delivery and evidence contracts.** SSE without epoch IDs,
   bounded replay, gap detection and scoped authorization can silently corrupt an
   orchestrator's state. Those contracts are implemented; a screen event is an
   invalidation, not an unbounded transcript feed.
4. **Completion is not attribution.** Shell notifications report what the
   terminal says happened. Only matching native prompt IDs correlate an end to a
   start. Orphans, missing IDs and monitor gaps do not become successful commands.
   Structured execution/output capture remains deferred instead of guessing.
5. **Input must be serialized and retry-aware.** The implementation adds leases,
   context guards, epoch-bound idempotency, bounded receipts, partial/unknown
   outcomes and broadcast suppression. Humans/native AI still are not locked out.
6. **run_forever is not lifecycle cleanup.** The public documentation says it
   keeps a script running; it does not establish the required ownership contract
   for an HTTP listener. The launcher owns all tasks and uses a bounded public RPC
   watchdog, closing sockets/tasks on failure. It does not silently select a new
   port and leave clients attached to an orphan.
7. **Previous tests were insufficient.** The v2 source had a pass-the-hash-style
   credential fallback, automatic legacy scope expansion, a missing multipart
   parser path, unsafe regex work and insufficient input preconditions. The tests
   now exercise the actual HTTP layer, not only helper functions.
8. **Splitting modules requires packaging changes.** Both symlink and copied
   installations now load the whole package from outside AutoLaunch. User config
   is separate from the installed code. The moving-archive/fixed-version formula
   is replaced with an honest HEAD-only formula pending release publication.

## Boundaries

`protocol.py`: strict HTTP framing/limits; `security.py`: grants, migration, audit;
`state.py`: replay, observations, freshness, leases/receipts; `iterm.py`: public
SDK adapter and supervised monitors; `filesystem.py`: rooted bounded regular-file
access; `prompt.py`: finite local consent; `server.py`: orchestration and dispatch;
`routes.py`: shared route/security discovery; launcher: process/task ownership.

Only the SDK adapter and consent module know native iTerm2/AppKit details. Pure
state and HTTP tests run without either. No extra web framework or AI-model
dependency was added.

## Scope intentionally not claimed

No native AI Chat or Workgroups bridge, browser DOM automation, MCP server,
selection/annotation editing, git/worktree manager, arbitrary agent-provider
command recognizer, structured execute-and-wait, exact stdout/stderr separation,
persistent event ledger, cross-restart action deduplication, or filesystem sandbox
for processes running inside a terminal. The absence is surfaced, not emulated
with guessed native state. No external AI service receives terminal contents.

Selection/annotations and a thin MCP adapter are reasonable subsequent adapters,
after live native validation of this tranche. They must reuse the same policy and
receipt machinery rather than establish a second unrestricted control path.

## Public API references consulted

- https://iterm2.com/python-api/session.html — content transactions, suppress_broadcast,
  session lifecycle, variables, selections and annotations.
- https://iterm2.com/python-api/prompt.html — PromptMonitor modes and optional IDs.
- https://iterm2.com/python-api/connection.html — documented runner behavior.
- https://iterm2.com/python-api/lifecycle.html — create/terminate/layout monitors.
- https://iterm2.com/python-api/focus.html — focus monitor and application activity.
- https://iterm2.com/python-api/app.html — app/session topology and variables.
- https://iterm2.com/python-api/window.html — window/tab creation.
- https://iterm2.com/documentation-variables.html — public pid and session variables.
- https://iterm2.com/documentation-session-status.html — native status mechanisms.
- https://iterm2.com/documentation-ai-chat.html — native AI permissions/features.

These documents do not substitute for live runtime validation. Tests bind the
implementation to public API-shaped contracts; the smoke checklist covers the
remaining macOS/application boundary.
