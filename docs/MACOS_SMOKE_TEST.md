# Live macOS verification checklist

Automated unit/HTTP tests do not complete this checklist. Record macOS, iTerm2,
iTerm2 Python runtime, Python SDK and PyObjC versions, plus the exact commit.
Use disposable terminals and nonsensitive test files, not production sessions.

1. Install via symlink, then in a separate attempt `--copy`; confirm only the
   launcher appears in AutoLaunch. Check version/config and verify only the
   configured loopback port listens. Invalid configuration and occupied ports
   must stop startup without silently broadening exposure or switching ports.
2. Request a read-only credential for one test session. Verify Allow, Deny, close
   and timeout on the AppKit dialog, including while iTerm2 itself is in use.
   Return must not accidentally grant consent. The iTerm2 UI must remain usable.
   Verify a missing/unusable AppKit path fails closed rather than freezing iTerm2.
3. Read inventory, screen geometry and focus. Test a buried/minimized pane and a
   shell over SSH/tmux. Verify restricted credentials never expose other sessions.
   Mark unavailable features as unavailable, not inferred data.
4. With Shell Integration enabled, run a short successful and failed command.
   Compare native prompt IDs and exit values with `/commands` and SSE. Run without
   Shell Integration and verify unknown/incomplete evidence. Disconnect/reconnect
   an SSE consumer; test valid replay, an old epoch and an overwritten cursor.
5. Publish agent status with a short TTL, verify source/reporter, then let it
   expire. Verify unknown rather than idle, ownership conflicts and stale sequence
   rejection. Do not equate this with native Session Status.
6. Obtain an input lease/context, send text/Enter to a disposable shell and TUI.
   Retry with the same idempotency key and verify only one input operation. Test
   two agents contending, expired leases, job/path changes and human focus changes.
   Verify `terminal.write` cannot be mistaken for read-only OS authority.
7. Enable iTerm2 input broadcast to a second disposable pane. Send through the
   harness and verify **only the addressed pane** receives text and Enter.
8. Deny window/tab/split/close/reload approval and verify zero side effects. Allow
   creation with a harmless profile; inspect its startup command. Close only a
   disposable target after exact approval. Verify no second indefinite modal.
9. Revoke/expire a streaming writer credential. Verify stream closes promptly and
   new or pending actions are refused. Test revocation/context changes between
   text and Enter; inspect partial-input receipt instead of resubmitting blindly.
10. Quit/restart iTerm2 and kill the API connection. Verify the watchdog closes
    the listener and client streams, the new process uses the configured port,
    and old epoch writes fail. Test explicit reload. Inspect audit metadata for
    missing secrets and sensitive raw payloads.
11. Under explicit canonical test roots, exercise file reads/writes/deletes,
    symlink escape, hardlink write, FIFO/device rejection, bounds and protected
    state/source paths. Remove test credentials/files after completing validation.

Do not mark the implementation production-validated solely because CI is green.
