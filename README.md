# iTerm2 Harness 2.1

An authenticated HTTP bridge to the user's real iTerm2 workspace, with scoped
credentials, observable shell activity, bounded event replay, and guarded input.
It uses iTerm2's public Python API and the standard library; AppKit/PyObjC is used
for local consent. It does **not** inherit native iTerm2 AI Chat permissions.

## What is implemented

- Session/window inventory, concrete session metadata, bounded terminal-grid reads.
- Server-sent events (SSE): prompt/command observations, screen invalidations,
  session/layout/focus changes, and explicitly reported agent status.
- Bounded command history observed since the harness started. Exit events are
  correlated only when a native prompt ID is available and matches.
- Expiring agent reports with reporter identity, sequence numbers, and provenance.
  These are separate from shell state and are **not native Session Status reads**.
- Create windows/tabs/splits, activate sessions, close individual sessions, rename,
  send text/keys, and get/set the `user.harness.*` variable namespace.
- Session-scoped credentials, expiry/revocation, input leases, context checks,
  idempotency receipts, broadcast suppression, and local approval for destructive
  or workspace-creating operations.
- Optional, explicitly rooted regular-file access. No arbitrary Python regex or
  multipart parsing; no file access by default.

`GET /api/v2/capabilities` distinguishes implemented features from unimplemented
native Workgroups, AI Chat control, browser automation, selection/annotations,
structured command execution, and MCP. A GUI feature is not assumed to have a
usable Python API. This is an implementation tranche, not feature parity with
native iTerm2 AI.

## Install

Requires macOS, iTerm2 with its Python API enabled, and a **Python 3.9+** iTerm2
runtime. Use a currently maintained Python runtime when available. Local consent
also requires working PyObjC/AppKit in that runtime. If it is unavailable, requests
requiring consent fail closed; there is no blocking modal fallback.

From a checkout:

```bash
./install.sh
# Or make an independent runtime copy, including the package:
./install.sh --copy
```

Then run **iTerm2 > Scripts > AutoLaunch > iterm2-harness.py**, or restart iTerm2.
The installer puts only the launcher symlink in AutoLaunch, not every module. It
creates `~/.iterm2-harness/config.json` only if absent and preserves existing user
configuration, credentials, and logs. `--uninstall` removes only the launcher.
A copied runtime remains under `~/.iterm2-harness/runtime.*` for manual cleanup.

The Homebrew formula is intentionally **HEAD-only** until a tagged archive and
checksum are published:

```bash
brew tap nullifyr/iterm2-harness https://github.com/nullifyr/iterm2-harness
brew install --HEAD nullifyr/iterm2-harness/iterm2-harness
```

This commit sets the code version to 2.1.0; it does not itself create a Git tag or
GitHub release. Do not install a moving `main.tar.gz` as a purported fixed release.

## Configuration and migration

The defaults are in `config.json`. Lookup order is `ITERM2_HARNESS_CONFIG`, then
`~/.iterm2-harness/config.json`, then the file beside the real launcher. Host, port,
and approval timeout can be overridden with `ITERM2_HARNESS_HOST`,
`ITERM2_HARNESS_PORT`, and `ITERM2_HARNESS_AUTH_TIMEOUT`. `ITERM2_HARNESS_HOME`
changes the state directory.

```bash
python3 iterm2-harness.py --version
python3 iterm2-harness.py --check-config
```

**Upgrade differences:** non-loopback binding now additionally requires
`allow_remote: true`; empty file roots deny access even when enabled. Invalid
configuration stops startup rather than silently broadening policy. The listener
uses the configured port without silently choosing another. Approval deadlines
are finite (10–120 seconds). Old Python 3.7/3.8 runtimes must be updated.

Legacy raw-token records are atomically migrated to hash-only storage. Their
privileges are frozen to the original seven capabilities; new lifecycle/status
permissions are never silently added. Existing tokens without expiry remain
usable, but should be reissued with an expiry and explicit session targets.

Existing `/api/v1` routes have explicit compatibility aliases. They retain basic
read/input operations, not every old permissive behavior: regex is disabled,
multipart is rejected, booleans must actually be JSON booleans, file budgets are
smaller, and input is no longer echoed in responses. New endpoints cannot be
accessed through v1 to bypass v2 preconditions. **Move writers to v2**: v1 cannot
provide the caller-supplied epoch/context/idempotency guarantees.

## Start with read access

```bash
BASE=http://127.0.0.1:6770
curl -sS -X POST "$BASE/api/v2/auth/request" \
  -H 'Content-Type: application/json' \
  -d '{"device_name":"observer","scopes":["terminal.read"],"expires_in":3600}'
```

Approve the local dialog and keep the returned `token` private. A `session_ids`
array narrows a grant to those concrete sessions; omitted/null means all sessions.
The historical default when `scopes` is omitted is terminal read **and write**;
request read-only explicitly for observers. The service never accepts tokens in
query strings. Cache credentials privately per server origin, not in shared logs.

```bash
curl -sS "$BASE/api/v2/snapshot" -H "Authorization: Bearer $TOKEN"
curl -N "$BASE/api/v2/events" -H "Authorization: Bearer $TOKEN"
```

Snapshots and events are observations, not instructions or trusted command
provenance. Missing Shell Integration, lost notifications, expired agent reports,
and restarts produce unknown/incomplete state, never an invented successful exit.

For guarded input, obtain metadata plus a lease and send the current epoch,
unique idempotency key, lease ID, and expected context. The complete example and
request contracts are in [docs/API.md](docs/API.md). Retrying the same request in
the same epoch returns its receipt; an unknown result requires inspection, not a
new key and blind resubmission.

## Security boundary

`terminal.write` is execution-class authority: a writable shell can access the
user's filesystem even if `files.write` is denied. Profile creation can execute
profile startup commands. API scopes and leases are **not an OS sandbox**, and
cannot exclude human input or native AI acting outside this harness.

Input always suppresses iTerm2 broadcast propagation. Focused-session input,
workspace creation, session closure, and reload receive local checks/approval;
`require_input_approval: true` requires consent for every input action. Closing a
session may terminate its running process. Named profiles must be allowlisted;
the default profile may also execute startup code and always requires consent.

The transport is plaintext HTTP. Keep it on loopback and use an authenticated
encrypted tunnel for remote access. Enabling a remote bind does not add TLS.
Browser-origin requests and unexpected Host headers are rejected. See
[SECURITY.md](SECURITY.md) for residual risks and exact limits.

## Development and validation

```bash
python3 -m compileall -q iterm2_harness iterm2-harness.py tests tools
python3 -m unittest discover -s tests -v
python3 tools/generate_docs.py --check
bash -n install.sh
```

Tests cover real local HTTP/SSE connections against public-API-shaped iTerm2
adapters, credential migration, path confinement, replay, partial input, and
listener cleanup. They do not simulate AppKit, a live PTY, or native AI. Complete
[the live macOS checklist](docs/MACOS_SMOKE_TEST.md) before relying on unattended
operation. The deeper design corrections are recorded in
[docs/REVIEW_V2_1.md](docs/REVIEW_V2_1.md).

Apache-2.0; see [LICENSE](LICENSE).
