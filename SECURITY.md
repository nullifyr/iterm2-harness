# Security model and limitations

This is a privileged automation bridge, not a sandbox or a certified safety
system. An agent with terminal-write access to a shell can execute code with the
shell user's privileges, including file operations denied by the separate file
API. Creating a profile can run its configured startup command. A compromised
same-user process can modify this harness, its state, or the terminal itself.

## Controls in 2.1

- Loopback default, explicit remote opt-in, Host validation, browser Origin
  rejection, strict HTTP framing, endpoint body limits and connection deadlines.
  Remote mode is still plaintext HTTP; use authenticated encryption outside it.
- Locally approved grants with explicit scopes, concrete session targets, expiry,
  hashed secrets, stable token IDs, revocation, and fixed legacy privileges.
- v2's legacy fallback could accept a stored digest as a bearer. It is removed:
  migration normalizes storage and authentication only looks up a computed hash.
  A raw secret is not accepted as a lookup key after migration.
- Local consent for new workspace resources, closing a session, reload, and
  protected focused-session input. Optional consent for all input. Unavailable
  AppKit fails closed. No remote approval endpoint or model-based safety classifier.
- Epoch-bound idempotency receipts, per-session serialization/leases, concrete
  target/context revalidation, and explicit unknown outcomes after uncertain or
  partial writes. Both text and Enter suppress iTerm2 input broadcast propagation.
- Scoped bounded SSE with replay-gap reporting and repeated authorization checks.
  Terminal content, Shell Integration and agent reports remain untrusted evidence;
  they cannot approve an action. Missing evidence never becomes a successful exit.
- Explicit file roots, descriptor-relative no-follow traversal, regular-file-only
  operations, protected source/state paths, bounded reads and atomic overwrites.
  Hardlinked file overwrite/append and symlink traversal are refused.
- Bounded ordinary audit records contain IDs, outcomes and payload hashes, not
  raw typed commands, bearer secrets, or terminal transcripts. Daily files rotate
  after 8 MiB; historical days still require an operator retention policy. This
  is not an append-only, tamper-proof or compliance-certified audit ledger.

## Limits you must understand

Leases coordinate harness clients only. Human typing, shell hooks, native iTerm2
AI and other programs can still change the target after a check. Metadata is not
a transactional guard on a PTY. A successful API acknowledgment does not prove a
command ran, succeeded, or was caused by a specific actor. No exactly-once
execution guarantee survives crashes. Pending/unknown operations require target
inspection before an explicit new attempt.

A scope targeting one session does not constrain what its shell can reach over
SSH, the filesystem, a tmux connection, or network credentials. For a real security
boundary, run agents with separate OS identities/containers/VMs and separate
secrets. Native AI Chat permissions and harness permissions are independent.

File root protections restrict this API, not code the terminal can execute. Local
same-user changes to configuration, credentials or directory mounts are outside
the hostile-client model. Filesystem bounds do not make a stalled storage device
fast; file work runs off the event loop. No arbitrary regex endpoint is offered.

Receipts and events are memory-bounded and nonpersistent. At receipt capacity the
service refuses new actions rather than forgetting keys. Stream/history gaps
require a new snapshot. Status freshness is TTL-based; no event is required at the
instant a report expires. Do not infer idle from a quiet terminal.

## Validation

Automated tests use real loopback HTTP/SSE and API-shaped doubles. They do not
validate AppKit event delivery, every iTerm2 release, live TUIs, or all shell/SSH/
tmux configurations. Complete `docs/MACOS_SMOKE_TEST.md` on the intended runtime.
Keep the listener local until that verification is complete.

For suspected vulnerabilities, contact the repository maintainer privately where
possible. Include the exact commit, runtime versions, minimal reproduction and
expected/actual behavior; omit real bearer tokens and sensitive terminal output.
