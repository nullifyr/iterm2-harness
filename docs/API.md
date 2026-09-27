# API 2.1: contracts and limits

The service version is 2.1.0; new routes use `/api/v2`. The generated route table
below and `GET /api/v2/openapi.json` share `iterm2_harness/routes.py` as their
source. OpenAPI describes routes, path/header parameters, and capability gates;
it is **not yet an exhaustive typed payload schema** for generated clients.

All non-public endpoints require `Authorization: Bearer TOKEN`. Scope checks and
session target checks are independent. Root discovery, health, and auth requests
are public; OpenAPI/capabilities are authenticated. JSON bodies must be objects;
duplicate keys, non-finite numbers, and string booleans are rejected.

<!-- BEGIN GENERATED ROUTES -->

| Method | Path | Required capability | v1 alias |
|---|---|---|---|
| GET | `/api/v2/health` | `Public` | Yes |
| GET | `/api/v2/openapi.json` | `Authenticated` | No |
| GET | `/api/v2/capabilities` | `Authenticated` | No |
| POST | `/api/v2/auth/request` | `Public` | Yes |
| GET | `/api/v2/auth/whoami` | `Authenticated` | Yes |
| GET | `/api/v2/auth/tokens` | `auth.manage` | Yes |
| DELETE | `/api/v2/auth/tokens/{token_id}` | `auth.manage` | Yes |
| POST | `/api/v2/reload` | `service.reload` | Yes |
| GET | `/api/v2/sessions` | `terminal.read` | Yes |
| GET | `/api/v2/windows` | `terminal.read` | Yes |
| GET | `/api/v2/snapshot` | `terminal.read` | No |
| GET | `/api/v2/focus` | `terminal.read` | No |
| GET | `/api/v2/events` | `terminal.read` | No |
| GET | `/api/v2/actions/{action_id}` | `Authenticated` | No |
| GET | `/api/v2/sessions/{sid}/screen` | `terminal.read` | Yes |
| GET | `/api/v2/sessions/{sid}/metadata` | `terminal.read` | Yes |
| GET | `/api/v2/sessions/{sid}/status` | `terminal.read` | No |
| PUT | `/api/v2/sessions/{sid}/status` | `status.write` | No |
| GET | `/api/v2/sessions/{sid}/commands` | `terminal.read` | No |
| GET | `/api/v2/sessions/{sid}/commands/{command_id}` | `terminal.read` | No |
| POST | `/api/v2/sessions/{sid}/lease` | `terminal.write` | No |
| DELETE | `/api/v2/sessions/{sid}/lease` | `terminal.write` | No |
| POST | `/api/v2/sessions/{sid}/send-text` | `terminal.write` | Yes |
| POST | `/api/v2/sessions/{sid}/send-key` | `terminal.write` | Yes |
| POST | `/api/v2/sessions/{sid}/set-title` | `terminal.write` | Yes |
| POST | `/api/v2/sessions/{sid}/activate` | `layout.write` | No |
| POST | `/api/v2/sessions/{sid}/split` | `session.create` | No |
| DELETE | `/api/v2/sessions/{sid}` | `session.close` | No |
| POST | `/api/v2/windows` | `session.create` | No |
| POST | `/api/v2/windows/{wid}/tabs` | `session.create` | No |
| GET | `/api/v2/sessions/{sid}/variables/{name}` | `terminal.read` | No |
| PUT | `/api/v2/sessions/{sid}/variables/{name}` | `variables.write` | No |
| GET | `/api/v2/files` | `files.read` | Yes |
| POST | `/api/v2/files` | `files.write` | Yes |
| DELETE | `/api/v2/files` | `files.delete` | Yes |
| GET | `/api/v2/files/list` | `files.read` | Yes |

<!-- END GENERATED ROUTES -->

## Credential requests

`POST /auth/request` accepts `device_name` (128 bytes), `scopes` (a list), optional
`session_ids` (null/all, or 1–256 concrete IDs), and `expires_in` (60–2,592,000
seconds; default 86,400). Approval shows the requested grant locally. Read-only
observers must explicitly request `terminal.read`; omitted scopes retain the
historical terminal read/write default. Device names and peer addresses are not
cryptographic device identities.

`GET /auth/whoami` returns grant metadata. `GET /auth/tokens` and
`DELETE /auth/tokens/{token_id}` require `auth.manage`; revocation is a v2 mutation
with epoch/idempotency headers. New capabilities do not expand legacy tokens.

## All v2 mutations

Except credential bootstrap, every POST/PUT/DELETE requires:

```
X-Harness-Epoch: value from capabilities/snapshot/health
Idempotency-Key: unique key for this logical request, maximum 128 bytes
```

Use the **same key, epoch, path, query and body** to recover a lost response.
Different content with the same key is `409`; a previous process epoch is `409`.
Receipts can be pending, completed, rejected, or unknown. `completed` means the
operation was acknowledged, not that a typed shell command succeeded. Only the
owning credential can fetch `GET /actions/{action_id}`.

Receipts are in memory, capped at 2,048 per epoch. At capacity new actions are
rejected rather than evicting keys and risking duplicate execution. Restart is
an explicit new epoch; inspect outstanding operations first. This is bounded
retry protection, **not exactly-once execution across crashes**.

## Read, lease, and send

For illustration, assign values returned by the preceding calls. Do not use the
literal placeholders as credentials, session IDs, or context IDs.

```bash
BASE=http://127.0.0.1:6770
# TOKEN has terminal.read and terminal.write for SID.
curl -sS "$BASE/api/v2/sessions/$SID/metadata" \
  -H "Authorization: Bearer $TOKEN"
# Save epoch as EPOCH and context_id as CONTEXT.

curl -sS -X POST "$BASE/api/v2/sessions/$SID/lease" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -H "X-Harness-Epoch: $EPOCH" -H 'Idempotency-Key: acquire-for-task-123' \
  -d '{"ttl_seconds":60}'
# Save lease_id as LEASE.

python3 -c 'import json,sys; print(json.dumps({"text":"git status --short", "enter":True, "lease_id":sys.argv[1], "expected_context":sys.argv[2]}))' \
  "$LEASE" "$CONTEXT" | \
  curl -sS -X POST "$BASE/api/v2/sessions/$SID/send-text" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -H "X-Harness-Epoch: $EPOCH" -H 'Idempotency-Key: input-for-task-123' \
    --data-binary @-
```

Lease TTL is 5–120 seconds. Renew with a **new** idempotency key; replaying the
old acquisition must not extend it. Release with DELETE `/sessions/{sid}/lease`
and `{"lease_id":"..."}`. Input, key, title, and close operations require a live
lease and `expected_context` from session metadata. Context includes session ID,
job/command, host and path; it is advisory terminal evidence, not an atomic PTY
ownership guarantee. Do not treat it as a fresh prompt readiness proof.

`send-text` accepts `text` (up to 32,768 UTF-8 bytes), boolean `enter` (default
false), and `enter_delay_ms` (0–1,000; default 30). Existing trailing CR/LF is not
followed by another Enter. Text and Enter are separate writes, each suppressing
broadcast. Credentials, lease, focus and context are rechecked before Enter;
a partial input failure is explicitly unknown and is never automatically retried.

`send-key` uses `key`: enter/return, tab, escape/esc, space, backspace, delete,
arrows, home/end, or ctrl+a through ctrl+z. `set-title` accepts `title` up to 1,024
bytes. No input action response echoes the raw text. Local approval must display
the complete payload; oversized approval descriptions are refused.

## Workspace lifecycle

Create a window with POST `/windows`, a tab with POST `/windows/{wid}/tabs`, or a
split with POST `/sessions/{sid}/split`. Bodies may specify `profile`; split also
accepts boolean `vertical` and `before`. Named profiles require `allowed_profiles`
and all creation requires a global session grant plus local consent. No arbitrary
`command` or profile customization field is executed. Tab creation requests
`select=false`; unsupported SDK behavior returns `501` rather than stealing focus.

POST `/sessions/{sid}/activate` requires `layout.write`. DELETE `/sessions/{sid}`
requires `session.close`, an input lease (therefore `terminal.write` to acquire
one), expected context, and exact-target local approval. After approval the SDK
close suppresses a second, potentially unbounded native modal. Process exit is
not asserted. Window/tab bulk close and native Workgroup manipulation are absent.

## Events and snapshots

`GET /snapshot` returns scoped observed state and a replay `cursor`. Subscribe to
`GET /events` with `Last-Event-ID: cursor`, or `since=cursor`. Optional
`session_id` further narrows a stream. Never put bearer tokens in the URL.

Event IDs are `process_epoch:sequence`. The ring retains 512 events. An unknown
epoch, future cursor, or overwritten history returns `409` before streaming. A
slow subscriber that falls behind after streaming starts receives
`event: resync_required` and disconnects. Fetch a new snapshot and reconcile;
do not assume missed command completions or replay input. Five-second heartbeats
and bounded writes detect dead clients; revocation is rechecked during streaming.

Events include session.created/unavailable/terminated, prompt.ready,
command.started/finished, screen.invalidated, layout.invalidated,
focus.invalidated, agent.status, and observation.gap. `unavailable` does not mean
native process termination; iTerm2's undo-close behavior can delay termination.
Screen events contain invalidations, not continuous transcripts. Re-read only
when needed. Sessions are capped at 256 observed sessions; snapshot is not an
atomic native workspace snapshot. Focus is advisory and may be unknown.

## Commands and status

`GET /sessions/{sid}/commands` returns up to 100 command observations retained
since startup; `GET /commands/{command_id}` selects one. Requires Shell Integration
notifications. History does not reconstruct commands that occurred before startup
or during a monitor gap. End events correlate only to a matching native prompt
ID; an orphan/no-ID completion stays separate. There is no exact raw stdout/stderr
capture, execution attribution, or structured execute-and-wait endpoint.

`GET /sessions/{sid}/status` separates shell state from agent reports. Report using
PUT with `state` (working/waiting/idle/unknown), integer `sequence`, `ttl_seconds`
(5–300), `provider`, and `detail`. Requires `status.write`. Reports are owned by the
credential until TTL expiry; another reporter or non-increasing sequence is
rejected. Expired reports return unknown, not idle. Clients must honor TTL even
without a new event. Reports do not set/read native Session Status or grant input
approval.

User variable endpoints only accept names starting `user.harness.`; PUT body is
`{"value":"..."}` up to 4,096 bytes. Requires `variables.write`; read requires
terminal.read. These values are untrusted integration data, not policy.

## Screens and files

Screens return terminal-grid text, not byte-exact program output. `limit` is
1–1,000 lines, `offset` 0–1,000,000; the adapter fetches only the requested slice
in a transaction, capped at 256 KiB returned text. `strip=true` loses layout;
soft wrapping, alternate screens, Unicode grid cells and escape sequences still
need interpretation. Responses include geometry, overflow, first line and source.

File endpoints require their file scope AND enabled explicit roots. Paths must
be absolute and use the canonical root path (on macOS `/tmp` is commonly an alias;
use the configured canonical location). Empty roots deny access. Symlinks,
nonregular files and paths into harness source/state are refused. Directory
creation is only below an already-existing allowed root. Use JSON utf-8 or strict
base64 for writes; multipart returns `415`. No arbitrary codec selection.

Reads cap input at 4 MiB; `lines` defaults to 2,000, maximum 10,000. Slice, bounded
tail, line numbers, substring grep and bounded context are supported. Regex is
refused: a short pattern can still consume unbounded CPU. Large-file streaming
and resumable directory cursors are not implemented. Listings cap at 2,000
entries and return explicit truncation; narrow the requested directory.
