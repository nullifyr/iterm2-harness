# Changelog

## 2.1.0 — second implementation tranche

- Modular public-SDK adapter, explicit task/listener ownership and bounded backend
  watchdog; stable configured port, no private RPC/websocket dependency.
- Scoped replayable SSE, epoch/gap recovery, prompt-ID-based command observations,
  TTL reporter status, snapshots/focus, guarded session lifecycle and user variables.
- Session-scoped expiring tokens; fix digest-as-bearer fallback, atomically migrate
  legacy plaintext storage, and freeze legacy capabilities.
- Serialized leased input, context checks, idempotency receipts, local approval,
  broadcast suppression, and explicit partial/unknown outcomes.
- Strict HTTP boundaries, browser Origin/Host checks, bounded connections/files,
  descriptor-relative no-follow filesystem access, no unsafe regex or multipart.
- Whole-package installers, persistent user configuration, HEAD-only Homebrew
  development formula, canonical discovery/docs, expanded HTTP/security tests.
- Native Workgroups/AI/browser adapters and structured command execution explicitly
  remain unavailable. Live macOS/iTerm2/AppKit verification is still required.

## 2.0.0

Initial hardening: loopback/file-off defaults, scopes and hash-addressed tokens,
public screen APIs, protocol limits and initial CI. The 2.1 review corrects the
legacy authentication fallback, lifecycle assumptions and incomplete boundaries
in that implementation. See docs/REVIEW_V2_1.md for the source-bound corrections.
