# Changelog

## 2.0.0 — 2026-09-26

- Secure-by-default loopback listener and disabled file access for fresh installs.
- Capability-scoped authorization and hashed-at-rest bearer tokens.
- Token inventory/revocation endpoints gated by `auth.manage`.
- Unified filesystem path authorization using canonical path containment.
- Replaced private iTerm2 scrollback RPCs with public `Session.async_get_line_info` / `async_get_contents` inside a transaction.
- Replaced direct websocket lifecycle inspection with iTerm2's documented `run_forever` daemon model.
- Hardened the minimal HTTP parser and added finite resource budgets.
- Bounded file reads, recursive listings, regex patterns, and terminal scrollback requests.
- Added regression tests and GitHub Actions CI.
- Corrected Homebrew/repository identity from `wsvn53` to `nullifyr`.
