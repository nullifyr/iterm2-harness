# Security

iTerm2 Harness is a privileged local automation service: an authorized client can read terminal contents and, depending on granted capabilities, inject terminal input or access files.

## v2 security model

Fresh installations bind to `127.0.0.1` and disable file access. Remote exposure is opt-in. For access from another host, prefer an encrypted authenticated tunnel such as SSH, Tailscale, or WireGuard.

Authorization tokens are capability-scoped and newly issued bearer secrets are stored only as SHA-256 hashes. Legacy v1 plaintext token records remain accepted for migration compatibility; revoke and reissue them to obtain hashed storage and explicit scopes.

File authorization resolves both the requested path and policy roots and compares them with `os.path.commonpath`, preventing prefix-sibling and symlink escape mistakes.

The built-in HTTP server rejects unsupported transfer encoding, duplicate or invalid Content-Length headers, over-limit request/header/body sizes, and unsupported HTTP versions. Agent-facing operations are bounded to prevent accidental unbounded reads/listings.

## Reporting a vulnerability

Please avoid publishing an exploit before the maintainer has had a reasonable opportunity to investigate. Include the affected version, reproduction steps, expected/actual behavior, and any proposed mitigation.
