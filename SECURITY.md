# Security Policy

pq-migration-lab is an educational reference for post-quantum migration
patterns (hybrid deployments, certificate migration, CA rotation,
interoperability), not a hardened library meant for production use as-is.
That said, real vulnerabilities are still worth reporting: bugs in the
demonstrated patterns (e.g. `internal/kem/hybrid`'s wire framing) or in
how this repo drives `liboqs`/`oqs-provider` could mislead someone
building on it.

## Reporting a Vulnerability

Please report security issues privately via GitHub's
[Private Vulnerability Reporting](https://github.com/arboreng/pq-migration-lab/security/advisories/new)
(Security tab → Report a vulnerability), rather than opening a public
issue. This lets us discuss and fix the issue before it's public.

We'll acknowledge your report and work with you to understand and
address it. There's no fixed SLA (this is a small project), but we
treat security reports as a priority over other work.

## Supported Versions

Only the `main` branch is supported. This section will be updated to
describe tagged version support if that changes.
