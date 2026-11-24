# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository and
include the version (`/api/health` shows it), what you did and what happened. You will get an
answer within a week.

## Supported versions

Only the latest release and `main` receive fixes.

## How NCC protects itself

See [docs/ENTERPRISE.md](docs/ENTERPRISE.md) for roles, the audit log, secrets and TLS. In
short: credentials live only in the vault, every write is role-checked and CSRF-protected on
the server, sign-ins are rate limited, and the audit log is hash-chained.
