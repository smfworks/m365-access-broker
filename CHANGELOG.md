# Changelog

## 0.2.0 — 2026-08-13

Production-hardening of the local M365 access control plane. Dry-run remains the supported
default. Allowlists, approval gates, the injection firewall, and the audit chain were not
weakened.

### Security

- Live Graph fail-closed: app-only tokens cannot call `/me`; require `BROKER_GRAPH_USER_ID`
  and issue `/users/{id}/…`.
- Require GUID tenant/client identifiers when a client secret is present.
- Jail `BROKER_AUDIT_LOG` to a project-relative path.
- Validate `BROKER_PORT` as an integer 1–65535.
- Sanitize handler errors returned to the agent; full detail stays in the redacted audit log.
- Audit control-plane events: `approval_minted` and `unauthorized`.
- Rate-limit approval minting (default 60 / 60s).
- Reject Graph search queries that contain quotes, control characters, or excess length.
- Add nosniff / no-store / frame-deny / no-referrer response headers.
- Destroy the request when the JSON body exceeds 1 MiB.

### Docs / ops

- SECURITY.md updated to the 0.2.0 control set (request-bound approvals, hash chain, live
  fail-closed).
- README approval example now mints with the same args the execute call will present.
- AGENTS.md added for contributors and agent workers.

### Tests / CI

- 91 tests (was 79). New production-gates, approval-audit, query-sanitizer, and mint
  rate-limit coverage.
- CI: Node 20/22/24 matrix; generate-and-verify an audit chain via `bin/verify-audit.js`.
