# Changelog

## 0.2.0 — 2026-08-13

Production-hardening pass (SMF Grok 4.6 challenge).

- Live Graph fail-closed: require `BROKER_GRAPH_USER_ID` and call `/users/{id}` (app-only tokens cannot use `/me`).
- Sanitize handler errors returned to the agent; keep detail in the redacted audit log.
- Jail `BROKER_AUDIT_LOG` to a repo-relative path.
- Validate `BROKER_PORT` (1–65535) and live tenant/client GUIDs.
- Add security headers on HTTP responses.
- CI: Node 24 matrix cell + `verify:audit` after tests.
- Add AGENTS.md, CONTRIBUTING.md, and this changelog.

## 0.1.0

Initial public broker: dry-run Graph, approval gates, hash-chained audit, injection firewall, memory hygiene linter.
