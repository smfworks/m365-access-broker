# Security Policy

The M365 Access Broker is a security control plane: its entire purpose is to keep an
autonomous agent's access to Microsoft 365 bounded, auditable, and approval-gated. We take
vulnerability reports seriously.

## Supported versions

This project is pre-1.0. Security fixes are applied to the latest `main` and the most recent
tagged release.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| `0.1.x` | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via one of:

- **GitHub Security Advisories** — use the **"Report a vulnerability"** button under the
  repository's **Security** tab (preferred; creates a private advisory).
- **Email** — `security@smfworks.com`.

When reporting, please include:

- A description of the issue and its impact (e.g., approval-gate bypass, scope escalation,
  audit-log tampering, injection-firewall evasion, credential leakage).
- Steps to reproduce or a proof of concept.
- The affected version / commit and your environment (Node version, OS, dry-run vs live).

## What to expect

- **Acknowledgement** within 3 business days.
- A **triage assessment** and severity rating shortly after.
- Coordinated disclosure: we'll work with you on a fix and a disclosure timeline, and credit
  you in the advisory unless you prefer to remain anonymous.

## Scope notes

High-value areas for this project:

- **Authority boundaries** — the agent key (`x-broker-key`) must never be able to mint or
  forge an approval; only the separate approver key (`x-approver-key`) can.
- **Approval tokens** — single-use, tool-scoped, time-limited.
- **Injection firewall** — retrieved M365/web content is evidence, never instruction;
  evasions that get embedded commands executed are in scope.
- **Audit integrity** — secrets must never be persisted in clear; entries must be attributable.

Out of scope: issues that require a compromised host or already-leaked broker/approver keys
(the broker assumes the local host and its key store are trusted).
