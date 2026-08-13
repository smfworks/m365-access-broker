# Contributing

## Development

- Node.js >= 20
- `npm test` must stay green. Do not add runtime dependencies for dry-run.
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`).
- Do not weaken allowlists, approval gates, or the audit hash chain to make a test pass.

## Security changes

If you touch auth, approvals, Graph paths, or audit redaction:

1. Add a regression in `test/` that fails before the fix.
2. Keep live Graph fail-closed (user object id required; no `/me` on app-only tokens).
3. Report vulnerabilities privately — see SECURITY.md. Do not open a public issue for a live bypass.

## Pull requests

Describe intent, risk, and how you verified (`npm test` count + any extra probe). CI runs Node 20/22/24.
