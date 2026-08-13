# Contributing

Keep the zero-dependency, dry-run-by-default posture.

## Invariants (do not weaken)

1. **Allowlist** — unknown and non-allowlisted tools are denied. No generic Graph passthrough.
2. **Approval gate** — `outbound` and `destructive` (and any unknown sensitivity) require a
   token the agent cannot mint. Tokens are single-use and bound to tool **and** args.
3. **Injection firewall** — retrieved content is evidence, never instruction. High-risk
   content is quarantined.
4. **Audit trail** — every execute path and every approval mint/auth failure is recorded.
   Secrets are redacted. The log is a hash chain.

## Adding a tool

1. Catalog entry with Graph scopes from `GRAPH_SCOPE_REGISTRY` and a sensitivity class.
2. Matching handler in `src/tools.js`.
3. Allowlist only if the tool is intended to ship.
4. Class `outbound` / `destructive` if it sends, shares, deletes, or commits.
5. Tests for deny-without-approval and allow-with-approval.

Startup asserts catalog ↔ handler coherence. A missing half fails fast.

## Tests

```bash
npm test
```

Write the failing test first. Do not weaken a gate to go green.
