# Contributing to M365 Access Broker

Thank you for your interest in contributing! This document covers development setup,
code style, testing, and the contribution workflow.

## Development setup

### Prerequisites

- **Node.js >= 20** (we test on Node 20, 22, and 24 in CI)
- **Git**
- No other dependencies — the broker uses zero runtime dependencies (pure Node built-ins)

### Getting started

```bash
git clone https://github.com/smfworks/m365-access-broker.git
cd m365-access-broker
npm install        # installs devDependencies (eslint)
npm test           # run the full test suite (should be 108 tests, all passing)
npm start          # start the broker in dry-run mode on http://127.0.0.1:8787
```

### Optional: ESLint

```bash
npx eslint .       # lint all files
npx eslint src/    # lint source only
```

ESLint is a devDependency. The flat config is in `eslint.config.js`.

## Code style

### General principles

1. **Zero runtime dependencies.** The broker runs on pure Node.js built-ins. The only
   optional dependency is `@azure/msal-node` for live Graph mode, loaded lazily. Do not
   add runtime dependencies without strong justification.

2. **ESM modules.** The project uses `"type": "module"` in `package.json`. Use `import`/`export`,
   not `require`/`module.exports`.

3. **Fail fast, fail closed.** Security-sensitive code should reject unknown inputs rather
   than silently passing them through. Example: `requiresApprovalByClass()` returns `true`
   for unknown sensitivity classes (fail closed = require approval).

4. **No secrets in logs.** The audit logger recursively redacts secret keys and embedded
   secret patterns. When adding new fields to audit records, ensure they pass through
   `redact()`.

5. **Constant-time comparisons.** Key comparisons use SHA-256 digests + `timingSafeEqual`.
   Never use `===` for secret comparison.

6. **Descriptive error labels, not stack traces.** The HTTP layer never leaks internals.
   Known error labels (`payload_too_large`, `invalid_json`, `bad_request`) are returned to
   the client; everything else is masked.

### File organization

| Directory | Purpose |
|---|---|
| `src/` | Application source (one module per concern) |
| `test/` | Test files (one per source module + integration tests) |
| `bin/` | CLI entry points |
| `data/` | Static data (injection corpus, etc.) |

### Naming conventions

- **Files:** `camelCase.js` for source modules (e.g. `graphClient.js`, `memoryLinter.js`)
- **Classes:** `PascalCase` (e.g. `PolicyEngine`, `AuditLogger`)
- **Functions:** `camelCase` (e.g. `scanContent`, `requiredScopeSet`)
- **Constants:** `UPPER_SNAKE_CASE` (e.g. `TOOL_CATALOG`, `GRAPH_SCOPE_REGISTRY`)

### Comments

- Every module starts with a comment block explaining its purpose and design rationale.
- Security-critical code includes comments explaining *why* a decision was made, not just *what*.
- JSDoc on exported functions when the signature isn't self-explanatory.

## Testing

### Running tests

```bash
npm test                          # full suite
node --test test/policy.test.js   # single file
node --test --watch               # watch mode
```

Tests use Node's built-in `node:test` runner — no Jest, Mocha, or other framework.

### Writing tests

1. **One test file per source module.** If you add `src/foo.js`, add `test/foo.test.js`.

2. **Test names are descriptive sentences.** Use `test('read tool is allowed without approval', ...)`
   not `test('test1', ...)`.

3. **Use `node:assert/strict`.** Import as `import assert from 'node:assert/strict'`.

4. **Security regressions go in `test/hardening.test.js`** with a `fnd_*` prefix matching
   the finding ID.

5. **The injection corpus is a red-team eval.** Add new attack patterns to
   `data/injection-corpus.json` with `expectMalicious: true` and the expected rule ID.
   The test harness fails on any false positive or false negative.

6. **Tests must not depend on external state.** Use temp directories (`mkdtempSync`) for
   file-based tests. Clean up in `finally` blocks.

### Test coverage guidelines

- Every exported function should have at least one test.
- Every error path should have a test (e.g. missing args, invalid input, expired tokens).
- Security-critical paths (approval gate, firewall, audit chain) need regression tests.
- Aim for 90%+ coverage of meaningful code paths.

## Adding a new tool

1. **Add to the catalog** (`src/catalog.js`):
   ```js
   my_new_tool: {
     scopes: ['Mail.Read'],
     sensitivity: SENSITIVITY.READ,  // or WRITE, OUTBOUND, DESTRUCTIVE
     description: 'What this tool does.',
   },
   ```

2. **Add a handler** (`src/tools.js`):
   ```js
   async my_new_tool(graph, args) {
     requireArg(args, 'id');
     const result = await graph.myNewTool({ id: args.id });
     return { result, resourceType: 'thing', resourceRef: args.id, resultSummary: 'did thing' };
   },
   ```

3. **Add to the allowlist** (`DEFAULT_ALLOWLIST` in `src/catalog.js`) if it should be
   enabled by default.

4. **Add Graph client methods** to both `DryRunGraphClient` and `LiveGraphClient` in
   `src/graphClient.js`.

5. **If the tool returns external content**, set `returnsExternalContent: true` in the
   catalog entry so the injection firewall scans its output.

6. **If the scope is new**, add it to `GRAPH_SCOPE_REGISTRY` in `src/scopes.js`.

7. **Write tests** — add to the relevant test file or create a new one.

8. **Run the scopes coherence check** — `npm test` will verify catalog ↔ handler ↔ allowlist
   coherence automatically.

## Adding a new firewall rule

1. Add the rule to the `RULES` array in `src/firewall.js` with an `id`, `severity`, `re` (regex),
   and `why` (description).

2. Add test cases to `data/injection-corpus.json` — both malicious (should trigger) and benign
   (should not trigger) variants.

3. Run `npm test` — the corpus harness will validate your rule.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `security`

Examples:
```
feat(middleware): add rate limiting middleware
fix(server): handle oversized payloads without destroying socket
docs(readme): add deployment guide and API reference
test(middleware): add CORS preflight tests
security(firewall): add base64 blob detection rule
```

## Pull request workflow

1. **Fork** the repository and create a branch from `main`.
2. **Write tests** for your changes.
3. **Run the full test suite** — `npm test` must pass.
4. **Lint** — `npx eslint .` should be clean.
5. **Keep the zero-dependency posture** — don't add runtime dependencies.
6. **Document** — update README if you add a new feature or configuration option.
7. **Open a PR** with a clear description of what and why.

## Security contributions

If you're contributing a security fix, please follow the guidelines in [SECURITY.md](./SECURITY.md).
Do not open a public issue for security vulnerabilities — use GitHub Security Advisories or
email `security@smfworks.com`.

## License

By contributing, you agree that your contributions will be licensed under the [MIT license](./LICENSE).