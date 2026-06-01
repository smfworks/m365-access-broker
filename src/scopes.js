import { TOOL_CATALOG, DEFAULT_ALLOWLIST } from './catalog.js';

// Scopes-as-contract. The catalog declares, per tool, the Microsoft Graph
// permissions that tool needs. Those declarations are only trustworthy if they
// are *verified*: a typo'd scope, a tool added without a handler, or a handler
// with no catalog entry are all silent privilege/coverage gaps. This module
// turns those failure modes into load-time errors instead of relying on whoever
// edits the catalog to remember the invariant — the broker's structural
// equivalent of least privilege.

// Canonical set of Graph permission strings the broker is allowed to declare.
// Anything outside this registry is a typo or an undeclared capability and must
// fail fast rather than be granted by accident. Extend deliberately when a new
// tool legitimately needs a new permission.
export const GRAPH_SCOPE_REGISTRY = Object.freeze(
  new Set([
    'User.Read',
    'Calendars.Read',
    'Mail.Read',
    'Mail.ReadWrite',
    'Mail.Send',
    'Files.Read',
    'Files.ReadWrite',
  ])
);

// Assert that every scope every catalog tool declares is a known Graph
// permission. Throws on the first unknown scope so an import of the broker fails
// at startup, not at the moment a mis-scoped tool is first called.
export function validateCatalogScopes(catalog = TOOL_CATALOG, registry = GRAPH_SCOPE_REGISTRY) {
  const unknown = [];
  for (const [tool, spec] of Object.entries(catalog)) {
    for (const scope of spec.scopes || []) {
      if (!registry.has(scope)) unknown.push(`${tool}:${scope}`);
    }
  }
  if (unknown.length) {
    throw new Error(`unknown_graph_scopes:${unknown.join(',')}`);
  }
  return true;
}

// The least-privilege scope set the broker actually needs: the sorted union of
// the scopes declared by every *allowlisted* tool. This is the exact permission
// set the app registration should be granted — nothing more. Tools that are in
// the catalog but not allowlisted contribute no scopes.
export function requiredScopeSet(allowlist = DEFAULT_ALLOWLIST, catalog = TOOL_CATALOG) {
  const scopes = new Set();
  for (const name of allowlist) {
    const spec = catalog[name];
    if (!spec) continue;
    for (const scope of spec.scopes || []) scopes.add(scope);
  }
  return [...scopes].sort();
}

// Assert 1:1 coherence between the catalog, the tool handlers, and the
// allowlist: every catalog tool has a handler, every handler has a catalog
// entry, and every allowlisted name actually exists in the catalog. A
// declared-but-unimplemented tool or an implemented-but-undeclared (therefore
// unscoped, unaudited) tool is a contract break. Throws with all breaks listed.
export function assertCatalogCoherence(catalog, handlers, allowlist = DEFAULT_ALLOWLIST) {
  const catalogNames = new Set(Object.keys(catalog));
  const handlerNames = new Set(Object.keys(handlers));
  const breaks = [];

  for (const name of catalogNames) {
    if (!handlerNames.has(name)) breaks.push(`catalog_without_handler:${name}`);
  }
  for (const name of handlerNames) {
    if (!catalogNames.has(name)) breaks.push(`handler_without_catalog:${name}`);
  }
  for (const name of allowlist) {
    if (!catalogNames.has(name)) breaks.push(`allowlisted_unknown_tool:${name}`);
  }

  if (breaks.length) {
    throw new Error(`catalog_incoherent:${breaks.join(',')}`);
  }
  return true;
}
