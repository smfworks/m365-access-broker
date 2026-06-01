import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  GRAPH_SCOPE_REGISTRY,
  validateCatalogScopes,
  requiredScopeSet,
  assertCatalogCoherence,
} from '../src/scopes.js';
import { TOOL_CATALOG, DEFAULT_ALLOWLIST } from '../src/catalog.js';
import { TOOL_HANDLERS } from '../src/tools.js';
import { PolicyEngine } from '../src/policy.js';

// #7 scopes-contract — the real catalog must be internally consistent.
test('scopes: every declared catalog scope is in the registry', () => {
  assert.equal(validateCatalogScopes(TOOL_CATALOG), true);
});

test('scopes: a typo scope fails validation', () => {
  const bad = { ...TOOL_CATALOG, list_today_events: { scopes: ['Calendars.Raed'], sensitivity: 'read' } };
  assert.throws(() => validateCatalogScopes(bad), /unknown_graph_scopes:list_today_events:Calendars\.Raed/);
});

test('scopes: requiredScopeSet is the sorted least-privilege union of the allowlist', () => {
  const scopes = requiredScopeSet(DEFAULT_ALLOWLIST, TOOL_CATALOG);
  // sorted + de-duped
  assert.deepEqual(scopes, [...scopes].sort());
  assert.equal(scopes.length, new Set(scopes).size);
  // every returned scope is a known Graph permission
  for (const s of scopes) assert.ok(GRAPH_SCOPE_REGISTRY.has(s), `unknown scope ${s}`);
  // a known low-risk scope is present; a scope only a non-allowlisted tool would
  // need is not silently included
  assert.ok(scopes.includes('User.Read'));
});

test('scopes: a non-allowlisted tool contributes no scopes', () => {
  const allowlist = ['m365_status']; // only User.Read
  assert.deepEqual(requiredScopeSet(allowlist, TOOL_CATALOG), ['User.Read']);
});

test('scopes: real catalog and handlers are coherent', () => {
  assert.equal(assertCatalogCoherence(TOOL_CATALOG, TOOL_HANDLERS, DEFAULT_ALLOWLIST), true);
});

test('scopes: a catalog tool with no handler is a coherence break', () => {
  const catalog = { ...TOOL_CATALOG, ghost_tool: { scopes: ['User.Read'], sensitivity: 'read' } };
  assert.throws(
    () => assertCatalogCoherence(catalog, TOOL_HANDLERS, DEFAULT_ALLOWLIST),
    /catalog_incoherent:.*catalog_without_handler:ghost_tool/
  );
});

test('scopes: a handler with no catalog entry is a coherence break', () => {
  const handlers = { ...TOOL_HANDLERS, rogue_handler: async () => ({}) };
  assert.throws(
    () => assertCatalogCoherence(TOOL_CATALOG, handlers, DEFAULT_ALLOWLIST),
    /handler_without_catalog:rogue_handler/
  );
});

test('scopes: an allowlisted name absent from the catalog is a coherence break', () => {
  assert.throws(
    () => assertCatalogCoherence(TOOL_CATALOG, TOOL_HANDLERS, [...DEFAULT_ALLOWLIST, 'phantom']),
    /allowlisted_unknown_tool:phantom/
  );
});

test('scopes: PolicyEngine exposes the required scope set and rejects a bad catalog', () => {
  const engine = new PolicyEngine();
  assert.deepEqual(engine.requiredScopes(), requiredScopeSet(DEFAULT_ALLOWLIST, TOOL_CATALOG));
  assert.throws(
    () => new PolicyEngine({ catalog: { x: { scopes: ['Not.AReal.Scope'], sensitivity: 'read' } } }),
    /unknown_graph_scopes/
  );
});
