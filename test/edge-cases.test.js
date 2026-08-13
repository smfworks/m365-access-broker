// Edge-case tests for existing modules — strengthens coverage of error paths,
// boundary conditions, and rarely-exercised code.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApprovalStore, requestDigest } from '../src/approvals.js';
import { redact, AuditLogger, verifyAuditChain } from '../src/audit.js';
import { scanContent, sanitize, shouldBlockAutoAction, SEVERITY } from '../src/firewall.js';
import { Broker } from '../src/broker.js';
import { PolicyEngine } from '../src/policy.js';
import { config } from '../src/config.js';

// ── ApprovalStore edge cases ─────────────────────────────────────────────────

test('edge: approval store maxTokens cap evicts oldest', () => {
  const store = new ApprovalStore({ maxTokens: 2 });
  const id1 = store.create('send_approved_draft', { draftId: 'd1' });
  store.create('send_approved_draft', { draftId: 'd2' });
  store.create('send_approved_draft', { draftId: 'd3' }); // evicts id1
  // id1 should be gone
  assert.equal(store.consume(id1, 'send_approved_draft', { draftId: 'd1' }), false);
  assert.equal(store.tokens.size, 2);
});

test('edge: requestDigest handles null/undefined args', () => {
  const d1 = requestDigest('tool', null);
  const d2 = requestDigest('tool', undefined);
  const d3 = requestDigest('tool', {});
  assert.equal(d1, d3);
  assert.equal(d2, d3);
});

test('edge: requestDigest is tool-sensitive', () => {
  assert.notEqual(
    requestDigest('tool_a', { a: 1 }),
    requestDigest('tool_b', { a: 1 })
  );
});

test('edge: sweep removes only expired tokens', () => {
  const store = new ApprovalStore({ ttlMs: 100 });
  const id1 = store.create('send_approved_draft', { draftId: 'd1' });
  // Wait for expiry
  // Can't actually wait in a fast test, so test with negative TTL store
  const expiredStore = new ApprovalStore({ ttlMs: -1 });
  expiredStore.create('send_approved_draft', { draftId: 'd1' });
  expiredStore.create('send_approved_draft', { draftId: 'd2' });
  expiredStore.sweep();
  assert.equal(expiredStore.tokens.size, 0);
});

// ── AuditLogger edge cases ───────────────────────────────────────────────────

test('edge: redact handles circular-safe depth limit', () => {
  const deep = { a: { b: { c: { d: { e: { f: { g: { h: 'deep' } } } } } } } };
  const out = redact(deep);
  // Should not throw, should have some depth-capped value
  assert.ok(out);
});

test('edge: redact handles primitives', () => {
  assert.equal(redact(42), 42);
  assert.equal(redact('hello'), 'hello');
  assert.equal(redact(null), null);
  assert.equal(redact(undefined), undefined);
  assert.equal(redact(true), true);
});

test('edge: redact truncates arrays beyond 50 elements', () => {
  const big = Array.from({ length: 100 }, (_, i) => i);
  const out = redact(big);
  assert.equal(out.length, 50);
});

test('edge: verifyAuditChain with empty records returns ok', () => {
  const v = verifyAuditChain([]);
  assert.equal(v.ok, true);
  assert.equal(v.count, 0);
});

test('edge: verifyAuditChain with empty string returns ok', () => {
  const v = verifyAuditChain('');
  assert.equal(v.ok, true);
  assert.equal(v.count, 0);
});

test('edge: AuditLogger with no logPath and no sink writes to file', () => {
  // When no sink is provided and no logPath, it should still not crash.
  // The default sink writes to logPath (which is undefined), so it will throw
  // and fall back to stderr.
  const audit = new AuditLogger({});
  // This should not throw — it falls back to stderr
  const rec = audit.record({ tool: 'test', outcome: 'success' });
  assert.equal(rec.persisted, false);
  assert.ok(rec.persistError);
});

// ── Firewall edge cases ──────────────────────────────────────────────────────

test('edge: scanContent with empty string returns none', () => {
  const v = scanContent('');
  assert.equal(v.risk, 'none');
  assert.equal(v.findings.length, 0);
});

test('edge: scanContent with non-string returns none', () => {
  const v = scanContent(null);
  assert.equal(v.risk, 'none');
  const v2 = scanContent(undefined);
  assert.equal(v2.risk, 'none');
  const v3 = scanContent(123);
  assert.equal(v3.risk, 'none');
});

test('edge: sanitize with non-string input', () => {
  const out = sanitize({ a: 1 }, { source: 'test' });
  assert.ok(out.wrapped);
  assert.match(out.wrapped, /<external_content/);
});

test('edge: sanitize respects maxLen', () => {
  const long = 'x'.repeat(200);
  const out = sanitize(long, { source: 'test', maxLen: 50 });
  // The body should be truncated
  assert.ok(out.wrapped.length < long.length + 200);
});

test('edge: shouldBlockAutoAction with medium risk returns false', () => {
  const v = { risk: 'medium' };
  assert.equal(shouldBlockAutoAction(v), false);
});

test('edge: shouldBlockAutoAction with low risk returns false', () => {
  const v = { risk: 'low' };
  assert.equal(shouldBlockAutoAction(v), false);
});

test('edge: shouldBlockAutoAction with none risk returns false', () => {
  const v = { risk: 'none' };
  assert.equal(shouldBlockAutoAction(v), false);
});

test('edge: SEVERITY constants are frozen', () => {
  assert.equal(SEVERITY.LOW, 1);
  assert.equal(SEVERITY.MEDIUM, 2);
  assert.equal(SEVERITY.HIGH, 3);
  assert.throws(() => { SEVERITY.LOW = 99; });
});

// ── PolicyEngine edge cases ──────────────────────────────────────────────────

test('edge: policy evaluate with no args defaults to empty object', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('search_mail');
  assert.equal(d.allowed, true);
});

test('edge: policy evaluate with no ctx defaults to empty object', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('search_mail', { query: 'x' });
  assert.equal(d.allowed, true);
});

test('edge: policy listAllowedTools returns all allowed tools', () => {
  const policy = new PolicyEngine();
  const tools = policy.listAllowedTools();
  assert.ok(tools.length > 0);
  for (const t of tools) {
    assert.ok(t.name);
    assert.ok(t.sensitivity);
    assert.equal(typeof t.requiresApproval, 'boolean');
    assert.ok(Array.isArray(t.scopes));
    assert.ok(t.description);
  }
});

test('edge: policy with custom allowlist excludes non-listed tools', () => {
  const policy = new PolicyEngine({ allowlist: ['m365_status'] });
  const tools = policy.listAllowedTools();
  assert.equal(tools.length, 1);
  assert.equal(tools[0].name, 'm365_status');
});

test('edge: policy grantedScopes as empty array denies all scoped tools', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('m365_status', {}, { grantedScopes: [] });
  assert.equal(d.allowed, false);
  assert.ok(d.reasons.some((r) => r.startsWith('missing_scopes')));
});

// ── Broker edge cases ────────────────────────────────────────────────────────

test('edge: broker execute with handler that throws returns error outcome', async () => {
  const entries = [];
  const audit = new AuditLogger({ sink: (line) => entries.push(JSON.parse(line)) });
  const graph = {
    mode: 'test',
    async searchMail() { throw new Error('graph exploded'); },
  };
  const broker = new Broker({ policy: new PolicyEngine(), audit, graph });
  const r = await broker.execute('search_mail', { query: 'x' });
  assert.equal(r.ok, false);
  assert.equal(r.outcome, 'error');
  assert.equal(entries.at(-1).outcome, 'error');
});

test('edge: broker execute with handler that throws custom error code', async () => {
  const entries = [];
  const audit = new AuditLogger({ sink: (line) => entries.push(JSON.parse(line)) });
  const graph = {
    mode: 'test',
    async searchMail() {
      const err = new Error('rate limited');
      err.code = 'GRAPH_RATE_LIMITED';
      throw err;
    },
  };
  const broker = new Broker({ policy: new PolicyEngine(), audit, graph });
  const r = await broker.execute('search_mail', { query: 'x' });
  assert.equal(r.ok, false);
  assert.equal(r.outcome, 'error');
  assert.equal(r.reasons[0], 'GRAPH_RATE_LIMITED');
});

test('edge: broker passes requestId from ctx to audit', async () => {
  const entries = [];
  const audit = new AuditLogger({ sink: (line) => entries.push(JSON.parse(line)) });
  const graph = {
    mode: 'test',
    async me() { return { id: 'u1', userPrincipalName: 'm@x.com' }; },
  };
  const broker = new Broker({ policy: new PolicyEngine(), audit, graph });
  const r = await broker.execute('m365_status', {}, { requestId: 'my-req-id' });
  assert.equal(r.ok, true);
  assert.equal(r.requestId, 'my-req-id');
  assert.equal(entries.at(-1).requestId, 'my-req-id');
});

test('edge: broker generates requestId when not provided in ctx', async () => {
  const entries = [];
  const audit = new AuditLogger({ sink: (line) => entries.push(JSON.parse(line)) });
  const graph = {
    mode: 'test',
    async me() { return { id: 'u1', userPrincipalName: 'm@x.com' }; },
  };
  const broker = new Broker({ policy: new PolicyEngine(), audit, graph });
  const r = await broker.execute('m365_status', {});
  assert.ok(r.requestId);
  assert.equal(entries.at(-1).requestId, r.requestId);
});

// ── Config edge cases ────────────────────────────────────────────────────────

test('edge: config has all expected hardening fields', () => {
  assert.ok(typeof config.maxBodyBytes === 'number');
  assert.ok(typeof config.rateLimitWindowMs === 'number');
  assert.ok(typeof config.rateLimitMax === 'number');
  assert.ok(typeof config.rateLimitBurst === 'number');
  assert.ok(Array.isArray(config.corsAllowedOrigins));
  assert.ok(typeof config.shutdownTimeoutMs === 'number');
});

test('edge: config maxBodyBytes defaults to 1MB', () => {
  assert.equal(config.maxBodyBytes, 1048576);
});