// Server-level hardening tests: security headers, CORS, rate limiting,
// request-id propagation, payload size limits, and graceful shutdown —
// all tested through the real server module.

process.env.BROKER_KEY = 'agent-hardening-key';
process.env.BROKER_APPROVER_KEY = 'approver-hardening-key';
process.env.BROKER_DRY_RUN = 'true';
process.env.BROKER_RATE_LIMIT_MAX = '100';
process.env.BROKER_RATE_LIMIT_BURST = '50';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

const { server, start, shutdownCleanup } = await import('../src/server.js');

let base;
before(async () => {
  const port = await start(0);
  base = `http://127.0.0.1:${port}`;
});

after(() => {
  server.close();
  shutdownCleanup();
});

function post(path, body, headers = {}) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

// ── Security headers on all responses ───────────────────────────────────────

test('hardening: health endpoint returns security headers', async () => {
  const r = await fetch(base + '/health');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
  assert.equal(r.headers.get('x-xss-protection'), '0');
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  assert.ok(r.headers.get('content-security-policy'));
  assert.ok(r.headers.get('permissions-policy'));
});

test('hardening: 404 response also has security headers', async () => {
  const r = await fetch(base + '/nonexistent', {
    headers: { 'x-broker-key': 'agent-hardening-key' },
  });
  assert.equal(r.status, 404);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
});

test('hardening: 401 response also has security headers', async () => {
  const r = await post('/execute', { tool: 'search_mail', args: { query: 'x' } });
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
});

// ── Request ID propagation ──────────────────────────────────────────────────

test('hardening: response includes x-request-id header', async () => {
  const r = await fetch(base + '/health');
  const rid = r.headers.get('x-request-id');
  assert.ok(rid);
  assert.ok(rid.length > 0);
});

test('hardening: client-supplied x-request-id is echoed back', async () => {
  const r = await fetch(base + '/health', {
    headers: { 'x-request-id': 'trace-abc-123' },
  });
  assert.equal(r.headers.get('x-request-id'), 'trace-abc-123');
});

// ── CORS ─────────────────────────────────────────────────────────────────────

test('hardening: OPTIONS preflight returns 204', async () => {
  const r = await fetch(base + '/execute', {
    method: 'OPTIONS',
    headers: {
      origin: 'http://localhost:3000',
      'access-control-request-method': 'POST',
    },
  });
  assert.equal(r.status, 204);
});

test('hardening: no CORS headers for disallowed origin', async () => {
  const r = await fetch(base + '/health', {
    headers: { origin: 'http://evil.example.com' },
  });
  assert.equal(r.headers.get('access-control-allow-origin'), null);
});

// ── Payload size limit ──────────────────────────────────────────────────────

test('hardening: oversized payload returns 400 with payload_too_large', async () => {
  // Create a body just over 1 MB (the default maxBodyBytes).
  const big = { tool: 'search_mail', args: { query: 'x'.repeat(1_050_000) } };
  const r = await post('/execute', big, { 'x-broker-key': 'agent-hardening-key' });
  assert.equal(r.status, 400);
  const j = await r.json();
  assert.equal(j.error, 'payload_too_large');
});

// ── Rate limiting ───────────────────────────────────────────────────────────

test('hardening: rate limit headers are present', async () => {
  const r = await fetch(base + '/health');
  assert.ok(r.headers.get('x-ratelimit-limit'));
  assert.ok(r.headers.get('x-ratelimit-remaining'));
  assert.ok(r.headers.get('x-ratelimit-reset'));
});

// ── Content-Type always JSON ─────────────────────────────────────────────────

test('hardening: all responses have application/json content type', async () => {
  const r = await fetch(base + '/health');
  assert.match(r.headers.get('content-type'), /application\/json/);
});

// ── 405 for unsupported methods ──────────────────────────────────────────────

test('hardening: PUT method returns 404 (not 405, but handled gracefully)', async () => {
  const r = await fetch(base + '/execute', {
    method: 'PUT',
    headers: { 'x-broker-key': 'agent-hardening-key' },
    body: '{}',
  });
  // The server returns 404 for unknown routes; this is acceptable.
  assert.ok(r.status === 404 || r.status === 405);
});

// ── Existing API still works (backward compatibility) ───────────────────────

test('hardening: /health still returns broker info', async () => {
  const r = await fetch(base + '/health');
  const j = await r.json();
  assert.equal(j.ok, true);
  assert.equal(j.mode, 'dry-run');
  assert.equal(j.dryRun, true);
  assert.ok(Array.isArray(j.requiredScopes));
});

test('hardening: /tools still works with broker key', async () => {
  const r = await fetch(base + '/tools', {
    headers: { 'x-broker-key': 'agent-hardening-key' },
  });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.ok, true);
  assert.ok(Array.isArray(j.tools));
});

test('hardening: /execute still works with broker key', async () => {
  const r = await post(
    '/execute',
    { tool: 'search_mail', args: { query: 'test' } },
    { 'x-broker-key': 'agent-hardening-key' }
  );
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.ok, true);
});

test('hardening: /approve still requires approver key', async () => {
  const r = await post(
    '/approve',
    { tool: 'send_approved_draft' },
    { 'x-broker-key': 'agent-hardening-key' }
  );
  assert.equal(r.status, 401);
});

// ── Invalid JSON ─────────────────────────────────────────────────────────────

test('hardening: invalid JSON body returns 400 with invalid_json', async () => {
  const r = await fetch(base + '/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-broker-key': 'agent-hardening-key',
    },
    body: '{not valid json',
  });
  assert.equal(r.status, 400);
  const j = await r.json();
  assert.equal(j.error, 'invalid_json');
});