import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  isGuid,
  parseBrokerPort,
  resolveAuditLogPath,
  liveGraphUserRoot,
  publicHandlerReasons,
  assertLiveMsIdentifiers,
} from '../src/config.js';
import { Broker } from '../src/broker.js';
import { assertSafeSearchQuery, assertSafeLimit } from '../src/graphClient.js';

const SAMPLE_GUID = '11111111-1111-4111-8111-111111111111';

test('isGuid accepts RFC-like GUIDs and rejects aliases', () => {
  assert.equal(isGuid(SAMPLE_GUID), true);
  assert.equal(isGuid('common'), false);
  assert.equal(isGuid('organizations'), false);
  assert.equal(isGuid(''), false);
  assert.equal(isGuid(null), false);
});

test('parseBrokerPort accepts 1-65535 and rejects NaN/out-of-range', () => {
  assert.equal(parseBrokerPort(undefined), 8787);
  assert.equal(parseBrokerPort('443'), 443);
  assert.throws(() => parseBrokerPort('0'), /invalid_broker_port/);
  assert.throws(() => parseBrokerPort('65536'), /invalid_broker_port/);
  assert.throws(() => parseBrokerPort('abc'), /invalid_broker_port/);
  assert.throws(() => parseBrokerPort('-1'), /invalid_broker_port/);
});

test('resolveAuditLogPath jails the log inside the project root', () => {
  const root = mkdtempSync(join(tmpdir(), 'broker-audit-'));
  try {
    assert.equal(resolveAuditLogPath(root, 'audit.log'), join(root, 'audit.log'));
    assert.equal(resolveAuditLogPath(root, 'data/audit.jsonl'), join(root, 'data/audit.jsonl'));
    assert.throws(() => resolveAuditLogPath(root, '/tmp/audit.log'), /audit_log_must_be_relative/);
    assert.throws(() => resolveAuditLogPath(root, '../audit.log'), /audit_log_escapes_project/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('liveGraphUserRoot requires a user object id (client-credentials cannot call /me)', () => {
  assert.equal(liveGraphUserRoot(SAMPLE_GUID), `/users/${SAMPLE_GUID}`);
  assert.throws(() => liveGraphUserRoot(''), /live_graph_requires_BROKER_GRAPH_USER_ID/);
  assert.throws(() => liveGraphUserRoot('me'), /live_graph_requires_BROKER_GRAPH_USER_ID/);
});

test('assertLiveMsIdentifiers fail-closed on non-GUID tenant/client when secret is present', () => {
  assert.doesNotThrow(() =>
    assertLiveMsIdentifiers({ tenantId: '', clientId: '', clientSecret: '' })
  );
  assert.throws(
    () =>
      assertLiveMsIdentifiers({
        tenantId: 'not-a-guid',
        clientId: SAMPLE_GUID,
        clientSecret: 'secret',
      }),
    /invalid_ms_tenant_id/
  );
  assert.throws(
    () =>
      assertLiveMsIdentifiers({
        tenantId: SAMPLE_GUID,
        clientId: 'not-a-guid',
        clientSecret: 'secret',
      }),
    /invalid_ms_client_id/
  );
});

test('publicHandlerReasons never forwards Graph/internal exception text', () => {
  const leak = new Error('Graph GET /me failed: 401 Bearer eyJhbGciOiJIUzI1NiJ9.leak');
  assert.deepEqual(publicHandlerReasons(leak), ['handler_error']);
  const missing = new Error('missing_required_arg:id');
  missing.code = 'BAD_ARGS';
  assert.deepEqual(publicHandlerReasons(missing), ['missing_required_arg:id']);
  const invalid = new Error('invalid_id');
  assert.deepEqual(publicHandlerReasons(invalid), ['invalid_id']);
});

test('broker execute returns sanitized reasons on handler throw', async () => {
  const graph = {
    mode: 'dry-run',
    async searchMail() {
      throw new Error('Graph GET /me/messages failed: 500 token=supersecret');
    },
  };
  const entries = [];
  const broker = new Broker({
    graph,
    audit: { record: (e) => entries.push(e) },
  });
  const result = await broker.execute('search_mail', { query: 'x' }, { user: 't' });
  assert.equal(result.ok, false);
  assert.deepEqual(result.reasons, ['handler_error']);
  assert.equal(entries[0].outcome, 'error');
  assert.match(entries[0].reasons.join(' '), /supersecret/);
});

test('assertSafeSearchQuery rejects control chars, quotes, and oversize queries', () => {
  assert.equal(assertSafeSearchQuery('project notes'), 'project notes');
  assert.equal(assertSafeSearchQuery(''), '');
  assert.throws(() => assertSafeSearchQuery("foo' or 1=1"), /invalid_query/);
  assert.throws(() => assertSafeSearchQuery('foo"bar'), /invalid_query/);
  assert.throws(() => assertSafeSearchQuery('foo\nbar'), /invalid_query/);
  assert.throws(() => assertSafeSearchQuery('x'.repeat(201)), /query_too_long/);
});

test('assertSafeLimit clamps to a small integer range', () => {
  assert.equal(assertSafeLimit(undefined), 5);
  assert.equal(assertSafeLimit(10), 10);
  assert.throws(() => assertSafeLimit(0), /invalid_limit/);
  assert.throws(() => assertSafeLimit(26), /invalid_limit/);
  assert.throws(() => assertSafeLimit('nope'), /invalid_limit/);
});
