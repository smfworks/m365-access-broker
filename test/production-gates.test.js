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

const SAMPLE_GUID = '11111111-1111-4111-8111-111111111111';

test('isGuid accepts RFC-like GUIDs and rejects aliases', () => {
  assert.equal(isGuid(SAMPLE_GUID), true);
  assert.equal(isGuid('common'), false);
  assert.equal(isGuid(''), false);
});

test('parseBrokerPort accepts 1-65535 and rejects out-of-range', () => {
  assert.equal(parseBrokerPort(undefined), 8787);
  assert.equal(parseBrokerPort('443'), 443);
  assert.throws(() => parseBrokerPort('0'), /invalid_broker_port/);
  assert.throws(() => parseBrokerPort('65536'), /invalid_broker_port/);
  assert.throws(() => parseBrokerPort('abc'), /invalid_broker_port/);
});

test('resolveAuditLogPath jails the log inside the project root', () => {
  const root = mkdtempSync(join(tmpdir(), 'broker-audit-'));
  try {
    assert.equal(resolveAuditLogPath(root, 'audit.log'), join(root, 'audit.log'));
    assert.throws(() => resolveAuditLogPath(root, '/tmp/audit.log'), /audit_log_must_be_relative/);
    assert.throws(() => resolveAuditLogPath(root, '../audit.log'), /audit_log_escapes_project/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('liveGraphUserRoot requires a user object id', () => {
  assert.equal(liveGraphUserRoot(SAMPLE_GUID), `/users/${SAMPLE_GUID}`);
  assert.throws(() => liveGraphUserRoot('me'), /live_graph_requires_BROKER_GRAPH_USER_ID/);
});

test('assertLiveMsIdentifiers fail-closed on non-GUID tenant/client when secret is present', () => {
  assert.throws(
    () =>
      assertLiveMsIdentifiers({
        tenantId: 'not-a-guid',
        clientId: SAMPLE_GUID,
        clientSecret: 'secret',
      }),
    /invalid_ms_tenant_id/
  );
});

test('publicHandlerReasons never forwards Graph/internal exception text', () => {
  const leak = new Error('Graph GET /me failed: 401 Bearer eyJhbGciOiJIUzI1NiJ9.leak');
  assert.deepEqual(publicHandlerReasons(leak), ['handler_error']);
  const missing = new Error('missing_required_arg:id');
  missing.code = 'BAD_ARGS';
  assert.deepEqual(publicHandlerReasons(missing), ['missing_required_arg:id']);
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
  assert.match(entries[0].reasons.join(' '), /supersecret/);
});
