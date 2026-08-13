import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AuditLogger, verifyAuditChain } from '../src/audit.js';
import { safeTop } from '../src/graphClient.js';

test('opp: HMAC chain verifies with the key and fails with the wrong key', () => {
  const lines = [];
  const logger = new AuditLogger({
    sink: (line) => lines.push(line),
    hmacKey: 'correct-hmac-key-for-tests',
  });
  logger.record({ tool: 'search_mail', outcome: 'success' });
  logger.record({ tool: 'send_approved_draft', outcome: 'success' });
  const recs = lines.map((l) => JSON.parse(l));
  assert.equal(recs[0].mac, 'hmac-sha256');
  assert.equal(verifyAuditChain(recs, { hmacKey: 'correct-hmac-key-for-tests' }).ok, true);
  assert.equal(verifyAuditChain(recs, { hmacKey: 'wrong-key' }).ok, false);
  assert.equal(verifyAuditChain(recs, { hmacKey: '' }).ok, false);
});

test('opp: unkeyed SHA-256 still verifies without a key (compat)', () => {
  const lines = [];
  const logger = new AuditLogger({ sink: (line) => lines.push(line), hmacKey: '' });
  logger.record({ tool: 'm365_status', outcome: 'success' });
  const recs = lines.map((l) => JSON.parse(l));
  assert.equal(recs[0].mac, undefined);
  assert.equal(verifyAuditChain(recs, { hmacKey: '' }).ok, true);
});

test('opp: safeTop rejects OData injection and out-of-range values', () => {
  assert.equal(safeTop(5), 5);
  assert.equal(safeTop('12'), 12);
  assert.throws(() => safeTop('5&$filter=true'), /invalid_limit/);
  assert.throws(() => safeTop(0), /invalid_limit/);
  assert.throws(() => safeTop(51), /invalid_limit/);
  assert.throws(() => safeTop('nope'), /invalid_limit/);
});

test('opp: live Graph source no longer calls /me', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const { dirname, join } = await import('node:path');
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../src/graphClient.js'), 'utf8');
  assert.equal((src.match(/`\/me/g) || []).length, 0);
  assert.equal((src.match(/'\/me'/g) || []).length, 0);
  assert.match(src, /_userRoot/);
  assert.match(src, /MS_USER_ID/);
});
