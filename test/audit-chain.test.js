import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  AuditLogger,
  AUDIT_GENESIS_HASH,
  verifyAuditChain,
  verifyAuditFile,
} from '../src/audit.js';

function collectingLogger() {
  const lines = [];
  const logger = new AuditLogger({ sink: (line) => lines.push(line) });
  return { logger, lines, records: () => lines.map((l) => JSON.parse(l)) };
}

// #8 audit-trail — every record is a tamper-evident link.
test('audit: records form a verifiable hash chain', () => {
  const { logger, lines, records } = collectingLogger();
  logger.record({ tool: 'm365_status', outcome: 'success' });
  logger.record({ tool: 'search_mail', outcome: 'success' });
  logger.record({ tool: 'delete_file', outcome: 'denied_needs_approval' });

  const recs = records();
  assert.deepEqual(recs.map((r) => r.seq), [1, 2, 3]);
  assert.equal(recs[0].prevHash, AUDIT_GENESIS_HASH);
  assert.equal(recs[1].prevHash, recs[0].hash);
  assert.equal(recs[2].prevHash, recs[1].hash);

  const v = verifyAuditChain(lines.join('\n'));
  assert.equal(v.ok, true);
  assert.equal(v.count, 3);
});

test('audit: editing a record body breaks verification', () => {
  const { logger, records } = collectingLogger();
  logger.record({ tool: 'send_approved_draft', outcome: 'success' });
  logger.record({ tool: 'search_mail', outcome: 'success' });
  const recs = records();
  // Tamper: change an outcome but keep the now-stale hash.
  recs[0].outcome = 'denied';
  const v = verifyAuditChain(recs);
  assert.equal(v.ok, false);
  assert.equal(v.index, 0);
  assert.equal(v.reason, 'hash_mismatch');
});

test('audit: deleting a record breaks the chain', () => {
  const { logger, records } = collectingLogger();
  logger.record({ tool: 'a', outcome: 'success' });
  logger.record({ tool: 'b', outcome: 'success' });
  logger.record({ tool: 'c', outcome: 'success' });
  const recs = records();
  recs.splice(1, 1); // drop the middle record
  const v = verifyAuditChain(recs);
  assert.equal(v.ok, false);
  // seq jumps 1 -> 3
  assert.equal(v.reason, 'seq_gap:expected_2_got_3');
});

test('audit: reordering records is detected', () => {
  const { logger, records } = collectingLogger();
  logger.record({ tool: 'a', outcome: 'success' });
  logger.record({ tool: 'b', outcome: 'success' });
  const recs = records();
  const swapped = [recs[1], recs[0]];
  const v = verifyAuditChain(swapped);
  assert.equal(v.ok, false);
});

test('audit: requestId correlates records emitted under one id', () => {
  const { logger, records } = collectingLogger();
  logger.record({ tool: 'x', outcome: 'success', requestId: 'req-123' });
  assert.equal(records()[0].requestId, 'req-123');
});

test('audit: chain recovers across logger restarts via the file tail', () => {
  const dir = mkdtempSync(join(tmpdir(), 'broker-audit-'));
  const logPath = join(dir, 'audit.log');
  try {
    const a = new AuditLogger({ logPath });
    a.record({ tool: 'a', outcome: 'success' });
    a.record({ tool: 'b', outcome: 'success' });

    // New logger over the same file must continue the chain, not restart it.
    const b = new AuditLogger({ logPath });
    b.record({ tool: 'c', outcome: 'success' });

    const v = verifyAuditFile(logPath);
    assert.equal(v.ok, true);
    assert.equal(v.count, 3);

    const recs = readFileSync(logPath, 'utf8')
      .split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
    assert.deepEqual(recs.map((r) => r.seq), [1, 2, 3]);
    assert.equal(recs[2].prevHash, recs[1].hash);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('audit: verifyAuditFile treats a missing log as a valid empty chain', () => {
  const v = verifyAuditFile(join(tmpdir(), 'does-not-exist-xyz.log'));
  assert.equal(v.ok, true);
  assert.equal(v.count, 0);
});

test('audit: hash covers redacted (persisted) form, secrets never enter the chain', () => {
  const { logger, records } = collectingLogger();
  const rec = logger.record({
    tool: 'create_email_draft',
    outcome: 'success',
    args: { access_token: 'super-secret-value', subject: 'hi' },
  });
  assert.equal(rec.args.access_token, '[REDACTED]');
  // Verification recomputes over the redacted form on disk and still matches.
  assert.equal(verifyAuditChain(records()).ok, true);
});
