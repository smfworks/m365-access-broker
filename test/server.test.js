// Set known keys BEFORE importing the server (config reads env at import time).
process.env.BROKER_KEY = 'agent-test-key';
process.env.BROKER_APPROVER_KEY = 'approver-test-key';
process.env.BROKER_DRY_RUN = 'true';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

const { server, start, broker } = await import('../src/server.js');

let base;
before(async () => {
  const port = await start(0); // ephemeral port
  base = `http://127.0.0.1:${port}`;
});
after(() => server.close());

function post(path, body, headers = {}) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

test('health is public and sets security headers', async () => {
  const r = await fetch(base + '/health');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
});

test('execute without broker key is 401', async () => {
  const r = await post('/execute', { tool: 'search_mail', args: { query: 'x' } });
  assert.equal(r.status, 401);
});

test('read tool works with broker key', async () => {
  const r = await post('/execute', { tool: 'search_mail', args: { query: 'x' } }, { 'x-broker-key': 'agent-test-key' });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.ok, true);
});

test('agent CANNOT self-approve by sending ctx.approvalGranted', async () => {
  // This is the core gate-bypass fix: a forged ctx must be ignored.
  const r = await post(
    '/execute',
    { tool: 'send_approved_draft', args: { draftId: 'd1' }, ctx: { approvalGranted: true } },
    { 'x-broker-key': 'agent-test-key' }
  );
  assert.equal(r.status, 403);
  const j = await r.json();
  assert.equal(j.ok, false);
  assert.equal(j.requiresApproval, true);
});

test('agent cannot mint approvals (needs approver key)', async () => {
  const r = await post('/approve', { tool: 'send_approved_draft' }, { 'x-broker-key': 'agent-test-key' });
  assert.equal(r.status, 401);
});

test('approver mints token, agent executes outbound tool with it', async () => {
  const mint = await post('/approve', { tool: 'send_approved_draft', args: { draftId: 'd1' } }, { 'x-approver-key': 'approver-test-key' });
  assert.equal(mint.status, 200);
  const { approvalId } = await mint.json();
  assert.ok(approvalId);

  const exec = await post(
    '/execute',
    { tool: 'send_approved_draft', args: { draftId: 'd1' }, approvalId },
    { 'x-broker-key': 'agent-test-key' }
  );
  assert.equal(exec.status, 200);
  assert.equal((await exec.json()).ok, true);
});

test('approval is bound to args: same tool, different args is denied', async () => {
  const mint = await post('/approve', { tool: 'send_approved_draft', args: { draftId: 'd1' } }, { 'x-approver-key': 'approver-test-key' });
  const { approvalId } = await mint.json();

  // Approval minted for draft d1 must not authorize sending draft d2.
  const exec = await post(
    '/execute',
    { tool: 'send_approved_draft', args: { draftId: 'd2' }, approvalId },
    { 'x-broker-key': 'agent-test-key' }
  );
  assert.equal(exec.status, 403);
  assert.equal((await exec.json()).ok, false);
});

test('approval token is single-use and tool-scoped', async () => {
  const mint = await post('/approve', { tool: 'send_approved_draft' }, { 'x-approver-key': 'approver-test-key' });
  const { approvalId } = await mint.json();

  // Wrong tool -> denied.
  const wrongTool = await post(
    '/execute',
    { tool: 'delete_file', args: { id: 'f1' }, approvalId },
    { 'x-broker-key': 'agent-test-key' }
  );
  assert.equal(wrongTool.status, 403);

  // Token already consumed -> reuse on correct tool also denied.
  const reuse = await post(
    '/execute',
    { tool: 'send_approved_draft', args: { draftId: 'd1' }, approvalId },
    { 'x-broker-key': 'agent-test-key' }
  );
  assert.equal(reuse.status, 403);
});

test('approval mint is recorded on the audit trail', async () => {
  const captured = [];
  const previous = broker.audit.sink;
  broker.audit.sink = (line) => {
    captured.push(JSON.parse(line));
    if (typeof previous === 'function') previous(line);
  };
  try {
    const mint = await post(
      '/approve',
      { tool: 'delete_file', args: { id: 'f-audit' } },
      { 'x-approver-key': 'approver-test-key' }
    );
    assert.equal(mint.status, 200);
    const rec = captured.find((e) => e.outcome === 'approval_minted');
    assert.ok(rec, 'expected approval_minted audit record');
    assert.equal(rec.tool, 'delete_file');
    assert.equal(rec.user, 'approver');
    assert.equal(rec.args.id, 'f-audit');
  } finally {
    broker.audit.sink = previous;
  }
});

test('failed approver auth is recorded on the audit trail', async () => {
  const captured = [];
  const previous = broker.audit.sink;
  broker.audit.sink = (line) => {
    captured.push(JSON.parse(line));
    if (typeof previous === 'function') previous(line);
  };
  try {
    const r = await post('/approve', { tool: 'delete_file' }, { 'x-approver-key': 'wrong' });
    assert.equal(r.status, 401);
    const rec = captured.find((e) => e.outcome === 'unauthorized');
    assert.ok(rec, 'expected unauthorized audit record');
    assert.equal(rec.tool, '/approve');
  } finally {
    broker.audit.sink = previous;
  }
});
