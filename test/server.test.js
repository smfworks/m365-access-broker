// Set known keys BEFORE importing the server (config reads env at import time).
process.env.BROKER_KEY = 'agent-test-key';
process.env.BROKER_APPROVER_KEY = 'approver-test-key';
process.env.BROKER_DRY_RUN = 'true';

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

const { server, start } = await import('../src/server.js');

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

test('health is public', async () => {
  const r = await fetch(base + '/health');
  assert.equal(r.status, 200);
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
  const mint = await post('/approve', { tool: 'send_approved_draft' }, { 'x-approver-key': 'approver-test-key' });
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
