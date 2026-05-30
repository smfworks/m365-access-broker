import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine } from '../src/policy.js';

test('read tool is allowed without approval', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('search_mail', { query: 'hi' });
  assert.equal(d.allowed, true);
  assert.equal(d.requiresApproval, false);
  assert.deepEqual(d.scopes, ['Mail.Read']);
});

test('unknown tool is blocked', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('run_graph_query', {});
  assert.equal(d.allowed, false);
  assert.match(d.reasons[0], /unknown_tool/);
});

test('tool outside allowlist is blocked even if in catalog', () => {
  const policy = new PolicyEngine({ allowlist: ['search_mail'] });
  const d = policy.evaluate('delete_file', { id: 'x' });
  assert.equal(d.allowed, false);
  assert.match(d.reasons[0], /tool_not_allowlisted/);
});

test('outbound tool requires approval and is denied without it', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('send_approved_draft', { draftId: 'd1' });
  assert.equal(d.requiresApproval, true);
  assert.equal(d.allowed, false);
  assert.match(d.reasons[0], /approval_required/);
});

test('outbound tool is allowed once approval is granted', () => {
  const policy = new PolicyEngine();
  const d = policy.evaluate('send_approved_draft', { draftId: 'd1' }, { approvalGranted: true });
  assert.equal(d.allowed, true);
  assert.equal(d.requiresApproval, true);
});

test('destructive tool requires approval', () => {
  const policy = new PolicyEngine();
  const denied = policy.evaluate('delete_file', { id: 'f1' });
  assert.equal(denied.allowed, false);
  const allowed = policy.evaluate('delete_file', { id: 'f1' }, { approvalGranted: true });
  assert.equal(allowed.allowed, true);
});
