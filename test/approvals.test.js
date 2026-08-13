import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApprovalStore } from '../src/approvals.js';

test('create then consume succeeds once for matching tool', () => {
  const store = new ApprovalStore();
  const id = store.create('send_approved_draft');
  assert.equal(store.consume(id, 'send_approved_draft'), true);
});

test('consume is single-use', () => {
  const store = new ApprovalStore();
  const id = store.create('send_approved_draft');
  store.consume(id, 'send_approved_draft');
  assert.equal(store.consume(id, 'send_approved_draft'), false);
});

test('consume rejects tool mismatch and burns the token', () => {
  const store = new ApprovalStore();
  const id = store.create('send_approved_draft');
  assert.equal(store.consume(id, 'delete_file'), false);
  assert.equal(store.consume(id, 'send_approved_draft'), false);
});

test('expired token is rejected', () => {
  const store = new ApprovalStore({ ttlMs: -1 });
  const id = store.create('send_approved_draft');
  assert.equal(store.consume(id, 'send_approved_draft'), false);
});

test('unknown / empty id is rejected', () => {
  const store = new ApprovalStore();
  assert.equal(store.consume('nope', 'send_approved_draft'), false);
  assert.equal(store.consume(undefined, 'send_approved_draft'), false);
});

test('minting is rate-limited so the store cannot be flooded', () => {
  const store = new ApprovalStore({ maxMintsPerWindow: 3, mintWindowMs: 60_000 });
  store.create('send_approved_draft', { draftId: 'a' });
  store.create('send_approved_draft', { draftId: 'b' });
  store.create('send_approved_draft', { draftId: 'c' });
  assert.throws(() => store.create('send_approved_draft', { draftId: 'd' }), /approval_rate_limited/);
  assert.equal(store.tokens.size, 3);
});
