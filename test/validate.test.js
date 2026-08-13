import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeId, encodePathSegment, safeTop, safeQuery, safeEmails, requireArg } from '../src/validate.js';

test('safeId rejects empty and path-delimiter values', () => {
  assert.equal(safeId('abc'), 'abc');
  assert.throws(() => safeId(''), /invalid_id/);
  assert.throws(() => safeId('a/b'), /invalid_id/);
  assert.throws(() => safeId('a?b'), /invalid_id/);
  assert.throws(() => safeId('a#b'), /invalid_id/);
});

test('encodePathSegment percent-encodes a validated id', () => {
  assert.equal(encodePathSegment('a b'), 'a%20b');
  assert.throws(() => encodePathSegment('../x'), /invalid_id/);
});

test('safeTop accepts integers 1-50 and rejects injection strings', () => {
  assert.equal(safeTop(undefined), 5);
  assert.equal(safeTop(10), 10);
  assert.equal(safeTop('7'), 7);
  assert.throws(() => safeTop(0), /invalid_limit/);
  assert.throws(() => safeTop(51), /invalid_limit/);
  assert.throws(() => safeTop('5&$expand=foo'), /invalid_limit/);
  assert.throws(() => safeTop(1.5), /invalid_limit/);
});

test('safeQuery rejects non-strings', () => {
  assert.equal(safeQuery(undefined), '');
  assert.equal(safeQuery('hello'), 'hello');
  assert.throws(() => safeQuery({ $filter: '1' }), /invalid_query/);
});

test('safeEmails requires a well-formed list', () => {
  assert.deepEqual(safeEmails('a@b.co'), ['a@b.co']);
  assert.deepEqual(safeEmails(['a@b.co', 'c@d.co']), ['a@b.co', 'c@d.co']);
  assert.throws(() => safeEmails('not-an-email'), /invalid_to/);
  assert.throws(() => safeEmails([]), /invalid_to/);
  assert.throws(() => safeEmails(['ok@x.com', 'nope']), /invalid_to/);
});

test('requireArg throws BAD_ARGS', () => {
  assert.throws(() => requireArg({}, 'id'), (err) => err.code === 'BAD_ARGS');
});
