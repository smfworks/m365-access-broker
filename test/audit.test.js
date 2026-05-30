import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, AuditLogger } from '../src/audit.js';

test('redact masks secret keys', () => {
  const out = redact({ authorization: 'Bearer abc', token: 'xyz', subject: 'hello' });
  assert.equal(out.authorization, '[REDACTED]');
  assert.equal(out.token, '[REDACTED]');
  assert.equal(out.subject, 'hello');
});

test('redact truncates long strings', () => {
  const long = 'a'.repeat(500);
  const out = redact({ body: long });
  assert.ok(out.body.length < 500);
  assert.match(out.body, /\+260/);
});

test('redact handles nested objects and arrays', () => {
  const out = redact({ user: { password: 'p', name: 'm' }, items: [{ secret: 's' }] });
  assert.equal(out.user.password, '[REDACTED]');
  assert.equal(out.user.name, 'm');
  assert.equal(out.items[0].secret, '[REDACTED]');
});

test('AuditLogger records a structured entry with id and timestamp', () => {
  const entries = [];
  const audit = new AuditLogger({ sink: (line) => entries.push(JSON.parse(line)) });
  const rec = audit.record({
    tool: 'search_mail',
    outcome: 'success',
    scopes: ['Mail.Read'],
    args: { query: 'x', token: 'should-be-hidden' },
  });
  assert.equal(entries.length, 1);
  assert.ok(rec.id);
  assert.ok(rec.timestamp);
  assert.equal(entries[0].args.token, '[REDACTED]');
});

test('redact scrubs secrets embedded inside non-secret-named string values', () => {
  const out = redact({ body: 'config is client_secret=supersecret123 and Bearer abcdef123456789' });
  assert.doesNotMatch(out.body, /supersecret123/);
  assert.doesNotMatch(out.body, /abcdef123456789/);
  assert.match(out.body, /\[REDACTED\]/);
});

test('redact masks JWT-shaped values', () => {
  const out = redact({ note: 'token eyJabcdef.ghijklmn.opqrstuv lives here' });
  assert.match(out.note, /\[REDACTED_JWT\]/);
});
