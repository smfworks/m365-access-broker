import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../src/rateLimit.js';

test('rate limiter allows up to max then denies', () => {
  const lim = new RateLimiter({ windowMs: 60_000, max: 3 });
  assert.equal(lim.allow('k'), true);
  assert.equal(lim.allow('k'), true);
  assert.equal(lim.allow('k'), true);
  assert.equal(lim.allow('k'), false);
  assert.equal(lim.remaining('k'), 0);
});

test('rate limiter keys are independent', () => {
  const lim = new RateLimiter({ windowMs: 60_000, max: 1 });
  assert.equal(lim.allow('a'), true);
  assert.equal(lim.allow('a'), false);
  assert.equal(lim.allow('b'), true);
});

test('rate limiter resets after the window', () => {
  const lim = new RateLimiter({ windowMs: 20, max: 1 });
  assert.equal(lim.allow('k'), true);
  assert.equal(lim.allow('k'), false);
  return new Promise((resolve) => {
    setTimeout(() => {
      assert.equal(lim.allow('k'), true);
      resolve();
    }, 30);
  });
});
