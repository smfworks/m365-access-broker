import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LiveGraphClient } from '../src/graphClient.js';
import { config } from '../src/config.js';

test('live client refuses app-only calls without MS_USER_ID', () => {
  const client = new LiveGraphClient();
  const prev = config.ms.userId;
  config.ms.userId = '';
  try {
    assert.throws(() => client._principal(), (err) => err.code === 'CONFIG');
  } finally {
    config.ms.userId = prev;
  }
});

test('live client addresses /users/{id} when MS_USER_ID is set', () => {
  const client = new LiveGraphClient();
  const prev = config.ms.userId;
  config.ms.userId = 'user-guid-1';
  try {
    assert.equal(client._principal(), '/users/user-guid-1');
  } finally {
    config.ms.userId = prev;
  }
});

test('live client rejects a userId that would alter the path', () => {
  const client = new LiveGraphClient();
  const prev = config.ms.userId;
  config.ms.userId = '../admin';
  try {
    assert.throws(() => client._principal(), /invalid_userId/);
  } finally {
    config.ms.userId = prev;
  }
});
