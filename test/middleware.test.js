import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

// We test middleware in isolation by creating a minimal HTTP server that
// runs the middleware chain and then responds with a simple JSON body.

import {
  requestId,
  securityHeaders,
  cors,
  rateLimit,
  requestLogger,
  gracefulShutdown,
} from '../src/middleware.js';

// ── Helper: create a test server with given middleware ──────────────────────
function makeServer(middleware, handler) {
  const server = createServer((req, res) => {
    let i = 0;
    function next() {
      if (i < middleware.length) {
        middleware[i++](req, res, next);
      } else {
        handler(req, res);
      }
    }
    next();
  });
  return server;
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

// ── Request ID ──────────────────────────────────────────────────────────────

test('requestId: generates a unique id per request', async () => {
  const server = makeServer([requestId()], (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: req.id }));
  });
  const base = await listen(server);
  try {
    const r1 = await fetch(base);
    const j1 = await r1.json();
    const r2 = await fetch(base);
    const j2 = await r2.json();
    assert.ok(j1.id);
    assert.ok(j2.id);
    assert.notEqual(j1.id, j2.id);
    // Echoed in response header
    assert.equal(r1.headers.get('x-request-id'), j1.id);
  } finally {
    server.close();
  }
});

test('requestId: accepts client-supplied x-request-id', async () => {
  const server = makeServer([requestId()], (req, res) => {
    res.writeHead(200);
    res.end(JSON.stringify({ id: req.id }));
  });
  const base = await listen(server);
  try {
    const r = await fetch(base, { headers: { 'x-request-id': 'my-trace-123' } });
    const j = await r.json();
    assert.equal(j.id, 'my-trace-123');
    assert.equal(r.headers.get('x-request-id'), 'my-trace-123');
  } finally {
    server.close();
  }
});

test('requestId: ignores excessively long client id', async () => {
  const server = makeServer([requestId()], (req, res) => {
    res.writeHead(200);
    res.end(JSON.stringify({ id: req.id }));
  });
  const base = await listen(server);
  try {
    const longId = 'x'.repeat(200);
    const r = await fetch(base, { headers: { 'x-request-id': longId } });
    const j = await r.json();
    assert.notEqual(j.id, longId);
    assert.ok(j.id.length <= 128);
  } finally {
    server.close();
  }
});

// ── Security headers ───────────────────────────────────────────────────────

test('securityHeaders: sets all expected headers', async () => {
  const server = makeServer([securityHeaders()], (req, res) => {
    res.writeHead(200);
    res.end('{}');
  });
  const base = await listen(server);
  try {
    const r = await fetch(base);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
    assert.equal(r.headers.get('x-xss-protection'), '0');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert.ok(r.headers.get('content-security-policy'));
    assert.ok(r.headers.get('permissions-policy'));
  } finally {
    server.close();
  }
});

// ── CORS ────────────────────────────────────────────────────────────────────

test('cors: allows requests from allowed origin', async () => {
  const server = makeServer(
    [cors({ allowedOrigins: ['http://localhost:3000'] })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    const r = await fetch(base, { headers: { origin: 'http://localhost:3000' } });
    assert.equal(r.headers.get('access-control-allow-origin'), 'http://localhost:3000');
    assert.equal(r.headers.get('access-control-allow-methods'), 'GET, POST, OPTIONS');
    assert.ok(r.headers.get('access-control-allow-headers'));
  } finally {
    server.close();
  }
});

test('cors: blocks requests from disallowed origin (no ACAO header)', async () => {
  const server = makeServer(
    [cors({ allowedOrigins: ['http://localhost:3000'] })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    const r = await fetch(base, { headers: { origin: 'http://evil.com' } });
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  } finally {
    server.close();
  }
});

test('cors: handles OPTIONS preflight with 204', async () => {
  const server = makeServer(
    [cors({ allowedOrigins: ['http://localhost:3000'] })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    const r = await fetch(base, {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:3000',
        'access-control-request-method': 'POST',
      },
    });
    assert.equal(r.status, 204);
    assert.equal(r.headers.get('access-control-allow-origin'), 'http://localhost:3000');
    assert.ok(r.headers.get('access-control-max-age'));
  } finally {
    server.close();
  }
});

test('cors: no CORS headers when allowedOrigins is empty', async () => {
  const server = makeServer([cors()], (req, res) => {
    res.writeHead(200);
    res.end('{}');
  });
  const base = await listen(server);
  try {
    const r = await fetch(base, { headers: { origin: 'http://localhost:3000' } });
    assert.equal(r.headers.get('access-control-allow-origin'), null);
  } finally {
    server.close();
  }
});

// ── Rate limiting ───────────────────────────────────────────────────────────

test('rateLimit: allows requests under the limit', async () => {
  const server = makeServer(
    [rateLimit({ windowMs: 10_000, maxRequests: 5, maxBurst: 5 })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    for (let i = 0; i < 10; i++) {
      const r = await fetch(base);
      assert.equal(r.status, 200);
      assert.ok(r.headers.get('x-ratelimit-remaining'));
    }
  } finally {
    server.close();
  }
});

test('rateLimit: returns 429 when limit exceeded', async () => {
  const server = makeServer(
    [rateLimit({ windowMs: 10_000, maxRequests: 2, maxBurst: 0 })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    // First 2 requests pass.
    await fetch(base);
    await fetch(base);
    // Third should be rate-limited.
    const r = await fetch(base);
    assert.equal(r.status, 429);
    const j = await r.json();
    assert.equal(j.error, 'rate_limited');
    assert.ok(r.headers.get('retry-after'));
  } finally {
    server.close();
  }
});

test('rateLimit: includes rate-limit headers', async () => {
  const server = makeServer(
    [rateLimit({ windowMs: 10_000, maxRequests: 10, maxBurst: 5 })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    const r = await fetch(base);
    assert.equal(r.headers.get('x-ratelimit-limit'), '15');
    assert.ok(parseInt(r.headers.get('x-ratelimit-remaining')) >= 0);
    assert.ok(parseInt(r.headers.get('x-ratelimit-reset')) >= 0);
  } finally {
    server.close();
  }
});

// ── Request logger ──────────────────────────────────────────────────────────

test('requestLogger: emits structured JSON log lines', async () => {
  const lines = [];
  const writable = { write: (s) => lines.push(s) };
  const server = makeServer(
    [requestId(), requestLogger({ log: writable })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    await fetch(base);
    // Wait for the 'finish' event to fire.
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(lines.length, 1);
    const entry = JSON.parse(lines[0]);
    assert.ok(entry.timestamp);
    assert.ok(entry.requestId);
    assert.equal(entry.method, 'GET');
    assert.equal(entry.statusCode, 200);
    assert.ok(entry.durationMs >= 0);
  } finally {
    server.close();
  }
});

test('requestLogger: never throws on write failure', async () => {
  const badLog = { write: () => { throw new Error('log broken'); } };
  const server = makeServer(
    [requestLogger({ log: badLog })],
    (req, res) => { res.writeHead(200); res.end('{}'); }
  );
  const base = await listen(server);
  try {
    const r = await fetch(base);
    assert.equal(r.status, 200); // request still succeeds
  } finally {
    server.close();
  }
});

// ── Graceful shutdown ───────────────────────────────────────────────────────

test('gracefulShutdown: closes the server on signal', async () => {
  const server = makeServer([], (req, res) => {
    res.writeHead(200);
    res.end('{}');
  });
  const base = await listen(server);
  const sockets = new Set();
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });

  const cleanup = gracefulShutdown(server, { timeoutMs: 500, sockets });

  // Verify server is still up before signal.
  const r = await fetch(base);
  assert.equal(r.status, 200);

  // Emit SIGTERM.
  process.emit('SIGTERM');

  // Wait for server to close.
  await new Promise((resolve) => {
    server.on('close', resolve);
    // Fallback timeout
    setTimeout(resolve, 1000);
  });

  // Verify server is no longer listening.
  await assert.rejects(() => fetch(base));

  // Cleanup listeners so they don't interfere with other tests.
  cleanup();
});