// HTTP middleware for the M365 Access Broker.
//
// All middleware is pure (no external dependencies) and follows a common
// pattern: (req, res, next) => void.  When a middleware wants to short-circuit
// the request it writes the response and does NOT call next().

import { randomBytes } from 'node:crypto';

// ──────────────────────────────────────────────────────────────────────────
// Request ID
// ──────────────────────────────────────────────────────────────────────────

/**
 * Attach a unique request id to every request.
 *
 * If the client sends `x-request-id` it is accepted as-is (useful for
 * distributed tracing) so long as it is a reasonable length.  Otherwise a
 * 16-byte hex id is generated.  The id is placed on `req.id` and echoed back
 * in the `x-request-id` response header.
 */
export function requestId() {
  return (req, res, next) => {
    const incoming = req.headers['x-request-id'];
    const id =
      typeof incoming === 'string' &&
      incoming.length > 0 &&
      incoming.length <= 128
        ? incoming
        : randomBytes(16).toString('hex');
    req.id = id;
    res.setHeader('x-request-id', id);
    next();
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Security headers
// ──────────────────────────────────────────────────────────────────────────

/**
 * Set a baseline set of security headers on every response.
 *
 * No Helmet dependency — just the headers that matter for an API server:
 *   - X-Content-Type-Options: nosniff
 *   - X-Frame-Options: DENY
 *   - Cache-Control: no-store
 *   - X-XSS-Protection: 0  (disable legacy auditor; CSP is the modern defence)
 *   - Referrer-Policy: no-referrer
 *   - Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
 *   - Permissions-Policy: deny everything
 */
export function securityHeaders() {
  const headers = {
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'cache-control': 'no-store, no-cache, must-revalidate',
    'x-xss-protection': '0',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
    'permissions-policy':
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
  };

  return (req, res, next) => {
    for (const [k, v] of Object.entries(headers)) {
      res.setHeader(k, v);
    }
    next();
  };
}

// ──────────────────────────────────────────────────────────────────────────
// CORS
// ──────────────────────────────────────────────────────────────────────────

/**
 * Minimal CORS policy.
 *
 * The broker is a loopback-only API, so CORS is restrictive by default.
 * `allowedOrigins` is a Set of exact origin strings.  If the request's
 * Origin header matches, it is echoed back; otherwise no
 * Access-Control-Allow-Origin header is set (browser blocks the response).
 *
 * Only the methods actually used by the broker are allowed.  The custom
 * auth headers are exposed so a browser-based host UI can read error
 * responses.
 */
export function cors({ allowedOrigins = [] } = {}) {
  const origins = new Set(allowedOrigins);

  return (req, res, next) => {
    const origin = req.headers.origin;
    // Always set Vary: Origin when CORS is configured (even on non-matching
    // responses) so caches don't poison the response for a different origin.
    if (origins.size > 0) {
      res.setHeader('vary', 'Origin');
    }
    if (origin && origins.has(origin)) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
      res.setHeader('access-control-allow-headers', 'Content-Type, x-broker-key, x-approver-key, x-request-id');
      res.setHeader('access-control-expose-headers', 'x-request-id');
      res.setHeader('access-control-max-age', '86400');
      // Explicitly do NOT set Allow-Credentials: true. The broker uses custom
      // auth headers, not cookies, so cross-origin credential requests should
      // be blocked by the browser.
    }

    // Preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    next();
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Rate limiting (fixed-window, in-memory, per-IP)
// ──────────────────────────────────────────────────────────────────────────

/**
 * Simple fixed-window rate limiter.
 *
 * Keeps a Map of IP → { count, windowStart }.  When the window elapses the
 * counter resets.  Returns 429 with a Retry-After header when the limit is
 * exceeded.
 *
 * @param {object} opts
 * @param {number} opts.windowMs   — window size in ms (default 60_000)
 * @param {number} opts.maxRequests — max requests per window per IP (default 120)
 * @param {number} opts.maxBurst    — extra requests allowed in a burst (default 30)
 */
export function rateLimit({ windowMs = 60_000, maxRequests = 120, maxBurst = 30 } = {}) {
  const buckets = new Map();
  const effectiveMax = maxRequests + maxBurst;

  // Periodic sweep so idle IPs don't linger forever.
  const sweepInterval = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of buckets) {
      if (now - entry.windowStart > windowMs * 2) buckets.delete(ip);
    }
  }, windowMs * 2);
  // Don't keep the event loop alive just for the sweeper.
  if (sweepInterval.unref) sweepInterval.unref();

  return (req, res, next) => {
    // Normalize the remote address so IPv4-mapped IPv6 addresses
    // (::ffff:1.2.3.4) and their plain IPv4 equivalents (1.2.3.4) share the
    // same rate-limit bucket — otherwise a local attacker gets two buckets.
    const rawIp = req.socket?.remoteAddress || 'unknown';
    const ip = rawIp.replace(/^::ffff:/, '');
    const now = Date.now();
    let entry = buckets.get(ip);

    if (!entry || now - entry.windowStart > windowMs) {
      entry = { count: 0, windowStart: now };
      buckets.set(ip, entry);
    }

    entry.count++;
    const remaining = Math.max(0, effectiveMax - entry.count);
    const resetSec = Math.ceil((entry.windowStart + windowMs - now) / 1000);

    res.setHeader('x-ratelimit-limit', String(effectiveMax));
    res.setHeader('x-ratelimit-remaining', String(remaining));
    res.setHeader('x-ratelimit-reset', String(resetSec));

    if (entry.count > effectiveMax) {
      res.setHeader('retry-after', String(resetSec));
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'rate_limited', retryAfterSec: resetSec }));
      return;
    }

    next();
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Structured request logging
// ──────────────────────────────────────────────────────────────────────────

/**
 * Lightweight structured request logger.
 *
 * Emits one JSON line per completed request to the given `log` stream
 * (defaults to stdout).  Each line includes: timestamp, requestId, method,
 * url, statusCode, durationMs, and remoteAddress.  Sensitive headers are
 * never logged.
 */
export function requestLogger({ log = process.stdout } = {}) {
  return (req, res, next) => {
    const start = Date.now();
    const onFinish = () => {
      const duration = Date.now() - start;
      const entry = {
        timestamp: new Date().toISOString(),
        requestId: req.id || null,
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        durationMs: duration,
        remoteAddress: req.socket?.remoteAddress || null,
      };
      try {
        log.write(JSON.stringify(entry) + '\n');
      } catch { /* never let logging crash a request */ }
      cleanup();
    };
    const onError = () => {
      const duration = Date.now() - start;
      const entry = {
        timestamp: new Date().toISOString(),
        requestId: req.id || null,
        method: req.method,
        url: req.url,
        statusCode: res.statusCode || 500,
        durationMs: duration,
        remoteAddress: req.socket?.remoteAddress || null,
        error: true,
      };
      try {
        log.write(JSON.stringify(entry) + '\n');
      } catch { /* ignore */ }
      cleanup();
    };
    const cleanup = () => {
      res.off('finish', onFinish);
      res.off('error', onError);
      res.off('close', onFinish);
    };
    res.on('finish', onFinish);
    res.on('error', onError);
    res.on('close', onFinish);
    next();
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Graceful shutdown helper
// ──────────────────────────────────────────────────────────────────────────

/**
 * Register SIGTERM / SIGINT handlers that close the server gracefully.
 *
 * Stops accepting new connections, waits up to `timeoutMs` for in-flight
 * requests to finish, then force-closes any remaining sockets.  Calls
 * `onShutdown` (if provided) before exiting so the app can flush buffers,
 * close DB connections, etc.
 *
 * @param {import('node:http').Server} server
 * @param {object} opts
 * @param {number} opts.timeoutMs — max wait for in-flight requests (default 10_000)
 * @param {Function} opts.onShutdown — async callback called before exit
 * @param {object} opts.sockets — Set of active sockets (tracked by connection listener)
 * @returns {Function} cleanup — removes the signal listeners (for tests)
 */
export function gracefulShutdown(server, { timeoutMs = 10_000, onShutdown, sockets } = {}) {
  let shuttingDown = false;

  const handler = async (signal) => {
    if (shuttingDown) return; // protect against double-signal
    shuttingDown = true;

    console.log(`\n${signal} received — shutting down gracefully…`);

    // Stop accepting new connections.
    server.close(() => {
      console.log('HTTP server closed.');
    });

    // Force-close any socket that is still open after the timeout.
    const forceTimer = setTimeout(() => {
      if (sockets) {
        for (const s of sockets) {
          try { s.destroy(); } catch { /* ignore */ }
        }
      }
      console.error('Force-closing remaining connections after timeout.');
      process.exit(1);
    }, timeoutMs);
    if (forceTimer.unref) forceTimer.unref();

    try {
      if (onShutdown) await onShutdown();
    } catch (err) {
      console.error('Error during shutdown callback:', err.message);
    }

    // If the server closed naturally before the timeout, clear the timer.
    server.on('close', () => {
      clearTimeout(forceTimer);
      console.log('Graceful shutdown complete.');
      process.exit(0);
    });
  };

  const signals = ['SIGTERM', 'SIGINT'];
  for (const sig of signals) {
    process.on(sig, handler);
  }

  // Return a cleanup function for tests.
  return function cleanup() {
    for (const sig of signals) {
      process.off(sig, handler);
    }
  };
}