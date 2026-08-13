import { createServer } from 'node:http';
import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { config, assertDistinctKeys } from './config.js';
import { Broker } from './broker.js';
import { ApprovalStore } from './approvals.js';
import { RateLimiter } from './rateLimit.js';

// Minimal local HTTP API exposing the broker to a local-first agent.
//
// Two distinct credentials separate the agent from the approver so the agent
// can never grant its own approval:
//   - brokerKey   (x-broker-key):   the agent uses this to read/draft/execute.
//   - approverKey (x-approver-key): the host UI uses this to mint approvals.
// Both are required. If unset, ephemeral keys are generated at startup — there
// is no "no auth" mode, which also blocks CSRF from malicious web pages (a
// cross-origin fetch cannot set the custom header without a rejected preflight).

const broker = new Broker();
const approvals = new ApprovalStore();
const executeLimit = new RateLimiter({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax });
const approveLimit = new RateLimiter({ windowMs: config.rateLimitWindowMs, max: config.rateLimitMax });

const brokerKey = config.brokerKey || randomBytes(24).toString('hex');
const approverKey = config.approverKey || randomBytes(24).toString('hex');
assertDistinctKeys(brokerKey, approverKey);
const ephemeral = !config.brokerKey || !config.approverKey;

function send(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
  res.end(JSON.stringify(body));
}

function requestIdOf(req) {
  const incoming = req.headers['x-request-id'];
  if (typeof incoming === 'string' && incoming.length > 0 && incoming.length <= 128) {
    return incoming;
  }
  return randomUUID();
}

function logAccess({ method, path, status, ms, requestId }) {
  process.stderr.write(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: 'info',
      msg: 'http',
      method,
      path,
      status,
      ms,
      requestId,
    }) + '\n'
  );
}

function readBody(req, { maxBytes = 1_000_000, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    let data = '';
    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      finish(new Error('payload_timeout'));
    }, timeoutMs);
    req.on('data', (chunk) => {
      if (settled) return;
      data += chunk;
      if (data.length > maxBytes) {
        req.pause();
        finish(new Error('payload_too_large'));
      }
    });
    req.on('end', () => {
      if (settled) return;
      if (!data) return finish(null, {});
      try {
        finish(null, JSON.parse(data));
      } catch {
        finish(new Error('invalid_json'));
      }
    });
    req.on('error', (err) => finish(err));
  });
}

function headerEquals(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  // Compare fixed-length digests so the check is constant-time and does not leak
  // the expected key's length or a matching-prefix timing oracle.
  const a = createHash('sha256').update(actual).digest();
  const b = createHash('sha256').update(expected).digest();
  return timingSafeEqual(a, b);
}

const KNOWN_BODY_ERRORS = new Set(['payload_too_large', 'invalid_json', 'payload_timeout']);

const server = createServer(async (req, res) => {
  const started = Date.now();
  const requestId = requestIdOf(req);
  const path = req.url || '/';
  const done = (status, body) => {
    logAccess({ method: req.method, path, status, ms: Date.now() - started, requestId });
    return send(res, status, body, { 'x-request-id': requestId });
  };
  try {
    if (req.method === 'GET' && path === '/health') {
      return done(200, {
        ok: true,
        mode: broker.graph.mode,
        dryRun: config.dryRun,
        requiredScopes: broker.policy.requiredScopes(),
      });
    }

    // Host-UI-only: mint an approval token for a specific tool.
    if (req.method === 'POST' && path === '/approve') {
      if (!headerEquals(req.headers['x-approver-key'], approverKey)) {
        return done(401, { ok: false, error: 'unauthorized_approver' });
      }
      if (!approveLimit.allow('approver')) {
        return done(429, { ok: false, error: 'rate_limited' });
      }
      const body = await readBody(req);
      if (!body.tool) return done(400, { ok: false, error: 'missing tool' });
      // Bind the approval to the exact tool AND args the approver saw.
      const approvalId = approvals.create(body.tool, body.args || {});
      return done(200, { ok: true, approvalId, expiresInMs: approvals.ttlMs });
    }

    // Everything below requires the agent (broker) key.
    if (!headerEquals(req.headers['x-broker-key'], brokerKey)) {
      return done(401, { ok: false, error: 'unauthorized' });
    }

    if (req.method === 'GET' && path === '/tools') {
      return done(200, { ok: true, tools: broker.listTools() });
    }

    if (req.method === 'POST' && path === '/execute') {
      if (!executeLimit.allow('agent')) {
        return done(429, { ok: false, error: 'rate_limited' });
      }
      const body = await readBody(req);
      if (!body.tool) return done(400, { ok: false, error: 'missing tool' });

      // Build ctx server-side. The agent CANNOT set approvalGranted directly;
      // it can only present an approvalId minted via /approve by the host UI.
      const ctx = { user: 'local-agent', requestId };
      if (body.approvalId) {
        // The token only validates for the same tool + args it was minted for.
        ctx.approvalGranted = approvals.consume(body.approvalId, body.tool, body.args || {});
      }

      const result = await broker.execute(body.tool, body.args || {}, ctx);
      return done(result.ok ? 200 : 403, result);
    }

    return done(404, { ok: false, error: 'not_found' });
  } catch (err) {
    // Never leak internals/stack — only a coarse, known error label.
    const known = KNOWN_BODY_ERRORS.has(err.message) ? err.message : 'bad_request';
    const status = err.message === 'payload_too_large' ? 413 : err.message === 'payload_timeout' ? 408 : 400;
    const result = done(status, { ok: false, error: known });
    if (err.message === 'payload_too_large' || err.message === 'payload_timeout') {
      res.on('finish', () => req.destroy());
    }
    return result;
  }
});

export function start(port = config.port) {
  return new Promise((resolve, reject) => {
    const onError = (err) => {
      server.off('error', onError);
      reject(err);
    };
    server.once('error', onError);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', onError);
      const addr = server.address();
      console.log(
        `OpenClaw M365 Broker listening on http://127.0.0.1:${addr.port} ` +
          `(mode=${broker.graph.mode}, dryRun=${config.dryRun})`
      );
      // Publish the least-privilege scope contract so the operator can grant the
      // app registration exactly these permissions — no more.
      console.log(`  least-privilege scopes: ${broker.policy.requiredScopes().join(', ')}`);
      if (config.auditHmacKey) {
        console.log('  audit chain: HMAC-SHA256 (BROKER_AUDIT_HMAC_KEY is set)');
      } else {
        console.log('  audit chain: unkeyed SHA-256 (set BROKER_AUDIT_HMAC_KEY for keyed integrity)');
      }
      if (ephemeral) {
        console.log('Ephemeral keys generated (set BROKER_KEY / BROKER_APPROVER_KEY to persist):');
        console.log(`  x-broker-key:   ${brokerKey}`);
        console.log(`  x-approver-key: ${approverKey}`);
      }
      resolve(addr.port);
    });
  });
}

const isMain = process.argv[1] && process.argv[1].endsWith('server.js');
if (isMain) {
  start().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}

export { server, broker, approvals, brokerKey, approverKey, executeLimit, approveLimit };
