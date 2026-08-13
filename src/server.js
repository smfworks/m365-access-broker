import { createServer } from 'node:http';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { config } from './config.js';
import { Broker } from './broker.js';
import { ApprovalStore } from './approvals.js';
import {
  requestId,
  securityHeaders,
  cors,
  rateLimit,
  requestLogger,
  gracefulShutdown,
} from './middleware.js';

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

const brokerKey = config.brokerKey || randomBytes(24).toString('hex');
let approverKey = config.approverKey || randomBytes(24).toString('hex');
// Ensure the broker and approver keys are never the same — if they happen
// to collide (or if the operator sets both to the same value) the agent
// could mint its own approvals, defeating the entire gate.
if (approverKey === brokerKey) {
  if (!config.approverKey) {
    // Collision on ephemeral keys: regenerate until different.
    do {
      approverKey = randomBytes(24).toString('hex');
    } while (approverKey === brokerKey);
  } else {
    // Operator set both keys to the same value — refuse to start.
    console.error('FATAL: BROKER_KEY and BROKER_APPROVER_KEY must be different.');
    process.exit(1);
  }
}
const ephemeral = !config.brokerKey || !config.approverKey;

// Track active sockets for graceful shutdown force-close.
const sockets = new Set();

// ── Middleware stack ─────────────────────────────────────────────────────────
const corsAllowedOrigins = config.corsAllowedOrigins;
const mw = [
  requestId(),
  securityHeaders(),
  cors({ allowedOrigins: corsAllowedOrigins }),
  rateLimit({
    windowMs: config.rateLimitWindowMs,
    maxRequests: config.rateLimitMax,
    maxBurst: config.rateLimitBurst,
  }),
  requestLogger({ log: process.stdout }),
];

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > config.maxBodyBytes) {
        tooLarge = true;
        // Stop reading the rest of the body to avoid buffering a huge payload.
        // Pause the stream (don't destroy — the socket must stay open for the
        // error response to be sent back).
        req.removeAllListeners('data');
        req.removeAllListeners('end');
        req.pause();
        reject(new Error('payload_too_large'));
      }
    });
    req.on('end', () => {
      if (tooLarge) return; // already rejected
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('invalid_json'));
      }
    });
    req.on('error', reject);
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

// ── Route handler (runs after middleware) ──────────────────────────────────
async function handleRoute(req, res) {
  if (req.method === 'GET' && req.url === '/health') {
    return send(res, 200, {
      ok: true,
      mode: broker.graph.mode,
      dryRun: config.dryRun,
      requiredScopes: broker.policy.requiredScopes(),
    });
  }

  // Host-UI-only: mint an approval token for a specific tool.
  if (req.method === 'POST' && req.url === '/approve') {
    if (!headerEquals(req.headers['x-approver-key'], approverKey)) {
      return send(res, 401, { ok: false, error: 'unauthorized_approver' });
    }
    const body = await readBody(req);
    if (!body.tool) return send(res, 400, { ok: false, error: 'missing tool' });
    // Bind the approval to the exact tool AND args the approver saw.
    const approvalId = approvals.create(body.tool, body.args || {});
    return send(res, 200, { ok: true, approvalId, expiresInMs: approvals.ttlMs });
  }

  // Everything below requires the agent (broker) key.
  if (!headerEquals(req.headers['x-broker-key'], brokerKey)) {
    return send(res, 401, { ok: false, error: 'unauthorized' });
  }

  if (req.method === 'GET' && req.url === '/tools') {
    return send(res, 200, { ok: true, tools: broker.listTools() });
  }

  if (req.method === 'POST' && req.url === '/execute') {
    const body = await readBody(req);
    if (!body.tool) return send(res, 400, { ok: false, error: 'missing tool' });

    // Build ctx server-side. The agent CANNOT set approvalGranted directly;
    // it can only present an approvalId minted via /approve by the host UI.
    const ctx = { user: 'local-agent', requestId: req.id };
    if (body.approvalId) {
      // The token only validates for the same tool + args it was minted for.
      ctx.approvalGranted = approvals.consume(body.approvalId, body.tool, body.args || {});
    }

    const result = await broker.execute(body.tool, body.args || {}, ctx);
    return send(res, result.ok ? 200 : 403, result);
  }

  return send(res, 404, { ok: false, error: 'not_found' });
}

// ── Server with middleware chain ───────────────────────────────────────────
const server = createServer((req, res) => {
  let i = 0;

  function next() {
    if (i < mw.length) {
      const layer = mw[i++];
      layer(req, res, next);
    } else {
      // All middleware passed — handle the route.
      handleRoute(req, res).catch((err) => {
        // Never leak internals/stack — only a coarse, known error label.
        const known = ['payload_too_large', 'invalid_json'].includes(err.message)
          ? err.message
          : 'bad_request';
        if (!res.headersSent) {
          send(res, 400, { ok: false, error: known });
        }
      });
    }
  }

  next();
});

// Track sockets for graceful shutdown.
server.on('connection', (socket) => {
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
});

// ── Graceful shutdown ──────────────────────────────────────────────────────
const shutdownCleanup = gracefulShutdown(server, {
  timeoutMs: config.shutdownTimeoutMs,
  sockets,
  onShutdown: async () => {
    // Flush any in-flight audit writes (the AuditLogger uses sync writes,
    // so there is nothing to drain, but the hook is here for future use).
    console.log('Shutdown hook complete.');
  },
});

export function start(port = config.port) {
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      console.log(
        `OpenClaw M365 Broker listening on http://127.0.0.1:${addr.port} ` +
          `(mode=${broker.graph.mode}, dryRun=${config.dryRun})`
      );
      // Publish the least-privilege scope contract so the operator can grant the
      // app registration exactly these permissions — no more.
      console.log(`  least-privilege scopes: ${broker.policy.requiredScopes().join(', ')}`);
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
  start();
}

export { server, broker, approvals, brokerKey, approverKey, shutdownCleanup, sockets };