import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { config } from './config.js';
import { Broker } from './broker.js';
import { ApprovalStore } from './approvals.js';

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
const approverKey = config.approverKey || randomBytes(24).toString('hex');
const ephemeral = !config.brokerKey || !config.approverKey;

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) reject(new Error('payload_too_large'));
    });
    req.on('end', () => {
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
  return typeof actual === 'string' && actual.length === expected.length && actual === expected;
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return send(res, 200, { ok: true, mode: broker.graph.mode, dryRun: config.dryRun });
    }

    // Host-UI-only: mint an approval token for a specific tool.
    if (req.method === 'POST' && req.url === '/approve') {
      if (!headerEquals(req.headers['x-approver-key'], approverKey)) {
        return send(res, 401, { ok: false, error: 'unauthorized_approver' });
      }
      const body = await readBody(req);
      if (!body.tool) return send(res, 400, { ok: false, error: 'missing tool' });
      const approvalId = approvals.create(body.tool);
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
      const ctx = { user: 'local-agent' };
      if (body.approvalId) {
        ctx.approvalGranted = approvals.consume(body.approvalId, body.tool);
      }

      const result = await broker.execute(body.tool, body.args || {}, ctx);
      return send(res, result.ok ? 200 : 403, result);
    }

    return send(res, 404, { ok: false, error: 'not_found' });
  } catch (err) {
    // Never leak internals/stack — only a coarse, known error label.
    const known = ['payload_too_large', 'invalid_json'].includes(err.message)
      ? err.message
      : 'bad_request';
    return send(res, 400, { ok: false, error: known });
  }
});

export function start(port = config.port) {
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      console.log(
        `OpenClaw M365 Broker listening on http://127.0.0.1:${addr.port} ` +
          `(mode=${broker.graph.mode}, dryRun=${config.dryRun})`
      );
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

export { server, broker, approvals, brokerKey, approverKey };
