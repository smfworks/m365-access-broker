import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(__dirname, '..');

const GUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Minimal .env loader (no dependency on dotenv).
function loadDotEnv() {
  const envPath = resolve(projectRoot, '.env');
  if (!existsSync(envPath)) return;
  const text = readFileSync(envPath, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

loadDotEnv();

function bool(value, fallback) {
  if (value === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function int(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function stringList(value, fallback) {
  if (!value || typeof value !== 'string') return fallback;
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function isGuid(value) {
  return typeof value === 'string' && GUID_RE.test(value.trim());
}

export function parseBrokerPort(value, fallback = 8787) {
  const raw = value === undefined || value === null || value === '' ? fallback : value;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    const err = new Error('invalid_broker_port');
    err.code = 'BAD_CONFIG';
    throw err;
  }
  return n;
}

// Audit log must stay inside the project tree. Absolute paths and `..` escape.
export function resolveAuditLogPath(root, requested) {
  const raw = requested || 'audit.log';
  if (typeof raw !== 'string' || !raw.trim()) {
    const err = new Error('invalid_audit_log_path');
    err.code = 'BAD_CONFIG';
    throw err;
  }
  if (isAbsolute(raw)) {
    const err = new Error('audit_log_must_be_relative');
    err.code = 'BAD_CONFIG';
    throw err;
  }
  const resolved = resolve(root, raw);
  const rel = relative(root, resolved);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) {
    const err = new Error('audit_log_escapes_project');
    err.code = 'BAD_CONFIG';
    throw err;
  }
  return resolved;
}

// Client-credentials Graph cannot call /me. Live mode requires an explicit user object id.
export function liveGraphUserRoot(userId) {
  if (!isGuid(userId)) {
    const err = new Error('live_graph_requires_BROKER_GRAPH_USER_ID');
    err.code = 'LIVE_GRAPH_MISCONFIGURED';
    throw err;
  }
  return `/users/${userId.trim()}`;
}

// Coarse reasons for the agent. Full detail stays in the redacted audit log.
export function publicHandlerReasons(err) {
  if (!err) return ['handler_error'];
  if (err.code === 'BAD_ARGS' && typeof err.message === 'string') return [err.message];
  if (typeof err.message === 'string' && /^invalid_[a-zA-Z0-9_]+$/.test(err.message)) {
    return [err.message];
  }
  if (err.code === 'LIVE_GRAPH_MISCONFIGURED') return ['live_graph_misconfigured'];
  if (typeof err.code === 'string' && /^[A-Z][A-Z0-9_]{2,40}$/.test(err.code)) {
    return [err.code];
  }
  return ['handler_error'];
}

export function assertLiveMsIdentifiers(ms) {
  if (!ms.tenantId || !ms.clientId || !ms.clientSecret) return;
  if (!isGuid(ms.tenantId)) {
    const err = new Error('invalid_ms_tenant_id');
    err.code = 'BAD_CONFIG';
    throw err;
  }
  if (!isGuid(ms.clientId)) {
    const err = new Error('invalid_ms_client_id');
    err.code = 'BAD_CONFIG';
    throw err;
  }
}

export const config = {
  projectRoot,
  dryRun: bool(process.env.BROKER_DRY_RUN, true),
  port: parseBrokerPort(process.env.BROKER_PORT, 8787),
  brokerKey: process.env.BROKER_KEY || '',
  approverKey: process.env.BROKER_APPROVER_KEY || '',
  auditLog: resolveAuditLogPath(projectRoot, process.env.BROKER_AUDIT_LOG || 'audit.log'),
  ms: {
    tenantId: process.env.MS_TENANT_ID || '',
    clientId: process.env.MS_CLIENT_ID || '',
    clientSecret: process.env.MS_CLIENT_SECRET || '',
    redirectUri: process.env.MS_REDIRECT_URI || 'http://localhost:3000/auth/callback',
    userId: process.env.BROKER_GRAPH_USER_ID || process.env.MS_USER_ID || '',
  },
  maxBodyBytes: int(process.env.BROKER_MAX_BODY_BYTES, 1_048_576),
  rateLimitWindowMs: int(process.env.BROKER_RATE_LIMIT_WINDOW_MS, 60_000),
  rateLimitMax: int(process.env.BROKER_RATE_LIMIT_MAX, 120),
  rateLimitBurst: int(process.env.BROKER_RATE_LIMIT_BURST, 30),
  corsAllowedOrigins: stringList(process.env.BROKER_CORS_ORIGINS, []),
  shutdownTimeoutMs: int(process.env.BROKER_SHUTDOWN_TIMEOUT_MS, 10_000),
};

export function hasRealCredentials() {
  return Boolean(config.ms.tenantId && config.ms.clientId && config.ms.clientSecret);
}
