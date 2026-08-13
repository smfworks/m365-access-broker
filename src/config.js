import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(__dirname, '..');

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

export const config = {
  projectRoot,
  dryRun: bool(process.env.BROKER_DRY_RUN, true),
  port: int(process.env.BROKER_PORT, 8787),
  brokerKey: process.env.BROKER_KEY || '',
  approverKey: process.env.BROKER_APPROVER_KEY || '',
  auditLog: resolve(projectRoot, process.env.BROKER_AUDIT_LOG || 'audit.log'),
  ms: {
    tenantId: process.env.MS_TENANT_ID || '',
    clientId: process.env.MS_CLIENT_ID || '',
    clientSecret: process.env.MS_CLIENT_SECRET || '',
    redirectUri: process.env.MS_REDIRECT_URI || 'http://localhost:3000/auth/callback',
    // App-only Graph cannot call /me. Require a user object id (or UPN).
    userId: process.env.MS_USER_ID || process.env.BROKER_GRAPH_USER_ID || '',
  },
  auditHmacKey: process.env.BROKER_AUDIT_HMAC_KEY || '',
  // ── Server hardening ──────────────────────────────────────────────────────
  // Maximum request body size in bytes (default 1 MB).
  maxBodyBytes: int(process.env.BROKER_MAX_BODY_BYTES, 1_048_576),
  // Rate limiting: fixed-window per-IP.
  rateLimitWindowMs: int(process.env.BROKER_RATE_LIMIT_WINDOW_MS, 60_000),
  rateLimitMax: int(process.env.BROKER_RATE_LIMIT_MAX, 120),
  rateLimitBurst: int(process.env.BROKER_RATE_LIMIT_BURST, 30),
  // CORS: comma-separated list of allowed origins. Empty = no CORS headers
  // (loopback-only; browser cross-origin requests are blocked by default).
  corsAllowedOrigins: stringList(process.env.BROKER_CORS_ORIGINS, []),
  // Graceful shutdown: how long to wait for in-flight requests (ms).
  shutdownTimeoutMs: int(process.env.BROKER_SHUTDOWN_TIMEOUT_MS, 10_000),
};

export function hasRealCredentials() {
  // Require the full client-credentials set the live Graph client needs, so we
  // never select the live path with an incomplete config that only fails later
  // at token acquisition.
  return Boolean(config.ms.tenantId && config.ms.clientId && config.ms.clientSecret);
}