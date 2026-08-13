import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, isAbsolute } from 'node:path';
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
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

// Keep the audit log inside the project unless the operator passes an
// explicit absolute path (their machine, their choice).
function auditLogPath(value) {
  const raw = value || 'audit.log';
  return isAbsolute(raw) ? raw : resolve(projectRoot, raw);
}

export function assertDistinctKeys(brokerKey, approverKey) {
  if (brokerKey && approverKey && brokerKey === approverKey) {
    throw new Error('BROKER_KEY and BROKER_APPROVER_KEY must be distinct');
  }
}

export const config = {
  projectRoot,
  dryRun: bool(process.env.BROKER_DRY_RUN, true),
  port: Number(process.env.BROKER_PORT || 8787),
  brokerKey: process.env.BROKER_KEY || '',
  approverKey: process.env.BROKER_APPROVER_KEY || '',
  auditLog: auditLogPath(process.env.BROKER_AUDIT_LOG),
  auditHmacKey: process.env.BROKER_AUDIT_HMAC_KEY || '',
  rateLimitMax: int(process.env.BROKER_RATE_LIMIT_MAX, 120),
  rateLimitWindowMs: int(process.env.BROKER_RATE_LIMIT_WINDOW_MS, 60_000),
  ms: {
    tenantId: process.env.MS_TENANT_ID || '',
    clientId: process.env.MS_CLIENT_ID || '',
    clientSecret: process.env.MS_CLIENT_SECRET || '',
    redirectUri: process.env.MS_REDIRECT_URI || 'http://localhost:3000/auth/callback',
    userId: process.env.MS_USER_ID || '',
  },
};

export function hasRealCredentials() {
  // Require the full client-credentials set the live Graph client needs, so we
  // never select the live path with an incomplete config that only fails later
  // at token acquisition.
  return Boolean(config.ms.tenantId && config.ms.clientId && config.ms.clientSecret);
}
