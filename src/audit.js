import { appendFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const SECRET_KEYS = /^(authorization|token|access_token|refresh_token|client_secret|password|secret|cookie|x-broker-key)$/i;
const MAX_STRING = 240;

// Secrets can hide inside non-secret-named string values (e.g. a mail "body"
// containing "client_secret=abc"). Scrub those patterns before truncation.
const VALUE_SECRET_PATTERNS = [
  /(Bearer\s+)[A-Za-z0-9._-]{8,}/gi,
  /\b(api[_-]?key|secret|password|client_secret|token)(\s*[:=]\s*)\S{4,}/gi,
  /\b(eyJ[A-Za-z0-9_-]{6,})\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g,
];

function scrubString(value) {
  let out = value;
  out = out.replace(VALUE_SECRET_PATTERNS[0], '$1[REDACTED]');
  out = out.replace(VALUE_SECRET_PATTERNS[1], '$1$2[REDACTED]');
  out = out.replace(VALUE_SECRET_PATTERNS[2], '[REDACTED_JWT]');
  return out;
}

// Recursively redact secrets and truncate long strings so the audit log never
// stores raw tokens or full private message bodies.
export function redact(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === 'string') {
    const scrubbed = scrubString(value);
    return scrubbed.length > MAX_STRING
      ? `${scrubbed.slice(0, MAX_STRING)}…[+${scrubbed.length - MAX_STRING}]`
      : scrubbed;
  }
  if (typeof value !== 'object') return value;
  if (depth > 6) return '[deep]';
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SECRET_KEYS.test(k)) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = redact(v, depth + 1);
    }
  }
  return out;
}

export class AuditLogger {
  constructor({ logPath, sink } = {}) {
    this.logPath = logPath;
    // sink lets tests capture entries without touching disk.
    this.sink = sink || ((line) => appendFileSync(this.logPath, line + '\n'));
  }

  record(entry) {
    const record = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      tool: entry.tool,
      user: entry.user || 'unknown',
      resourceType: entry.resourceType || null,
      resourceRef: entry.resourceRef || null,
      scopes: entry.scopes || [],
      sensitivity: entry.sensitivity || null,
      requiresApproval: Boolean(entry.requiresApproval),
      approvalGranted: Boolean(entry.approvalGranted),
      outcome: entry.outcome,
      reasons: entry.reasons || [],
      args: redact(entry.args || {}),
      resultSummary: typeof entry.resultSummary === 'string'
        ? redact(entry.resultSummary)
        : entry.resultSummary || null,
    };
    this.sink(JSON.stringify(record));
    return record;
  }
}
