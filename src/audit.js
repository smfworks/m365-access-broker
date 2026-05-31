import { appendFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const MAX_STRING = 240;

// Normalized substrings that mark a key as secret-bearing. Matched against a
// lowercased, separator-stripped form of the key so snake_case, camelCase,
// PascalCase, and kebab-case all collapse to the same form
// (access_token / accessToken / AccessToken / x-broker-key / clientSecret / apiKey).
const SECRET_KEY_PARTS = [
  'authorization', 'token', 'secret', 'password', 'passwd', 'pwd',
  'cookie', 'apikey', 'credential', 'clientsecret', 'xbrokerkey', 'sessionid',
];

function normalizeKey(k) {
  return String(k).toLowerCase().replace(/[_\-\s]/g, '');
}

export function isSecretKey(k) {
  const n = normalizeKey(k);
  return SECRET_KEY_PARTS.some((part) => n.includes(part));
}

// Sensitive query-string / fragment / form parameters whose VALUES must never be
// logged, even when embedded in an otherwise innocuous URL string (OAuth
// callbacks, share links, etc.).
const QUERY_SECRET_PARAMS =
  /([?&#](?:access_token|refresh_token|id_token|code|client_secret|secret|token|password|pwd|sig|signature|session|sid|state|api[_-]?key)=)[^&\s#]+/gi;

// Secrets can hide inside non-secret-named string values (e.g. a mail "body"
// containing "client_secret=abc"). Scrub those patterns before truncation.
const VALUE_SECRET_PATTERNS = [
  /(Bearer\s+)[A-Za-z0-9._-]{8,}/gi,
  /\b(api[_-]?key|secret|password|client_secret|token)(\s*[:=]\s*)\S{4,}/gi,
  /\b(eyJ[A-Za-z0-9_-]{6,})\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g,
];

function scrubString(value) {
  let out = value;
  out = out.replace(QUERY_SECRET_PARAMS, '$1[REDACTED]');
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
    if (isSecretKey(k)) {
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
      // resourceRef and reasons carry user-supplied ids/queries and error/Graph
      // path text, so they must be scrubbed like args.
      resourceRef: entry.resourceRef != null ? redact(entry.resourceRef) : null,
      scopes: entry.scopes || [],
      sensitivity: entry.sensitivity || null,
      requiresApproval: Boolean(entry.requiresApproval),
      approvalGranted: Boolean(entry.approvalGranted),
      outcome: entry.outcome,
      reasons: redact(entry.reasons || []),
      args: redact(entry.args || {}),
      resultSummary: typeof entry.resultSummary === 'string'
        ? redact(entry.resultSummary)
        : entry.resultSummary || null,
    };
    const line = JSON.stringify(record);
    try {
      this.sink(line);
      record.persisted = true;
    } catch (err) {
      // Never lose an audit entry: a sensitive Graph action has already run by
      // the time we log, so a write failure must not leave it entirely
      // unrecorded. Fall back to stderr and a sidecar file.
      record.persisted = false;
      record.persistError = err.message;
      try {
        process.stderr.write(`[audit-fallback] ${line}\n`);
      } catch { /* ignore */ }
      if (this.logPath) {
        try {
          appendFileSync(this.logPath + '.fallback', line + '\n');
        } catch { /* ignore */ }
      }
    }
    return record;
  }
}
