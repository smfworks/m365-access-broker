import { appendFileSync, existsSync, readFileSync, lstatSync, statSync, renameSync } from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';

const MAX_STRING = 240;

// Genesis hash: the fixed anchor every audit chain starts from. The first
// record's prevHash is this value.
export const AUDIT_GENESIS_HASH = '0'.repeat(64);

// Deterministic, key-order-independent serialization so a record always hashes
// to the same value regardless of property insertion order.
// Uses Object.keys() which only returns own enumerable properties, so
// inherited properties like __proto__ and constructor are not included.
function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  // Object.keys returns only own-enumerable properties, excluding __proto__,
  // constructor, and other inherited properties — no prototype pollution.
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

// Hash of a record's content (everything except the hash field) chained to the
// previous record's hash. Any edit, reorder, or deletion changes a downstream
// hash and is therefore detectable.
function chainHash(base, prevHash) {
  return createHash('sha256')
    .update(stableStringify(base) + '\u0000' + prevHash)
    .digest('hex');
}

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
  if (value === null || value === undefined) return value;
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
    // Defense-in-depth: skip keys that could hijack the prototype chain.
    // Object.entries already only returns own enumerable properties (not
    // inherited), but an attacker-supplied JSON key named __proto__ or
    // constructor is still assigned via out[k] = ... and could be problematic
    // for downstream consumers that use for...in or .hasOwnProperty.
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (isSecretKey(k)) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = redact(v, depth + 1);
    }
  }
  return out;
}

export class AuditLogger {
  constructor({ logPath, sink, genesisHash = AUDIT_GENESIS_HASH, maxLogBytes = 100 * 1024 * 1024 } = {}) {
    this.logPath = logPath;
    this.genesisHash = genesisHash;
    this.maxLogBytes = maxLogBytes;
    // Check for symlink at construction time — refuse to start if the log
    // path is a symlink, since an attacker could redirect/lose audit evidence.
    this._assertNotSymlink(this.logPath);
    // sink lets tests capture entries without touching disk.
    this.sink = sink || ((line) => this._appendToFile(line));
    // Chain state. Recover the tail from an existing log so the chain continues
    // unbroken across process restarts; otherwise start at genesis.
    this.seq = 0;
    this.prevHash = genesisHash;
    if (!sink) this._recoverChain();
  }

  // Symlink guard: refuse to write if the log path is a symlink. An attacker
  // who can create a symlink at the audit log path could redirect entries to
  // /dev/null (losing audit evidence) or overwrite an arbitrary file.
  // Throws on detection; returns silently if the file doesn't exist yet.
  _assertNotSymlink(path) {
    if (!path) return;
    try {
      const st = lstatSync(path);
      if (st.isSymbolicLink()) {
        throw new Error(`audit log path is a symlink: ${path}`);
      }
    } catch (err) {
      if (err.message && err.message.includes('symlink')) throw err;
      // File doesn't exist yet — fine. Other errors (permission) are ignored
      // at this stage; they'll surface on the actual write.
    }
  }

  // Append with symlink protection and size guard.
  _appendToFile(line) {
    if (!this.logPath) throw new Error('no audit log path configured');
    this._assertNotSymlink(this.logPath);
    // Enforce a maximum log size to prevent unbounded growth (disk exhaustion).
    // When exceeded, rotate: move the current log to .old and start fresh.
    try {
      const st = statSync(this.logPath);
      if (st.size + line.length + 1 > this.maxLogBytes) {
        this._rotateLog();
      }
    } catch {
      // File might not exist yet — fine, just proceed.
    }
    appendFileSync(this.logPath, line + '\n');
  }

  // Rotate the audit log by renaming the current file to <path>.old.
  // The old chain is preserved; the new file starts a fresh chain at genesis.
  _rotateLog() {
    try {
      const oldPath = this.logPath + '.old';
      // Don't overwrite a previous rotation if it's a symlink.
      this._assertNotSymlink(oldPath);
      try { renameSync(this.logPath, oldPath); } catch { /* ignore */ }
      // Reset the chain to genesis for the new log.
      this.seq = 0;
      this.prevHash = this.genesisHash;
    } catch { /* best-effort rotation */ }
  }

  // Best-effort recovery: read the last parseable record from the existing log
  // and resume seq/prevHash from it. A corrupt or absent tail simply starts a
  // fresh chain at genesis rather than throwing — a logger must never refuse to
  // log because an old line is unreadable.
  _recoverChain() {
    try {
      if (!this.logPath || !existsSync(this.logPath)) return;
      // Refuse to recover from a symlink — an attacker could point it at
      // /dev/null or a crafted file to reset the chain to a known state.
      this._assertNotSymlink(this.logPath);
      const text = readFileSync(this.logPath, 'utf8');
      const lines = text.split('\n').filter((l) => l.trim() !== '');
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const rec = JSON.parse(lines[i]);
          if (typeof rec.seq === 'number' && typeof rec.hash === 'string') {
            this.seq = rec.seq;
            this.prevHash = rec.hash;
            return;
          }
        } catch { /* skip unparseable line */ }
      }
    } catch { /* unreadable file — start fresh at genesis */ }
  }

  record(entry) {
    // Content of the record (hashed). `seq`, `prevHash`, and `hash` make it a
    // tamper-evident link in an append-only chain.
    const base = {
      v: 1,
      seq: this.seq + 1,
      prevHash: this.prevHash,
      id: randomUUID(),
      // requestId correlates every record emitted while handling one broker
      // request (decision, execution, result) under a single id.
      requestId: entry.requestId || null,
      timestamp: new Date().toISOString(),
      tool: entry.tool,
      user: entry.user || 'unknown',
      resourceType: entry.resourceType || null,
      // resourceRef and reasons carry user-supplied ids/queries and error/Graph
      // path text, so they must be scrubbed like args.
      resourceRef: entry.resourceRef !== null && entry.resourceRef !== undefined ? redact(entry.resourceRef) : null,
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
    const hash = chainHash(base, this.prevHash);
    const record = { ...base, hash };

    // Advance the chain as soon as the link is formed, before attempting the
    // write: the record logically exists, and the fallback path below still
    // persists it, so the next record must chain onto this hash regardless of a
    // primary-sink failure.
    this.seq = base.seq;
    this.prevHash = hash;

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
          this._assertNotSymlink(this.logPath + '.fallback');
          appendFileSync(this.logPath + '.fallback', line + '\n');
        } catch { /* ignore */ }
      }
    }
    return record;
  }
}

// Walk an ordered list of audit records (parsed objects) and confirm the hash
// chain is intact: monotonic seq, prevHash linkage, and a recomputed content
// hash that matches. Returns the first break found. `records` may also be a raw
// newline-delimited log string.
export function verifyAuditChain(records, { genesisHash = AUDIT_GENESIS_HASH } = {}) {
  let parsed = records;
  if (typeof records === 'string') {
    parsed = records
      .split('\n')
      .filter((l) => l.trim() !== '')
      .map((l) => JSON.parse(l));
  }
  let prevHash = genesisHash;
  let expectedSeq = 1;
  for (let i = 0; i < parsed.length; i++) {
    const rec = parsed[i];
    if (rec.seq !== expectedSeq) {
      return { ok: false, index: i, seq: rec.seq, reason: `seq_gap:expected_${expectedSeq}_got_${rec.seq}`, count: parsed.length };
    }
    if (rec.prevHash !== prevHash) {
      return { ok: false, index: i, seq: rec.seq, reason: 'prevhash_mismatch', count: parsed.length };
    }
    const { hash, persisted, persistError, ...base } = rec;
    const recomputed = chainHash(base, rec.prevHash);
    if (recomputed !== hash) {
      return { ok: false, index: i, seq: rec.seq, reason: 'hash_mismatch', count: parsed.length };
    }
    prevHash = hash;
    expectedSeq++;
  }
  return { ok: true, count: parsed.length, head: prevHash };
}

// Convenience wrapper: verify a chain stored at a file path. A missing file is
// a valid empty chain.
export function verifyAuditFile(path) {
  if (!existsSync(path)) return { ok: true, count: 0, head: AUDIT_GENESIS_HASH };
  return verifyAuditChain(readFileSync(path, 'utf8'));
}
