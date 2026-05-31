import { randomUUID, createHash } from 'node:crypto';

// Deterministic, key-order-independent serialization so the same logical args
// always produce the same digest.
function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

// An approval authorizes a specific (tool, args) request, not merely a tool
// name. Binding the token to a canonical digest of the arguments prevents an
// approval minted for one action (send draft A, delete file X) from being
// replayed to authorize a different action on the same tool (send draft B,
// delete file Y).
export function requestDigest(tool, args = {}) {
  return createHash('sha256')
    .update(String(tool) + '\u0000' + stableStringify(args ?? {}))
    .digest('hex');
}

// Server-side approval registry. The whole point of the approval gate is that
// the *agent* cannot grant its own approval. The host UI (holding the separate
// approver key) calls /approve to mint a single-use, request-scoped, short-lived
// token. /execute only sets ctx.approvalGranted after consuming a valid token.
export class ApprovalStore {
  constructor({ ttlMs = 120_000, maxTokens = 1000 } = {}) {
    this.ttlMs = ttlMs;
    this.maxTokens = maxTokens;
    this.tokens = new Map();
  }

  create(tool, args = {}) {
    // Evict expired tokens on every mint so the Map cannot grow unbounded with
    // approvals that were never consumed.
    this.sweep();
    const id = randomUUID();
    this.tokens.set(id, {
      tool,
      digest: requestDigest(tool, args),
      expiresAt: Date.now() + this.ttlMs,
    });
    // Hard cap as a backstop against rapid minting; drop the oldest entry.
    if (this.tokens.size > this.maxTokens) {
      const oldest = this.tokens.keys().next().value;
      this.tokens.delete(oldest);
    }
    return id;
  }

  // Single-use: the token is removed whether or not it validates. It is valid
  // only for the exact tool AND argument set it was minted for.
  consume(id, tool, args = {}) {
    if (!id) return false;
    const rec = this.tokens.get(id);
    this.tokens.delete(id);
    if (!rec) return false;
    if (rec.expiresAt < Date.now()) return false;
    if (rec.tool !== tool) return false;
    if (rec.digest !== requestDigest(tool, args)) return false;
    return true;
  }

  sweep(now = Date.now()) {
    for (const [id, rec] of this.tokens) {
      if (rec.expiresAt < now) this.tokens.delete(id);
    }
  }
}
