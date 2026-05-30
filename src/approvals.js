import { randomUUID } from 'node:crypto';

// Server-side approval registry. The whole point of the approval gate is that
// the *agent* cannot grant its own approval. The host UI (holding the separate
// approver key) calls /approve to mint a single-use, tool-scoped, short-lived
// token. /execute only sets ctx.approvalGranted after consuming a valid token.
export class ApprovalStore {
  constructor({ ttlMs = 120_000 } = {}) {
    this.ttlMs = ttlMs;
    this.tokens = new Map();
  }

  create(tool) {
    const id = randomUUID();
    this.tokens.set(id, { tool, expiresAt: Date.now() + this.ttlMs });
    return id;
  }

  // Single-use: the token is removed whether or not it validates.
  consume(id, tool) {
    if (!id) return false;
    const rec = this.tokens.get(id);
    this.tokens.delete(id);
    if (!rec) return false;
    if (rec.expiresAt < Date.now()) return false;
    if (rec.tool !== tool) return false;
    return true;
  }

  sweep(now = Date.now()) {
    for (const [id, rec] of this.tokens) {
      if (rec.expiresAt < now) this.tokens.delete(id);
    }
  }
}
