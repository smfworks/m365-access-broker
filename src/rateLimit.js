// Fixed-window rate limiter. In-process, fail-closed. Adequate for a single
// loopback broker process — not a distributed quota.

export class RateLimiter {
  constructor({ windowMs = 60_000, max = 120 } = {}) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map();
  }

  allow(key) {
    const now = Date.now();
    const rec = this.hits.get(key);
    if (!rec || now - rec.start >= this.windowMs) {
      this.hits.set(key, { start: now, count: 1 });
      return true;
    }
    rec.count += 1;
    return rec.count <= this.max;
  }

  remaining(key) {
    const rec = this.hits.get(key);
    if (!rec) return this.max;
    if (Date.now() - rec.start >= this.windowMs) return this.max;
    return Math.max(0, this.max - rec.count);
  }
}
