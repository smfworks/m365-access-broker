# Dockerfile for the M365 Access Broker.
# Multi-stage build: build stage is a no-op (zero runtime deps), but the
# pattern is kept for future build steps (e.g. bundling).
#
# The broker is a loopback-only HTTP server. In Docker it is exposed on
# 0.0.0.0:8787 inside the container — pair with docker-compose port mapping
# or a reverse proxy that restricts access to 127.0.0.1 on the host.

# ── Base ────────────────────────────────────────────────────────────────────
# Pin a specific digest for supply-chain reproducibility.
FROM node:24-slim AS base
WORKDIR /app

# ── Dependencies ─────────────────────────────────────────────────────────────
# Copy only package manifests for deterministic layer caching.
FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund --no-cache \
    || npm install --omit=dev --no-audit --no-fund --no-cache

# ── Runtime ─────────────────────────────────────────────────────────────────
FROM base AS runtime

# Install only production deps.
COPY --from=deps /app/node_modules ./node_modules

# Copy application source.
COPY package.json ./
COPY src/ ./src/
COPY bin/ ./bin/
COPY data/ ./data/

# Create a non-root user for security — no home directory, no shell login.
RUN groupadd --system broker \
    && useradd --system --gid broker --no-create-home --shell /usr/sbin/nologin broker \
    && chown -R broker:broker /app \
    && chmod -R go-w /app

USER broker

# Default env — override at runtime.
ENV BROKER_DRY_RUN=true
ENV BROKER_PORT=8787
ENV NODE_ENV=production

# Health check: hit the public /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.BROKER_PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

EXPOSE 8787

# Run the server.
CMD ["node", "src/server.js"]