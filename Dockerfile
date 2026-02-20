# ==============================================================================
# SaltaX — Multi-stage Docker Build
# Stage 1: Compile TypeScript proxy (Node 22)
# Stage 2: Python 3.11 runtime with compiled TS + Node binary
# ==============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build TypeScript proxy
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 node:22-slim AS ts-builder

WORKDIR /app/github-proxy
COPY github-proxy/package.json github-proxy/package-lock.json* ./
RUN npm ci --production=false
COPY github-proxy/tsconfig.json ./
COPY github-proxy/src ./src
RUN npx tsc

# ---------------------------------------------------------------------------
# Stage 2: Python runtime (production image)
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Node.js binary from stage 1 (exact v22 — avoids stale Debian apt packages)
COPY --from=ts-builder /usr/local/bin/node /usr/local/bin/node

WORKDIR /app

# Python dependencies — copy source alongside pyproject.toml so non-editable
# install can find the package (editable install would fail without source).
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install ".[prod]" --no-cache-dir

# Copy TS proxy build artifacts
COPY --from=ts-builder /app/github-proxy/dist ./github-proxy/dist
COPY --from=ts-builder /app/github-proxy/node_modules ./github-proxy/node_modules
COPY github-proxy/package.json ./github-proxy/

# Copy application assets
COPY rules/ ./rules/
COPY saltax.config.yaml ./
COPY scripts/ ./scripts/

# Non-root user (defense-in-depth alongside TEE isolation)
RUN useradd -m saltax
USER saltax

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/status || exit 1

EXPOSE 8080

ENTRYPOINT ["python", "-m", "src.main"]
