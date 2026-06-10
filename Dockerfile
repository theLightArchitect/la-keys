# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the larc-keys service.
# Final image: ~18 MB distroless cc-debian12 (nonroot user).
#
# Build:   docker build -t larc-keys .
# Run:     docker run --rm -p 3800:3800 \
#              -v larc_keys_data:/data \
#              -e LARC_ENV=production \
#              -e LARC_HMAC_PEPPER=... \
#              -e LARC_JWT_SECRET=... \
#              -e LARC_DATABASE_PATH=/data/larc.db \
#              larc-keys

# ─── Stage 1: build ────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Copy manifests first so the dependency cache layer is reused when only
# source files change.
COPY Cargo.toml Cargo.lock ./

# Stub source so cargo can resolve + cache the dep graph.
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo fetch --locked

# Copy the real source.
COPY src/ ./src/
COPY README.md ./

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release --bin larc-keys \
    && cp target/release/larc-keys /work/larc-keys

# ─── Stage 2: runtime ──────────────────────────────────────────────────────
# debian:bookworm-slim (not distroless) so `fly ssh console` has a shell.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /work/larc-keys /app/larc-keys

# Runs as root inside Fly's VM — Fly provides VM-level isolation.
# Volume /data is mounted root-owned; running non-root would require chown.
ENV LARC_DATABASE_PATH=/data/larc.db
EXPOSE 3800

ENTRYPOINT ["/app/larc-keys"]
