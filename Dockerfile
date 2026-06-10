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
FROM rust:1.87-bookworm-slim AS build

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
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app
COPY --from=build /work/larc-keys /app/larc-keys

# `:nonroot` distroless image runs as uid 65532.  The mounted volume must be
# writable by that uid — see fly.toml `[mounts]` section for the production
# wiring, and docker-compose for local parity.
ENV LARC_DATABASE_PATH=/data/larc.db
EXPOSE 3800
USER nonroot:nonroot

ENTRYPOINT ["/app/larc-keys"]
