# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

la-keys is an Axum HTTP service for API key lifecycle management. Three-tier key state machine (`NoKey → GracePeriod → Valid`) with deterministic transitions for rotation and revocation. Uses scripture-derived HKDF domain separation (same concept as `la-crypto` but implemented independently).

## Build & Deploy

```bash
cargo build --release --bin larc-api-keys   # Build
cargo test --all-features                    # Run all tests
make quality                                 # fmt + clippy + test
make deploy                                  # quality + build + deploy to ~/.larc/bin/
make deploy-fast                             # Skip quality gates
make fix                                    # Auto-fix fmt + clippy

# First-time setup
la-keys init                                  # Interactive wizard for secret store

# Run server
LA_KEYS_ENV=production la-keys serve --port 8080
```

## Architecture

Binary crate only (no library). Axum HTTP server on port 3800 by default.

```
src/
├── main.rs        # CLI entry point (init subcommand + HTTP server)
├── config.rs      # Config from env vars + secrets backend (Keychain/File/Env)
├── auth.rs        # Authentication + JWT handling
├── keys.rs        # Key lifecycle: creation, rotation, revocation, validation
├── handlers.rs    # Axum route handlers
├── db.rs          # SQLite operations (rusqlite + migrations)
├── repo.rs        # Repository/data access layer
├── types.rs       # Domain types (KeyState, KeyId, etc.)
├── rate_limit.rs  # Per-key rate limiting with sliding windows
├── webhooks.rs    # HMAC-signed webhook fanout on key lifecycle events
├── error.rs       # Error types
└── verses.rs      # ~42KB KJV verse module for HKDF domain separation
```

## REST API

```
POST   /api/v1/keys           # Issue a new key
GET    /api/v1/keys           # List keys
POST   /api/v1/keys/:id/rotate  # Rotate a key
DELETE /api/v1/keys/:id       # Revoke a key
POST   /api/v1/keys/verify   # Validate a key
GET    /health                # Health check
```

## Key Dependencies

- `axum` 0.8 (HTTP framework), `tokio` 1 (async runtime)
- `rusqlite` 0.32 (SQLite with bundled + migrations)
- `jsonwebtoken` 9, `hmac`/`sha2`/`hkdf` (crypto)
- `secrecy` + `zeroize` (secret handling)
- `reqwest` (webhook HTTP client)

## Data

SQLite database at `./data/larc.db`. Schema managed by `rusqlite_migration`.