# la-keys

API key management service for the [Light Architects](https://github.com/theLightArchitect/lightarchitects-platform) platform.

A self-contained Axum HTTP service that issues, validates, rotates, and revokes API keys with three-tier auth, [`la-crypto`](https://github.com/theLightArchitect/la-crypto)-derived key material, and webhook event notifications.

## Features

- **Three-tier auth**: `NoKey` → `GracePeriod` → `Valid` state machine with deterministic transitions
- **Key derivation** via [`la-crypto`](https://github.com/theLightArchitect/la-crypto) HKDF + verse-based domain separation
- **SQLite-backed** persistent storage with `rusqlite_migration` schema versioning
- **JWT issuance** for short-lived bearer tokens
- **Webhook notifications** on key lifecycle events (created, rotated, revoked, expired)
- **Multiple secret backends**: macOS Keychain (native API), TOML file, environment variables
- **Rate limiting** with configurable per-key quotas
- **Key rotation** with grace-period overlap

## Architecture

```
┌─────────────────────────────────────────────┐
│  HTTP Service (Axum)                        │
│  ├── POST   /keys              (issue)      │
│  ├── GET    /keys/:id          (status)     │
│  ├── PATCH  /keys/:id/rotate   (rotate)     │
│  ├── DELETE /keys/:id          (revoke)     │
│  └── POST   /keys/validate     (validate)   │
└─────────────────────────────────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │                                 │
   ▼                                 ▼
┌──────────────────┐         ┌──────────────────┐
│  SQLite store    │         │  Webhook fanout  │
│  - keys          │         │  - HTTPS signed  │
│  - audit log     │         │  - HMAC-SHA256   │
│  - rate counters │         │  - retries       │
└──────────────────┘         └──────────────────┘
```

## Secret backends

| Backend     | Trigger                      | Use case                              |
|-------------|------------------------------|---------------------------------------|
| `Keychain`  | macOS default                | Production single-machine deployments |
| `File`      | `LA_KEYS_SECRETS_PATH` set   | Container / Linux production          |
| `Env`       | All other vars               | CI / development                      |

The legacy on-disk identifier `.larc/` and Keychain service name `larc-api-keys` are preserved for compatibility with existing deployments — see comments in `src/config.rs`.

## Getting started

```bash
# Initialize secrets store (interactive wizard)
la-keys init

# Run the service
LA_KEYS_ENV=production la-keys serve --port 8080
```

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
