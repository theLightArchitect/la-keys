use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use rusqlite_migration::{M, Migrations};
use tokio::sync::Mutex;

use crate::error::{AppError, Result};

/// All schema migrations, applied atomically on startup.
const MIGRATIONS: &[M<'static>] = &[
    M::up(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY NOT NULL,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            prefix TEXT NOT NULL,
            last_four TEXT NOT NULL,
            environment TEXT NOT NULL DEFAULT 'live',
            status TEXT NOT NULL DEFAULT 'active',
            lineage_id TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            expires_at TEXT,
            last_used_at TEXT,
            revoked_at TEXT
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS key_scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT NOT NULL REFERENCES api_keys(id),
            service TEXT NOT NULL,
            permission TEXT NOT NULL,
            UNIQUE(key_id, service, permission)
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            response_time_ms INTEGER NOT NULL,
            timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS webhook_configs (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL REFERENCES users(id),
            url TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id TEXT NOT NULL REFERENCES webhook_configs(id),
            event_type TEXT NOT NULL
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS webhook_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id TEXT NOT NULL REFERENCES webhook_configs(id),
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            status_code INTEGER,
            attempt INTEGER NOT NULL DEFAULT 1,
            success INTEGER NOT NULL DEFAULT 0,
            error_message TEXT,
            delivered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );",
    ),
    // Indexes for common query patterns
    M::up(
        "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
         CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
         CREATE INDEX IF NOT EXISTS idx_api_keys_lineage_id ON api_keys(lineage_id);
         CREATE INDEX IF NOT EXISTS idx_key_scopes_key_id ON key_scopes(key_id);
         CREATE INDEX IF NOT EXISTS idx_usage_log_key_id ON usage_log(key_id);
         CREATE INDEX IF NOT EXISTS idx_usage_log_timestamp ON usage_log(timestamp);
         CREATE INDEX IF NOT EXISTS idx_webhook_configs_user_id ON webhook_configs(user_id);",
    ),
];

/// Database handle wrapping a `SQLite` connection with WAL mode.
/// Uses `tokio::sync::Mutex` for async-safe access from axum handlers.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open (or create) the database at the given path, enable WAL, run migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for concurrent reads + single writer
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
        // Checkpoint every 1000 pages to prevent unbounded WAL growth (GUARD §4.1)
        conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
        // Enable foreign keys
        conn.pragma_update(None, "foreign_keys", "ON")?;

        // Run migrations atomically
        let migrations = Migrations::new(MIGRATIONS.to_vec());
        let mut conn = conn;
        migrations.to_latest(&mut conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        Self::open(Path::new(":memory:"))
    }

    /// Get a lock on the underlying connection.
    pub async fn conn(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.lock().await
    }
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").finish_non_exhaustive()
    }
}

/// Ensure the database directory exists with restrictive permissions (GUARD §4.2).
pub fn ensure_db_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| AppError::Internal(format!("failed to create db dir: {e}")))?;

        // Set directory permissions to 0o700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(parent, perms)
                .map_err(|e| AppError::Internal(format!("failed to set db dir perms: {e}")))?;
        }
    }
    Ok(())
}
