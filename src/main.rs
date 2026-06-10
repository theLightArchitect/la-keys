// WHY: ApiKeyPrincipal + bearer-auth extractors reserved for the production
// auth flow (POST /api/v1/auth/login + key-bearer endpoints).
#[allow(dead_code)]
mod auth;
mod cli_create_admin;
mod config;
mod db;
mod error;
mod handlers;
// WHY: generate_key_with_verse is pub for verse-pinned issuance (future API).
// validate_key_checksum + parse_key_prefix are unused pending client SDK.
#[allow(dead_code)]
mod keys;
mod rate_limit;
mod repo;
// WHY: KeyStatus variants (Deprecated/Revoked) + ApiKeyPrincipal reserved for
// key-status endpoints and bearer-auth extractor.
#[allow(dead_code)]
mod types;
// WHY: verse_hkdf_info is used by keys.rs; other verse helpers are reserved
// for the verse-browsing endpoint.
#[allow(dead_code)]
mod verses;
// WHY: WebhookDispatcher + delivery loop reserved for post-alpha webhook fanout.
#[allow(dead_code)]
mod webhooks;

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::db::Database;
use crate::rate_limit::RateLimiter;

/// Shared application state available to all handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Arc<Config>,
    pub rate_limiter: RateLimiter,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Handle subcommands before initializing the server
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        match args[1].as_str() {
            "init" => {
                config::run_init().map_err(|e| anyhow::anyhow!("init error: {e}"))?;
                return Ok(());
            }
            "create-admin" => {
                // Initialize logging first so the bootstrap path emits structured
                // events too — useful when the operator runs the CLI inside a
                // container and `tracing-subscriber` is the only sink.
                tracing_subscriber::fmt()
                    .with_env_filter(
                        EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| EnvFilter::new("info")),
                    )
                    .json()
                    .init();
                cli_create_admin::run().await?;
                return Ok(());
            }
            "help" | "--help" | "-h" => {
                println!("L-ARC API Key Service\n");
                println!("Usage: larc-keys [command]\n");
                println!("Commands:");
                println!("  init           First-time setup wizard (choose secret storage backend)");
                println!("  create-admin   Bootstrap the first admin row in `users`");
                println!("                 (larc-keys create-admin --email <e> [--name <n>])");
                println!("  help           Show this help message");
                println!("\nWithout a command, starts the HTTP server on port 3800.");
                return Ok(());
            }
            other => {
                eprintln!("Unknown command: {other}");
                eprintln!("Run `larc-keys help` for usage.");
                std::process::exit(1);
            }
        }
    }

    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // Load configuration from environment + secrets backend
    let config = Config::from_env().map_err(|e| anyhow::anyhow!("config error: {e}"))?;

    // Ensure database directory exists with secure permissions
    db::ensure_db_dir(&config.database_path)?;

    // Open database and run migrations
    let database = Database::open(&config.database_path)?;

    let bind_addr = format!("{}:{}", config.host, config.port);

    tracing::info!(
        host = %config.host,
        port = config.port,
        db = %config.database_path.display(),
        "L-ARC API Key Service starting"
    );

    // Rate limiter with 60-second sliding window
    let rate_limiter = RateLimiter::new(60);

    let state = AppState {
        db: database,
        config: Arc::new(config),
        rate_limiter,
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    tracing::info!(addr = %bind_addr, "listening");

    axum::serve(listener, app).await?;

    Ok(())
}

fn build_router(state: AppState) -> Router {
    let api_v1 = Router::new()
        .route("/keys", post(handlers::create_key))
        .route("/keys", get(handlers::list_keys))
        .route("/keys/{id}/rotate", post(handlers::rotate_key))
        .route("/keys/{id}", delete(handlers::revoke_key))
        .route("/keys/verify", post(handlers::verify_key_handler));

    Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1", api_v1)
        .with_state(state)
}

async fn health_check() -> &'static str {
    "ok"
}
