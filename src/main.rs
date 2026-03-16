#[allow(dead_code)]
mod auth;
mod config;
mod db;
mod error;
mod handlers;
#[allow(dead_code)]
mod keys;
#[allow(dead_code)]
mod rate_limit;
mod repo;
#[allow(dead_code)]
mod types;
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
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // Load configuration from environment
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
