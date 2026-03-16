use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("migration error: {0}")]
    Migration(#[from] rusqlite_migration::Error),

    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limited")]
    RateLimited { retry_after_secs: u64 },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("internal error")]
    Internal(String),

    #[error("webhook delivery failed: {0}")]
    WebhookDelivery(String),

    #[error("invalid scope: {0}")]
    InvalidScope(String),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // SECURITY: Never expose internal details in error responses.
        // Log the real error server-side, return opaque message to client.
        let (status, message) = match &self {
            Self::Database(_) | Self::Migration(_) | Self::Internal(_) => {
                tracing::error!(error = %self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            Self::NotFound => (StatusCode::NOT_FOUND, "not found"),
            Self::Unauthorized | Self::Jwt(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            Self::BadRequest(msg) => {
                // BadRequest can include user-facing validation messages
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({ "error": msg })),
                )
                    .into_response();
            }
            Self::Conflict(msg) => {
                return (
                    StatusCode::CONFLICT,
                    axum::Json(serde_json::json!({ "error": msg })),
                )
                    .into_response();
            }
            Self::WebhookDelivery(_) => {
                tracing::error!(error = %self, "webhook delivery failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            Self::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid scope"),
        };

        let body = serde_json::json!({ "error": message });

        let mut response = (status, axum::Json(body)).into_response();

        if let Self::RateLimited { retry_after_secs } = &self {
            response.headers_mut().insert(
                "Retry-After",
                retry_after_secs
                    .to_string()
                    .parse()
                    .unwrap_or_else(|_| "60".parse().expect("static value")),
            );
        }

        response
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
