use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::auth::AdminPrincipal;
use crate::error::{AppError, Result};
use crate::repo;
use crate::types::{ApiKeyInfo, KeyEnvironment, Scope};

// ─── Request / Response DTOs ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    #[serde(default = "default_env")]
    pub environment: String,
    pub scopes: Vec<String>,
}

fn default_env() -> String {
    "live".to_string()
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub key: String,
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub environment: String,
    pub scopes: Vec<String>,
    pub verse: String,
    pub verse_text: String,
    pub warning: &'static str,
}

#[derive(Debug, Serialize)]
pub struct KeyInfoResponse {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub last_four: String,
    pub environment: String,
    pub status: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyKeyRequest {
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyKeyResponse {
    pub valid: bool,
    pub key_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub deprecated: bool,
}

// ─── Key Management Handlers (JWT admin auth) ─────────────────────────────────

/// POST /api/v1/keys — create a new API key.
///
/// Requires admin JWT auth. Returns the full key ONCE.
pub async fn create_key(
    admin: AdminPrincipal,
    State(state): State<AppState>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<impl IntoResponse> {
    if req.name.is_empty() || req.name.len() > 128 {
        return Err(AppError::BadRequest(
            "name must be 1-128 characters".to_string(),
        ));
    }

    let environment = match req.environment.as_str() {
        "live" => KeyEnvironment::Live,
        "test" => KeyEnvironment::Test,
        other => {
            return Err(AppError::BadRequest(format!(
                "invalid environment: {other} (must be 'live' or 'test')"
            )));
        }
    };

    let scopes = parse_scopes(&req.scopes)?;

    if scopes.is_empty() {
        return Err(AppError::BadRequest(
            "at least one scope is required".to_string(),
        ));
    }

    let (generated, info) = repo::create_key(
        &state.db,
        admin.user_id,
        &req.name,
        environment,
        &scopes,
        &state.config.hmac_pepper,
        state.config.max_keys_per_user,
    )
    .await?;

    let response = CreateKeyResponse {
        key: generated.raw_key.expose_secret().to_string(),
        id: info.id,
        name: info.name,
        prefix: info.prefix,
        environment: environment.as_str().to_string(),
        scopes: req.scopes,
        verse: generated.verse_ref,
        verse_text: generated.verse_text,
        warning: "Store this key securely. It will not be shown again.",
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/keys — list all keys for the authenticated admin user.
///
/// SECURITY: Never returns the key itself or its hash.
pub async fn list_keys(
    admin: AdminPrincipal,
    State(state): State<AppState>,
) -> Result<Json<Vec<KeyInfoResponse>>> {
    let keys = repo::list_keys(&state.db, admin.user_id).await?;
    let responses: Vec<KeyInfoResponse> = keys.into_iter().map(info_to_response).collect();

    Ok(Json(responses))
}

/// POST /api/v1/keys/:id/rotate — rotate a key (create new, deprecate old).
///
/// Requires admin JWT. Returns the new key ONCE.
pub async fn rotate_key(
    admin: AdminPrincipal,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let (generated, info) = repo::rotate_key(
        &state.db,
        key_id,
        admin.user_id,
        &state.config.hmac_pepper,
        state.config.rotation_grace_hours,
        state.config.max_keys_per_user,
    )
    .await?;

    let scopes: Vec<String> = info.scopes.iter().map(ToString::to_string).collect();

    let response = CreateKeyResponse {
        key: generated.raw_key.expose_secret().to_string(),
        id: info.id,
        name: info.name,
        prefix: info.prefix,
        environment: info.environment.as_str().to_string(),
        scopes,
        verse: generated.verse_ref,
        verse_text: generated.verse_text,
        warning: "Store this key securely. It will not be shown again. The previous key will remain valid during the grace period.",
    };

    Ok((StatusCode::OK, Json(response)))
}

/// DELETE /api/v1/keys/:id — revoke a key (soft-delete).
pub async fn revoke_key(
    admin: AdminPrincipal,
    State(state): State<AppState>,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode> {
    repo::revoke_key(&state.db, key_id, admin.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/keys/verify — verify an API key.
///
/// This endpoint accepts unauthenticated requests (service-to-service validation).
pub async fn verify_key_handler(
    State(state): State<AppState>,
    Json(req): Json<VerifyKeyRequest>,
) -> Result<Json<VerifyKeyResponse>> {
    let result = repo::verify_api_key(&state.db, &req.key, &state.config.hmac_pepper).await?;

    match result {
        Some(info) => Ok(Json(VerifyKeyResponse {
            valid: true,
            key_id: Some(info.id),
            scopes: info.scopes.iter().map(ToString::to_string).collect(),
            deprecated: info.status == crate::types::KeyStatus::Deprecated,
        })),
        None => Ok(Json(VerifyKeyResponse {
            valid: false,
            key_id: None,
            scopes: vec![],
            deprecated: false,
        })),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_scopes(scope_strings: &[String]) -> Result<Vec<Scope>> {
    scope_strings
        .iter()
        .map(|s| {
            Scope::parse(s).ok_or_else(|| AppError::InvalidScope(format!("invalid scope: {s}")))
        })
        .collect()
}

fn info_to_response(info: ApiKeyInfo) -> KeyInfoResponse {
    KeyInfoResponse {
        id: info.id,
        name: info.name,
        prefix: info.prefix,
        last_four: info.last_four,
        environment: info.environment.as_str().to_string(),
        status: info.status.as_str().to_string(),
        scopes: info.scopes.iter().map(ToString::to_string).collect(),
        created_at: info.created_at.to_rfc3339(),
        last_used_at: info.last_used_at.map(|dt| dt.to_rfc3339()),
    }
}
