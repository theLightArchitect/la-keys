use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::repo;
use crate::types::Scope;

// ─── Principal Types (GUARD §5 — distinct, non-interchangeable) ───────────────

/// Admin principal — extracted from JWT Bearer tokens.
/// Used for admin dashboard and user management endpoints.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    pub user_id: Uuid,
    pub email: String,
}

/// API key principal — extracted from `lak_*` Bearer tokens.
/// Used for API endpoints that consume services.
#[derive(Debug, Clone)]
pub struct ApiKeyPrincipal {
    pub user_id: Uuid,
    pub key_id: Uuid,
    pub scopes: Vec<Scope>,
    pub deprecated: bool,
}

impl ApiKeyPrincipal {
    /// Check if this principal has the required scope.
    #[must_use]
    pub fn has_scope(&self, required: Scope) -> bool {
        self.scopes.iter().any(|s| s.grants(required))
    }
}

// ─── JWT Claims ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub email: String,
    pub exp: i64,
    pub iat: i64,
}

/// Generate a JWT token for an admin user.
pub fn generate_jwt(
    user_id: Uuid,
    email: &str,
    secret: &secrecy::SecretString,
    expiry_secs: u64,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    let claims = JwtClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        #[allow(clippy::cast_possible_wrap)]
        exp: now.saturating_add(expiry_secs as i64),
        iat: now,
    };

    // GUARD §5.1: Explicitly set algorithm — never use default
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.expose_secret().as_bytes());

    encode(&header, &claims, &key).map_err(AppError::Jwt)
}

/// Validate a JWT token and extract claims.
pub fn validate_jwt(token: &str, secret: &secrecy::SecretString) -> Result<JwtClaims, AppError> {
    // GUARD §5.1: Explicitly require HS256 — reject alg:none and all others
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = false;

    let key = DecodingKey::from_secret(secret.expose_secret().as_bytes());

    let token_data = decode::<JwtClaims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

// ─── Axum Extractors ──────────────────────────────────────────────────────────

impl FromRequestParts<AppState> for AdminPrincipal {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;

        if token.starts_with("lak_") {
            return Err(AppError::Forbidden(
                "API keys cannot access admin endpoints".to_string(),
            ));
        }

        let claims = validate_jwt(&token, &state.config.jwt_secret)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;

        Ok(Self {
            user_id,
            email: claims.email,
        })
    }
}

impl FromRequestParts<AppState> for ApiKeyPrincipal {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;

        if !token.starts_with("lak_") {
            return Err(AppError::Unauthorized);
        }

        let info = repo::verify_api_key(&state.db, &token, &state.config.hmac_pepper)
            .await?
            .ok_or(AppError::Unauthorized)?;

        Ok(Self {
            user_id: info.user_id,
            key_id: info.id,
            scopes: info.scopes,
            deprecated: info.status == crate::types::KeyStatus::Deprecated,
        })
    }
}

fn extract_bearer_token(parts: &Parts) -> Result<String, AppError> {
    let auth_header = parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;

    if token.is_empty() {
        return Err(AppError::Unauthorized);
    }

    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Permission, ServiceName};

    fn test_secret() -> secrecy::SecretString {
        secrecy::SecretString::from("test-jwt-secret-that-is-at-least-32-chars-long!!".to_string())
    }

    #[test]
    fn test_jwt_roundtrip() {
        let secret = test_secret();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";

        let token = generate_jwt(user_id, email, &secret, 3600).unwrap();
        let claims = validate_jwt(&token, &secret).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
    }

    #[test]
    fn test_jwt_wrong_secret() {
        let secret1 = test_secret();
        let secret2 =
            secrecy::SecretString::from("different-secret-that-is-also-32-chars!!!".to_string());

        let user_id = Uuid::new_v4();
        let token = generate_jwt(user_id, "test@example.com", &secret1, 3600).unwrap();

        let result = validate_jwt(&token, &secret2);
        assert!(result.is_err(), "wrong secret should fail validation");
    }

    #[test]
    fn test_jwt_explicit_hs256() {
        let secret = test_secret();
        let user_id = Uuid::new_v4();

        let token = generate_jwt(user_id, "test@example.com", &secret, 3600).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::HS256, "must use HS256 explicitly");
    }

    #[test]
    fn test_api_key_principal_scope_check() {
        let principal = ApiKeyPrincipal {
            user_id: Uuid::new_v4(),
            key_id: Uuid::new_v4(),
            scopes: vec![
                Scope::new(ServiceName::Eva, Permission::Read),
                Scope::new(ServiceName::Corso, Permission::Write),
            ],
            deprecated: false,
        };

        assert!(principal.has_scope(Scope::new(ServiceName::Eva, Permission::Read)));
        assert!(principal.has_scope(Scope::new(ServiceName::Corso, Permission::Read)));
        assert!(!principal.has_scope(Scope::new(ServiceName::Soul, Permission::Read)));
        assert!(!principal.has_scope(Scope::new(ServiceName::Eva, Permission::Write)));
    }
}
