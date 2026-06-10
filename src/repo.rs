use chrono::{DateTime, Utc};
use secrecy::SecretString;
use uuid::Uuid;

use crate::db::Database;
use crate::error::{AppError, Result};
use crate::keys::{GeneratedKey, generate_key, hash_key};
use crate::types::{ApiKeyInfo, KeyEnvironment, KeyStatus, Permission, Scope, ServiceName};

/// Create a new API key for a user.
///
/// Returns the `GeneratedKey` containing the raw key (shown once) and metadata.
/// The raw key is never stored — only the HMAC-SHA256 hash.
pub async fn create_key(
    db: &Database,
    user_id: Uuid,
    name: &str,
    environment: KeyEnvironment,
    scopes: &[Scope],
    pepper: &SecretString,
    max_keys: u32,
) -> Result<(GeneratedKey, ApiKeyInfo)> {
    let conn = db.conn().await;

    // Check key limit per user
    let count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM api_keys WHERE user_id = ?1 AND status != 'revoked'",
        [user_id.to_string()],
        |row| row.get(0),
    )?;

    if count >= max_keys {
        return Err(AppError::Conflict(format!(
            "key limit reached ({max_keys} active keys)"
        )));
    }

    // Validate scopes — no wildcard via API (GUARD §6.4)
    for scope in scopes {
        if scope.service == ServiceName::All {
            return Err(AppError::Forbidden(
                "wildcard scope cannot be assigned via API".to_string(),
            ));
        }
    }

    let generated = generate_key(environment, pepper)?;
    let key_id = Uuid::new_v4();
    let lineage_id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    // Insert key record
    conn.execute(
        "INSERT INTO api_keys (id, user_id, name, key_hash, prefix, last_four, environment, status, lineage_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
        rusqlite::params![
            key_id.to_string(),
            user_id.to_string(),
            name,
            generated.key_hash,
            generated.prefix,
            generated.last_four,
            environment.as_str(),
            lineage_id.to_string(),
            now,
        ],
    )?;

    // Insert scopes
    for scope in scopes {
        conn.execute(
            "INSERT INTO key_scopes (key_id, service, permission) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                key_id.to_string(),
                scope.service.as_str(),
                scope.permission.as_str()
            ],
        )?;
    }

    let info = ApiKeyInfo {
        id: key_id,
        user_id,
        name: name.to_string(),
        prefix: generated.prefix.clone(),
        last_four: generated.last_four.clone(),
        environment,
        status: KeyStatus::Active,
        scopes: scopes.to_vec(),
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        revoked_at: None,
        lineage_id,
    };

    Ok((generated, info))
}

/// List all API keys for a user (metadata only — never the key or hash).
pub async fn list_keys(db: &Database, user_id: Uuid) -> Result<Vec<ApiKeyInfo>> {
    let conn = db.conn().await;

    let mut stmt = conn.prepare(
        "SELECT id, user_id, name, prefix, last_four, environment, status,
                lineage_id, created_at, expires_at, last_used_at, revoked_at
         FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC",
    )?;

    let keys: Vec<ApiKeyInfo> = stmt
        .query_map([user_id.to_string()], |row| {
            Ok(KeyRow {
                id: row.get(0)?,
                user_id: row.get(1)?,
                name: row.get(2)?,
                prefix: row.get(3)?,
                last_four: row.get(4)?,
                environment: row.get(5)?,
                status: row.get(6)?,
                lineage_id: row.get(7)?,
                created_at: row.get(8)?,
                expires_at: row.get(9)?,
                last_used_at: row.get(10)?,
                revoked_at: row.get(11)?,
            })
        })?
        .filter_map(std::result::Result::ok)
        .filter_map(|row| row_to_info(&conn, row).ok())
        .collect();

    Ok(keys)
}

/// Revoke a key (soft-delete).
pub async fn revoke_key(db: &Database, key_id: Uuid, user_id: Uuid) -> Result<()> {
    let conn = db.conn().await;
    let now = Utc::now().to_rfc3339();

    let updated = conn.execute(
        "UPDATE api_keys SET status = 'revoked', revoked_at = ?1
         WHERE id = ?2 AND user_id = ?3 AND status != 'revoked'",
        rusqlite::params![now, key_id.to_string(), user_id.to_string()],
    )?;

    if updated == 0 {
        return Err(AppError::NotFound);
    }

    Ok(())
}

/// Rotate a key: create a new one and deprecate the old one.
///
/// The old key enters a grace period (`deprecated` status) where it still works
/// but responses include a deprecation header. After the grace period expires,
/// a background job revokes it.
pub async fn rotate_key(
    db: &Database,
    old_key_id: Uuid,
    user_id: Uuid,
    pepper: &SecretString,
    grace_hours: u64,
    _max_keys: u32,
) -> Result<(GeneratedKey, ApiKeyInfo)> {
    let conn = db.conn().await;

    // Load the old key to get its metadata
    let old_key: KeyRow = conn
        .query_row(
            "SELECT id, user_id, name, prefix, last_four, environment, status,
                    lineage_id, created_at, expires_at, last_used_at, revoked_at
             FROM api_keys WHERE id = ?1 AND user_id = ?2 AND status = 'active'",
            rusqlite::params![old_key_id.to_string(), user_id.to_string()],
            |row| {
                Ok(KeyRow {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    name: row.get(2)?,
                    prefix: row.get(3)?,
                    last_four: row.get(4)?,
                    environment: row.get(5)?,
                    status: row.get(6)?,
                    lineage_id: row.get(7)?,
                    created_at: row.get(8)?,
                    expires_at: row.get(9)?,
                    last_used_at: row.get(10)?,
                    revoked_at: row.get(11)?,
                })
            },
        )
        .map_err(|_| AppError::NotFound)?;

    // Load old key's scopes
    let scopes = load_scopes(&conn, &old_key.id)?;
    let env = parse_env(&old_key.environment)?;
    let lineage_id = parse_uuid(&old_key.lineage_id)?;

    // Generate new key
    let generated = generate_key(env, pepper)?;
    let new_key_id = Uuid::new_v4();
    let now = Utc::now();
    #[allow(clippy::cast_possible_wrap)]
    let grace_hours_i64 = grace_hours as i64;
    let expires_at = now + chrono::Duration::hours(grace_hours_i64);

    // Deprecate old key (it still works during grace period)
    conn.execute(
        "UPDATE api_keys SET status = 'deprecated', expires_at = ?1
         WHERE id = ?2",
        rusqlite::params![expires_at.to_rfc3339(), old_key_id.to_string()],
    )?;

    // Create new key with same lineage
    conn.execute(
        "INSERT INTO api_keys (id, user_id, name, key_hash, prefix, last_four, environment, status, lineage_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
        rusqlite::params![
            new_key_id.to_string(),
            user_id.to_string(),
            old_key.name,
            generated.key_hash,
            generated.prefix,
            generated.last_four,
            old_key.environment,
            lineage_id.to_string(),
            now.to_rfc3339(),
        ],
    )?;

    // Copy scopes to new key
    for scope in &scopes {
        conn.execute(
            "INSERT INTO key_scopes (key_id, service, permission) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                new_key_id.to_string(),
                scope.service.as_str(),
                scope.permission.as_str()
            ],
        )?;
    }

    let info = ApiKeyInfo {
        id: new_key_id,
        user_id,
        name: old_key.name.clone(),
        prefix: generated.prefix.clone(),
        last_four: generated.last_four.clone(),
        environment: env,
        status: KeyStatus::Active,
        scopes,
        created_at: now,
        expires_at: None,
        last_used_at: None,
        revoked_at: None,
        lineage_id,
    };

    Ok((generated, info))
}

/// Verify a raw API key and return its metadata + scopes if valid.
pub async fn verify_api_key(
    db: &Database,
    raw_key: &str,
    pepper: &SecretString,
) -> Result<Option<ApiKeyInfo>> {
    let conn = db.conn().await;
    let key_hash = hash_key(raw_key, pepper)?;

    // Look up by hash (the primary lookup path)
    let row: Option<KeyRow> = conn
        .query_row(
            "SELECT id, user_id, name, prefix, last_four, environment, status,
                    lineage_id, created_at, expires_at, last_used_at, revoked_at
             FROM api_keys WHERE key_hash = ?1 AND status IN ('active', 'deprecated')",
            [&key_hash],
            |row| {
                Ok(KeyRow {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    name: row.get(2)?,
                    prefix: row.get(3)?,
                    last_four: row.get(4)?,
                    environment: row.get(5)?,
                    status: row.get(6)?,
                    lineage_id: row.get(7)?,
                    created_at: row.get(8)?,
                    expires_at: row.get(9)?,
                    last_used_at: row.get(10)?,
                    revoked_at: row.get(11)?,
                })
            },
        )
        .ok();

    let Some(row) = row else {
        return Ok(None);
    };

    // Check if deprecated key has expired
    if row.status == "deprecated"
        && let Some(ref expires) = row.expires_at
        && let Ok(exp) = DateTime::parse_from_rfc3339(expires)
        && exp < Utc::now()
    {
        return Ok(None);
    }

    // Update last_used_at
    let now = Utc::now().to_rfc3339();
    let _ = conn.execute(
        "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
        rusqlite::params![now, row.id],
    );

    row_to_info(&conn, row).map(Some)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

#[derive(Debug)]
struct KeyRow {
    id: String,
    user_id: String,
    name: String,
    prefix: String,
    last_four: String,
    environment: String,
    status: String,
    lineage_id: String,
    created_at: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
}

fn row_to_info(conn: &rusqlite::Connection, row: KeyRow) -> Result<ApiKeyInfo> {
    let scopes = load_scopes(conn, &row.id)?;

    Ok(ApiKeyInfo {
        id: parse_uuid(&row.id)?,
        user_id: parse_uuid(&row.user_id)?,
        name: row.name,
        prefix: row.prefix,
        last_four: row.last_four,
        environment: parse_env(&row.environment)?,
        status: parse_status(&row.status)?,
        scopes,
        created_at: parse_datetime(&row.created_at)?,
        expires_at: row
            .expires_at
            .as_deref()
            .and_then(|s| parse_datetime(s).ok()),
        last_used_at: row
            .last_used_at
            .as_deref()
            .and_then(|s| parse_datetime(s).ok()),
        revoked_at: row
            .revoked_at
            .as_deref()
            .and_then(|s| parse_datetime(s).ok()),
        lineage_id: parse_uuid(&row.lineage_id)?,
    })
}

fn load_scopes(conn: &rusqlite::Connection, key_id: &str) -> Result<Vec<Scope>> {
    let mut stmt = conn.prepare("SELECT service, permission FROM key_scopes WHERE key_id = ?1")?;

    let scopes: Vec<Scope> = stmt
        .query_map([key_id], |row| {
            let service: String = row.get(0)?;
            let permission: String = row.get(1)?;
            Ok((service, permission))
        })?
        .filter_map(std::result::Result::ok)
        .filter_map(|(s, p)| {
            let service = ServiceName::from_str_strict(&s)?;
            let permission = Permission::from_str_strict(&p)?;
            Some(Scope {
                service,
                permission,
            })
        })
        .collect();

    Ok(scopes)
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| AppError::Internal(format!("invalid UUID: {e}")))
}

fn parse_env(s: &str) -> Result<KeyEnvironment> {
    match s {
        "live" => Ok(KeyEnvironment::Live),
        "test" => Ok(KeyEnvironment::Test),
        other => Err(AppError::Internal(format!("invalid environment: {other}"))),
    }
}

fn parse_status(s: &str) -> Result<KeyStatus> {
    match s {
        "active" => Ok(KeyStatus::Active),
        "deprecated" => Ok(KeyStatus::Deprecated),
        "revoked" => Ok(KeyStatus::Revoked),
        other => Err(AppError::Internal(format!("invalid status: {other}"))),
    }
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| AppError::Internal(format!("invalid datetime: {e}")))
}

// ── users ────────────────────────────────────────────────────────────────────
//
// larc-keys' `POST /api/v1/keys` endpoint is `AdminPrincipal`-gated (JWT) — the
// JWT carries the `user_id` of the admin issuing the key.  The schema therefore
// requires at least one row in `users` before any key can be issued.
//
// The functions below give the `larc-keys create-admin` CLI a typed insertion
// path so the bootstrap user can be seeded out-of-band without raw SQL.

/// Lookup an existing user by email.  Returns `Ok(None)` when no row matches.
pub async fn find_user_by_email(db: &Database, email: &str) -> Result<Option<Uuid>> {
    let conn = db.conn().await;
    let row: Option<String> = conn
        .query_row(
            "SELECT id FROM users WHERE email = ?1 LIMIT 1",
            [email],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| {
            if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                Ok(None)
            } else {
                Err(e)
            }
        })?;
    match row {
        Some(s) => Ok(Some(parse_uuid(&s)?)),
        None => Ok(None),
    }
}

/// Insert a new user with the given email + name + pre-hashed password.
///
/// Returns the freshly-minted user UUID.  Fails with `AppError::Conflict` when
/// a row with the same email already exists (UNIQUE constraint on `users.email`).
pub async fn create_user(
    db: &Database,
    email: &str,
    name: &str,
    password_hash: &str,
) -> Result<Uuid> {
    let conn = db.conn().await;
    let user_id = Uuid::new_v4();
    let result = conn.execute(
        "INSERT INTO users (id, email, name, password_hash) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![user_id.to_string(), email, name, password_hash],
    );
    match result {
        Ok(_) => Ok(user_id),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(AppError::Conflict(format!(
                "user with email `{email}` already exists"
            )))
        }
        Err(e) => Err(e.into()),
    }
}
