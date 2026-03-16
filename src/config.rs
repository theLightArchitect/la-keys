use std::path::{Path, PathBuf};

use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Default secrets file location.
const SECRETS_PATH: &str = ".larc/secrets.toml";

/// Application configuration, loaded from env vars + secrets file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Host to bind the HTTP server to.
    pub host: String,
    /// Port to bind the HTTP server to.
    pub port: u16,
    /// Path to the `SQLite` database file.
    pub database_path: PathBuf,
    /// HMAC pepper for key hashing — loaded from secrets file or env var.
    pub hmac_pepper: SecretString,
    /// JWT signing secret — loaded from secrets file or env var.
    pub jwt_secret: SecretString,
    /// JWT token expiry in seconds (default: 900 = 15 minutes).
    pub jwt_expiry_secs: u64,
    /// Key rotation grace period in hours (default: 168 = 7 days).
    pub rotation_grace_hours: u64,
    /// Maximum keys per user.
    pub max_keys_per_user: u32,
}

/// Secrets persisted to `~/.larc/secrets.toml`.
#[derive(Debug, Serialize, Deserialize)]
struct SecretsFile {
    hmac_pepper: String,
    jwt_secret: String,
}

impl Config {
    /// Load configuration.
    ///
    /// Secret resolution order (first wins):
    /// 1. Environment variables (`LARC_HMAC_PEPPER`, `LARC_JWT_SECRET`)
    /// 2. Secrets file (`~/.larc/secrets.toml`)
    /// 3. Auto-generate + persist to secrets file (dev mode only)
    ///
    /// In production (`LARC_ENV=production`), env vars are required —
    /// no auto-generation, no file fallback.
    pub fn from_env() -> Result<Self, ConfigError> {
        let is_production = std::env::var("LARC_ENV")
            .map(|v| v == "production")
            .unwrap_or(false);

        let secrets = resolve_secrets(is_production)?;

        if let Ok(ref jwt) = std::env::var("LARC_JWT_SECRET")
            && jwt.len() < 32
        {
            return Err(ConfigError::Invalid(
                "LARC_JWT_SECRET must be at least 32 characters",
            ));
        }

        Ok(Self {
            host: std::env::var("LARC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: std::env::var("LARC_PORT")
                .unwrap_or_else(|_| "3800".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("LARC_PORT must be a valid port number"))?,
            database_path: PathBuf::from(
                std::env::var("LARC_DATABASE_PATH")
                    .unwrap_or_else(|_| "./data/larc.db".to_string()),
            ),
            hmac_pepper: SecretString::from(secrets.hmac_pepper),
            jwt_secret: SecretString::from(secrets.jwt_secret),
            jwt_expiry_secs: std::env::var("LARC_JWT_EXPIRY_SECS")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("LARC_JWT_EXPIRY_SECS must be a number"))?,
            rotation_grace_hours: std::env::var("LARC_ROTATION_GRACE_HOURS")
                .unwrap_or_else(|_| "168".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("LARC_ROTATION_GRACE_HOURS must be a number"))?,
            max_keys_per_user: std::env::var("LARC_MAX_KEYS_PER_USER")
                .unwrap_or_else(|_| "25".to_string())
                .parse()
                .map_err(|_| ConfigError::Invalid("LARC_MAX_KEYS_PER_USER must be a number"))?,
        })
    }
}

/// Resolve secrets from env vars, file, or auto-generation.
fn resolve_secrets(is_production: bool) -> Result<SecretsFile, ConfigError> {
    let env_pepper = std::env::var("LARC_HMAC_PEPPER").ok();
    let env_jwt = std::env::var("LARC_JWT_SECRET").ok();

    // If both env vars are set, use them directly (highest priority)
    if let (Some(pepper), Some(jwt)) = (env_pepper.clone(), env_jwt.clone()) {
        return Ok(SecretsFile {
            hmac_pepper: pepper,
            jwt_secret: jwt,
        });
    }

    // Try loading from secrets file
    let secrets_path = secrets_file_path();
    if let Some(file_secrets) = load_secrets_file(&secrets_path) {
        // Env vars override individual fields from the file
        return Ok(SecretsFile {
            hmac_pepper: env_pepper.unwrap_or(file_secrets.hmac_pepper),
            jwt_secret: env_jwt.unwrap_or(file_secrets.jwt_secret),
        });
    }

    // No file found — production requires explicit secrets
    if is_production {
        return Err(ConfigError::Missing(
            "LARC_HMAC_PEPPER and LARC_JWT_SECRET (required in production)",
        ));
    }

    // Dev mode: auto-generate and persist
    let secrets = SecretsFile {
        hmac_pepper: generate_random_hex(),
        jwt_secret: generate_random_hex(),
    };

    if let Err(e) = write_secrets_file(&secrets_path, &secrets) {
        tracing::warn!(
            "could not persist secrets to {}: {e}",
            secrets_path.display()
        );
        tracing::warn!("secrets are ephemeral — they will change on next restart");
    } else {
        tracing::info!(
            path = %secrets_path.display(),
            "generated secrets and saved to file (first run)"
        );
    }

    Ok(secrets)
}

/// Generate a random 32-byte hex-encoded secret (64 hex chars).
fn generate_random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::keys::hex::encode(bytes)
}

/// Resolve the secrets file path: `~/.larc/secrets.toml`.
fn secrets_file_path() -> PathBuf {
    if let Ok(custom) = std::env::var("LARC_SECRETS_FILE") {
        return PathBuf::from(custom);
    }
    dirs_home().map_or_else(|| PathBuf::from(SECRETS_PATH), |h| h.join(SECRETS_PATH))
}

/// Get the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Load and parse an existing secrets file.
fn load_secrets_file(path: &Path) -> Option<SecretsFile> {
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
}

/// Write secrets to file with restrictive permissions.
fn write_secrets_file(path: &Path, secrets: &SecretsFile) -> Result<(), ConfigError> {
    // Create parent directory
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io(format!("create dir: {e}")))?;

        // Set directory permissions to 0o700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(parent, perms);
        }
    }

    let content =
        toml::to_string_pretty(secrets).map_err(|e| ConfigError::Io(format!("serialize: {e}")))?;

    std::fs::write(path, &content).map_err(|e| ConfigError::Io(format!("write: {e}")))?;

    // Set file permissions to 0o600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| ConfigError::Io(format!("chmod: {e}")))?;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required config: {0}")]
    Missing(&'static str),
    #[error("invalid config: {0}")]
    Invalid(&'static str),
    #[error("I/O error: {0}")]
    Io(String),
}
