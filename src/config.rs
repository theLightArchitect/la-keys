use std::path::{Path, PathBuf};
use std::process::Command;

use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Default secrets file location.
const SECRETS_PATH: &str = ".larc/secrets.toml";
/// Keychain service name for L-ARC secrets.
const KEYCHAIN_SERVICE: &str = "larc-api-keys";

/// Application configuration, loaded from env vars + secrets file + keychain.
#[derive(Debug, Clone)]
pub struct Config {
    /// Host to bind the HTTP server to.
    pub host: String,
    /// Port to bind the HTTP server to.
    pub port: u16,
    /// Path to the `SQLite` database file.
    pub database_path: PathBuf,
    /// HMAC pepper for key hashing.
    pub hmac_pepper: SecretString,
    /// JWT signing secret.
    pub jwt_secret: SecretString,
    /// JWT token expiry in seconds (default: 900 = 15 minutes).
    pub jwt_expiry_secs: u64,
    /// Key rotation grace period in hours (default: 168 = 7 days).
    pub rotation_grace_hours: u64,
    /// Maximum keys per user.
    pub max_keys_per_user: u32,
}

/// Secrets — the two critical values that protect everything.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretsFile {
    pub hmac_pepper: String,
    pub jwt_secret: String,
}

/// Where secrets are stored — chosen during `larc-api-keys init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackend {
    /// macOS Keychain (recommended on macOS)
    Keychain,
    /// TOML file at `~/.larc/secrets.toml` (chmod 600)
    File,
}

/// Settings persisted to `~/.larc/config.toml` (non-secret preferences).
#[derive(Debug, Serialize, Deserialize)]
pub struct LarcSettings {
    pub secret_backend: SecretBackend,
    #[serde(default = "default_true")]
    pub initialized: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Load configuration.
    ///
    /// Secret resolution order (first wins):
    /// 1. Environment variables (`LARC_HMAC_PEPPER`, `LARC_JWT_SECRET`)
    /// 2. macOS Keychain (if configured as backend)
    /// 3. Secrets file (`~/.larc/secrets.toml`)
    /// 4. Auto-generate + persist to chosen backend (dev mode only)
    ///
    /// In production (`LARC_ENV=production`), env vars are required.
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

// ─── Secret Resolution ────────────────────────────────────────────────────────

/// Resolve secrets: env vars → keychain → file → auto-generate.
fn resolve_secrets(is_production: bool) -> Result<SecretsFile, ConfigError> {
    let env_pepper = std::env::var("LARC_HMAC_PEPPER").ok();
    let env_jwt = std::env::var("LARC_JWT_SECRET").ok();

    // Priority 1: Both env vars set → use directly
    if let (Some(pepper), Some(jwt)) = (env_pepper.clone(), env_jwt.clone()) {
        return Ok(SecretsFile {
            hmac_pepper: pepper,
            jwt_secret: jwt,
        });
    }

    // Load user's backend preference
    let backend = load_settings().map_or(SecretBackend::File, |s| s.secret_backend);

    // Priority 2: Try configured backend
    let backend_secrets = match backend {
        SecretBackend::Keychain => load_from_keychain(),
        SecretBackend::File => {
            let path = secrets_file_path();
            load_secrets_file(&path)
        }
    };

    if let Some(stored) = backend_secrets {
        return Ok(SecretsFile {
            hmac_pepper: env_pepper.unwrap_or(stored.hmac_pepper),
            jwt_secret: env_jwt.unwrap_or(stored.jwt_secret),
        });
    }

    // Priority 3: Try the other backend as fallback
    let fallback_secrets = match backend {
        SecretBackend::Keychain => {
            let path = secrets_file_path();
            load_secrets_file(&path)
        }
        SecretBackend::File => load_from_keychain(),
    };

    if let Some(stored) = fallback_secrets {
        return Ok(SecretsFile {
            hmac_pepper: env_pepper.unwrap_or(stored.hmac_pepper),
            jwt_secret: env_jwt.unwrap_or(stored.jwt_secret),
        });
    }

    // No secrets anywhere — production fails, dev auto-generates
    if is_production {
        return Err(ConfigError::Missing(
            "LARC_HMAC_PEPPER and LARC_JWT_SECRET (required in production)",
        ));
    }

    // Auto-generate and persist to the configured backend
    let secrets = SecretsFile {
        hmac_pepper: generate_random_hex(),
        jwt_secret: generate_random_hex(),
    };

    persist_secrets(&secrets, backend);
    Ok(secrets)
}

/// Persist secrets to the configured backend.
fn persist_secrets(secrets: &SecretsFile, backend: SecretBackend) {
    match backend {
        SecretBackend::Keychain => {
            if save_to_keychain(secrets) {
                tracing::info!("generated secrets and saved to macOS Keychain (first run)");
            } else {
                // Fallback to file if Keychain fails
                let path = secrets_file_path();
                if write_secrets_file(&path, secrets).is_ok() {
                    tracing::info!(
                        path = %path.display(),
                        "Keychain unavailable — saved secrets to file instead"
                    );
                } else {
                    tracing::warn!("secrets are ephemeral — could not persist to Keychain or file");
                }
            }
        }
        SecretBackend::File => {
            let path = secrets_file_path();
            if let Err(e) = write_secrets_file(&path, secrets) {
                tracing::warn!("could not persist secrets to {}: {e}", path.display());
                tracing::warn!("secrets are ephemeral — they will change on next restart");
            } else {
                tracing::info!(
                    path = %path.display(),
                    "generated secrets and saved to file (first run)"
                );
            }
        }
    }
}

// ─── macOS Keychain Backend ───────────────────────────────────────────────────

/// Load secrets from macOS Keychain.
fn load_from_keychain() -> Option<SecretsFile> {
    let pepper = keychain_get("hmac-pepper")?;
    let jwt = keychain_get("jwt-secret")?;
    Some(SecretsFile {
        hmac_pepper: pepper,
        jwt_secret: jwt,
    })
}

/// Save secrets to macOS Keychain.
fn save_to_keychain(secrets: &SecretsFile) -> bool {
    keychain_set("hmac-pepper", &secrets.hmac_pepper)
        && keychain_set("jwt-secret", &secrets.jwt_secret)
}

/// Read a value from macOS Keychain.
fn keychain_get(account: &str) -> Option<String> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Write a value to macOS Keychain. Updates if exists.
fn keychain_set(account: &str, value: &str) -> bool {
    // Try to delete existing entry first (update pattern)
    let _ = Command::new("security")
        .args([
            "delete-generic-password",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
        ])
        .output();

    Command::new("security")
        .args([
            "add-generic-password",
            "-a",
            account,
            "-s",
            KEYCHAIN_SERVICE,
            "-l",
            &format!("L-ARC {account}"),
            "-w",
            value,
            "-T",
            "",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── File Backend ─────────────────────────────────────────────────────────────

fn generate_random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::keys::hex::encode(bytes)
}

fn secrets_file_path() -> PathBuf {
    if let Ok(custom) = std::env::var("LARC_SECRETS_FILE") {
        return PathBuf::from(custom);
    }
    dirs_home().map_or_else(|| PathBuf::from(SECRETS_PATH), |h| h.join(SECRETS_PATH))
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn load_secrets_file(path: &Path) -> Option<SecretsFile> {
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
}

fn write_secrets_file(path: &Path, secrets: &SecretsFile) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io(format!("create dir: {e}")))?;

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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| ConfigError::Io(format!("chmod: {e}")))?;
    }

    Ok(())
}

// ─── Settings (non-secret preferences) ────────────────────────────────────────

fn settings_path() -> PathBuf {
    dirs_home().map_or_else(
        || PathBuf::from(".larc/config.toml"),
        |h| h.join(".larc/config.toml"),
    )
}

fn load_settings() -> Option<LarcSettings> {
    let content = std::fs::read_to_string(settings_path()).ok()?;
    toml::from_str(&content).ok()
}

/// Save user preferences to `~/.larc/config.toml`.
pub fn save_settings(settings: &LarcSettings) -> Result<(), ConfigError> {
    let path = settings_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io(format!("create dir: {e}")))?;
    }

    let content =
        toml::to_string_pretty(settings).map_err(|e| ConfigError::Io(format!("serialize: {e}")))?;

    std::fs::write(&path, &content).map_err(|e| ConfigError::Io(format!("write: {e}")))?;

    Ok(())
}

// ─── Init Command ─────────────────────────────────────────────────────────────

/// Run the first-time initialization wizard.
/// Called via `larc-api-keys init`.
pub fn run_init() -> Result<(), ConfigError> {
    println!("L-ARC API Key Service — First-Time Setup\n");

    // Check if already initialized
    if let Some(settings) = load_settings()
        && settings.initialized
    {
        println!(
            "Already initialized (backend: {:?}).",
            settings.secret_backend
        );
        println!("To re-initialize, delete ~/.larc/config.toml and run again.");
        return Ok(());
    }

    // Detect platform capabilities
    let keychain_available = cfg!(target_os = "macos") && keychain_test();

    let backend = if keychain_available {
        println!("Where should L-ARC store its secrets?\n");
        println!("  1. macOS Keychain (recommended) — hardware-backed encryption, OS-native");
        println!("  2. File (~/.larc/secrets.toml)  — chmod 600, portable across platforms\n");

        print!("Choice [1]: ");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        let choice = input.trim();

        if choice == "2" {
            SecretBackend::File
        } else {
            SecretBackend::Keychain
        }
    } else {
        println!("macOS Keychain not available — using file-based secrets.");
        SecretBackend::File
    };

    // Generate and persist secrets
    let secrets = SecretsFile {
        hmac_pepper: generate_random_hex(),
        jwt_secret: generate_random_hex(),
    };

    match backend {
        SecretBackend::Keychain => {
            if save_to_keychain(&secrets) {
                println!("\nSecrets stored in macOS Keychain.");
            } else {
                println!("\nKeychain failed — falling back to file.");
                let path = secrets_file_path();
                write_secrets_file(&path, &secrets)?;
                println!("Secrets written to {}", path.display());
            }
        }
        SecretBackend::File => {
            let path = secrets_file_path();
            write_secrets_file(&path, &secrets)?;
            println!("\nSecrets written to {} (chmod 600)", path.display());
        }
    }

    // Save preferences
    let settings = LarcSettings {
        secret_backend: backend,
        initialized: true,
    };
    save_settings(&settings)?;

    println!("\nSetup complete. Run `larc-api-keys` to start the service.");
    Ok(())
}

/// Test if macOS Keychain is accessible.
fn keychain_test() -> bool {
    Command::new("security")
        .args(["list-keychains"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
