use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Service Scoping (Rust enums, NOT strings — GUARD amendment #6) ───────────

/// Services that API keys can be scoped to.
/// Using an enum prevents scope bypass via string manipulation (GUARD §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceName {
    Eva,
    Corso,
    Soul,
    Quantum,
    Seraph,
    Ayin,
    /// Wildcard access — only assignable by super-admin, never via API
    All,
}

impl ServiceName {
    /// Parse from string, rejecting unknown services.
    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "eva" => Some(Self::Eva),
            "corso" => Some(Self::Corso),
            "soul" => Some(Self::Soul),
            "quantum" => Some(Self::Quantum),
            "seraph" => Some(Self::Seraph),
            "ayin" => Some(Self::Ayin),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eva => "eva",
            Self::Corso => "corso",
            Self::Soul => "soul",
            Self::Quantum => "quantum",
            Self::Seraph => "seraph",
            Self::Ayin => "ayin",
            Self::All => "all",
        }
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Permission levels for scoped access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Write,
    Admin,
}

impl Permission {
    /// Check if this permission implies another.
    /// admin implies write implies read.
    #[must_use]
    pub fn implies(self, other: Self) -> bool {
        match self {
            Self::Admin => true,
            Self::Write => other == Self::Write || other == Self::Read,
            Self::Read => other == Self::Read,
        }
    }

    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single scope entry: service + permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Scope {
    pub service: ServiceName,
    pub permission: Permission,
}

impl Scope {
    #[must_use]
    pub fn new(service: ServiceName, permission: Permission) -> Self {
        Self {
            service,
            permission,
        }
    }

    /// Check if this scope grants access for the requested scope.
    /// `ServiceName::All` matches any service.
    #[must_use]
    pub fn grants(self, requested: Self) -> bool {
        let service_match = self.service == ServiceName::All || self.service == requested.service;
        service_match && self.permission.implies(requested.permission)
    }

    /// Parse "service:permission" format.
    /// Returns None if either component is invalid.
    pub fn parse(s: &str) -> Option<Self> {
        let (service_str, perm_str) = s.split_once(':')?;
        let service = ServiceName::from_str_strict(service_str)?;
        let permission = Permission::from_str_strict(perm_str)?;
        Some(Self {
            service,
            permission,
        })
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.service, self.permission)
    }
}

// ─── Key Environment ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEnvironment {
    Live,
    Test,
}

impl KeyEnvironment {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Test => "test",
        }
    }
}

impl std::fmt::Display for KeyEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Key Status ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Deprecated,
    Revoked,
}

impl KeyStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Core Data Models ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub tier: UserTier,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserTier {
    Free,
    Pro,
    Unlimited,
}

impl UserTier {
    /// Requests per minute for this tier.
    #[must_use]
    pub fn rate_limit(self) -> Option<u32> {
        match self {
            Self::Free => Some(100),
            Self::Pro => Some(1000),
            Self::Unlimited => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Unlimited => "unlimited",
        }
    }

    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "free" => Some(Self::Free),
            "pro" => Some(Self::Pro),
            "unlimited" => Some(Self::Unlimited),
            _ => None,
        }
    }
}

impl std::fmt::Display for UserTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// API key metadata (never contains the raw key or hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub prefix: String,
    pub last_four: String,
    pub environment: KeyEnvironment,
    pub status: KeyStatus,
    pub scopes: Vec<Scope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Lineage ID for rate limit tracking across rotations (GUARD amendment #8).
    pub lineage_id: Uuid,
}

/// Webhook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: Uuid,
    pub user_id: Uuid,
    pub url: String,
    pub events: Vec<WebhookEvent>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    KeyCreated,
    KeyRotated,
    KeyRevoked,
    RateLimitExceeded,
}

impl WebhookEvent {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyCreated => "key.created",
            Self::KeyRotated => "key.rotated",
            Self::KeyRevoked => "key.revoked",
            Self::RateLimitExceeded => "rate_limit.exceeded",
        }
    }
}

impl std::fmt::Display for WebhookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Usage log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEntry {
    pub id: i64,
    pub key_id: Uuid,
    pub user_id: Uuid,
    pub endpoint: String,
    pub method: String,
    pub status_code: u16,
    pub timestamp: DateTime<Utc>,
    pub response_time_ms: u32,
}
