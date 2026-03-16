use hmac::{Hmac, Mac};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
#[allow(unused_imports)]
use zeroize::Zeroizing;

use crate::error::{AppError, Result};
use crate::types::KeyEnvironment;

type HmacSha256 = Hmac<Sha256>;

/// Length of the raw random key material in bytes (256 bits of entropy).
const KEY_RANDOM_BYTES: usize = 32;

/// Number of prefix characters stored for key identification.
const PREFIX_DISPLAY_LEN: usize = 8;

/// Number of trailing characters stored for display (e.g., "...a1b2").
const LAST_CHARS_LEN: usize = 4;

/// Result of key generation — the raw key (shown once) and its hash (stored).
pub struct GeneratedKey {
    /// The full API key string, shown to the user exactly once.
    /// Format: `lak_{env}_{base62(32 random bytes)}{base62(crc32)}`
    pub raw_key: SecretString,
    /// HMAC-SHA256 hash of the raw key, hex-encoded. Stored in the database.
    pub key_hash: String,
    /// First 8 characters of the key body (after the `lak_{env}_` prefix).
    pub prefix: String,
    /// Last 4 characters of the full key string.
    pub last_four: String,
}

/// Generate a new API key with cryptographic randomness.
///
/// Key format: `lak_{env}_{base62(32 random bytes)}{base62(crc32)}`
/// - `lak` = Light Architects Key (prefix for secret scanning tools)
/// - `env` = `live` or `test`
/// - Body = base62-encoded 32 bytes of CSPRNG randomness
/// - Checksum = base62-encoded CRC32 of the body (client-side validation)
pub fn generate_key(env: KeyEnvironment, pepper: &SecretString) -> Result<GeneratedKey> {
    // Generate 32 bytes of cryptographic randomness (256 bits)
    let mut random_bytes = Zeroizing::new([0u8; KEY_RANDOM_BYTES]);
    rand::thread_rng().fill_bytes(random_bytes.as_mut());

    // Base62-encode as two u128 halves (the crate only accepts Into<u128>)
    let (first_half, second_half) = random_bytes.split_at(16);
    let n1 = u128::from_be_bytes(first_half.try_into().expect("16 bytes"));
    let n2 = u128::from_be_bytes(second_half.try_into().expect("16 bytes"));
    let body = format!("{}{}", base62::encode(n1), base62::encode(n2));

    // CRC32 checksum of the body for client-side validation (GitHub pattern)
    let checksum = crc32fast::hash(body.as_bytes());
    let checksum_str = base62::encode(u128::from(checksum));

    // Assemble the full key: lak_{env}_{body}{checksum}
    let full_key = format!("lak_{}_{body}{checksum_str}", env.as_str());

    // Extract prefix and last-four for identification
    let key_body_start = format!("lak_{}_", env.as_str()).len();
    let prefix = if full_key.len() >= key_body_start + PREFIX_DISPLAY_LEN {
        full_key[key_body_start..key_body_start + PREFIX_DISPLAY_LEN].to_string()
    } else {
        full_key[key_body_start..].to_string()
    };

    let last_four = if full_key.len() >= LAST_CHARS_LEN {
        full_key[full_key.len() - LAST_CHARS_LEN..].to_string()
    } else {
        full_key.clone()
    };

    // HMAC-SHA256 hash with server-side pepper
    let key_hash = hash_key(&full_key, pepper)?;

    Ok(GeneratedKey {
        raw_key: SecretString::from(full_key),
        key_hash,
        prefix,
        last_four,
    })
}

/// Hash an API key using HMAC-SHA256 with the server-side pepper.
///
/// Returns the hex-encoded hash. The pepper ensures that a database dump
/// alone cannot be used to verify keys — the attacker needs both the DB
/// and the pepper.
pub fn hash_key(raw_key: &str, pepper: &SecretString) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(pepper.expose_secret().as_bytes())
        .map_err(|e| AppError::Internal(format!("HMAC initialization failed: {e}")))?;
    mac.update(raw_key.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verify a raw API key against a stored hash.
///
/// Uses constant-time comparison (via HMAC verify) to prevent timing attacks.
pub fn verify_key(raw_key: &str, stored_hash: &str, pepper: &SecretString) -> Result<bool> {
    let computed_hash = hash_key(raw_key, pepper)?;

    // Constant-time comparison to prevent timing attacks.
    // Both hashes are hex strings of the same HMAC output, so same length.
    let computed_bytes = computed_hash.as_bytes();
    let stored_bytes = stored_hash.as_bytes();

    if computed_bytes.len() != stored_bytes.len() {
        return Ok(false);
    }

    // XOR-based constant-time comparison
    let mut diff = 0u8;
    for (a, b) in computed_bytes.iter().zip(stored_bytes.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

/// Validate the format of a raw API key.
/// Returns the environment if valid.
pub fn parse_key_prefix(raw_key: &str) -> Option<KeyEnvironment> {
    if raw_key.starts_with("lak_live_") {
        Some(KeyEnvironment::Live)
    } else if raw_key.starts_with("lak_test_") {
        Some(KeyEnvironment::Test)
    } else {
        None
    }
}

/// Validate the CRC32 checksum embedded in the key (client-side validation).
/// Returns true if the checksum matches, false otherwise.
pub fn validate_key_checksum(raw_key: &str) -> bool {
    // Extract environment prefix length
    let prefix_len = if raw_key.starts_with("lak_live_") {
        "lak_live_".len()
    } else if raw_key.starts_with("lak_test_") {
        "lak_test_".len()
    } else {
        return false;
    };

    let body_and_checksum = &raw_key[prefix_len..];

    // The checksum is the last few base62-encoded characters of a u32.
    // CRC32 produces a u32 (4 bytes), which base62-encodes to 1-6 characters.
    // We need to try different checksum lengths to find the right split.
    // In practice, base62(u32) is typically 5-6 chars.
    for checksum_len in 1..=7 {
        if body_and_checksum.len() <= checksum_len {
            continue;
        }
        let split = body_and_checksum.len() - checksum_len;
        let body = &body_and_checksum[..split];
        let checksum_str = &body_and_checksum[split..];

        // Try to decode the checksum portion as base62 -> u128
        if let Ok(checksum_value) = base62::decode(checksum_str) {
            // CRC32 is a u32 — reject if decoded value exceeds u32::MAX
            if checksum_value <= u128::from(u32::MAX) {
                let expected_checksum = u128::from(crc32fast::hash(body.as_bytes()));
                if expected_checksum == checksum_value {
                    return true;
                }
            }
        }
    }

    false
}

// Hex encoding utility — used by keys and webhooks
pub mod hex {
    /// Encode bytes as lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(bytes.as_ref().len() * 2);
        for b in bytes.as_ref() {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pepper() -> SecretString {
        SecretString::from("test-pepper-for-unit-tests-32chars!!".to_string())
    }

    #[test]
    fn test_generate_key_live() {
        let pepper = test_pepper();
        let result = generate_key(KeyEnvironment::Live, &pepper).unwrap();

        let raw = result.raw_key.expose_secret();
        assert!(
            raw.starts_with("lak_live_"),
            "key should start with lak_live_"
        );
        assert!(!result.key_hash.is_empty(), "hash should not be empty");
        assert_eq!(
            result.prefix.len(),
            PREFIX_DISPLAY_LEN,
            "prefix should be 8 chars"
        );
        assert_eq!(
            result.last_four.len(),
            LAST_CHARS_LEN,
            "last_four should be 4 chars"
        );
    }

    #[test]
    fn test_generate_key_test_env() {
        let pepper = test_pepper();
        let result = generate_key(KeyEnvironment::Test, &pepper).unwrap();

        let raw = result.raw_key.expose_secret();
        assert!(
            raw.starts_with("lak_test_"),
            "key should start with lak_test_"
        );
    }

    #[test]
    fn test_key_uniqueness() {
        let pepper = test_pepper();
        let key1 = generate_key(KeyEnvironment::Live, &pepper).unwrap();
        let key2 = generate_key(KeyEnvironment::Live, &pepper).unwrap();

        assert_ne!(
            key1.raw_key.expose_secret(),
            key2.raw_key.expose_secret(),
            "two generated keys should not be equal"
        );
        assert_ne!(
            key1.key_hash, key2.key_hash,
            "two hashes should not be equal"
        );
    }

    #[test]
    fn test_hash_and_verify() {
        let pepper = test_pepper();
        let raw_key = "lak_live_testkey123456789";
        let hash = hash_key(raw_key, &pepper).unwrap();

        assert!(
            verify_key(raw_key, &hash, &pepper).unwrap(),
            "valid key should verify"
        );
        assert!(
            !verify_key("lak_live_wrongkey987654321", &hash, &pepper).unwrap(),
            "wrong key should not verify"
        );
    }

    #[test]
    fn test_verify_different_pepper() {
        let pepper1 = test_pepper();
        let pepper2 = SecretString::from("different-pepper-for-testing-32c!!".to_string());

        let raw_key = "lak_live_testkey123456789";
        let hash = hash_key(raw_key, &pepper1).unwrap();

        assert!(
            !verify_key(raw_key, &hash, &pepper2).unwrap(),
            "key hashed with different pepper should not verify"
        );
    }

    #[test]
    fn test_parse_key_prefix() {
        assert_eq!(
            parse_key_prefix("lak_live_abc123"),
            Some(KeyEnvironment::Live)
        );
        assert_eq!(
            parse_key_prefix("lak_test_abc123"),
            Some(KeyEnvironment::Test)
        );
        assert_eq!(parse_key_prefix("sk_live_abc123"), None);
        assert_eq!(parse_key_prefix("invalid"), None);
    }

    #[test]
    fn test_constant_time_comparison() {
        let pepper = test_pepper();
        let raw_key = "lak_live_testkey123456789";
        let hash = hash_key(raw_key, &pepper).unwrap();

        // Both "not found" and "wrong key" should take similar time
        // (we can't measure timing in a unit test, but we verify the code path)
        assert!(!verify_key("lak_live_nonexistent", &hash, &pepper).unwrap());
        assert!(!verify_key("completely_wrong", &hash, &pepper).unwrap());
    }
}
