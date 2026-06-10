// WHY: all webhook delivery code is reserved for post-alpha fanout;
// no endpoint wires these functions yet.
#![allow(dead_code)]

use std::net::IpAddr;
use std::time::Duration;

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{AppError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Validate a webhook URL for SSRF safety (GUARD §3).
///
/// Rejects:
/// - Non-HTTPS schemes
/// - Private IP ranges (RFC 1918, loopback, link-local, metadata)
/// - IPv6 private ranges
/// - IPv4-mapped IPv6 addresses
pub fn validate_webhook_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|_| AppError::BadRequest("invalid webhook URL".to_string()))?;

    // HTTPS only (GUARD §3 — no http://, file://, gopher://, etc.)
    if parsed.scheme() != "https" {
        return Err(AppError::BadRequest(
            "webhook URLs must use HTTPS".to_string(),
        ));
    }

    // Must have a host
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("webhook URL must have a host".to_string()))?;

    // Resolve hostname and check all IPs against deny-list
    // Note: In production, use tokio::net::lookup_host for async resolution.
    // For validation, we check the hostname pattern.
    if let Ok(ip) = host.parse::<IpAddr>()
        && is_private_ip(&ip)
    {
        return Err(AppError::BadRequest(
            "webhook URLs cannot point to private/internal addresses".to_string(),
        ));
    }

    // Block common internal hostnames (not file paths — suppress false positive)
    let host_lower = host.to_lowercase();
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let is_internal = host_lower == "localhost"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
        || host_lower == "metadata.google.internal"
        || host_lower.contains("169.254");
    if is_internal {
        return Err(AppError::BadRequest(
            "webhook URLs cannot point to internal hosts".to_string(),
        ));
    }

    Ok(())
}

/// Check if an IP address is in a private/reserved range (GUARD §3 deny-list).
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                // 127.0.0.0/8
                || v4.is_private()           // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()        // 169.254.0.0/16 (cloud metadata)
                || v4.is_unspecified()       // 0.0.0.0/8
                || v4.is_broadcast()         // 255.255.255.255
                || is_cgnat(*v4) // 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                 // ::1
                || v6.is_unspecified()       // ::
                || is_ipv6_private(v6)       // fc00::/7, fe80::/10
                || is_ipv4_mapped_private(v6) // ::ffff:127.0.0.1, etc.
        }
    }
}

/// Check for Carrier-Grade NAT range (100.64.0.0/10).
fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// Check for IPv6 unique local (`fc00::/7`) and link-local (`fe80::/10`).
fn is_ipv6_private(ip: &std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    // fc00::/7 — unique local
    (segments[0] & 0xFE00) == 0xFC00
    // fe80::/10 — link-local
    || (segments[0] & 0xFFC0) == 0xFE80
}

/// Check if an IPv4-mapped IPv6 address (`::ffff:x.x.x.x`) maps to a private IPv4.
fn is_ipv4_mapped_private(ip: &std::net::Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        is_private_ip(&IpAddr::V4(v4))
    } else {
        false
    }
}

/// Generate a webhook signature using the Stripe pattern.
///
/// Format: `t={unix_timestamp},v1={hex_hmac_sha256}`
/// Signed payload: `"{timestamp}.{raw_body}"`
pub fn sign_webhook_payload(body: &[u8], secret: &str, timestamp: i64) -> Result<String> {
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| AppError::Internal(format!("HMAC init failed: {e}")))?;
    mac.update(signed_payload.as_bytes());
    let signature = crate::keys::hex::encode(mac.finalize().into_bytes());

    Ok(format!("t={timestamp},v1={signature}"))
}

/// Verify a webhook signature.
pub fn verify_webhook_signature(
    body: &[u8],
    secret: &str,
    signature_header: &str,
    tolerance_secs: i64,
) -> Result<bool> {
    // Parse header: t={ts},v1={sig}
    let mut timestamp = None;
    let mut signature = None;

    for part in signature_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = ts.parse::<i64>().ok();
        } else if let Some(sig) = part.strip_prefix("v1=") {
            signature = Some(sig.to_string());
        }
    }

    let ts = timestamp.ok_or(AppError::BadRequest(
        "missing timestamp in signature".to_string(),
    ))?;
    let sig = signature.ok_or(AppError::BadRequest("missing v1 signature".to_string()))?;

    // Replay protection — reject if timestamp is too old
    let now = Utc::now().timestamp();
    if (now - ts).abs() > tolerance_secs {
        return Ok(false);
    }

    // Recompute and compare
    let expected = sign_webhook_payload(body, secret, ts)?;
    let expected_sig = expected
        .split(',')
        .find_map(|p| p.strip_prefix("v1="))
        .ok_or(AppError::Internal(
            "signature generation failed".to_string(),
        ))?;

    // Constant-time comparison
    let a = sig.as_bytes();
    let b = expected_sig.as_bytes();
    if a.len() != b.len() {
        return Ok(false);
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    Ok(diff == 0)
}

/// Build a reqwest client configured for webhook delivery (GUARD §3).
pub fn webhook_client() -> reqwest::Client {
    reqwest::Client::builder()
        // No redirect following — prevents SSRF via 302 to internal IPs
        .redirect(reqwest::redirect::Policy::none())
        // Aggressive timeouts
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        // HTTPS only enforced at URL validation, not client level
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_https_required() {
        assert!(validate_webhook_url("https://example.com/hook").is_ok());
        assert!(validate_webhook_url("http://example.com/hook").is_err());
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
    }

    #[test]
    fn test_validate_blocks_private_ips() {
        assert!(validate_webhook_url("https://127.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://192.168.1.1/hook").is_err());
        assert!(validate_webhook_url("https://172.16.0.1/hook").is_err());
        assert!(validate_webhook_url("https://169.254.169.254/hook").is_err());
    }

    #[test]
    fn test_validate_blocks_localhost() {
        assert!(validate_webhook_url("https://localhost/hook").is_err());
        assert!(validate_webhook_url("https://myhost.local/hook").is_err());
    }

    #[test]
    fn test_validate_allows_public() {
        assert!(validate_webhook_url("https://api.example.com/webhooks").is_ok());
        assert!(validate_webhook_url("https://hooks.slack.com/services/abc").is_ok());
    }

    #[test]
    fn test_sign_and_verify() {
        let body = b"test payload";
        let secret = "webhook-secret-32-chars-minimum!";
        let now = Utc::now().timestamp();

        let signature = sign_webhook_payload(body, secret, now).unwrap();
        assert!(signature.starts_with("t="));
        assert!(signature.contains(",v1="));

        let valid = verify_webhook_signature(body, secret, &signature, 300).unwrap();
        assert!(valid, "signature should verify with correct secret");

        let invalid = verify_webhook_signature(b"wrong body", secret, &signature, 300).unwrap();
        assert!(!invalid, "signature should fail with wrong body");
    }

    #[test]
    fn test_replay_protection() {
        let body = b"test payload";
        let secret = "webhook-secret-32-chars-minimum!";
        let old_timestamp = Utc::now().timestamp() - 600; // 10 minutes ago

        let signature = sign_webhook_payload(body, secret, old_timestamp).unwrap();

        // With 5-minute tolerance, should reject
        let result = verify_webhook_signature(body, secret, &signature, 300).unwrap();
        assert!(!result, "old signature should be rejected");
    }

    #[test]
    fn test_is_private_ip_v4() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ip_v6() {
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
    }
}
