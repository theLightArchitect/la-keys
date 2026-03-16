use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use uuid::Uuid;

/// Sliding window rate limiter — in-memory, no external dependencies.
///
/// Tracks request counts per key using a weighted sliding window algorithm:
/// - Current window count + (previous window count * overlap ratio)
/// - Near-exact accuracy without storing individual timestamps
/// - O(1) memory per key regardless of request volume
#[derive(Debug, Clone)]
pub struct RateLimiter {
    state: Arc<RwLock<RateLimitState>>,
    window_secs: u64,
}

#[derive(Debug)]
struct RateLimitState {
    /// Keyed by `lineage_id` (survives key rotation — GUARD amendment #8)
    counters: HashMap<Uuid, WindowCounter>,
    /// Per-IP counters for global IP-based limiting
    ip_counters: HashMap<String, WindowCounter>,
}

#[derive(Debug, Clone)]
struct WindowCounter {
    current_count: u32,
    previous_count: u32,
    window_start: Instant,
}

/// Result of a rate limit check.
#[derive(Debug)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_at_secs: u64,
    pub retry_after_secs: Option<u64>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given window size.
    #[must_use]
    pub fn new(window_secs: u64) -> Self {
        Self {
            state: Arc::new(RwLock::new(RateLimitState {
                counters: HashMap::new(),
                ip_counters: HashMap::new(),
            })),
            window_secs,
        }
    }

    /// Check and record a request against the per-lineage rate limit.
    ///
    /// Uses the `lineage_id` (not `key_id`) so rate limit state survives key rotation.
    pub async fn check_lineage(&self, lineage_id: Uuid, limit: u32) -> RateLimitResult {
        let mut state = self.state.write().await;
        let window_duration = Duration::from_secs(self.window_secs);

        let counter = state
            .counters
            .entry(lineage_id)
            .or_insert_with(|| WindowCounter {
                current_count: 0,
                previous_count: 0,
                window_start: Instant::now(),
            });

        self.check_counter(counter, limit, window_duration)
    }

    /// Check and record a request against the per-IP rate limit.
    pub async fn check_ip(&self, ip: &str, limit: u32) -> RateLimitResult {
        let mut state = self.state.write().await;
        let window_duration = Duration::from_secs(self.window_secs);

        let counter = state
            .ip_counters
            .entry(ip.to_string())
            .or_insert_with(|| WindowCounter {
                current_count: 0,
                previous_count: 0,
                window_start: Instant::now(),
            });

        self.check_counter(counter, limit, window_duration)
    }

    fn check_counter(
        &self,
        counter: &mut WindowCounter,
        limit: u32,
        window_duration: Duration,
    ) -> RateLimitResult {
        let now = Instant::now();
        let elapsed = now.duration_since(counter.window_start);

        // Rotate window if needed
        if elapsed >= window_duration {
            let windows_passed = elapsed.as_secs() / window_duration.as_secs();
            if windows_passed >= 2 {
                // More than 2 windows have passed — reset everything
                counter.previous_count = 0;
                counter.current_count = 0;
            } else {
                // Exactly 1 window passed — rotate
                counter.previous_count = counter.current_count;
                counter.current_count = 0;
            }
            counter.window_start = now;
        }

        // Calculate weighted count (sliding window approximation)
        let elapsed_in_window = now.duration_since(counter.window_start);
        let overlap_ratio = if self.window_secs > 0 {
            #[allow(clippy::cast_precision_loss)] // Window secs is small, precision loss irrelevant
            {
                1.0 - (elapsed_in_window.as_secs_f64() / self.window_secs as f64)
            }
        } else {
            0.0
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let weighted_count = counter.current_count
            + (f64::from(counter.previous_count) * overlap_ratio.max(0.0)) as u32;

        if weighted_count >= limit {
            let remaining_window = window_duration.saturating_sub(elapsed_in_window);

            return RateLimitResult {
                allowed: false,
                limit,
                remaining: 0,
                reset_at_secs: remaining_window.as_secs(),
                retry_after_secs: Some(remaining_window.as_secs().max(1)),
            };
        }

        counter.current_count = counter.current_count.saturating_add(1);

        let remaining_window = window_duration.saturating_sub(elapsed_in_window);
        let remaining = limit.saturating_sub(weighted_count + 1);

        RateLimitResult {
            allowed: true,
            limit,
            remaining,
            reset_at_secs: remaining_window.as_secs(),
            retry_after_secs: None,
        }
    }

    /// Prune expired entries to prevent unbounded memory growth.
    /// Call periodically (e.g., every 5 minutes) from a background task.
    pub async fn prune_expired(&self) {
        let mut state = self.state.write().await;
        let window_duration = Duration::from_secs(self.window_secs.saturating_mul(2));
        let now = Instant::now();

        state
            .counters
            .retain(|_, counter| now.duration_since(counter.window_start) < window_duration);
        state
            .ip_counters
            .retain(|_, counter| now.duration_since(counter.window_start) < window_duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_rate_limiting() {
        let limiter = RateLimiter::new(60);
        let lineage = Uuid::new_v4();

        // First request should be allowed
        let result = limiter.check_lineage(lineage, 3).await;
        assert!(result.allowed);
        assert_eq!(result.remaining, 2);

        // Second request
        let result = limiter.check_lineage(lineage, 3).await;
        assert!(result.allowed);
        assert_eq!(result.remaining, 1);

        // Third request
        let result = limiter.check_lineage(lineage, 3).await;
        assert!(result.allowed);
        assert_eq!(result.remaining, 0);

        // Fourth request — should be rate limited
        let result = limiter.check_lineage(lineage, 3).await;
        assert!(!result.allowed);
        assert!(result.retry_after_secs.is_some());
    }

    #[tokio::test]
    async fn test_different_lineages_independent() {
        let limiter = RateLimiter::new(60);
        let lineage1 = Uuid::new_v4();
        let lineage2 = Uuid::new_v4();

        // Fill up lineage1
        for _ in 0..3 {
            limiter.check_lineage(lineage1, 3).await;
        }
        let result = limiter.check_lineage(lineage1, 3).await;
        assert!(!result.allowed, "lineage1 should be rate limited");

        // lineage2 should still be allowed
        let result = limiter.check_lineage(lineage2, 3).await;
        assert!(result.allowed, "lineage2 should not be affected");
    }

    #[tokio::test]
    async fn test_ip_rate_limiting() {
        let limiter = RateLimiter::new(60);

        let result = limiter.check_ip("192.168.1.1", 2).await;
        assert!(result.allowed);

        let result = limiter.check_ip("192.168.1.1", 2).await;
        assert!(result.allowed);

        let result = limiter.check_ip("192.168.1.1", 2).await;
        assert!(!result.allowed, "IP should be rate limited");

        // Different IP should be fine
        let result = limiter.check_ip("192.168.1.2", 2).await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_unlimited_tier() {
        let limiter = RateLimiter::new(60);
        let lineage = Uuid::new_v4();

        // With a very high limit, should never be rate limited
        for _ in 0..100 {
            let result = limiter.check_lineage(lineage, u32::MAX).await;
            assert!(result.allowed);
        }
    }

    #[tokio::test]
    async fn test_prune_expired() {
        let limiter = RateLimiter::new(1); // 1 second window
        let lineage = Uuid::new_v4();

        limiter.check_lineage(lineage, 100).await;

        // Prune should keep recent entries
        limiter.prune_expired().await;

        let state = limiter.state.read().await;
        assert_eq!(state.counters.len(), 1);
    }
}
