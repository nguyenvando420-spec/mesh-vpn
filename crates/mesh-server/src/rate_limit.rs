//! Real-client-IP token-bucket rate limiter respecting `trusted_proxies` (`US-042`, `WP-S1-01`).

/// Source-IP token bucket limiter skeleton.
#[derive(Debug, Default)]
pub(crate) struct RateLimiter;

impl RateLimiter {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "rate_limiter:ready"
    }
}
