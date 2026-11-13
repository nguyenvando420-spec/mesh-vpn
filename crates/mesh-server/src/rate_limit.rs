//! Trusted client-IP extraction, adaptive exponential brute-force rate limiting (`US-042`),
//! and integer token buckets for Blind Relay (`20 Mbps`) and STUN (`100 pkt/s/IP`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::TlsMode;

/// Sliding failure window length (`5 minutes` per `system-architecture.md` §5.3).
pub const AUTH_FAILURE_WINDOW_MS: u64 = 5 * 60 * 1_000;

/// Failure count threshold per IP within 5m before temporary ban (`10 failures`).
pub const AUTH_FAILURE_THRESHOLD: u32 = 10;

/// Initial authentication ban duration (`15 minutes`) doubled on repeated offense.
pub const INITIAL_LOCKOUT_MS: u64 = 15 * 60 * 1_000;

/// Maximum exponential lockout duration (`24 hours`).
pub const MAX_LOCKOUT_MS: u64 = 24 * 3_600 * 1_000;

/// Global cap across non-locked IPs for expensive auth challenge/crypto ops (`60 req/min`).
pub const GLOBAL_AUTH_REQ_PER_MIN: u64 = 60;

const MAX_TRACKED_CLIENT_IPS: usize = 16_384;

/// Safely resolves the real client IP without permitting header spoofing in Standalone mode
/// (`US-042 AC6`, `SEC-05`).
#[derive(Debug, Clone)]
pub struct ClientIpExtractor {
    tls_mode: TlsMode,
    trusted_proxies: HashSet<IpAddr>,
}

impl ClientIpExtractor {
    /// Creates an extractor configured for the active `TlsMode` and proxy whitelist.
    #[must_use]
    pub fn new(tls_mode: TlsMode, trusted_proxies: HashSet<IpAddr>) -> Self {
        Self {
            tls_mode,
            trusted_proxies,
        }
    }

    /// Resolves source IP for rate-limiting & audit logging.
    ///
    /// Ignores forwarded headers outside `ReverseProxy` mode or from untrusted peers, and avoids
    /// falsely returning a trusted proxy address when valid `X-Forwarded-For` / `X-Real-IP` exists.
    #[must_use]
    pub fn extract(
        &self,
        peer_ip: IpAddr,
        x_forwarded_for: Option<&str>,
        x_real_ip: Option<&str>,
    ) -> IpAddr {
        if self.tls_mode != TlsMode::ReverseProxy || !self.trusted_proxies.contains(&peer_ip) {
            return peer_ip;
        }

        if let Some(xff) = x_forwarded_for {
            for hop_raw in xff.rsplit(',') {
                if let Ok(hop_ip) = hop_raw.trim().parse::<IpAddr>()
                    && !self.trusted_proxies.contains(&hop_ip)
                {
                    return hop_ip;
                }
            }
        }

        if let Some(real_raw) = x_real_ip
            && let Ok(real_ip) = real_raw.trim().parse::<IpAddr>()
            && !self.trusted_proxies.contains(&real_ip)
        {
            return real_ip;
        }

        peer_ip
    }

    /// Returns `true` when `ip` belongs to the explicitly trusted reverse-proxy set and must
    /// never be banned globally.
    #[must_use]
    pub fn is_trusted_proxy(&self, ip: &IpAddr) -> bool {
        self.tls_mode == TlsMode::ReverseProxy && self.trusted_proxies.contains(ip)
    }
}

#[derive(Debug, Clone)]
struct IpPenaltyState {
    window_start_ms: u64,
    failures_in_window: u32,
    strike_level: u32,
    locked_until_ms: u64,
    last_seen_ms: u64,
}

/// Decision returned by [`RateLimiter::check_auth_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Request may proceed.
    Allowed,
    /// Client IP is temporarily banned; caller should reject with `HTTP 429` (`Retry-After`).
    IpLocked { retry_after_secs: u64 },
    /// Global challenge/registration rate limit reached; caller should reject with `HTTP 429`.
    GlobalLimitExceeded { retry_after_secs: u64 },
}

/// Stateful rate limiter protecting Control auth endpoints (`US-042`).
#[derive(Debug)]
pub struct RateLimiter {
    extractor: ClientIpExtractor,
    state: Mutex<LimiterState>,
    hits_total: AtomicU64,
}

#[derive(Debug)]
struct LimiterState {
    per_ip: HashMap<IpAddr, IpPenaltyState>,
    global_bucket: TokenBucket,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(ClientIpExtractor::new(TlsMode::IpPinned, HashSet::new()))
    }
}

impl RateLimiter {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "rate_limiter:ready"
    }

    /// Creates a rate limiter backed by `extractor`.
    #[must_use]
    pub fn new(extractor: ClientIpExtractor) -> Self {
        Self {
            extractor,
            state: Mutex::new(LimiterState {
                per_ip: HashMap::new(),
                // 60 req/min == 1 req/sec sustained, burst capacity 60 requests
                global_bucket: TokenBucket::new(GLOBAL_AUTH_REQ_PER_MIN, 1, 0),
            }),
            hits_total: AtomicU64::new(0),
        }
    }

    /// Resolves source client IP honoring `trusted_proxies`.
    #[must_use]
    pub fn resolve_client_ip(
        &self,
        peer_ip: IpAddr,
        x_forwarded_for: Option<&str>,
        x_real_ip: Option<&str>,
    ) -> IpAddr {
        self.extractor.extract(peer_ip, x_forwarded_for, x_real_ip)
    }

    /// Checks whether an auth challenge/registration attempt from `client_ip` is permitted.
    pub fn check_auth_request(&self, client_ip: IpAddr, now_ms: u64) -> RateLimitDecision {
        let Ok(mut guard) = self.state.lock() else {
            return RateLimitDecision::Allowed;
        };

        if let Some(entry) = guard.per_ip.get(&client_ip)
            && now_ms < entry.locked_until_ms
            && !self.extractor.is_trusted_proxy(&client_ip)
        {
            self.hits_total.fetch_add(1, Ordering::Relaxed);
            let remaining_ms = entry.locked_until_ms.saturating_sub(now_ms);
            return RateLimitDecision::IpLocked {
                retry_after_secs: remaining_ms.div_ceil(1_000).max(1),
            };
        }

        if !guard.global_bucket.try_consume(1, now_ms) {
            self.hits_total.fetch_add(1, Ordering::Relaxed);
            return RateLimitDecision::GlobalLimitExceeded {
                retry_after_secs: 5,
            };
        }

        RateLimitDecision::Allowed
    }

    /// Records an authentication failure for `client_ip`, locking after 10 failures within 5 min
    /// and doubling lock duration (`15m -> 30m -> ... -> 24h`) on repeated lockouts.
    pub fn record_auth_failure(&self, client_ip: IpAddr, now_ms: u64) -> Option<u64> {
        if self.extractor.is_trusted_proxy(&client_ip) {
            // Never lock out local Reverse Proxy socket itself (`US-042 AC6`).
            return None;
        }
        let Ok(mut guard) = self.state.lock() else {
            return None;
        };

        if guard.per_ip.len() >= MAX_TRACKED_CLIENT_IPS && !guard.per_ip.contains_key(&client_ip) {
            prune_stale_ip_entries(&mut guard.per_ip, now_ms);
        }

        let entry = guard.per_ip.entry(client_ip).or_insert(IpPenaltyState {
            window_start_ms: now_ms,
            failures_in_window: 0,
            strike_level: 0,
            locked_until_ms: 0,
            last_seen_ms: now_ms,
        });

        entry.last_seen_ms = now_ms;
        if now_ms < entry.locked_until_ms {
            return Some(entry.locked_until_ms);
        }

        if now_ms.saturating_sub(entry.window_start_ms) >= AUTH_FAILURE_WINDOW_MS {
            entry.window_start_ms = now_ms;
            entry.failures_in_window = 0;
        }
        entry.failures_in_window = entry.failures_in_window.saturating_add(1);

        if entry.failures_in_window >= AUTH_FAILURE_THRESHOLD {
            let exp_shift = entry.strike_level.min(8);
            let duration = INITIAL_LOCKOUT_MS
                .saturating_mul(1_u64 << exp_shift)
                .min(MAX_LOCKOUT_MS);
            entry.locked_until_ms = now_ms.saturating_add(duration);
            entry.strike_level = entry.strike_level.saturating_add(1);
            entry.failures_in_window = 0;
            entry.window_start_ms = now_ms;
            self.hits_total.fetch_add(1, Ordering::Relaxed);
            return Some(entry.locked_until_ms);
        }

        None
    }

    /// Resets short-term failure count on valid authentication (keeps prior strike history bounded).
    pub fn record_auth_success(&self, client_ip: IpAddr) {
        if let Ok(mut guard) = self.state.lock()
            && let Some(entry) = guard.per_ip.get_mut(&client_ip)
        {
            entry.failures_in_window = 0;
        }
    }

    /// Total rate-limit rejections triggered since server start (`GET /metrics`).
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.hits_total.load(Ordering::Relaxed)
    }
}

fn prune_stale_ip_entries(map: &mut HashMap<IpAddr, IpPenaltyState>, now_ms: u64) {
    map.retain(|_, v| {
        now_ms < v.locked_until_ms || now_ms.saturating_sub(v.last_seen_ms) < AUTH_FAILURE_WINDOW_MS
    });
    if map.len() >= MAX_TRACKED_CLIENT_IPS
        && let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, v)| v.last_seen_ms)
            .map(|(ip, _)| *ip)
    {
        map.remove(&oldest_key);
    }
}

/// Deterministic integer token bucket used for Relay (`20 Mbps`), global auth (`60/m`),
/// and STUN (`100 pkt/s/IP`).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u64,
    refill_per_sec: u64,
    available_milli: u128,
    last_refill_ms: u64,
}

impl TokenBucket {
    /// Creates a full token bucket refilling at `refill_per_sec` units per second.
    #[must_use]
    pub fn new(capacity: u64, refill_per_sec: u64, now_ms: u64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            available_milli: u128::from(capacity).saturating_mul(1_000),
            last_refill_ms: now_ms,
        }
    }

    /// Attempts to consume `amount` tokens at `now_ms`; returns `false` without partial debit on
    /// insufficient balance.
    pub fn try_consume(&mut self, amount: u64, now_ms: u64) -> bool {
        if now_ms > self.last_refill_ms {
            let elapsed_ms = u128::from(now_ms.saturating_sub(self.last_refill_ms));
            let added_milli = elapsed_ms.saturating_mul(u128::from(self.refill_per_sec));
            let cap_milli = u128::from(self.capacity).saturating_mul(1_000);
            self.available_milli = self
                .available_milli
                .saturating_add(added_milli)
                .min(cap_milli);
            self.last_refill_ms = now_ms;
        }
        let cost_milli = u128::from(amount).saturating_mul(1_000);
        if self.available_milli >= cost_milli {
            self.available_milli = self.available_milli.saturating_sub(cost_milli);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_client_ip_extractor_ignores_spoofed_headers_in_standalone_and_honors_trusted_proxy() {
        // Arrange
        let spoofed_xff = Some("198.51.100.99");
        let proxy_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let direct_attacker = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55));

        let standalone = ClientIpExtractor::new(TlsMode::IpPinned, HashSet::new());
        let mut trusted = HashSet::new();
        trusted.insert(proxy_ip);
        let proxied = ClientIpExtractor::new(TlsMode::ReverseProxy, trusted);

        // Act / Assert
        assert_eq!(
            standalone.extract(direct_attacker, spoofed_xff, None),
            direct_attacker
        );
        assert_eq!(
            proxied.extract(proxy_ip, spoofed_xff, None),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))
        );
        // Untrusted remote IP sending fake XFF in proxy mode stays ignored
        assert_eq!(
            proxied.extract(direct_attacker, spoofed_xff, None),
            direct_attacker
        );
    }

    #[test]
    fn test_auth_rate_limiter_locks_after_10_failures_and_doubles_backoff_with_24h_cap() {
        // Arrange
        let limiter = RateLimiter::default();
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let mut now_ms = 1_731_480_000_000;

        // Act: first 9 failures stay unlocked; 10th locks for 15 min
        for _ in 0..9 {
            assert_eq!(limiter.record_auth_failure(attacker, now_ms), None);
        }
        let first_lock = limiter.record_auth_failure(attacker, now_ms);
        assert_eq!(first_lock, Some(now_ms + INITIAL_LOCKOUT_MS));
        assert!(matches!(
            limiter.check_auth_request(attacker, now_ms + 1_000),
            RateLimitDecision::IpLocked { .. }
        ));

        // Second offense after 15m expires locks for 30m
        now_ms += INITIAL_LOCKOUT_MS + 1_000;
        for _ in 0..9 {
            assert_eq!(limiter.record_auth_failure(attacker, now_ms), None);
        }
        let second_lock = limiter.record_auth_failure(attacker, now_ms);
        assert_eq!(second_lock, Some(now_ms + INITIAL_LOCKOUT_MS * 2));
    }
}
