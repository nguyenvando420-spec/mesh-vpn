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

/// Per-IP `/v1/relay` WebSocket handshake burst threshold per second (`50 req/s/IP`, `US-027 AC5`).
pub const RELAY_HANDSHAKES_PER_SEC_PER_IP: u32 = 50;

/// Audit-log cooldown per IP/event under brute-force flood (`60 s`, `US-042 AC4`).
pub const LOCKOUT_AUDIT_DEDUP_MS: u64 = 60_000;

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

    /// Resolves source IP for rate-limiting & audit logging using the configured boot `TlsMode`.
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
        self.extract_for_mode(self.tls_mode, peer_ip, x_forwarded_for, x_real_ip)
    }

    /// Resolves source IP honoring the effective `TlsMode` of the accepting listener (`HR-W21-05`).
    #[must_use]
    pub fn extract_for_mode(
        &self,
        listener_tls_mode: TlsMode,
        peer_ip: IpAddr,
        x_forwarded_for: Option<&str>,
        x_real_ip: Option<&str>,
    ) -> IpAddr {
        if listener_tls_mode != TlsMode::ReverseProxy || !self.trusted_proxies.contains(&peer_ip) {
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

    /// Returns `true` when `ip` belongs to the explicitly trusted reverse-proxy set under the
    /// configured boot `TlsMode`.
    #[must_use]
    pub fn is_trusted_proxy(&self, ip: &IpAddr) -> bool {
        self.is_trusted_proxy_for_mode(self.tls_mode, ip)
    }

    /// Returns `true` when `ip` belongs to `trusted_proxies` under `listener_tls_mode` (`HR-W21-05`).
    #[must_use]
    pub fn is_trusted_proxy_for_mode(&self, listener_tls_mode: TlsMode, ip: &IpAddr) -> bool {
        listener_tls_mode == TlsMode::ReverseProxy && self.trusted_proxies.contains(ip)
    }
}

#[derive(Debug, Clone)]
struct IpPenaltyState {
    window_start_ms: u64,
    failures_in_window: u32,
    relay_sec_start_ms: u64,
    relay_attempts_in_sec: u32,
    strike_level: u32,
    locked_until_ms: u64,
    last_audit_logged_ms: u64,
    last_seen_ms: u64,
}

/// Control/Relay endpoint class tracked in `mesh_control_rate_limited_requests_total` (`US-048`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitEndpoint {
    /// `POST /v1/auth/challenge`
    Challenge,
    /// `POST /v1/nodes/register`
    Register,
    /// `GET /v1/relay`
    Relay,
}

/// Registration attempt outcome exported via `mesh_control_registrations_total` (`US-048`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// Node registered or re-authenticated cleanly.
    Success,
    /// Pre-auth key, PoP signature, or auth validation failed.
    Unauthenticated,
    /// Node name/pubkey ownership collision rejected.
    Conflict,
    /// Rejected due to IP ban or global rate limiter.
    RateLimited,
}

/// Snapshot of rate-limiter and registration outcome counters for `/metrics` (`US-048`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateLimiterMetricsSnapshot {
    /// Total rate-limit rejections across all endpoints.
    pub total_hits: u64,
    /// Rate-limit rejections on `/v1/auth/challenge`.
    pub hits_challenge_total: u64,
    /// Rate-limit rejections on `/v1/nodes/register`.
    pub hits_register_total: u64,
    /// Rate-limit rejections on `/v1/relay`.
    pub hits_relay_total: u64,
    /// Registration outcomes: `success`.
    pub registrations_success_total: u64,
    /// Registration outcomes: `unauthenticated`.
    pub registrations_unauthenticated_total: u64,
    /// Registration outcomes: `conflict`.
    pub registrations_conflict_total: u64,
    /// Registration outcomes: `rate_limited`.
    pub registrations_rate_limited_total: u64,
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

/// Stateful rate limiter protecting Control & Relay endpoints (`US-042`, `US-027 AC5`).
#[derive(Debug)]
pub struct RateLimiter {
    extractor: ClientIpExtractor,
    state: Mutex<LimiterState>,
    hits_total: AtomicU64,
    hits_challenge_total: AtomicU64,
    hits_register_total: AtomicU64,
    hits_relay_total: AtomicU64,
    registrations_success_total: AtomicU64,
    registrations_unauthenticated_total: AtomicU64,
    registrations_conflict_total: AtomicU64,
    registrations_rate_limited_total: AtomicU64,
}

#[derive(Debug)]
struct LimiterState {
    per_ip: HashMap<IpAddr, IpPenaltyState>,
    global_bucket: TokenBucket,
    last_global_audit_logged_ms: u64,
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
                last_global_audit_logged_ms: 0,
            }),
            hits_total: AtomicU64::new(0),
            hits_challenge_total: AtomicU64::new(0),
            hits_register_total: AtomicU64::new(0),
            hits_relay_total: AtomicU64::new(0),
            registrations_success_total: AtomicU64::new(0),
            registrations_unauthenticated_total: AtomicU64::new(0),
            registrations_conflict_total: AtomicU64::new(0),
            registrations_rate_limited_total: AtomicU64::new(0),
        }
    }

    /// Resolves source client IP honoring `trusted_proxies` for the configured boot `TlsMode`.
    #[must_use]
    pub fn resolve_client_ip(
        &self,
        peer_ip: IpAddr,
        x_forwarded_for: Option<&str>,
        x_real_ip: Option<&str>,
    ) -> IpAddr {
        self.extractor.extract(peer_ip, x_forwarded_for, x_real_ip)
    }

    /// Resolves source client IP honoring `trusted_proxies` for the accepting listener's `TlsMode` (`HR-W21-05`).
    #[must_use]
    pub fn resolve_client_ip_for_mode(
        &self,
        listener_tls_mode: TlsMode,
        peer_ip: IpAddr,
        x_forwarded_for: Option<&str>,
        x_real_ip: Option<&str>,
    ) -> IpAddr {
        self.extractor
            .extract_for_mode(listener_tls_mode, peer_ip, x_forwarded_for, x_real_ip)
    }

    /// Checks ONLY whether `client_ip` is currently under an active auth penalty lockout
    /// without consuming unauthenticated challenge/register global bucket quota (`HR-W21-03`).
    #[must_use]
    pub fn check_ip_lockout_for_mode(
        &self,
        listener_tls_mode: TlsMode,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> Option<u64> {
        if self
            .extractor
            .is_trusted_proxy_for_mode(listener_tls_mode, &client_ip)
        {
            return None;
        }
        let Ok(guard) = self.state.lock() else {
            return None;
        };
        let entry = guard.per_ip.get(&client_ip)?;
        if now_ms < entry.locked_until_ms {
            let remaining_ms = entry.locked_until_ms.saturating_sub(now_ms);
            Some(remaining_ms.div_ceil(1_000).max(1))
        } else {
            None
        }
    }

    /// Checks whether a challenge or registration request from `client_ip` is permitted.
    pub fn check_auth_request(&self, client_ip: IpAddr, now_ms: u64) -> RateLimitDecision {
        self.check_endpoint_request(RateLimitEndpoint::Challenge, client_ip, now_ms)
    }

    /// Checks whether a request on `endpoint` from `client_ip` is permitted (`US-042`, `US-027 AC5`).
    pub fn check_endpoint_request(
        &self,
        endpoint: RateLimitEndpoint,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> RateLimitDecision {
        self.check_endpoint_request_for_mode(self.extractor.tls_mode, endpoint, client_ip, now_ms)
    }

    /// Checks whether a request on `endpoint` from `client_ip` is permitted for `listener_tls_mode` (`HR-W21-05`).
    pub fn check_endpoint_request_for_mode(
        &self,
        listener_tls_mode: TlsMode,
        endpoint: RateLimitEndpoint,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> RateLimitDecision {
        let Ok(mut guard) = self.state.lock() else {
            return RateLimitDecision::Allowed;
        };

        if let Some(entry) = guard.per_ip.get(&client_ip)
            && now_ms < entry.locked_until_ms
            && !self
                .extractor
                .is_trusted_proxy_for_mode(listener_tls_mode, &client_ip)
        {
            self.record_endpoint_hit(endpoint);
            let remaining_ms = entry.locked_until_ms.saturating_sub(now_ms);
            return RateLimitDecision::IpLocked {
                retry_after_secs: remaining_ms.div_ceil(1_000).max(1),
            };
        }

        if endpoint == RateLimitEndpoint::Relay {
            if self
                .extractor
                .is_trusted_proxy_for_mode(listener_tls_mode, &client_ip)
            {
                return RateLimitDecision::Allowed;
            }
            if guard.per_ip.len() >= MAX_TRACKED_CLIENT_IPS
                && !guard.per_ip.contains_key(&client_ip)
            {
                prune_stale_ip_entries(&mut guard.per_ip, now_ms);
            }
            let entry = guard.per_ip.entry(client_ip).or_insert(IpPenaltyState {
                window_start_ms: now_ms,
                failures_in_window: 0,
                relay_sec_start_ms: now_ms,
                relay_attempts_in_sec: 0,
                strike_level: 0,
                locked_until_ms: 0,
                last_audit_logged_ms: 0,
                last_seen_ms: now_ms,
            });
            entry.last_seen_ms = now_ms;
            if now_ms.saturating_sub(entry.relay_sec_start_ms) >= 1_000 {
                entry.relay_sec_start_ms = now_ms;
                entry.relay_attempts_in_sec = 0;
            }
            entry.relay_attempts_in_sec = entry.relay_attempts_in_sec.saturating_add(1);
            if entry.relay_attempts_in_sec > RELAY_HANDSHAKES_PER_SEC_PER_IP {
                let exp_shift = entry.strike_level.min(8);
                let duration = INITIAL_LOCKOUT_MS
                    .saturating_mul(1_u64 << exp_shift)
                    .min(MAX_LOCKOUT_MS);
                entry.locked_until_ms = now_ms.saturating_add(duration);
                entry.strike_level = entry.strike_level.saturating_add(1);
                self.record_endpoint_hit(RateLimitEndpoint::Relay);
                return RateLimitDecision::IpLocked {
                    retry_after_secs: duration.div_ceil(1_000).max(1),
                };
            }
            return RateLimitDecision::Allowed;
        }

        if !guard.global_bucket.try_consume(1, now_ms) {
            self.record_endpoint_hit(endpoint);
            return RateLimitDecision::GlobalLimitExceeded {
                retry_after_secs: 5,
            };
        }

        RateLimitDecision::Allowed
    }

    fn record_endpoint_hit(&self, endpoint: RateLimitEndpoint) {
        self.hits_total.fetch_add(1, Ordering::Relaxed);
        match endpoint {
            RateLimitEndpoint::Challenge => {
                self.hits_challenge_total.fetch_add(1, Ordering::Relaxed);
            }
            RateLimitEndpoint::Register => {
                self.hits_register_total.fetch_add(1, Ordering::Relaxed);
            }
            RateLimitEndpoint::Relay => {
                self.hits_relay_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records a registration attempt outcome for Prometheus telemetry (`US-048`).
    pub fn record_registration_outcome(&self, outcome: RegistrationOutcome) {
        match outcome {
            RegistrationOutcome::Success => {
                self.registrations_success_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RegistrationOutcome::Unauthenticated => {
                self.registrations_unauthenticated_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RegistrationOutcome::Conflict => {
                self.registrations_conflict_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            RegistrationOutcome::RateLimited => {
                self.registrations_rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Rate-limits audit-event writes per IP (`>= 60 s`) so 1000 req/s floods cannot saturate CPU/DB.
    pub fn should_emit_lockout_audit(&self, client_ip: IpAddr, now_ms: u64) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return false;
        };
        let Some(entry) = guard.per_ip.get_mut(&client_ip) else {
            return true;
        };
        if now_ms.saturating_sub(entry.last_audit_logged_ms) >= LOCKOUT_AUDIT_DEDUP_MS
            || entry.last_audit_logged_ms == 0
        {
            entry.last_audit_logged_ms = now_ms;
            true
        } else {
            false
        }
    }

    /// Rate-limits global 429 audit-event writes (`>= 60 s`) under DoS surge (`US-042 AC4`).
    pub fn should_emit_global_limit_audit(&self, now_ms: u64) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return false;
        };
        if now_ms.saturating_sub(guard.last_global_audit_logged_ms) >= LOCKOUT_AUDIT_DEDUP_MS
            || guard.last_global_audit_logged_ms == 0
        {
            guard.last_global_audit_logged_ms = now_ms;
            true
        } else {
            false
        }
    }

    /// Records an authentication failure for `client_ip`, locking after 10 failures within 5 min
    /// and doubling lock duration (`15m -> 30m -> ... -> 24h`) on repeated lockouts.
    pub fn record_auth_failure(&self, client_ip: IpAddr, now_ms: u64) -> Option<u64> {
        self.record_auth_failure_for_mode(self.extractor.tls_mode, client_ip, now_ms)
    }

    /// Records an authentication failure honoring `listener_tls_mode` when checking whether
    /// `client_ip` is an exempt trusted reverse proxy (`HR-W21-05`).
    pub fn record_auth_failure_for_mode(
        &self,
        listener_tls_mode: TlsMode,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> Option<u64> {
        if self
            .extractor
            .is_trusted_proxy_for_mode(listener_tls_mode, &client_ip)
        {
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
            relay_sec_start_ms: now_ms,
            relay_attempts_in_sec: 0,
            strike_level: 0,
            locked_until_ms: 0,
            last_audit_logged_ms: 0,
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

    /// Full labeled counters exported to Prometheus `/metrics` (`US-048`).
    #[must_use]
    pub fn metrics_snapshot(&self) -> RateLimiterMetricsSnapshot {
        RateLimiterMetricsSnapshot {
            total_hits: self.hits_total.load(Ordering::Relaxed),
            hits_challenge_total: self.hits_challenge_total.load(Ordering::Relaxed),
            hits_register_total: self.hits_register_total.load(Ordering::Relaxed),
            hits_relay_total: self.hits_relay_total.load(Ordering::Relaxed),
            registrations_success_total: self.registrations_success_total.load(Ordering::Relaxed),
            registrations_unauthenticated_total: self
                .registrations_unauthenticated_total
                .load(Ordering::Relaxed),
            registrations_conflict_total: self.registrations_conflict_total.load(Ordering::Relaxed),
            registrations_rate_limited_total: self
                .registrations_rate_limited_total
                .load(Ordering::Relaxed),
        }
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

    /// Refills accrued tokens up to `capacity` at `now_ms`.
    pub fn refill(&mut self, now_ms: u64) {
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
    }

    /// Refills and returns `true` when at least `amount` tokens are available without debiting.
    pub fn can_consume(&mut self, amount: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        let cost_milli = u128::from(amount).saturating_mul(1_000);
        self.available_milli >= cost_milli
    }

    /// Attempts to consume `amount` tokens at `now_ms`; returns `false` without partial debit on
    /// insufficient balance.
    pub fn try_consume(&mut self, amount: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
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

        // Repeated strikes cap at 24h (`MAX_LOCKOUT_MS`)
        for _ in 0..8 {
            now_ms += MAX_LOCKOUT_MS + 1_000;
            for _ in 0..AUTH_FAILURE_THRESHOLD {
                let _unused = limiter.record_auth_failure(attacker, now_ms);
            }
        }
        now_ms += MAX_LOCKOUT_MS + 1_000;
        for _ in 0..9 {
            assert_eq!(limiter.record_auth_failure(attacker, now_ms), None);
        }
        let capped_lock = limiter.record_auth_failure(attacker, now_ms);
        assert_eq!(capped_lock, Some(now_ms + MAX_LOCKOUT_MS));
    }

    #[test]
    fn test_rate_limiter_trusted_proxy_never_locked_global_cap_and_relay_burst() {
        // Arrange
        let proxy_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut trusted = HashSet::new();
        trusted.insert(proxy_ip);
        let limiter = RateLimiter::new(ClientIpExtractor::new(TlsMode::ReverseProxy, trusted));
        let now_ms = 1_762_958_200_000_u64;

        // Multi-hop XFF resolves right-most non-trusted client IP
        let extracted =
            limiter.resolve_client_ip(proxy_ip, Some("10.0.0.5, 203.0.113.44, 127.0.0.1"), None);
        assert_eq!(extracted, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44)));

        // Trusted proxy itself is never banned
        for _ in 0..25 {
            assert_eq!(limiter.record_auth_failure(proxy_ip, now_ms), None);
        }
        assert_eq!(
            limiter.check_endpoint_request(RateLimitEndpoint::Challenge, proxy_ip, now_ms),
            RateLimitDecision::Allowed
        );

        // Relay handshake burst (> 50/s) temporarily bans abusive non-trusted client IP
        let flood_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
        for _ in 0..RELAY_HANDSHAKES_PER_SEC_PER_IP {
            assert_eq!(
                limiter.check_endpoint_request(RateLimitEndpoint::Relay, flood_ip, now_ms),
                RateLimitDecision::Allowed
            );
        }
        assert!(matches!(
            limiter.check_endpoint_request(RateLimitEndpoint::Relay, flood_ip, now_ms),
            RateLimitDecision::IpLocked { .. }
        ));
        assert!(limiter.metrics_snapshot().hits_relay_total >= 1);

        // Global registration/challenge cap blocks once 60-token burst exhausted
        let clean_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        for _ in 0..(GLOBAL_AUTH_REQ_PER_MIN - 1) {
            assert_eq!(
                limiter.check_endpoint_request(RateLimitEndpoint::Register, clean_ip, now_ms),
                RateLimitDecision::Allowed
            );
        }
        assert!(matches!(
            limiter.check_endpoint_request(RateLimitEndpoint::Register, clean_ip, now_ms),
            RateLimitDecision::GlobalLimitExceeded { .. }
        ));
        assert_eq!(limiter.metrics_snapshot().hits_register_total, 1);
    }
}
