//! Embedded RFC 5389 UDP STUN responder enforcing `100 pkt/s/IP` DoS rate limiting (`US-019`,
//! `WP-S1-01`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult, Clock};
use mesh_proto::stun::{STUN_BINDING_REQUEST, encode_binding_success_response, parse_stun_packet};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::rate_limit::TokenBucket;

const MAX_STUN_TRACKED_IPS: usize = 16_384;
const STUN_IDLE_PRUNE_MS: u64 = 120_000;

/// Per-source-IP token bucket table protecting the embedded UDP STUN responder (`100 pkt/s/IP`).
#[derive(Debug)]
pub struct StunIpRateLimiter {
    pps_limit: u64,
    buckets: HashMap<IpAddr, (TokenBucket, u64)>,
}

impl StunIpRateLimiter {
    /// Creates a new STUN rate limiter capped at `pps_limit` requests per source IP per second.
    #[must_use]
    pub fn new(pps_limit: u32) -> Self {
        Self {
            pps_limit: u64::from(pps_limit.max(1)),
            buckets: HashMap::new(),
        }
    }

    /// Returns `true` when `ip` stays within its `pps_limit` budget at `now_ms`.
    pub fn allow(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        if self.buckets.len() >= MAX_STUN_TRACKED_IPS && !self.buckets.contains_key(&ip) {
            self.buckets
                .retain(|_, (_, last_ms)| now_ms.saturating_sub(*last_ms) < STUN_IDLE_PRUNE_MS);
            if self.buckets.len() >= MAX_STUN_TRACKED_IPS
                && let Some(oldest_ip) = self
                    .buckets
                    .iter()
                    .min_by_key(|(_, (_, last_ms))| *last_ms)
                    .map(|(k, _)| *k)
            {
                self.buckets.remove(&oldest_ip);
            }
        }

        let limit = self.pps_limit;
        let (bucket, last_ms) = self
            .buckets
            .entry(ip)
            .or_insert_with(|| (TokenBucket::new(limit, limit, now_ms), now_ms));
        *last_ms = now_ms;
        bucket.try_consume(1, now_ms)
    }
}

/// Runtime observability and health state shared by [`run_stun_socket_loop`].
#[derive(Debug)]
pub struct StunServiceState {
    healthy: AtomicBool,
    requests_total: AtomicU64,
    dropped_rate_limited_total: AtomicU64,
}

impl Default for StunServiceState {
    fn default() -> Self {
        Self::new()
    }
}

impl StunServiceState {
    /// Creates an inactive/healthy tracker prior to socket bind.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            healthy: AtomicBool::new(false),
            requests_total: AtomicU64::new(0),
            dropped_rate_limited_total: AtomicU64::new(0),
        }
    }

    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "stun_service:ready"
    }

    /// Marks the UDP STUN socket as healthy/unhealthy for `/readyz`.
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::SeqCst);
    }

    /// Returns `true` when the UDP STUN socket loop is bound and serving cleanly.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Total valid STUN Binding Responses sent.
    #[must_use]
    pub fn requests_total(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }

    /// Total STUN datagrams dropped due to per-IP rate limiting.
    #[must_use]
    pub fn dropped_rate_limited_total(&self) -> u64 {
        self.dropped_rate_limited_total.load(Ordering::Relaxed)
    }
}

/// Processes a single STUN datagram, returning an RFC 5389 Binding Success Response if valid & allowed.
#[must_use]
pub fn process_stun_datagram(
    payload: &[u8],
    peer_addr: SocketAddr,
    now_ms: u64,
    limiter: &mut StunIpRateLimiter,
    metrics: &StunServiceState,
) -> Option<Vec<u8>> {
    let Ok(msg) = parse_stun_packet(payload) else {
        return None;
    };
    if msg.msg_type != STUN_BINDING_REQUEST {
        return None;
    }
    if !limiter.allow(peer_addr.ip(), now_ms) {
        metrics
            .dropped_rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
        return None;
    }
    metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    Some(encode_binding_success_response(msg.tx_id, peer_addr))
}

/// Binds a non-privileged UDP socket at `bind_addr`.
pub async fn bind_stun_udp_socket(bind_addr: SocketAddr) -> AppResult<Arc<UdpSocket>> {
    let sock = UdpSocket::bind(bind_addr).await.map_err(|err| {
        AppError::conflict(format!(
            "failed binding UDP STUN socket on {bind_addr}: {err}"
        ))
    })?;
    Ok(Arc::new(sock))
}

/// Runs the bounded `[u8; 2048]` RFC 5389 UDP STUN loop until `cancel` is triggered.
pub async fn run_stun_socket_loop(
    socket: Arc<UdpSocket>,
    pps_limit_per_ip: u32,
    clock: Arc<dyn Clock>,
    state: Arc<StunServiceState>,
    cancel: CancellationToken,
) {
    let mut limiter = StunIpRateLimiter::new(pps_limit_per_ip);
    let mut buf = [0_u8; MAX_FRAME_SIZE];
    state.set_healthy(true);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                break;
            }
            recv_res = socket.recv_from(&mut buf) => {
                match recv_res {
                    Ok((len, peer_addr)) => {
                        let Some(slice) = buf.get(..len) else {
                            continue;
                        };
                        let now_ms = clock.now_unix_ms();
                        if let Some(reply) = process_stun_datagram(slice, peer_addr, now_ms, &mut limiter, &state)
                            && let Err(err) = socket.send_to(&reply, peer_addr).await
                        {
                            tracing::debug!(
                                component = "stun_service",
                                event = "stun_send_error",
                                error = %err,
                                "failed sending STUN binding response"
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            component = "stun_service",
                            event = "stun_recv_transient_error",
                            error = %err,
                            "STUN UDP socket receive transient error; backing off 20ms"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
            }
        }
    }

    state.set_healthy(false);
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use mesh_proto::stun::{
        STUN_BINDING_SUCCESS_RESPONSE, encode_binding_request, parse_stun_packet,
    };

    use super::{StunIpRateLimiter, StunServiceState, process_stun_datagram};

    #[test]
    fn test_stun_binding_response_and_100_pps_per_ip_limit() {
        // Arrange
        let mut limiter = StunIpRateLimiter::new(100);
        let state = StunServiceState::new();
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 54321);
        let other_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 54322);
        let tx_id = [0x99_u8; 12];
        let req = encode_binding_request(tx_id);
        let now_ms = 1_762_958_151_000_u64;

        // Act: 100 packets pass cleanly, 101st in same millisecond drops; other IP unaffected
        for i in 0..100 {
            let reply = process_stun_datagram(&req, peer, now_ms, &mut limiter, &state)
                .expect("within 100 pps");
            if i == 0 {
                let parsed = parse_stun_packet(&reply).expect("valid binding response");
                assert_eq!(parsed.msg_type, STUN_BINDING_SUCCESS_RESPONSE);
                assert_eq!(parsed.tx_id, tx_id);
                assert_eq!(parsed.xor_mapped_addr, Some(peer));
                assert!(parsed.has_valid_fingerprint);
            }
        }
        assert!(process_stun_datagram(&req, peer, now_ms, &mut limiter, &state).is_none());
        assert!(process_stun_datagram(&req, other_peer, now_ms, &mut limiter, &state).is_some());
        assert_eq!(state.dropped_rate_limited_total(), 1);
    }
}
