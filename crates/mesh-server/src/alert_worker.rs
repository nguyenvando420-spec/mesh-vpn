//! Background operational alert evaluator, automatic node expiry / emergency compaction
//! sweeper, and rate-limited (`1/hour/condition` + recovery) webhook dispatcher (`US-049`, `WP-S1-01`).

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mesh_core::Clock;
use mesh_proto::control::TerminationReason;
use mesh_proto::relay::RelayNoticeCode;
use mesh_store::ControlStore;
use mesh_sys::{SysResult, filesystem_usage_percent};
use serde::Serialize;
use tokio::time::{interval, sleep};
use tokio_util::sync::CancellationToken;

use crate::acme::AcmeManager;
use crate::netmap_hub::NetmapHub;
use crate::obs_service::{ObsAppState, evaluate_readiness};
use crate::relay_hub::RelayHub;

const ALERT_REPEAT_COOLDOWN_MS: u64 = 3_600 * 1_000;
const READYZ_DOWN_THRESHOLD_MS: u64 = 120_000;
const NODE_KEY_EXPIRING_ALERT_MS: u64 = 7 * 86_400 * 1_000;
const WORKER_TICK_INTERVAL_SECS: u64 = 25;

/// Canonical alert conditions monitored by `mesh-server` (`US-049`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertCondition {
    /// `/readyz` failed continuously for more than 2 minutes.
    ReadyzDown,
    /// Server TLS certificate expires within 14 days.
    CertExpiring,
    /// Relay throughput utilization exceeds configured threshold (`80%`).
    RelaySaturation,
    /// State/backup storage footprint exceeds configured threshold (`85%`).
    DiskUsageHigh,
    /// One or more active node keys expire within 7 days.
    NodeKeyExpiring,
}

#[derive(Debug, Serialize)]
struct WebhookAlertPayload {
    condition: AlertCondition,
    state: &'static str,
    summary: String,
    timestamp_at_ms: u64,
}

#[derive(Debug, Default)]
struct AlertTracker {
    readyz_down_since_ms: Option<u64>,
    last_relay_sample_ms: Option<u64>,
    last_relay_forwarded_bytes: u64,
    last_relay_throttled_packets: u64,
    last_notified_ms: HashMap<AlertCondition, u64>,
    currently_firing: HashMap<AlertCondition, String>,
}

const DEFAULT_DISK_ALERT_THRESHOLD_PCT: u8 = 85;
const DISK_ALERT_HYSTERESIS_PCT: u8 = 5;

type DiskUsageProbe = Arc<dyn Fn(&Path) -> SysResult<u8> + Send + Sync>;

/// Evaluates operational health conditions and emits rate-limited webhook & structured alerts.
pub struct AlertEvaluator {
    webhook_url: Option<String>,
    relay_threshold_pct: u8,
    relay_global_bps: u64,
    disk_threshold_pct: u8,
    disk_usage_probe: DiskUsageProbe,
    tracker: Mutex<AlertTracker>,
}

impl fmt::Debug for AlertEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlertEvaluator")
            .field("webhook_url", &self.webhook_url)
            .field("relay_threshold_pct", &self.relay_threshold_pct)
            .field("relay_global_bps", &self.relay_global_bps)
            .field("disk_threshold_pct", &self.disk_threshold_pct)
            .field("tracker", &self.tracker)
            .finish_non_exhaustive()
    }
}

impl AlertEvaluator {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "alert_worker:ready"
    }

    /// Creates an [`AlertEvaluator`] using configured webhook target and thresholds.
    #[must_use]
    pub fn new(
        webhook_url: Option<String>,
        relay_threshold_pct: u8,
        relay_global_bps: u64,
    ) -> Self {
        Self {
            webhook_url,
            relay_threshold_pct,
            relay_global_bps: relay_global_bps.max(1),
            disk_threshold_pct: DEFAULT_DISK_ALERT_THRESHOLD_PCT,
            disk_usage_probe: Arc::new(filesystem_usage_percent),
            tracker: Mutex::new(AlertTracker::default()),
        }
    }

    /// Overrides the disk usage firing threshold percentage (default `85%`, recovers `< threshold - 5%`).
    #[must_use]
    pub fn with_disk_threshold(mut self, disk_threshold_pct: u8) -> Self {
        self.disk_threshold_pct = disk_threshold_pct;
        self
    }

    /// Overrides the OS disk utilization probe function for deterministic unit testing.
    #[must_use]
    pub fn with_disk_usage_probe<F>(mut self, probe: F) -> Self
    where
        F: Fn(&Path) -> SysResult<u8> + Send + Sync + 'static,
    {
        self.disk_usage_probe = Arc::new(probe);
        self
    }

    /// Configured optional alert webhook destination URL.
    #[must_use]
    pub fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }

    /// Evaluates active alert predicates at `now_ms`, returning `(condition, is_firing, summary)` events
    /// that passed the 1/hour/condition rate limit or transitioned to `[RESOLVED]`.
    pub fn evaluate_tick(
        &self,
        obs_state: &ObsAppState,
        acme: &AcmeManager,
        now_ms: u64,
    ) -> Vec<(AlertCondition, bool, String)> {
        let mut active: HashMap<AlertCondition, String> = HashMap::new();
        let readiness = evaluate_readiness(obs_state);

        if let Ok(mut guard) = self.tracker.lock() {
            if readiness.status != "ready" {
                let since = *guard.readyz_down_since_ms.get_or_insert(now_ms);
                if now_ms.saturating_sub(since) > READYZ_DOWN_THRESHOLD_MS {
                    active.insert(
                        AlertCondition::ReadyzDown,
                        readiness
                            .reason
                            .unwrap_or_else(|| "/readyz unhealthy > 2m".to_owned()),
                    );
                }
            } else {
                guard.readyz_down_since_ms = None;
            }
        }

        if acme.cert_expires_within_14_days(now_ms) {
            active.insert(
                AlertCondition::CertExpiring,
                "server TLS certificate expires within 14 days".to_owned(),
            );
        }

        let relay_snap = obs_state.relay_hub.metrics_snapshot();
        if let Ok(mut guard) = self.tracker.lock() {
            if let Some(prev_ms) = guard.last_relay_sample_ms
                && now_ms > prev_ms
            {
                let elapsed_ms = now_ms.saturating_sub(prev_ms).max(1);
                let delta_bytes = relay_snap
                    .forwarded_bytes_total
                    .saturating_sub(guard.last_relay_forwarded_bytes);
                let observed_bps = delta_bytes.saturating_mul(1_000) / elapsed_ms;
                let threshold_bps = self
                    .relay_global_bps
                    .saturating_mul(u64::from(self.relay_threshold_pct))
                    / 100;
                let throttled_delta = relay_snap
                    .throttled_packets_total
                    .saturating_sub(guard.last_relay_throttled_packets);
                if (threshold_bps > 0 && observed_bps >= threshold_bps) || throttled_delta > 0 {
                    active.insert(
                        AlertCondition::RelaySaturation,
                        format!(
                            "relay throughput {observed_bps} B/s >= {}% of {} B/s cap (throttled +{throttled_delta})",
                            self.relay_threshold_pct, self.relay_global_bps
                        ),
                    );
                }
            }
            guard.last_relay_sample_ms = Some(now_ms);
            guard.last_relay_forwarded_bytes = relay_snap.forwarded_bytes_total;
            guard.last_relay_throttled_packets = relay_snap.throttled_packets_total;
        }

        if let Ok(nodes) = obs_state.store.list_nodes() {
            let expiring_soon = nodes.iter().any(|n| {
                n.status == mesh_store::NodeStatus::Active
                    && n.key_expires_at_ms > now_ms
                    && n.key_expires_at_ms.saturating_sub(now_ms) <= NODE_KEY_EXPIRING_ALERT_MS
            });
            if expiring_soon {
                active.insert(
                    AlertCondition::NodeKeyExpiring,
                    "active node key expires within 7 days".to_owned(),
                );
            }
        }

        let disk_fire_pct = self.disk_threshold_pct.clamp(10, 100);
        let disk_clear_pct = disk_fire_pct.saturating_sub(DISK_ALERT_HYSTERESIS_PCT);
        let was_disk_firing = self.tracker.lock().ok().is_some_and(|g| {
            g.currently_firing
                .contains_key(&AlertCondition::DiskUsageHigh)
        });
        match (self.disk_usage_probe)(&obs_state.store.config().db_path) {
            Ok(usage_pct) => {
                if usage_pct >= disk_fire_pct || (was_disk_firing && usage_pct >= disk_clear_pct) {
                    active.insert(
                        AlertCondition::DiskUsageHigh,
                        format!(
                            "state volume disk usage {usage_pct}% >= {disk_fire_pct}% threshold"
                        ),
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    component = "alert_worker",
                    event = "disk_usage_probe_failed",
                    error = %err,
                    "failed probing filesystem usage for db_path"
                );
            }
        }

        let Ok(mut guard) = self.tracker.lock() else {
            return Vec::new();
        };

        let mut events = Vec::new();
        for (cond, summary) in &active {
            let should_send = match guard.last_notified_ms.get(cond) {
                Some(&last_ms) => now_ms.saturating_sub(last_ms) >= ALERT_REPEAT_COOLDOWN_MS,
                None => true,
            };
            if should_send {
                guard.last_notified_ms.insert(*cond, now_ms);
                guard.currently_firing.insert(*cond, summary.clone());
                events.push((*cond, true, summary.clone()));
            }
        }

        let resolved: Vec<AlertCondition> = guard
            .currently_firing
            .keys()
            .filter(|c| !active.contains_key(*c))
            .copied()
            .collect();
        for cond in resolved {
            guard.currently_firing.remove(&cond);
            guard.last_notified_ms.remove(&cond);
            events.push((cond, false, format!("[RESOLVED] {cond:?} recovered")));
        }

        events
    }
}

/// Shared dependencies for the background maintenance loop.
#[derive(Clone, Debug)]
pub struct MaintenanceContext {
    /// Control ACID store handle.
    pub store: Arc<ControlStore>,
    /// ACME / IP-Pinned certificate lifecycle manager.
    pub acme: Arc<AcmeManager>,
    /// Control WebSocket snapshot/heartbeat hub.
    pub netmap_hub: Arc<NetmapHub>,
    /// Blind Relay hub.
    pub relay_hub: Arc<RelayHub>,
    /// Shared observability state used by readiness & alert checks.
    pub obs_state: ObsAppState,
    /// Stateful alert deduplication evaluator.
    pub evaluator: Arc<AlertEvaluator>,
    /// Graceful shutdown signal.
    pub cancel: CancellationToken,
}

/// Runs periodic maintenance (control heartbeats without version bumps, emergency compaction,
/// expired node sweeps, ACME checks, migration cutovers, and webhook alert delivery).
pub async fn run_background_maintenance(ctx: MaintenanceContext) {
    let MaintenanceContext {
        store,
        acme,
        netmap_hub,
        relay_hub,
        obs_state,
        evaluator,
        cancel,
    } = ctx;
    let mut ticker = interval(Duration::from_secs(WORKER_TICK_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let now_ms = store.clock().now_unix_ms();
                let _ = netmap_hub.broadcast_heartbeats(now_ms);
                obs_state.listeners.check_migration_cutover();

                if store.is_disk_degraded()
                    && let Err(err) = store.try_compact_emergency_revocations()
                {
                    tracing::debug!(
                        component = "alert_worker",
                        event = "compaction_deferred",
                        error = %err,
                        "deferring emergency compaction until storage recovers"
                    );
                }

                if let Ok(expired) = store.sweep_expired_nodes() {
                    for outcome in expired {
                        netmap_hub.terminate_node_stream(
                            outcome.node_id,
                            TerminationReason::NodeKeyExpired,
                            "node key expired",
                            now_ms,
                        );
                        relay_hub.disconnect_node(outcome.node_id, RelayNoticeCode::NodeKeyExpired);
                        if outcome.must_disconnect_all_peers_to_reauth {
                            netmap_hub.close_all_streams_for_reauth();
                            relay_hub.close_all_sessions();
                        } else if let Some(ver) = outcome.netmap_version
                            && let Err(err) = netmap_hub.broadcast_snapshot(ver)
                        {
                            tracing::warn!(
                                component = "alert_worker",
                                event = "expiry_broadcast_failed",
                                error = %err,
                                "failed broadcasting netmap snapshot after node key expiry"
                            );
                        }
                    }
                }

                if let Err(err) = acme.run_renewal_check().await {
                    tracing::warn!(
                        component = "alert_worker",
                        event = "acme_renewal_failed",
                        error = %err,
                        "ACME renewal check deferred"
                    );
                }

                let events = evaluator.evaluate_tick(&obs_state, &acme, now_ms);
                if let Some(url) = evaluator.webhook_url() {
                    for (cond, is_firing, summary) in events {
                        let payload = WebhookAlertPayload {
                            condition: cond,
                            state: if is_firing { "firing" } else { "resolved" },
                            summary,
                            timestamp_at_ms: now_ms,
                        };
                        dispatch_webhook_with_retries(url, &payload, &cancel).await;
                    }
                }
            }
        }
    }
    let _ = Arc::strong_count(&store) as u64;
    let _: Option<&dyn Clock> = Some(store.clock());
}

async fn dispatch_webhook_with_retries(
    url: &str,
    payload: &WebhookAlertPayload,
    cancel: &CancellationToken,
) {
    crate::acme::ensure_rustls_ring_provider();
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    else {
        return;
    };
    for attempt in 0_u32..3 {
        if cancel.is_cancelled() {
            return;
        }
        if let Ok(resp) = client.post(url).json(payload).send().await
            && resp.status().is_success()
        {
            return;
        }
        let backoff_secs = 1_u64 << attempt;
        tokio::select! {
            () = cancel.cancelled() => return,
            () = sleep(Duration::from_secs(backoff_secs)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};

    use mesh_core::FakeClock;
    use mesh_store::{ControlStore, ControlStoreConfig};
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{AlertCondition, AlertEvaluator};
    use crate::acme::AcmeManager;
    use crate::config::ServerConfig;
    use crate::control_handlers::{ControlAppState, PendingChallengeStore};
    use crate::listener_set::ListenerSet;
    use crate::netmap_hub::NetmapHub;
    use crate::obs_service::ObsAppState;
    use crate::rate_limit::{ClientIpExtractor, RateLimiter};
    use crate::relay_hub::RelayHub;

    #[tokio::test]
    async fn test_alert_rate_limiting_and_recovery_notification() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let start_ms = 1_762_958_151_000_u64;
        let clock = Arc::new(FakeClock::new(start_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock.clone(),
            )
            .expect("open store"),
        );
        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: 0,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: 0,
            ..ServerConfig::default()
        });
        // Pick free ephemeral ports because ServerConfig::validate requires non-zero ports
        let tcp_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let udp_probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let free_tcp = tcp_probe.local_addr().expect("addr").port();
        let free_udp = udp_probe.local_addr().expect("addr").port();
        drop((tcp_probe, udp_probe));
        let cfg = Arc::new(ServerConfig {
            control_tcp_port: free_tcp,
            stun_udp_port: free_udp,
            ..(*cfg).clone()
        });

        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let netmap_hub = Arc::new(NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let challenges = Arc::new(PendingChallengeStore::new());
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let ctrl_state = ControlAppState {
            config: cfg,
            trusted_proxies: Arc::new(Default::default()),
            store: store.clone(),
            rate_limiter: rate_limiter.clone(),
            challenges: challenges.clone(),
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = ListenerSet::bind_and_start(ctrl_state, acme.clone())
            .await
            .expect("bind listeners");
        let obs_state = ObsAppState {
            store,
            listeners,
            netmap_hub,
            relay_hub,
            challenges,
            rate_limiter,
        };
        let evaluator = AlertEvaluator::new(None, 80, 50_000_000).with_disk_usage_probe(|_| Ok(25));

        // Act: advance clock to 80d (cert expires in 10d < 14d) -> fires once; within 1h suppressed
        let t1 = start_ms + 80 * 86_400 * 1_000;
        let ev1 = evaluator.evaluate_tick(&obs_state, &acme, t1);
        assert_eq!(ev1.len(), 1);
        let first_event = ev1.first().expect("expected one alert");
        assert_eq!(first_event.0, AlertCondition::CertExpiring);
        assert!(first_event.1);

        let ev2 = evaluator.evaluate_tick(&obs_state, &acme, t1 + 60_000);
        assert!(ev2.is_empty());

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn test_relay_saturation_alert_fires_and_recovers() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let start_ms = 1_762_958_151_000_u64;
        let clock = Arc::new(FakeClock::new(start_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock,
            )
            .expect("open store"),
        );
        let tcp_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let udp_probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let free_tcp = tcp_probe.local_addr().expect("addr").port();
        let free_udp = udp_probe.local_addr().expect("addr").port();
        drop((tcp_probe, udp_probe));
        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: free_tcp,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: free_udp,
            relay_bytes_per_sec: 1_000_000,
            relay_global_bytes_per_sec: 100,
            ..ServerConfig::default()
        });
        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let netmap_hub = Arc::new(NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let challenges = Arc::new(PendingChallengeStore::new());
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let ctrl_state = ControlAppState {
            config: cfg,
            trusted_proxies: Arc::new(Default::default()),
            store: store.clone(),
            rate_limiter: rate_limiter.clone(),
            challenges: challenges.clone(),
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = ListenerSet::bind_and_start(ctrl_state, acme.clone())
            .await
            .expect("bind listeners");
        let obs_state = ObsAppState {
            store,
            listeners,
            netmap_hub,
            relay_hub: relay_hub.clone(),
            challenges,
            rate_limiter,
        };
        let evaluator = AlertEvaluator::new(None, 80, 100).with_disk_usage_probe(|_| Ok(25));

        let kp_a = mesh_crypto::NodeKeypair::generate();
        let kp_b = mesh_crypto::NodeKeypair::generate();
        let node_a = mesh_core::NodeId::new_v7(start_ms);
        let node_b = mesh_core::NodeId::new_v7(start_ms + 1);
        let _ha = relay_hub.register_session(node_a, kp_a.public_key(), start_ms);
        let _hb = relay_hub.register_session(node_b, kp_b.public_key(), start_ms);

        // Baseline sample
        assert!(
            evaluator
                .evaluate_tick(&obs_state, &acme, start_ms)
                .is_empty()
        );

        // Act 1: forward 128-byte packet exceeding 100 B/s global cap -> fires RelaySaturation
        let pkt = mesh_proto::relay::RelayFrame::ClientToPeerPacket {
            dst_pubkey: kp_b.public_key(),
            ciphertext: bytes::Bytes::from(vec![0xAB; 128]),
        }
        .encode()
        .expect("encode");
        let _ = relay_hub.handle_inbound_frame(node_a, kp_a.public_key(), &pkt, start_ms + 500);

        let firing = evaluator.evaluate_tick(&obs_state, &acme, start_ms + 1_000);
        assert!(
            firing
                .iter()
                .any(|(c, is_firing, _)| *c == AlertCondition::RelaySaturation && *is_firing),
            "expected RelaySaturation alert to fire"
        );

        // Act 2: quiet window recovers and emits [RESOLVED]
        let recovered = evaluator.evaluate_tick(&obs_state, &acme, start_ms + 11_000);
        assert!(
            recovered
                .iter()
                .any(|(c, is_firing, msg)| *c == AlertCondition::RelaySaturation
                    && !*is_firing
                    && msg.contains("[RESOLVED]")),
            "expected RelaySaturation recovery notification"
        );

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn test_disk_usage_high_alert_fires_hysteresis_and_recovers() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let start_ms = 1_762_958_151_000_u64;
        let clock = Arc::new(FakeClock::new(start_ms));
        let store = Arc::new(
            ControlStore::open_with_clock(
                ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock,
            )
            .expect("open store"),
        );
        let tcp_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("tcp");
        let udp_probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp");
        let free_tcp = tcp_probe.local_addr().expect("addr").port();
        let free_udp = udp_probe.local_addr().expect("addr").port();
        drop((tcp_probe, udp_probe));
        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: free_tcp,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: free_udp,
            ..ServerConfig::default()
        });
        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let netmap_hub = Arc::new(NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let challenges = Arc::new(PendingChallengeStore::new());
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let ctrl_state = ControlAppState {
            config: cfg,
            trusted_proxies: Arc::new(Default::default()),
            store: store.clone(),
            rate_limiter: rate_limiter.clone(),
            challenges: challenges.clone(),
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = ListenerSet::bind_and_start(ctrl_state, acme.clone())
            .await
            .expect("bind listeners");
        let obs_state = ObsAppState {
            store: store.clone(),
            listeners,
            netmap_hub,
            relay_hub,
            challenges,
            rate_limiter,
        };

        // Sanity-check real OS probe from mesh_sys succeeds cleanly
        let real_pct = mesh_sys::filesystem_usage_percent(&store.config().db_path)
            .expect("real filesystem_usage_percent must succeed on live db_path");
        assert!(real_pct <= 100);

        let simulated_pct = Arc::new(AtomicU8::new(84));
        let probe_pct = Arc::clone(&simulated_pct);
        let evaluator = AlertEvaluator::new(None, 80, 50_000_000)
            .with_disk_threshold(85)
            .with_disk_usage_probe(move |_| Ok(probe_pct.load(Ordering::SeqCst)));

        // Act & Assert: 84% (< 85%) -> no alert
        assert!(
            evaluator
                .evaluate_tick(&obs_state, &acme, start_ms)
                .is_empty()
        );

        // 85% -> fires DiskUsageHigh
        simulated_pct.store(85, Ordering::SeqCst);
        let fired = evaluator.evaluate_tick(&obs_state, &acme, start_ms + 25_000);
        assert!(
            fired
                .iter()
                .any(|(c, is_firing, _)| *c == AlertCondition::DiskUsageHigh && *is_firing),
            "expected DiskUsageHigh to fire at 85%"
        );

        // 80% -> hysteresis keeps alert active without resolving (< 80% required to resolve)
        simulated_pct.store(80, Ordering::SeqCst);
        let held = evaluator.evaluate_tick(&obs_state, &acme, start_ms + 50_000);
        assert!(held.is_empty(), "expected hysteresis to hold firing at 80%");

        // 79% -> resolves DiskUsageHigh with [RESOLVED]
        simulated_pct.store(79, Ordering::SeqCst);
        let resolved = evaluator.evaluate_tick(&obs_state, &acme, start_ms + 75_000);
        assert!(
            resolved
                .iter()
                .any(|(c, is_firing, msg)| *c == AlertCondition::DiskUsageHigh
                    && !*is_firing
                    && msg.contains("[RESOLVED]")),
            "expected DiskUsageHigh recovery below 80%"
        );

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }
}
