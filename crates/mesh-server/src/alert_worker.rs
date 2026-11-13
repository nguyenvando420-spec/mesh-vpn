//! Background operational alert evaluator, automatic node expiry / emergency compaction
//! sweeper, and rate-limited (`1/hour/condition` + recovery) webhook dispatcher (`US-049`, `WP-S1-01`).

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mesh_proto::control::TerminationReason;
use mesh_proto::relay::RelayNoticeCode;
use mesh_store::ControlStore;
use mesh_sys::{SysResult, filesystem_usage_percent};
use serde::Serialize;
use serde_json::json;
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
    telegram_chat_id: Option<String>,
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
            .field("telegram_chat_id", &self.telegram_chat_id)
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
            telegram_chat_id: None,
            relay_threshold_pct,
            relay_global_bps: relay_global_bps.max(1),
            disk_threshold_pct: DEFAULT_DISK_ALERT_THRESHOLD_PCT,
            disk_usage_probe: Arc::new(filesystem_usage_percent),
            tracker: Mutex::new(AlertTracker::default()),
        }
    }

    /// Configures an optional Telegram `chat_id` when `alert_webhook_url` targets `api.telegram.org`.
    #[must_use]
    pub fn with_telegram_chat_id(mut self, telegram_chat_id: Option<String>) -> Self {
        self.telegram_chat_id = telegram_chat_id;
        self
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

    /// Configured optional Telegram target chat ID.
    #[must_use]
    pub fn telegram_chat_id(&self) -> Option<&str> {
        self.telegram_chat_id.as_deref()
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
                    && n.key_expires_at_ms.is_some_and(|exp| {
                        exp > now_ms && exp.saturating_sub(now_ms) <= NODE_KEY_EXPIRING_ALERT_MS
                    })
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

/// Tracks periodic housekeeping timestamps across maintenance ticks (`US-006`, `US-045`).
#[derive(Debug, Clone, Copy)]
pub struct MaintenanceSchedule {
    /// Timestamp of the last completed automatic snapshot backup (UTC ms).
    pub last_backup_at_ms: u64,
    /// Timestamp of the last overlay-IP quarantine sweep (UTC ms).
    pub last_quarantine_reclaim_ms: u64,
}

impl MaintenanceSchedule {
    /// Initializes schedule watermarks to `now_ms`.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            last_backup_at_ms: now_ms,
            last_quarantine_reclaim_ms: now_ms,
        }
    }
}

/// Executes one deterministic maintenance cycle (used by [`run_background_maintenance`] and tests).
pub async fn run_maintenance_cycle(ctx: &MaintenanceContext, sched: &mut MaintenanceSchedule) {
    let now_ms = ctx.store.clock().now_unix_ms();
    let cfg = ctx.obs_state.listeners.config();
    let _sent_hb = ctx.netmap_hub.broadcast_heartbeats(now_ms);
    let _cutover = ctx.obs_state.listeners.check_migration_cutover();

    if ctx.store.is_disk_degraded() {
        match ctx.store.try_compact_emergency_revocations() {
            Ok(Some(compacted_ver)) => {
                if let Err(err) = ctx.netmap_hub.broadcast_snapshot(compacted_ver) {
                    tracing::warn!(
                        component = "alert_worker",
                        event = "compaction_broadcast_failed",
                        netmap_version = compacted_ver,
                        error = %err,
                        "failed broadcasting netmap snapshot after emergency compaction"
                    );
                }
            }
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(
                    component = "alert_worker",
                    event = "compaction_deferred",
                    error = %err,
                    "deferring emergency compaction until storage recovers"
                );
            }
        }
    }

    if let Ok(expired) = ctx.store.sweep_expired_nodes() {
        for outcome in expired {
            ctx.netmap_hub.terminate_node_stream(
                outcome.node_id,
                TerminationReason::NodeKeyExpired,
                "node key expired",
                now_ms,
            );
            ctx.relay_hub
                .disconnect_node(outcome.node_id, RelayNoticeCode::NodeKeyExpired);
            if outcome.must_disconnect_all_peers_to_reauth {
                ctx.netmap_hub.close_all_streams_for_reauth();
                ctx.relay_hub.close_all_sessions();
            } else if let Some(ver) = outcome.netmap_version
                && let Err(err) = ctx.netmap_hub.broadcast_snapshot(ver)
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

    match ctx.store.reap_expired_ephemeral_nodes(
        cfg.ephemeral_timeout_secs,
        |id| ctx.netmap_hub.node_runtime_info(id).is_some(),
        "ephemeral-reaper",
    ) {
        Ok((reaped_nodes, latest_ver)) if !reaped_nodes.is_empty() => {
            for rec in &reaped_nodes {
                ctx.netmap_hub.terminate_node_stream(
                    rec.node_id,
                    TerminationReason::NodeRevoked,
                    "ephemeral node offline timeout reaped",
                    now_ms,
                );
                ctx.relay_hub
                    .disconnect_node(rec.node_id, RelayNoticeCode::NodeRevoked);
            }
            if let Some(ver) = latest_ver
                && let Err(err) = ctx.netmap_hub.broadcast_snapshot(ver)
            {
                tracing::warn!(
                    component = "alert_worker",
                    event = "ephemeral_reap_broadcast_failed",
                    error = %err,
                    "failed broadcasting netmap snapshot after ephemeral reap"
                );
            }
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(
                component = "alert_worker",
                event = "ephemeral_reap_failed",
                error = %err,
                "ephemeral offline reaper encountered an error"
            );
        }
    }

    if now_ms.saturating_sub(sched.last_quarantine_reclaim_ms) >= 60_000 {
        sched.last_quarantine_reclaim_ms = now_ms;
        if let Err(err) = ctx.store.reclaim_expired_quarantines() {
            tracing::debug!(
                component = "alert_worker",
                event = "quarantine_reclaim_failed",
                error = %err,
                "periodic overlay IP quarantine sweep failed"
            );
        }
    }

    let backup_interval_ms = cfg.backup_interval_secs.saturating_mul(1_000);
    if backup_interval_ms > 0
        && now_ms.saturating_sub(sched.last_backup_at_ms) >= backup_interval_ms
    {
        match ctx
            .store
            .create_backup(&cfg.backup_dir(), "auto-backup-scheduler")
        {
            Ok(artifact) => {
                sched.last_backup_at_ms = now_ms;
                tracing::info!(
                    component = "alert_worker",
                    event = "scheduled_backup_completed",
                    snapshot = %artifact.snapshot_path.display(),
                    size_bytes = artifact.size_bytes,
                    "scheduled automatic hot backup succeeded"
                );
            }
            Err(err) => {
                tracing::warn!(
                    component = "alert_worker",
                    event = "scheduled_backup_failed",
                    error = %err,
                    "scheduled automatic hot backup failed"
                );
            }
        }
    }

    if let Err(err) = ctx.acme.run_renewal_check().await {
        tracing::warn!(
            component = "alert_worker",
            event = "acme_renewal_failed",
            error = %err,
            "ACME renewal check deferred"
        );
    }

    let events = ctx
        .evaluator
        .evaluate_tick(&ctx.obs_state, &ctx.acme, now_ms);
    if let Some(url) = ctx.evaluator.webhook_url() {
        for (cond, is_firing, summary) in events {
            let payload = WebhookAlertPayload {
                condition: cond,
                state: if is_firing { "firing" } else { "resolved" },
                summary,
                timestamp_at_ms: now_ms,
            };
            dispatch_webhook_with_retries(
                url,
                ctx.evaluator.telegram_chat_id(),
                &payload,
                &ctx.cancel,
            )
            .await;
        }
    }
}

/// Runs periodic maintenance (control heartbeats without version bumps, emergency compaction,
/// expired node sweeps, ephemeral reaper, quarantine reclamation, 24h backups, ACME checks,
/// migration cutovers, and webhook/Telegram alert delivery).
pub async fn run_background_maintenance(ctx: MaintenanceContext) {
    let mut ticker = interval(Duration::from_secs(WORKER_TICK_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sched = MaintenanceSchedule::new(ctx.store.clock().now_unix_ms());

    loop {
        tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => break,
            _ = ticker.tick() => {
                run_maintenance_cycle(&ctx, &mut sched).await;
            }
        }
    }
}

fn build_alert_http_body(
    url: &str,
    telegram_chat_id: Option<&str>,
    payload: &WebhookAlertPayload,
) -> serde_json::Value {
    if url.contains("api.telegram.org") {
        let query_chat_id = url.split_once('?').and_then(|(_, q)| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("chat_id="))
                .map(str::trim)
                .filter(|v| !v.is_empty())
        });
        if let Some(chat_id) = telegram_chat_id
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .or(query_chat_id)
        {
            return json!({
                "chat_id": chat_id,
                "text": format!(
                    "[mesh-server][{}] {:?}: {} (ts={})",
                    payload.state.to_ascii_uppercase(),
                    payload.condition,
                    payload.summary,
                    payload.timestamp_at_ms
                ),
            });
        }
        tracing::warn!(
            component = "alert_worker",
            event = "telegram_chat_id_missing",
            "alert_webhook_url points to api.telegram.org without alert_telegram_chat_id; sending raw JSON payload"
        );
    }
    serde_json::to_value(payload).unwrap_or_else(|_| {
        json!({
            "state": payload.state,
            "summary": payload.summary,
            "timestamp_at_ms": payload.timestamp_at_ms,
        })
    })
}

async fn dispatch_webhook_with_retries(
    url: &str,
    telegram_chat_id: Option<&str>,
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
    let body = build_alert_http_body(url, telegram_chat_id, payload);
    for attempt in 0_u32..3 {
        if cancel.is_cancelled() {
            return;
        }
        if let Ok(resp) = client.post(url).json(&body).send().await
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
        let _fwd = relay_hub.handle_inbound_frame(node_a, kp_a.public_key(), &pkt, start_ms + 500);

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

    #[tokio::test]
    async fn test_maintenance_cycle_reaps_ephemeral_runs_daily_backup_and_formats_telegram() {
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
            state_dir: dir.path().to_path_buf(),
            ephemeral_timeout_secs: 60,
            backup_interval_secs: 86_400,
            ..ServerConfig::default()
        });

        let tok_hash = mesh_crypto::sha256_digest(b"mpk_ephem_worker_token");
        store
            .create_preauth_key(
                &mesh_store::CreatePreAuthKeyInput {
                    key_id: mesh_core::KeyId::new_v7(start_ms),
                    token_hash: tok_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: Some(1),
                    ephemeral: true,
                    ephemeral_timeout_secs: Some(30),
                    ttl_secs: 3_600,
                    now_unix_ms: start_ms,
                },
                "admin",
            )
            .expect("create key");
        let eph_kp = mesh_crypto::NodeKeypair::generate();
        let eph_dkp = mesh_crypto::DiscoKeypair::generate();
        let (eph_reg, _) = store
            .register_node(&mesh_store::RegisterNodeInput {
                pubkey: eph_kp.public_key(),
                disco_pubkey: eph_dkp.public_key(),
                previous_node_pubkey: None,
                requested_name: mesh_core::NodeName::parse("ephem-ci").expect("name"),
                preauth_token_hash: tok_hash,
                public_control_host: "203.0.113.10",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: mesh_store::DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: start_ms,
            })
            .expect("register ephemeral node");

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
            config: cfg.clone(),
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
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            challenges,
            rate_limiter,
        };
        let evaluator = Arc::new(
            AlertEvaluator::new(
                Some("https://api.telegram.org/botTOKEN/sendMessage".to_owned()),
                80,
                50_000_000,
            )
            .with_telegram_chat_id(Some("123456789".to_owned()))
            .with_disk_usage_probe(|_| Ok(25)),
        );
        let ctx = super::MaintenanceContext {
            store: store.clone(),
            acme,
            netmap_hub,
            relay_hub,
            obs_state,
            evaluator,
            cancel: shutdown.clone(),
        };
        let mut sched = super::MaintenanceSchedule::new(start_ms);

        // Act 1: 20s (< 30s) offline keeps ephemeral node intact
        clock.advance(20_000);
        super::run_maintenance_cycle(&ctx, &mut sched).await;
        assert!(
            store
                .find_node_by_id(eph_reg.record.node_id)
                .expect("lookup")
                .is_some()
        );

        // Act 2: +15s (35s > 30s) offline reaps ephemeral node and releases IP immediately
        clock.advance(15_000);
        super::run_maintenance_cycle(&ctx, &mut sched).await;
        assert!(
            store
                .find_node_by_id(eph_reg.record.node_id)
                .expect("lookup after reap")
                .is_none()
        );

        // Act 3: advance 24h triggers automatic hot snapshot + .sha256 in backup_dir (`US-045 AC1`)
        clock.advance(86_400 * 1_000);
        super::run_maintenance_cycle(&ctx, &mut sched).await;
        let backups: Vec<_> = std::fs::read_dir(cfg.backup_dir())
            .expect("backup dir exists")
            .filter_map(Result::ok)
            .collect();
        assert!(
            backups
                .iter()
                .any(|e| e.file_name().to_string_lossy().ends_with(".redb"))
        );
        assert!(
            backups
                .iter()
                .any(|e| e.file_name().to_string_lossy().ends_with(".sha256"))
        );

        // Act 4: verify Telegram formatting vs generic webhook formatting (`US-049`)
        let sample = super::WebhookAlertPayload {
            condition: AlertCondition::NodeKeyExpiring,
            state: "firing",
            summary: "node-a key expires in 5 days".to_owned(),
            timestamp_at_ms: start_ms,
        };
        let tg = super::build_alert_http_body(
            "https://api.telegram.org/botXYZ/sendMessage",
            Some("-1009988"),
            &sample,
        );
        assert_eq!(tg.get("chat_id").and_then(|v| v.as_str()), Some("-1009988"));
        assert!(
            tg.get("text")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.contains("node-a key expires in 5 days"))
        );
        let generic =
            super::build_alert_http_body("https://hooks.example.com/alert", None, &sample);
        assert_eq!(
            generic.get("state").and_then(|v| v.as_str()),
            Some("firing")
        );

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn test_compaction_on_maintenance_cycle_broadcasts_updated_netmap_snapshot() {
        // Arrange (`HR-W21-12`)
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
                Arc::clone(&clock) as Arc<dyn mesh_core::Clock>,
            )
            .expect("open store"),
        );
        store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("identity");

        let token_hash = [0x91_u8; 32];
        store
            .create_preauth_key(
                &mesh_store::CreatePreAuthKeyInput {
                    key_id: mesh_core::KeyId::new_v7(start_ms),
                    token_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: true,
                    max_uses: Some(4),
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: start_ms,
                },
                "admin",
            )
            .expect("key");
        let (reg_a, _) = store
            .register_node(&mesh_store::RegisterNodeInput {
                pubkey: mesh_core::PublicKey::from_bytes([0x92_u8; 32]).expect("pk_a"),
                disco_pubkey: mesh_core::PublicKey::from_bytes([0x93_u8; 32]).expect("dpk_a"),
                previous_node_pubkey: None,
                requested_name: mesh_core::NodeName::parse("compact-peer-a").expect("name_a"),
                preauth_token_hash: token_hash,
                public_control_host: "127.0.0.1",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: mesh_store::DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: start_ms,
            })
            .expect("register a");
        let (reg_b, ver_before_revoke) = store
            .register_node(&mesh_store::RegisterNodeInput {
                pubkey: mesh_core::PublicKey::from_bytes([0x94_u8; 32]).expect("pk_b"),
                disco_pubkey: mesh_core::PublicKey::from_bytes([0x95_u8; 32]).expect("dpk_b"),
                previous_node_pubkey: None,
                requested_name: mesh_core::NodeName::parse("compact-peer-b").expect("name_b"),
                preauth_token_hash: token_hash,
                public_control_host: "127.0.0.1",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: mesh_store::DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: start_ms,
            })
            .expect("register b");

        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            stun_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: 0,
            stun_udp_port: 0,
            ..ServerConfig::default()
        });
        let acme = AcmeManager::initialize(&cfg, store.clone()).expect("acme");
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
            .expect("bind");
        let obs_state = ObsAppState {
            store: store.clone(),
            listeners,
            netmap_hub: netmap_hub.clone(),
            relay_hub: relay_hub.clone(),
            challenges,
            rate_limiter,
        };
        let evaluator = Arc::new(AlertEvaluator::new(None, 80, 100));
        let ctx = super::MaintenanceContext {
            store: store.clone(),
            acme,
            netmap_hub: netmap_hub.clone(),
            relay_hub,
            obs_state,
            evaluator,
            cancel: shutdown.clone(),
        };
        let mut sched = super::MaintenanceSchedule::new(start_ms);

        // Subscribe peer A, then revoke peer B under redb write failure so compaction is deferred.
        let mut sub_a = netmap_hub.subscribe(reg_a.record.node_id, start_ms);
        store.inject_redb_failure(false, true);
        let revoked = store
            .revoke_node(reg_b.record.node_id, "admin")
            .expect("emergency revoke");
        assert_eq!(
            revoked.persistence_tier,
            mesh_proto::admin_ipc::PersistenceTier::EmergencySlot
        );
        assert!(store.is_disk_degraded());

        // Clear fault and run maintenance cycle -> compaction persists and broadcasts snapshot.
        store.inject_redb_failure(false, false);
        while sub_a.rx.try_recv().is_ok() {}
        super::run_maintenance_cycle(&ctx, &mut sched).await;

        assert!(!store.is_disk_degraded());
        assert!(store.current_netmap_version() > ver_before_revoke);
        let snapshot_netmap = std::iter::from_fn(|| sub_a.rx.try_recv().ok())
            .find_map(|frame| match frame {
                mesh_proto::control::ServerControlFrame::NetmapSnapshot { netmap, .. } => {
                    Some(netmap)
                }
                _ => None,
            })
            .expect("subscriber must receive netmap snapshot after compaction");
        assert!(snapshot_netmap.netmap_version > ver_before_revoke);
        assert!(
            snapshot_netmap
                .peers
                .iter()
                .all(|p| p.node_id != reg_b.record.node_id)
        );

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }
}
