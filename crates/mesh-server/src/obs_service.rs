//! Dedicated read-only loopback HTTP observability listener exposing ONLY `/healthz`, `/readyz`,
//! and `/metrics` with zero secret fields (`SEC-01`, `US-044`, `WP-S1-01`).

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use mesh_core::{AppError, AppResult};
use mesh_net::serve_ipc_http_connection;
use mesh_proto::admin_ipc::{HealthResponse, ReadinessResponse};
use mesh_store::ControlStore;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::control_handlers::{PendingChallengeStore, json_response};
use crate::listener_set::ListenerSet;
use crate::netmap_hub::NetmapHub;
use crate::rate_limit::RateLimiter;
use crate::relay_hub::RelayHub;

/// Shared read-only references needed to render health, readiness, and Prometheus metrics.
#[derive(Clone, Debug)]
pub struct ObsAppState {
    /// Control ACID store (`is_disk_degraded`, `check_integrity`, `netmap_version`).
    pub store: Arc<ControlStore>,
    /// Public TCP/UDP listener health tracker.
    pub listeners: Arc<ListenerSet>,
    /// Live Control WebSocket subscriber hub.
    pub netmap_hub: Arc<NetmapHub>,
    /// Live Blind Relay session & traffic metrics hub.
    pub relay_hub: Arc<RelayHub>,
    /// Pending single-use challenge counter.
    pub challenges: Arc<PendingChallengeStore>,
    /// Auth rate limiter counters.
    pub rate_limiter: Arc<RateLimiter>,
}

/// Evaluates server readiness matching `/readyz` semantics (`503` when degraded or unhealthy).
#[must_use]
pub fn evaluate_readiness(state: &ObsAppState) -> ReadinessResponse {
    if state.store.is_disk_degraded() {
        return ReadinessResponse {
            status: "not_ready".to_owned(),
            db_healthy: false,
            control_tcp_listener_healthy: state.listeners.is_control_healthy(),
            stun_udp_listener_healthy: state.listeners.is_stun_healthy(),
            reason: state
                .store
                .degraded_reason()
                .or_else(|| Some("disk storage is degraded".to_owned())),
        };
    }

    if let Err(err) = state.store.check_integrity() {
        return ReadinessResponse {
            status: "not_ready".to_owned(),
            db_healthy: false,
            control_tcp_listener_healthy: state.listeners.is_control_healthy(),
            stun_udp_listener_healthy: state.listeners.is_stun_healthy(),
            reason: Some(format!("database integrity check failed: {err}")),
        };
    }

    let ctrl_ok = state.listeners.is_control_healthy();
    let stun_ok = state.listeners.is_stun_healthy();
    if state.listeners.config().tls_mode == crate::config::TlsMode::Acme {
        let ca_verified = state
            .listeners
            .acme()
            .status()
            .is_some_and(|s| s.ca_verified);
        if !ca_verified {
            return ReadinessResponse {
                status: "not_ready".to_owned(),
                db_healthy: true,
                control_tcp_listener_healthy: ctrl_ok,
                stun_udp_listener_healthy: stun_ok,
                reason: Some("ACME public CA certificate not yet issued".to_owned()),
            };
        }
    }
    let ready = ctrl_ok && stun_ok;
    let reason = if ready {
        None
    } else if !ctrl_ok {
        Some("control TCP listener unhealthy".to_owned())
    } else {
        Some("embedded STUN UDP listener unhealthy".to_owned())
    };

    ReadinessResponse {
        status: if ready {
            "ready".to_owned()
        } else {
            "not_ready".to_owned()
        },
        db_healthy: true,
        control_tcp_listener_healthy: ctrl_ok,
        stun_udp_listener_healthy: stun_ok,
        reason,
    }
}

/// Renders Prometheus text exposition (`0.0.4`) guaranteed free of secret key material.
#[must_use]
pub fn render_prometheus_metrics(state: &ObsAppState) -> String {
    let relay = state.relay_hub.metrics_snapshot();
    let stun = state.listeners.stun_state();
    let mut out = String::with_capacity(1024);

    push_metric(
        &mut out,
        "mesh_netmap_version",
        "gauge",
        "Current monotonic netmap version.",
        state.store.current_netmap_version(),
    );
    push_metric(
        &mut out,
        "mesh_online_control_streams",
        "gauge",
        "Active /v1/netmap/stream WebSocket connections.",
        u64::try_from(state.netmap_hub.active_stream_count()).unwrap_or(u64::MAX),
    );
    push_metric(
        &mut out,
        "mesh_relay_active_sessions",
        "gauge",
        "Active /v1/relay WebSocket connections.",
        u64::try_from(relay.active_sessions).unwrap_or(u64::MAX),
    );
    push_metric(
        &mut out,
        "mesh_relay_forwarded_packets_total",
        "counter",
        "Total packets relayed via Blind Relay.",
        relay.forwarded_packets_total,
    );
    push_metric(
        &mut out,
        "mesh_relay_forwarded_bytes_total",
        "counter",
        "Total payload bytes relayed via Blind Relay.",
        relay.forwarded_bytes_total,
    );
    push_metric(
        &mut out,
        "mesh_relay_dropped_packets_total",
        "counter",
        "Packets dropped due to full 256-slot peer queue or offline peer.",
        relay.dropped_packets_total,
    );
    push_metric(
        &mut out,
        "mesh_relay_throttled_packets_total",
        "counter",
        "Packets throttled by 20 Mbps per-node or global relay cap.",
        relay.throttled_packets_total,
    );
    push_metric(
        &mut out,
        "mesh_stun_requests_total",
        "counter",
        "Valid STUN Binding Responses sent.",
        stun.requests_total(),
    );
    push_metric(
        &mut out,
        "mesh_stun_rate_limited_total",
        "counter",
        "STUN packets dropped by per-IP 100 pps limit.",
        stun.dropped_rate_limited_total(),
    );
    push_metric(
        &mut out,
        "mesh_auth_rate_limit_hits_total",
        "counter",
        "Authentication requests throttled or IP-locked.",
        state.rate_limiter.total_hits(),
    );
    push_metric(
        &mut out,
        "mesh_pending_challenges",
        "gauge",
        "Active single-use challenges awaiting consumption.",
        u64::try_from(state.challenges.len()).unwrap_or(u64::MAX),
    );
    push_metric(
        &mut out,
        "mesh_disk_degraded",
        "gauge",
        "Non-zero when primary redb failed and emergency storage is active.",
        u64::from(u8::from(state.store.is_disk_degraded())),
    );
    out
}

fn push_metric(out: &mut String, name: &str, metric_type: &str, help: &str, value: u64) {
    if let Err(err) = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} {metric_type}\n{name} {value}"
    ) {
        tracing::debug!(
            component = "obs_service",
            event = "metric_format_error",
            error = %err,
            "failed formatting prometheus metric"
        );
    }
}

/// Builds the dedicated read-only Axum observability router (`/healthz`, `/readyz`, `/metrics`).
pub fn build_obs_router(state: ObsAppState) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/readyz", get(handle_readyz))
        .route("/metrics", get(handle_metrics))
        .with_state(state)
}

/// Starts the isolated read-only observability TCP listener (`127.0.0.1:9091` default).
pub async fn start_obs_listener(
    bind_addr: SocketAddr,
    state: ObsAppState,
    tracker: &TaskTracker,
    shutdown: CancellationToken,
) -> AppResult<SocketAddr> {
    let listener = TcpListener::bind(bind_addr).await.map_err(|err| {
        AppError::conflict(format!(
            "failed binding observability HTTP socket on {bind_addr}: {err}"
        ))
    })?;
    let local_addr = listener.local_addr().unwrap_or(bind_addr);
    let router = build_obs_router(state);
    let loop_tracker = tracker.clone();

    tracker.spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                res = listener.accept() => {
                    if let Ok((stream, _)) = res {
                        let r = router.clone();
                        let conn_cancel = shutdown.clone();
                        loop_tracker.spawn(async move {
                            let res = tokio::select! {
                                () = conn_cancel.cancelled() => Ok(()),
                                srv = serve_ipc_http_connection(stream, r) => srv,
                            };
                            if let Err(err) = res {
                                tracing::debug!(
                                    component = "obs_service",
                                    event = "obs_connection_closed",
                                    error = %err,
                                    "observability HTTP connection ended"
                                );
                            }
                        });
                    }
                }
            }
        }
    });

    Ok(local_addr)
}

async fn handle_healthz(State(_state): State<ObsAppState>) -> Response {
    json_response(
        StatusCode::OK,
        &HealthResponse {
            status: "alive".to_owned(),
        },
    )
}

async fn handle_readyz(State(state): State<ObsAppState>) -> Response {
    let readiness = evaluate_readiness(&state);
    let status = if readiness.status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    json_response(status, &readiness)
}

async fn handle_metrics(State(state): State<ObsAppState>) -> Response {
    let text = render_prometheus_metrics(&state);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(text))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Summary label for initialization diagnostics.
#[must_use]
pub(crate) const fn status_label() -> &'static str {
    "obs_service:ready"
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use mesh_core::{Clock as _, FakeClock, SystemClock};
    use mesh_proto::admin_ipc::{HealthResponse, ReadinessResponse};
    use mesh_store::{ControlStore, ControlStoreConfig};
    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use super::{ObsAppState, start_obs_listener};
    use crate::acme::AcmeManager;
    use crate::config::ServerConfig;
    use crate::control_handlers::{ControlAppState, PendingChallengeStore};
    use crate::listener_set::ListenerSet;
    use crate::netmap_hub::NetmapHub;
    use crate::rate_limit::{ClientIpExtractor, RateLimiter};
    use crate::relay_hub::RelayHub;

    #[tokio::test]
    async fn test_obs_endpoints_healthz_readyz_metrics_and_no_admin_routes() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let now_ms = SystemClock::new().now_unix_ms();
        let clock = Arc::new(FakeClock::new(now_ms));
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
            .expect("tcp probe");
        let udp_probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp probe");
        let free_tcp = tcp_probe.local_addr().expect("tcp addr").port();
        let free_udp = udp_probe.local_addr().expect("udp addr").port();
        drop((tcp_probe, udp_probe));

        let cfg = Arc::new(ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: free_tcp,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: free_udp,
            public_host: "127.0.0.1".to_owned(),
            ..ServerConfig::default()
        });
        let acme = AcmeManager::initialize(&cfg, Arc::clone(&store)).expect("init acme");
        let netmap_hub = Arc::new(NetmapHub::new(
            Arc::clone(&store),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(RelayHub::new(
            Arc::clone(&store),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let challenges = Arc::new(PendingChallengeStore::new());
        let rate_limiter = Arc::new(RateLimiter::new(ClientIpExtractor::new(
            cfg.tls_mode,
            cfg.trusted_proxy_set(),
        )));
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let listeners = ListenerSet::bind_and_start(
            ControlAppState {
                config: cfg,
                trusted_proxies: Arc::new(Default::default()),
                store: Arc::clone(&store),
                rate_limiter: Arc::clone(&rate_limiter),
                challenges: Arc::clone(&challenges),
                netmap_hub: Arc::clone(&netmap_hub),
                relay_hub: Arc::clone(&relay_hub),
                ws_tracker: tracker.clone(),
                shutdown: shutdown.clone(),
            },
            acme,
        )
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
        let obs_addr = start_obs_listener(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            obs_state,
            &tracker,
            shutdown.clone(),
        )
        .await
        .expect("start obs listener");

        crate::acme::ensure_rustls_ring_provider();
        let client = reqwest::Client::new();
        let base = format!("http://{obs_addr}");

        // Act & Assert: /healthz 200 OK
        let hz = client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .expect("get healthz");
        assert_eq!(hz.status(), reqwest::StatusCode::OK);
        let hz_body: HealthResponse = hz.json().await.expect("decode healthz");
        assert_eq!(hz_body.status, "alive");

        // /readyz 200 OK when healthy
        let rz = client
            .get(format!("{base}/readyz"))
            .send()
            .await
            .expect("get readyz");
        assert_eq!(rz.status(), reqwest::StatusCode::OK);
        let rz_body: ReadinessResponse = rz.json().await.expect("decode readyz");
        assert_eq!(rz_body.status, "ready");
        assert!(rz_body.db_healthy);

        // /metrics renders expected counters without private key markers
        let metrics_resp = client
            .get(format!("{base}/metrics"))
            .send()
            .await
            .expect("get metrics");
        assert_eq!(metrics_resp.status(), reqwest::StatusCode::OK);
        let metrics_text = metrics_resp.text().await.expect("metrics text");
        assert!(metrics_text.contains("mesh_netmap_version"));
        assert!(metrics_text.contains("mesh_disk_degraded 0"));
        assert!(!metrics_text.contains("BEGIN PRIVATE KEY"));

        // Admin routes MUST NOT exist on the read-only observability listener (`SEC-14`)
        let admin_probe = client
            .get(format!("{base}/v1/admin/server/status"))
            .send()
            .await
            .expect("probe admin route");
        assert_eq!(admin_probe.status(), reqwest::StatusCode::NOT_FOUND);

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }
}
