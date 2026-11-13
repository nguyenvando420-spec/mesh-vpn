//! Public Control/Relay TCP+TLS listener set, embedded STUN UDP binding, and zero-downtime
//! dual-socket endpoint migration manager (`US-046 AC5`, `US-074`, `WP-S1-01`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hyper::server::conn::http1 as hyper_http1;
use hyper::service::{Service as _, service_fn};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use mesh_core::defaults::{CONNECT_TIMEOUT_MS, DEFAULT_CONTROL_TCP_PORT};
use mesh_core::{AppError, AppResult, Clock};
use mesh_crypto::extract_tls_exporter_binding;
use mesh_proto::admin_ipc::{MigrateEndpointRequest, MigrateEndpointResponse};
use mesh_store::ControlStore;
use rustls::ServerConfig as RustlsServerConfig;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::acme::AcmeManager;
use crate::config::{AcmeChallengeKind, ServerConfig, TlsMode};
use crate::control_handlers::{ConnectionTlsContext, ControlAppState, build_control_router};
use crate::netmap_hub::NetmapHub;
use crate::relay_hub::RelayHub;
use crate::stun_service::{StunServiceState, bind_stun_udp_socket, run_stun_socket_loop};

const DEFAULT_MIGRATION_GRACE_SECS: u64 = 300;
const MAX_MIGRATION_GRACE_SECS: u64 = 86_400;

#[derive(Debug)]
struct ActivePortState {
    control_tcp_port: u16,
    stun_udp_port: u16,
    tls_mode: TlsMode,
    public_host: String,
    active_tcp_cancel: CancellationToken,
    active_stun_cancel: CancellationToken,
    previous_tcp_cancel: Option<CancellationToken>,
    previous_stun_cancel: Option<CancellationToken>,
    transition_deadline_at_ms: Option<u64>,
}

/// Owns the public Control/Relay TCP listener(s) and UDP STUN socket(s), tracking readiness and
/// orchestrating dual-listener zero-downtime port migrations (`US-074`).
#[derive(Debug)]
pub struct ListenerSet {
    config: Arc<ServerConfig>,
    store: Arc<ControlStore>,
    acme: Arc<AcmeManager>,
    netmap_hub: Arc<NetmapHub>,
    relay_hub: Arc<RelayHub>,
    router: Router,
    tracker: TaskTracker,
    shutdown: CancellationToken,
    control_healthy: AtomicBool,
    stun_state: Arc<StunServiceState>,
    ports: Mutex<ActivePortState>,
}

impl ListenerSet {
    /// Summary label for initialization diagnostics.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "listener_set:ready"
    }

    /// Returns the shared [`ServerConfig`].
    #[must_use]
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.config
    }

    /// Returns the shared [`AcmeManager`].
    #[must_use]
    pub fn acme(&self) -> &Arc<AcmeManager> {
        &self.acme
    }

    /// Verifies TCP & UDP ports are available BEFORE starting background tasks (`US-046 AC5`),
    /// then spawns the primary Control HTTPS/WS and UDP STUN listener loops cleanly.
    pub async fn bind_and_start(
        control_state: ControlAppState,
        acme: Arc<AcmeManager>,
    ) -> AppResult<Arc<Self>> {
        let config = Arc::clone(&control_state.config);
        let control_addr = config.control_socket_addr()?;
        let stun_addr = config.stun_socket_addr()?;

        let tcp_listener = bind_control_tcp_listener(control_addr).await?;
        let udp_socket = bind_stun_udp_socket(stun_addr).await?;
        let actual_tcp_port = tcp_listener
            .local_addr()
            .map_or(config.control_tcp_port, |a| a.port());
        let actual_udp_port = udp_socket
            .local_addr()
            .map_or(config.stun_udp_port, |a| a.port());

        let router = build_control_router(control_state.clone());
        let active_tcp_cancel = control_state.shutdown.child_token();
        let active_stun_cancel = control_state.shutdown.child_token();

        let set = Arc::new(Self {
            config: Arc::clone(&config),
            store: Arc::clone(&control_state.store),
            acme: Arc::clone(&acme),
            netmap_hub: Arc::clone(&control_state.netmap_hub),
            relay_hub: Arc::clone(&control_state.relay_hub),
            router,
            tracker: control_state.ws_tracker.clone(),
            shutdown: control_state.shutdown.clone(),
            control_healthy: AtomicBool::new(false),
            stun_state: Arc::new(StunServiceState::new()),
            ports: Mutex::new(ActivePortState {
                control_tcp_port: actual_tcp_port,
                stun_udp_port: actual_udp_port,
                tls_mode: config.tls_mode,
                public_host: config.public_host.clone(),
                active_tcp_cancel: active_tcp_cancel.clone(),
                active_stun_cancel: active_stun_cancel.clone(),
                previous_tcp_cancel: None,
                previous_stun_cancel: None,
                transition_deadline_at_ms: None,
            }),
        });

        set.spawn_control_accept_loop(tcp_listener, active_tcp_cancel, config.tls_mode)?;
        set.spawn_stun_loop(udp_socket, active_stun_cancel);
        Ok(set)
    }

    /// Returns `true` when the active TCP Control/Relay listener loop is serving cleanly.
    #[must_use]
    pub fn is_control_healthy(&self) -> bool {
        self.control_healthy.load(Ordering::SeqCst)
    }

    /// Returns `true` when the active UDP STUN responder loop is healthy.
    #[must_use]
    pub fn is_stun_healthy(&self) -> bool {
        self.stun_state.is_healthy()
    }

    /// Reference to embedded UDP STUN metrics & health tracker.
    #[must_use]
    pub fn stun_state(&self) -> &Arc<StunServiceState> {
        &self.stun_state
    }

    /// Current bound `(control_tcp_port, stun_udp_port)` tuple.
    #[must_use]
    pub fn active_ports(&self) -> (u16, u16) {
        self.ports
            .lock()
            .map(|p| (p.control_tcp_port, p.stun_udp_port))
            .unwrap_or((self.config.control_tcp_port, self.config.stun_udp_port))
    }

    /// Active Control/Relay TLS termination mode (`US-074`, `US-048`).
    #[must_use]
    pub fn active_tls_mode(&self) -> TlsMode {
        self.ports
            .lock()
            .map(|p| p.tls_mode)
            .unwrap_or(self.config.tls_mode)
    }

    /// Current advertised public host/IP updated atomically on endpoint migration (`HR-W21-11`).
    #[must_use]
    pub fn active_public_host(&self) -> String {
        self.ports
            .lock()
            .map(|p| p.public_host.clone())
            .unwrap_or_else(|_| self.config.public_host.clone())
    }

    /// Builds active Subject Alternative Names from live `public_host` & `tls_mode` (`HR-W21-11`).
    #[must_use]
    pub fn active_tls_sans(&self) -> Vec<String> {
        self.build_tls_sans(&self.active_public_host(), self.active_tls_mode())
    }

    fn build_tls_sans(&self, host: &str, tls_mode: TlsMode) -> Vec<String> {
        let mut sans = Vec::new();
        if tls_mode == TlsMode::Acme
            && let Some(ref domain) = self.config.acme.domain
        {
            let trimmed = domain.trim();
            if !trimmed.is_empty() {
                sans.push(trimmed.to_owned());
            }
        }
        if !sans.iter().any(|s| s == host) {
            sans.push(host.to_owned());
        }
        if tls_mode != TlsMode::Acme {
            let loopback_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST).to_string();
            if !sans.contains(&loopback_v4) {
                sans.push(loopback_v4);
            }
        }
        sans
    }

    /// Executes a zero-downtime dual-listener port/host/TLS-mode migration (`US-074 AC1..AC7`).
    ///
    /// Probes and binds new sockets first so existing sessions remain uninterrupted if a target
    /// port is already occupied (`US-046 AC5`). Keeps old listeners alive until all peers ack or
    /// `grace_secs` elapses.
    pub async fn migrate_endpoints(
        &self,
        req: &MigrateEndpointRequest,
        actor: &str,
    ) -> AppResult<MigrateEndpointResponse> {
        let now_ms = self.store.clock().now_unix_ms();
        let (old_tcp_port, old_stun_port) = self.active_ports();
        let current_tls_mode = self.active_tls_mode();
        let current_public_host = self.active_public_host();
        let target_tcp_port = req.tcp_port.map_or(old_tcp_port, |p| p.get());
        let target_stun_port = req.stun_port.map_or(old_stun_port, |p| p.get());
        let target_tls_mode = match req.tls_mode.as_deref() {
            Some(raw) => TlsMode::parse(raw)?,
            None => current_tls_mode,
        };

        if let Some(extend_secs) = req.extend_window_secs {
            let new_deadline = now_ms.saturating_add(
                extend_secs
                    .clamp(5, MAX_MIGRATION_GRACE_SECS)
                    .saturating_mul(1_000),
            );
            if let Ok(mut guard) = self.ports.lock() {
                guard.transition_deadline_at_ms = Some(new_deadline);
            }
            let (ep_ver, ctrl_ep, stun_eps) = self.netmap_hub.current_endpoints();
            return Ok(MigrateEndpointResponse {
                endpoint_version: ep_ver,
                netmap_version: self.store.current_netmap_version(),
                control_tcp_endpoint: ctrl_ep,
                stun_udp_endpoint: stun_eps.into_iter().next().unwrap_or_default(),
                transition_deadline_at_ms: Some(new_deadline),
            });
        }

        validate_migration_target(
            &self.config,
            current_tls_mode,
            old_tcp_port,
            target_tcp_port,
            target_tls_mode,
        )?;

        let new_host = match req.host.as_deref() {
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(AppError::invalid_argument(
                        "migrate-endpoint --host cannot be empty",
                    ));
                }
                trimmed
            }
            None => current_public_host.as_str(),
        };

        let grace_secs = req
            .transition_window_secs
            .unwrap_or(DEFAULT_MIGRATION_GRACE_SECS)
            .clamp(5, MAX_MIGRATION_GRACE_SECS);
        let deadline_ms = now_ms.saturating_add(grace_secs.saturating_mul(1_000));

        let new_tcp_listener = if target_tcp_port == old_tcp_port {
            None
        } else {
            let ip: IpAddr = self
                .config
                .control_bind_ip
                .parse()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            Some(bind_control_tcp_listener(SocketAddr::new(ip, target_tcp_port)).await?)
        };
        let new_udp_socket = if target_stun_port == old_stun_port {
            None
        } else {
            let ip: IpAddr = self
                .config
                .stun_bind_ip
                .parse()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            Some(bind_stun_udp_socket(SocketAddr::new(ip, target_stun_port)).await?)
        };

        // Update leaf certificate SANs reusing the active keypair BEFORE spawning any new TLS
        // listener so clients pinning SPKI verify the migrated `--host` seamlessly (`HR-W21-11`).
        if target_tls_mode == TlsMode::IpPinned
            && (new_host != current_public_host || target_tls_mode != current_tls_mode)
        {
            let sans = self.build_tls_sans(new_host, target_tls_mode);
            let _identity = self.store.reissue_cert_same_key(&sans, 90, actor)?;
            self.acme.reload_from_store()?;
        }

        if let Some(listener) = new_tcp_listener {
            let new_cancel = self.shutdown.child_token();
            self.spawn_control_accept_loop(listener, new_cancel.clone(), target_tls_mode)?;
            if let Ok(mut guard) = self.ports.lock() {
                let prev_tcp = guard.active_tcp_cancel.clone();
                if let Some(stale) = guard.previous_tcp_cancel.replace(prev_tcp) {
                    stale.cancel();
                }
                guard.active_tcp_cancel = new_cancel;
                guard.control_tcp_port = target_tcp_port;
                guard.tls_mode = target_tls_mode;
                guard.public_host = new_host.to_owned();
            }
        } else if let Ok(mut guard) = self.ports.lock() {
            guard.tls_mode = target_tls_mode;
            guard.public_host = new_host.to_owned();
        }
        if let Some(sock) = new_udp_socket {
            let new_cancel = self.shutdown.child_token();
            self.spawn_stun_loop(sock, new_cancel.clone());
            if let Ok(mut guard) = self.ports.lock() {
                let prev_stun = guard.active_stun_cancel.clone();
                if let Some(stale) = guard.previous_stun_cancel.replace(prev_stun) {
                    stale.cancel();
                }
                guard.active_stun_cancel = new_cancel;
                guard.stun_udp_port = target_stun_port;
            }
        }
        if let Ok(mut guard) = self.ports.lock() {
            guard.transition_deadline_at_ms = Some(deadline_ms);
        }

        let new_ctrl_ep = format_host_port(new_host, target_tcp_port);
        let new_stun_ep = format_host_port(new_host, target_stun_port);
        let ep_ver = self.netmap_hub.update_advertised_endpoints(
            Some(new_ctrl_ep.clone()),
            Some(new_ctrl_ep.clone()),
            Some(vec![new_stun_ep.clone()]),
        );

        // Notify peers on old sockets cleanly & bump monotonic netmap_version (`US-074 AC4/AC5`)
        self.relay_hub.broadcast_migrating_notice();
        let netmap_ver = self.store.allocate_next_netmap_version()?;
        if let Err(err) = self.netmap_hub.broadcast_snapshot(netmap_ver) {
            tracing::warn!(
                component = "listener_set",
                event = "migration_broadcast_failed",
                error = %err,
                "failed broadcasting migration netmap snapshot"
            );
        }
        self.store
            .record_audit_best_effort(&mesh_store::AuditEventInput {
                occurred_at_ms: now_ms,
                actor,
                action: "server_endpoint_migrated",
                target: &new_ctrl_ep,
                outcome: "success",
                metadata: json!({
                    "endpoint_version": ep_ver,
                    "netmap_version": netmap_ver,
                    "old_control_port": old_tcp_port,
                    "new_control_port": target_tcp_port,
                    "old_stun_port": old_stun_port,
                    "new_stun_port": target_stun_port,
                    "tls_mode": target_tls_mode.as_str(),
                    "transition_deadline_at_ms": deadline_ms,
                }),
            });

        Ok(MigrateEndpointResponse {
            endpoint_version: ep_ver,
            netmap_version: netmap_ver,
            control_tcp_endpoint: new_ctrl_ep,
            stun_udp_endpoint: new_stun_ep,
            transition_deadline_at_ms: Some(deadline_ms),
        })
    }

    /// Evaluates whether the dual-listener migration cutover grace window may retire old sockets cleanly.
    pub fn check_migration_cutover(&self) -> bool {
        let now_ms = self.store.clock().now_unix_ms();
        let active_registered = self
            .store
            .list_nodes()
            .map(|nodes| {
                u64::try_from(
                    nodes
                        .into_iter()
                        .filter(|n| n.status == mesh_store::NodeStatus::Active)
                        .count(),
                )
                .unwrap_or(u64::MAX)
            })
            .unwrap_or(u64::MAX);
        let (_, acked, _) = self.netmap_hub.migration_ack_progress();
        let Ok(mut guard) = self.ports.lock() else {
            return false;
        };
        let Some(deadline_ms) = guard.transition_deadline_at_ms else {
            return false;
        };
        let all_acked =
            active_registered > 0 && u64::try_from(acked).unwrap_or(u64::MAX) >= active_registered;
        if now_ms < deadline_ms && !all_acked {
            return false;
        }
        if let Some(old_tcp) = guard.previous_tcp_cancel.take() {
            old_tcp.cancel();
        }
        if let Some(old_stun) = guard.previous_stun_cancel.take() {
            old_stun.cancel();
        }
        guard.transition_deadline_at_ms = None;
        true
    }

    fn spawn_control_accept_loop(
        &self,
        listener: TcpListener,
        cancel: CancellationToken,
        tls_mode: TlsMode,
    ) -> AppResult<()> {
        let tls_acceptor = if tls_mode == TlsMode::ReverseProxy {
            None
        } else {
            let rustls_cfg: Arc<RustlsServerConfig> = self.acme.build_rustls_config()?;
            Some(TlsAcceptor::from(rustls_cfg))
        };

        let router = self.router.clone();
        let tracker = self.tracker.clone();
        self.control_healthy.store(true, Ordering::SeqCst);

        self.tracker.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, peer_addr)) => {
                                let conn_router = router.clone();
                                let conn_acceptor = tls_acceptor.clone();
                                let conn_cancel = cancel.clone();
                                tracker.spawn(async move {
                                    serve_accepted_connection(
                                        stream,
                                        peer_addr,
                                        conn_acceptor,
                                        tls_mode,
                                        conn_router,
                                        conn_cancel,
                                    )
                                    .await;
                                });
                            }
                            Err(err) => {
                                tracing::warn!(
                                    component = "listener_set",
                                    event = "tcp_accept_error",
                                    error = %err,
                                    "Control TCP accept error"
                                );
                            }
                        }
                    }
                }
            }
        });
        Ok(())
    }

    fn spawn_stun_loop(&self, socket: Arc<UdpSocket>, cancel: CancellationToken) {
        let clock: Arc<dyn Clock> = Arc::new(mesh_core::SystemClock::new());
        let pps = self.config.stun_pps_limit_per_ip;
        let stun_state = Arc::clone(&self.stun_state);
        self.tracker.spawn(async move {
            run_stun_socket_loop(socket, pps, clock, stun_state, cancel).await;
        });
    }
}

async fn bind_control_tcp_listener(addr: SocketAddr) -> AppResult<TcpListener> {
    TcpListener::bind(addr).await.map_err(|err| {
        AppError::conflict(format!("port conflict or bind error on TCP {addr}: {err}"))
    })
}

async fn serve_accepted_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
    tls_mode: TlsMode,
    router: Router,
    cancel: CancellationToken,
) {
    let connect_budget = Duration::from_millis(CONNECT_TIMEOUT_MS);
    match tls_acceptor {
        Some(acceptor) => {
            let Ok(Ok(tls_stream)) = timeout(connect_budget, acceptor.accept(stream)).await else {
                return;
            };
            let exporter_b64 = extract_tls_exporter_binding(tls_stream.get_ref().1)
                .ok()
                .map(|raw| BASE64_STANDARD.encode(raw));
            let ctx = ConnectionTlsContext {
                peer_addr,
                tls_exporter_b64: exporter_b64,
                listener_tls_mode: tls_mode,
            };
            serve_http1_with_upgrades(tls_stream, ctx, router, cancel).await;
        }
        None => {
            let ctx = ConnectionTlsContext {
                peer_addr,
                tls_exporter_b64: None,
                listener_tls_mode: tls_mode,
            };
            serve_http1_with_upgrades(stream, ctx, router, cancel).await;
        }
    }
}

async fn serve_http1_with_upgrades<S>(
    io: S,
    ctx: ConnectionTlsContext,
    router: Router,
    cancel: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
        let router_clone = router.clone();
        let ctx_clone = ctx.clone();
        async move {
            let (parts, incoming) = req.into_parts();
            let mut axum_req = Request::from_parts(parts, Body::new(incoming));
            axum_req.extensions_mut().insert(ctx_clone);
            TowerToHyperService::new(router_clone).call(axum_req).await
        }
    });

    let conn = hyper_http1::Builder::new()
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades();
    tokio::pin!(conn);

    tokio::select! {
        biased;
        () = cancel.cancelled() => {
            conn.as_mut().graceful_shutdown();
            if timeout(Duration::from_secs(2), &mut conn).await.is_err() {
                tracing::debug!(
                    component = "listener_set",
                    event = "conn_graceful_shutdown_timeout",
                    "control TLS connection did not finish closing within 2s grace"
                );
            }
        }
        _ = &mut conn => {}
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn validate_migration_target(
    config: &ServerConfig,
    current_tls_mode: TlsMode,
    old_tcp_port: u16,
    target_tcp_port: u16,
    target_tls_mode: TlsMode,
) -> AppResult<()> {
    if target_tls_mode == TlsMode::ReverseProxy {
        if config.trusted_proxies.is_empty() {
            return Err(AppError::invalid_argument(
                "reverse_proxy mode requires non-empty trusted_proxies list (SEC-05)",
            ));
        }
        let bind_is_loopback = config
            .control_bind_ip
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        if !bind_is_loopback {
            return Err(AppError::permission_denied(format!(
                "reverse_proxy mode requires loopback control_bind_ip; refusing non-loopback bind `{}` (SEC-05)",
                config.control_bind_ip
            )));
        }
    }
    if target_tls_mode == TlsMode::Acme {
        let domain = config.acme.domain.as_deref().map(str::trim).unwrap_or("");
        if domain.is_empty() {
            return Err(AppError::invalid_argument(
                "acme mode requires non-empty acme.domain in server configuration",
            ));
        }
        if config.acme.challenge == AcmeChallengeKind::TlsAlpn01
            && target_tcp_port != DEFAULT_CONTROL_TCP_PORT
        {
            return Err(AppError::invalid_argument(format!(
                "ACME TLS-ALPN-01 requires tcp_port == {DEFAULT_CONTROL_TCP_PORT}; use DNS-01 or ReverseProxy for port {target_tcp_port}"
            )));
        }
    }
    if (current_tls_mode == TlsMode::ReverseProxy) != (target_tls_mode == TlsMode::ReverseProxy)
        && target_tcp_port == old_tcp_port
    {
        return Err(AppError::invalid_argument(
            "switching between TLS and reverse_proxy requires binding a new tcp_port for dual-listener migration",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use tempfile::TempDir;
    use tokio::net::{TcpListener, UdpSocket};

    use super::bind_control_tcp_listener;
    use crate::stun_service::bind_stun_udp_socket;

    #[tokio::test]
    async fn test_pre_bind_detects_tcp_and_udp_port_conflicts_cleanly() {
        // Arrange
        let occupied_tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let tcp_port = occupied_tcp.local_addr().expect("addr").port();
        let occupied_udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let udp_port = occupied_udp.local_addr().expect("addr").port();

        // Act
        let tcp_err =
            bind_control_tcp_listener(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), tcp_port))
                .await;
        let udp_err =
            bind_stun_udp_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_port)).await;

        // Assert: fails fast with conflict instead of stealing ports (`US-046 AC5`)
        assert!(tcp_err.is_err());
        assert!(udp_err.is_err());
    }

    #[tokio::test]
    async fn test_migration_cutover_waits_for_deadline_when_active_nodes_offline() {
        // Arrange
        let dir = TempDir::new().expect("tempdir");
        let start_ms = 1_762_958_151_000_u64;
        let clock = Arc::new(mesh_core::FakeClock::new(start_ms));
        let store = Arc::new(
            mesh_store::ControlStore::open_with_clock(
                mesh_store::ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                clock.clone(),
            )
            .expect("open store"),
        );

        let token_hash = mesh_crypto::sha256_digest(b"mpk_cutover_test_token");
        store
            .create_preauth_key(
                &mesh_store::CreatePreAuthKeyInput {
                    key_id: mesh_core::KeyId::new_v7(start_ms),
                    token_hash,
                    label: None,
                    bound_node_name: None,
                    reusable: false,
                    max_uses: None,
                    ephemeral: false,
                    ephemeral_timeout_secs: None,
                    ttl_secs: 3_600,
                    now_unix_ms: start_ms,
                },
                "admin",
            )
            .expect("create key");
        let node_kp = mesh_crypto::NodeKeypair::generate();
        let disco_kp = mesh_crypto::DiscoKeypair::generate();
        store
            .register_node(&mesh_store::RegisterNodeInput {
                pubkey: node_kp.public_key(),
                disco_pubkey: disco_kp.public_key(),
                previous_node_pubkey: None,
                requested_name: mesh_core::NodeName::parse("sleeping-laptop").expect("name"),
                preauth_token_hash: token_hash,
                public_control_host: "127.0.0.1",
                domain_suffix: "mesh.internal",
                os_arch: "linux/amd64",
                agent_version: "0.1.0",
                protocol_version: 1,
                node_key_ttl_ms: mesh_store::DEFAULT_NODE_KEY_TTL_MS,
                now_unix_ms: start_ms,
            })
            .expect("register offline node");

        let tcp_probe = TcpListener::bind("127.0.0.1:0").await.expect("tcp0");
        let new_tcp_probe = TcpListener::bind("127.0.0.1:0").await.expect("tcp1");
        let udp_probe = UdpSocket::bind("127.0.0.1:0").await.expect("udp0");
        let tcp_port = tcp_probe.local_addr().expect("addr").port();
        let new_tcp_port = new_tcp_probe.local_addr().expect("addr").port();
        let udp_port = udp_probe.local_addr().expect("addr").port();
        drop((tcp_probe, new_tcp_probe, udp_probe));

        let cfg = Arc::new(crate::config::ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            control_tcp_port: tcp_port,
            stun_bind_ip: "127.0.0.1".to_owned(),
            stun_udp_port: udp_port,
            ..crate::config::ServerConfig::default()
        });
        let acme = crate::acme::AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let netmap_hub = Arc::new(crate::netmap_hub::NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(crate::relay_hub::RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(crate::rate_limit::RateLimiter::new(
            crate::rate_limit::ClientIpExtractor::new(cfg.tls_mode, cfg.trusted_proxy_set()),
        ));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let tracker = tokio_util::task::TaskTracker::new();
        let ctrl_state = crate::control_handlers::ControlAppState {
            config: cfg,
            trusted_proxies: Arc::new(Default::default()),
            store: store.clone(),
            rate_limiter,
            challenges: Arc::new(crate::control_handlers::PendingChallengeStore::new()),
            netmap_hub,
            relay_hub,
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = super::ListenerSet::bind_and_start(ctrl_state, acme)
            .await
            .expect("bind listeners");

        // Act: start 30s migration window with 1 active node registered and 0 online
        listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    tcp_port: Some(mesh_core::Port::from_u16(new_tcp_port).expect("port")),
                    stun_port: None,
                    host: None,
                    tls_mode: None,
                    transition_window_secs: Some(30),
                    extend_window_secs: None,
                },
                "admin",
            )
            .await
            .expect("start migration");

        // Assert: must NOT retire old listener before deadline when offline active peers exist (`HR-S1-02`)
        assert!(!listeners.check_migration_cutover());
        clock.advance(29_000);
        assert!(!listeners.check_migration_cutover());
        clock.advance(2_000);
        assert!(listeners.check_migration_cutover());

        // Verify netmap_version bumped, port conflict leaves existing listener untouched, and
        // switching to ReverseProxy without trusted_proxies or new tcp_port is rejected (`US-074`)
        assert!(store.current_netmap_version() >= 2);
        let occupied = TcpListener::bind("127.0.0.1:0").await.expect("occupied");
        let occupied_port = occupied.local_addr().expect("occ addr").port();
        let conflict = listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    tcp_port: Some(mesh_core::Port::from_u16(occupied_port).expect("port")),
                    stun_port: None,
                    host: None,
                    tls_mode: None,
                    transition_window_secs: Some(30),
                    extend_window_secs: None,
                },
                "admin",
            )
            .await;
        assert!(conflict.is_err());
        assert_eq!(listeners.active_ports().0, new_tcp_port);

        let proxy_err = listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    tcp_port: None,
                    stun_port: None,
                    host: None,
                    tls_mode: Some("reverse_proxy".to_owned()),
                    transition_window_secs: None,
                    extend_window_secs: None,
                },
                "admin",
            )
            .await;
        assert!(proxy_err.is_err());
        assert_eq!(
            listeners.active_tls_mode(),
            crate::config::TlsMode::IpPinned
        );

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn test_migrate_host_reissues_cert_and_dual_listener_validation_and_tls_modes() {
        // Arrange (`HR-W21-11`, `HR-W21-05`)
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let bad_proxy_cfg = crate::config::ServerConfig {
            control_bind_ip: "203.0.113.1".to_owned(),
            trusted_proxies: vec!["127.0.0.1".parse().expect("proxy ip")],
            ..crate::config::ServerConfig::default()
        };
        let non_loopback_err = super::validate_migration_target(
            &bad_proxy_cfg,
            crate::config::TlsMode::IpPinned,
            8443,
            8444,
            crate::config::TlsMode::ReverseProxy,
        )
        .expect_err("non-loopback reverse proxy bind must fail");
        assert_eq!(
            non_loopback_err.kind(),
            mesh_core::ErrorKind::PermissionDenied
        );

        let missing_domain_cfg = crate::config::ServerConfig::default();
        let acme_err = super::validate_migration_target(
            &missing_domain_cfg,
            crate::config::TlsMode::IpPinned,
            8443,
            443,
            crate::config::TlsMode::Acme,
        )
        .expect_err("acme without domain must fail");
        assert_eq!(acme_err.kind(), mesh_core::ErrorKind::InvalidArgument);

        let dir = TempDir::new().expect("tempdir");
        let start_ms = 1_762_958_151_000_u64;
        let clock = Arc::new(mesh_core::FakeClock::new(start_ms));
        let store = Arc::new(
            mesh_store::ControlStore::open_with_clock(
                mesh_store::ControlStoreConfig {
                    db_path: dir.path().join("control.redb"),
                    emergency_revocations_path: dir.path().join("emergency-revocations.bin"),
                },
                "10.100.0.0/24",
                Arc::clone(&clock) as Arc<dyn mesh_core::Clock>,
            )
            .expect("open store"),
        );
        let init_id = store
            .ensure_or_init_identity(&["127.0.0.1".to_owned()], 365)
            .expect("init identity");

        let tcp0 = TcpListener::bind("127.0.0.1:0").await.expect("tcp0");
        let tcp1 = TcpListener::bind("127.0.0.1:0").await.expect("tcp1");
        let tcp2 = TcpListener::bind("127.0.0.1:0").await.expect("tcp2");
        let udp0 = UdpSocket::bind("127.0.0.1:0").await.expect("udp0");
        let port0 = tcp0.local_addr().expect("a0").port();
        let port1 = tcp1.local_addr().expect("a1").port();
        let port2 = tcp2.local_addr().expect("a2").port();
        let stun_port = udp0.local_addr().expect("u0").port();
        drop((tcp0, tcp1, tcp2, udp0));

        let cfg = Arc::new(crate::config::ServerConfig {
            control_bind_ip: "127.0.0.1".to_owned(),
            stun_bind_ip: "127.0.0.1".to_owned(),
            public_host: "127.0.0.1".to_owned(),
            control_tcp_port: port0,
            stun_udp_port: stun_port,
            trusted_proxies: vec!["127.0.0.1".parse().expect("proxy ip")],
            ..crate::config::ServerConfig::default()
        });
        let acme = crate::acme::AcmeManager::initialize(&cfg, store.clone()).expect("init acme");
        let netmap_hub = Arc::new(crate::netmap_hub::NetmapHub::new(
            store.clone(),
            cfg.public_control_endpoint(),
            cfg.public_control_endpoint(),
            vec![cfg.public_stun_endpoint()],
            cfg.domain_suffix.clone(),
        ));
        let relay_hub = Arc::new(crate::relay_hub::RelayHub::new(
            store.clone(),
            cfg.relay_bytes_per_sec,
            cfg.relay_global_bytes_per_sec,
        ));
        let rate_limiter = Arc::new(crate::rate_limit::RateLimiter::new(
            crate::rate_limit::ClientIpExtractor::new(cfg.tls_mode, cfg.trusted_proxy_set()),
        ));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let tracker = tokio_util::task::TaskTracker::new();
        let ctrl_state = crate::control_handlers::ControlAppState {
            config: cfg.clone(),
            trusted_proxies: Arc::new(cfg.trusted_proxy_set()),
            store: store.clone(),
            rate_limiter,
            challenges: Arc::new(crate::control_handlers::PendingChallengeStore::new()),
            netmap_hub,
            relay_hub,
            ws_tracker: tracker.clone(),
            shutdown: shutdown.clone(),
        };
        let listeners = super::ListenerSet::bind_and_start(ctrl_state, acme)
            .await
            .expect("bind");

        // Act 1: host-only migration reissues cert with same SPKI pin and updates active_public_host
        let host_mig = listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    tcp_port: None,
                    stun_port: None,
                    host: Some("edge-2.example.net".to_owned()),
                    tls_mode: None,
                    transition_window_secs: Some(30),
                    extend_window_secs: None,
                },
                "admin",
            )
            .await
            .expect("migrate host");
        assert_eq!(
            host_mig.control_tcp_endpoint,
            format!("edge-2.example.net:{port0}")
        );
        assert_eq!(listeners.active_public_host(), "edge-2.example.net");
        let reissued = store.load_active_identity().expect("reissued id");
        assert_eq!(reissued.spki_pin, init_id.spki_pin);
        assert_ne!(reissued.cert_chain_der, init_id.cert_chain_der);

        // Act 2: follow-up port migration preserves active_public_host across migrations
        let port_mig = listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    tcp_port: Some(mesh_core::Port::from_u16(port1).expect("port1")),
                    stun_port: None,
                    host: None,
                    tls_mode: None,
                    transition_window_secs: Some(30),
                    extend_window_secs: None,
                },
                "admin",
            )
            .await
            .expect("migrate port preserving host");
        assert_eq!(
            port_mig.control_tcp_endpoint,
            format!("edge-2.example.net:{port1}")
        );

        // Act 3: migrate IpPinned(port1) -> ReverseProxy(port2) on loopback with trusted_proxies
        let proxy_mig = listeners
            .migrate_endpoints(
                &mesh_proto::admin_ipc::MigrateEndpointRequest {
                    tcp_port: Some(mesh_core::Port::from_u16(port2).expect("port2")),
                    stun_port: None,
                    host: None,
                    tls_mode: Some("reverse_proxy".to_owned()),
                    transition_window_secs: Some(60),
                    extend_window_secs: None,
                },
                "admin",
            )
            .await
            .expect("migrate to reverse_proxy");
        assert_eq!(
            listeners.active_tls_mode(),
            crate::config::TlsMode::ReverseProxy
        );
        assert_eq!(
            proxy_mig.control_tcp_endpoint,
            format!("edge-2.example.net:{port2}")
        );

        // Plaintext HTTP succeeds on ReverseProxy listener `port2`, while old TLS listener `port1`
        // still runs TLS (`HR-W21-05`) and rejects plaintext HTTP.
        let kp = mesh_crypto::NodeKeypair::generate();
        let dkp = mesh_crypto::DiscoKeypair::generate();
        let ch_json = serde_json::to_vec(&mesh_proto::control::ChallengeRequest {
            node_pubkey: kp.public_key(),
            disco_pubkey: dkp.public_key(),
            protocol_version: 1,
            agent_version: "0.1.0".to_owned(),
            os: mesh_proto::control::TargetOs::Linux,
            arch: mesh_proto::control::TargetArch::Amd64,
        })
        .expect("ch json");
        let http_req = format!(
            "POST /v1/auth/challenge HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            ch_json.len()
        );

        let mut proxy_sock = tokio::net::TcpStream::connect(("127.0.0.1", port2))
            .await
            .expect("connect reverse_proxy listener");
        proxy_sock
            .write_all(http_req.as_bytes())
            .await
            .expect("write hdrs");
        proxy_sock.write_all(&ch_json).await.expect("write body");
        let mut resp_buf = Vec::new();
        proxy_sock
            .read_to_end(&mut resp_buf)
            .await
            .expect("read proxy resp");
        let resp_str = String::from_utf8_lossy(&resp_buf);
        assert!(
            resp_str.starts_with("HTTP/1.1 200"),
            "reverse_proxy listener must accept plaintext HTTP; got: {resp_str}"
        );

        let mut tls_sock = tokio::net::TcpStream::connect(("127.0.0.1", port1))
            .await
            .expect("connect still-active TLS listener");
        let _ignored = tls_sock.write_all(http_req.as_bytes()).await;
        let mut tls_buf = Vec::new();
        let read_res = tls_sock.read_to_end(&mut tls_buf).await;
        assert!(
            read_res.is_err() || !String::from_utf8_lossy(&tls_buf).starts_with("HTTP/1.1 200"),
            "old IpPinned listener must reject plaintext HTTP during dual-listener window"
        );

        shutdown.cancel();
        tracker.close();
        tracker.wait().await;
    }
}
