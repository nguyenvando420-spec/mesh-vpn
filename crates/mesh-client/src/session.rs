//! Shared OS-neutral client session supervisor orchestrating identity registration, Control TLS/WS
//! streams, Blind Relay, DatapathEngine, RoamingLoop, and bounded shutdown (`<= 5 s`, `US-099`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};
use zeroize::Zeroize as _;

use mesh_core::clock::Clock;
use mesh_core::defaults::{
    DEFAULT_OVERLAY_CIDR, GRACEFUL_SHUTDOWN_BUDGET_MS, RELAY_QUEUE_CAPACITY,
};
use mesh_core::{AppError, AppResult, ErrorKind, NodeId, NodeName, OverlayCidr, OverlayIp, Port};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_datapath::{
    DatapathCommand, DatapathConfig, DatapathEngine, DatapathEngineOptions, DatapathHandle,
    DiscoConfig, DnsPacketInterceptor, MagicSocketConfig, RebindCommand, RebindHandle, RelayClient,
    RelayClientConfig, RelayClientOptions, RelayConnectionState, RelayEvent, StunClientConfig,
    is_protocol_incompatible_error,
};
use mesh_net::endpoint_filter::detect_overlay_subnet_conflict;
use mesh_net::keystore::StoredNodeIdentity;
use mesh_net::nat64::{NoopSocketProtector, SocketProtector};
use mesh_net::netmon::{NetMonitor, NetworkChangeEvent};
use mesh_net::tun::TunConfig;
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentRotateKeyRequest, AgentSetRequest, AgentUpRequest, BugreportResponse,
    DaemonState, TlsAuthMode,
};
use mesh_proto::control::{RegisterNodeRequest, RegisterNodeResponse, TerminationReason};
use mesh_proto::netmap::NetmapSnapshot;

use crate::config::{
    BootstrapConfig, ClientRuntimeConfig, derive_overlay_dns_ip, detect_default_node_name,
    split_host_port, validate_tls_trust_policy,
};
use crate::control_loop::{
    ControlDialOptions, ControlLoop, ControlLoopContext, ControlWakeSignal,
    build_relay_client_config_for_runtime,
};
use crate::diagnostics::{BugreportBuildOptions, create_bugreport_tar_bundle};
use crate::hooks::{ClientPlatformHooks, ClientStateStore};
use crate::netmap_cache::{DEFAULT_KEY_EXPIRY_GRACE_HOURS, NetmapCacheFile};
use crate::ping_probe::PingProbe;
use crate::roaming_loop::{NETWORK_CHANGE_CHANNEL_CAPACITY, RoamingLoop};
use crate::state::ClientRuntimeState;

const SUPERVISOR_CMD_CAPACITY: usize = 32;
const WS_CLOSE_PHASE_WAIT: Duration = Duration::from_millis(50);
const SESSION_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const BUGREPORT_NETCHECK_TIMEOUT: Duration = Duration::from_secs(2);
const RELAY_EVENT_CAPACITY: usize = RELAY_QUEUE_CAPACITY / 2;
const PROTOCOL_INCOMPATIBLE_RELAY_MSG: &str =
    "protocol incompatible (agent upgrade required): blind relay rejected client";

/// Commands routed from IPC (`meshd`) or Mobile FFI bridges (`WP-M-A4`) to the session supervisor.
#[derive(Debug)]
pub enum ClientCommand {
    /// Registers (if needed) and starts the overlay tunnel session (`POST /v1/agent/up`).
    Up {
        /// Registration and Control endpoint parameters.
        req: AgentUpRequest,
        /// Reply channel receiving outcome.
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Gracefully stops the active tunnel session (`POST /v1/agent/down`).
    Down {
        /// Reply channel receiving outcome.
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Forces idempotent platform route/TUN cleanup (`POST /v1/agent/cleanup`).
    Cleanup {
        /// Reply channel receiving outcome.
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Updates Control server endpoint / pins cleanly (`POST /v1/agent/set`).
    Set {
        /// Updated endpoint / pin parameters.
        req: AgentSetRequest,
        /// Reply channel receiving outcome.
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Rotates WireGuard identity keypair with `previous_node_pubkey` (`POST /v1/agent/rotate-key`).
    RotateKey {
        /// Optional pre-auth key authorizing rotation.
        req: AgentRotateKeyRequest,
        /// Reply channel receiving outcome.
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Executes zero-TUN Control enrollment or key rotation (iOS Container App Process 1 flow).
    EnrollOrRotate {
        /// Enrollment or rotation parameters.
        req: EnrollOrRotateRequest,
        /// Reply channel receiving assigned registration metadata.
        reply: oneshot::Sender<AppResult<EnrollOrRotateResult>>,
    },
    /// Generates a scrubbed streaming `.tar` diagnostic archive (`POST /v1/agent/bugreport`).
    Bugreport {
        /// Reply channel receiving archive path, size, and redaction count.
        reply: oneshot::Sender<AppResult<BugreportResponse>>,
    },
}

/// Request for standalone zero-TUN Control enrollment or key rotation (`ADR-014`).
pub struct EnrollOrRotateRequest {
    /// Control-plane `<host_or_ip>:<port>` endpoint.
    pub server_endpoint: String,
    /// Optional port override applied to `server_endpoint`.
    pub port_override: Option<Port>,
    /// Optional pinned server certificate SPKI fingerprint (`None` selects `system_ca`).
    pub server_pin: Option<mesh_core::SpkiPin>,
    /// Optional requested RFC 1123 node label.
    pub node_name: Option<NodeName>,
    /// Single-use or reusable pre-authentication key (redacted in Debug, zeroized on Drop).
    pub preauth_key: Option<String>,
    /// When `true`, rotates existing local identity keys while sending `previous_node_pubkey`.
    pub rotate_existing_keypair: bool,
}

impl Drop for EnrollOrRotateRequest {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.preauth_key {
            key.zeroize();
        }
    }
}

impl std::fmt::Debug for EnrollOrRotateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollOrRotateRequest")
            .field("server_endpoint", &self.server_endpoint)
            .field("port_override", &self.port_override)
            .field("server_pin", &self.server_pin)
            .field("node_name", &self.node_name)
            .field(
                "preauth_key",
                &self.preauth_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("rotate_existing_keypair", &self.rotate_existing_keypair)
            .finish()
    }
}

/// Summary returned after zero-TUN enrollment or key rotation persists updated trust state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollOrRotateResult {
    /// Control-assigned node UUID.
    pub node_id: NodeId,
    /// Control-assigned RFC 1123 node label.
    pub node_name: NodeName,
    /// Assigned mesh FQDN.
    pub fqdn: String,
    /// Assigned local overlay IPv4 address.
    pub overlay_ip: OverlayIp,
    /// Mesh overlay subnet CIDR.
    pub overlay_cidr: OverlayCidr,
    /// Optional Control-enforced node identity key expiration UTC ms.
    pub key_expires_at_ms: Option<u64>,
    /// Initial validated Netmap snapshot received at registration time.
    pub netmap: NetmapSnapshot,
}

/// Parameterized startup and budget configuration for [`ClientSessionSupervisor`].
#[derive(Clone)]
pub struct ClientSessionOptions {
    /// Desktop vs Mobile frame, timer, heartbeat, and bugreport budgets (`ADR-016`).
    pub runtime_cfg: ClientRuntimeConfig,
    /// Optional initial physical underlay interface index.
    pub underlay_if_index: Option<u32>,
    /// Optional Linux policy routing `SO_MARK` (`REL-09`).
    pub linux_fwmark: Option<u32>,
    /// Requested TUN interface name hint (`mesh0`, `utun`, `tun0`, `MeshVPN`).
    pub default_tun_ifname: String,
    /// Output directory for scrubbed streaming bugreport archives.
    pub bugreport_dir: PathBuf,
    /// Binary / component identifier written into bugreport `version.txt`.
    pub bugreport_binary_name: String,
    /// Log directories inspected during bugreport generation (`Desktop`).
    pub log_dirs: Vec<PathBuf>,
    /// Optional in-memory log buffer captured by mobile VPN extensions (`Mobile`).
    pub in_memory_logs: Option<String>,
    /// Optional pre-`CryptokeyValidator` L3 MagicDNS interceptor (`Mobile`).
    pub dns_interceptor: Option<Arc<dyn DnsPacketInterceptor>>,
}

impl std::fmt::Debug for ClientSessionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSessionOptions")
            .field("runtime_cfg", &self.runtime_cfg)
            .field("underlay_if_index", &self.underlay_if_index)
            .field("linux_fwmark", &self.linux_fwmark)
            .field("default_tun_ifname", &self.default_tun_ifname)
            .field("bugreport_dir", &self.bugreport_dir)
            .field("bugreport_binary_name", &self.bugreport_binary_name)
            .field("has_dns_interceptor", &self.dns_interceptor.is_some())
            .finish()
    }
}

impl ClientSessionOptions {
    /// Builds default supervisor options around `runtime_cfg`.
    #[must_use]
    pub fn new(runtime_cfg: ClientRuntimeConfig) -> Self {
        Self {
            runtime_cfg,
            underlay_if_index: None,
            linux_fwmark: None,
            default_tun_ifname: "mesh0".to_owned(),
            bugreport_dir: PathBuf::from("."),
            bugreport_binary_name: "mesh-client".to_owned(),
            log_dirs: Vec::new(),
            in_memory_logs: None,
            dns_interceptor: None,
        }
    }

    /// Configures underlay interface index and optional Linux `fwmark`.
    #[must_use]
    pub fn with_underlay(mut self, if_index: Option<u32>, fwmark: Option<u32>) -> Self {
        self.underlay_if_index = if_index;
        self.linux_fwmark = fwmark;
        self
    }

    /// Sets preferred TUN interface hint (`utun`, `tun0`, `mesh0`, `MeshVPN`).
    #[must_use]
    pub fn with_default_tun_ifname(mut self, name: impl Into<String>) -> Self {
        self.default_tun_ifname = name.into();
        self
    }

    /// Configures bugreport output directory, binary name, log search paths, and memory ring logs.
    #[must_use]
    pub fn with_bugreport(
        mut self,
        dir: PathBuf,
        binary_name: impl Into<String>,
        log_dirs: Vec<PathBuf>,
        in_memory_logs: Option<String>,
    ) -> Self {
        self.bugreport_dir = dir;
        self.bugreport_binary_name = binary_name.into();
        self.log_dirs = log_dirs;
        self.in_memory_logs = in_memory_logs;
        self
    }

    /// Attaches an optional pre-`CryptokeyValidator` L3 [`DnsPacketInterceptor`].
    #[must_use]
    pub fn with_dns_interceptor(mut self, interceptor: Arc<dyn DnsPacketInterceptor>) -> Self {
        self.dns_interceptor = Some(interceptor);
        self
    }
}

struct ActiveTunnelSession {
    cancel: CancellationToken,
    tracker: TaskTracker,
    wake_tx: mpsc::Sender<ControlWakeSignal>,
}

/// OS-neutral VPN lifecycle supervisor shared across `meshd` and Mobile FFI extensions.
pub struct ClientSessionSupervisor {
    options: ClientSessionOptions,
    clock: Arc<dyn Clock>,
    platform_hooks: Arc<dyn ClientPlatformHooks>,
    state_store: Arc<dyn ClientStateStore>,
    runtime: Arc<ClientRuntimeState>,
    roaming_control_tx: mpsc::Sender<NetworkChangeEvent>,
    roaming_control_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
    termination_tx: mpsc::Sender<(TerminationReason, String)>,
    termination_rx: mpsc::Receiver<(TerminationReason, String)>,
    protocol_incompatible_tx: mpsc::Sender<String>,
    protocol_incompatible_rx: mpsc::Receiver<String>,
    cmd_tx: mpsc::Sender<ClientCommand>,
    cmd_rx: mpsc::Receiver<ClientCommand>,
    active_wake_tx: Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>>,
    overlay_route_installed: Arc<AtomicBool>,
    active_session: Option<ActiveTunnelSession>,
}

impl std::fmt::Debug for ClientSessionSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSessionSupervisor")
            .field("runtime_cfg", &self.options.runtime_cfg)
            .field("active_session", &self.active_session.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientSessionSupervisor {
    /// Returns diagnostic subsystem label (`status_label`).
    #[must_use]
    pub fn status_label() -> String {
        format!(
            "client_supervisor:ready({}, {}, {}, {})",
            NetmapCacheStoreLabel::LABEL,
            ControlLoop::status_label(),
            RoamingLoop::status_label(),
            PingProbe::status_label(),
        )
    }

    /// Boots the supervisor, enforces startup platform security checks BEFORE allocating any TUN
    /// or route resources, and hydrates verified offline recovery state (`US-055 AC5`).
    pub fn boot(
        options: ClientSessionOptions,
        clock: Arc<dyn Clock>,
        platform_hooks: Arc<dyn ClientPlatformHooks>,
        state_store: Arc<dyn ClientStateStore>,
    ) -> AppResult<Self> {
        platform_hooks.enforce_startup_security()?;

        let now_ms = clock.now_unix_ms();
        let bootstrap = state_store.load_bootstrap()?;
        let cached_file = load_valid_netmap_cache(state_store.as_ref(), now_ms);

        let runtime = Arc::new(ClientRuntimeState::new_with_now(
            bootstrap,
            Arc::clone(&state_store),
            cached_file.as_ref(),
            options.runtime_cfg.tun_mtu,
            options.runtime_cfg.timer_mode,
            now_ms,
        ));
        hydrate_initial_underlay_metadata(&runtime, &options, platform_hooks.as_ref());

        let (roaming_control_tx, roaming_control_rx) =
            mpsc::channel(NETWORK_CHANGE_CHANNEL_CAPACITY);
        let (termination_tx, termination_rx) = mpsc::channel(4);
        let (protocol_incompatible_tx, protocol_incompatible_rx) = mpsc::channel(4);
        let (cmd_tx, cmd_rx) = mpsc::channel(SUPERVISOR_CMD_CAPACITY);

        Ok(Self {
            options,
            clock,
            platform_hooks,
            state_store,
            runtime,
            roaming_control_tx,
            roaming_control_rx: Arc::new(Mutex::new(roaming_control_rx)),
            termination_tx,
            termination_rx,
            protocol_incompatible_tx,
            protocol_incompatible_rx,
            cmd_tx,
            cmd_rx,
            active_wake_tx: Arc::new(StdMutex::new(None)),
            overlay_route_installed: Arc::new(AtomicBool::new(false)),
            active_session: None,
        })
    }

    /// Returns a cloned shared runtime state handle for IPC/FFI inspection.
    #[must_use]
    pub fn runtime_state(&self) -> Arc<ClientRuntimeState> {
        Arc::clone(&self.runtime)
    }

    /// Returns a clone of the supervisor command channel sender.
    #[must_use]
    pub fn command_sender(&self) -> mpsc::Sender<ClientCommand> {
        self.cmd_tx.clone()
    }

    /// Returns a clone of the debounced roaming-event channel forwarded to `ControlLoop`.
    #[must_use]
    pub fn roaming_control_sender(&self) -> mpsc::Sender<NetworkChangeEvent> {
        self.roaming_control_tx.clone()
    }

    /// Returns a clone of the active `ClientPlatformHooks` implementation.
    #[must_use]
    pub fn platform_hooks(&self) -> Arc<dyn ClientPlatformHooks> {
        Arc::clone(&self.platform_hooks)
    }

    /// Returns whether an active tunnel session tracker is currently running.
    #[must_use]
    pub fn has_active_session(&self) -> bool {
        self.active_session.is_some()
    }

    /// Returns shared wake sender slot for supervisor / roaming coordination tests.
    #[must_use]
    pub fn active_wake_slot(&self) -> Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>> {
        Arc::clone(&self.active_wake_tx)
    }

    /// Returns shared atomic flag tracking whether an overlay route is currently installed.
    #[must_use]
    pub fn overlay_route_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.overlay_route_installed)
    }

    /// Runs RoamingLoop, optional auto-resume, and supervisor command loop until `root_shutdown`.
    pub async fn run(
        self,
        monitor: Arc<dyn NetMonitor>,
        root_shutdown: CancellationToken,
    ) -> AppResult<()> {
        let tracker = TaskTracker::new();
        self.run_with_tracker(monitor, tracker, root_shutdown).await
    }

    /// Runs the supervisor using an externally shared `TaskTracker` (used by `meshd` IPC listeners).
    pub async fn run_with_tracker(
        mut self,
        monitor: Arc<dyn NetMonitor>,
        daemon_tracker: TaskTracker,
        root_shutdown: CancellationToken,
    ) -> AppResult<()> {
        let (roam_rebind_handle, mut roam_rebind_rx) = RebindHandle::channel();
        let (rebind_feedback_tx, rebind_feedback_rx) = mpsc::channel::<AppResult<()>>(8);
        let forward_ctx = self.build_rebind_context(Some(rebind_feedback_tx), &root_shutdown);
        daemon_tracker.spawn(async move {
            forward_rebind_loop(forward_ctx, &mut roam_rebind_rx).await;
        });

        let roaming = RoamingLoop::new(
            monitor,
            Arc::clone(&self.clock),
            roam_rebind_handle,
            self.roaming_control_tx.clone(),
        )
        .with_probe(self.platform_hooks.network_probe())
        .with_runtime(Arc::clone(&self.runtime))
        .with_rebind_feedback(rebind_feedback_rx);
        daemon_tracker.spawn(roaming.run(root_shutdown.clone()));

        self.auto_resume_enrolled_session_best_effort(&root_shutdown)
            .await;

        loop {
            tokio::select! {
                () = root_shutdown.cancelled() => break,
                maybe_term = self.termination_rx.recv() => {
                    if let Some((reason, message)) = maybe_term {
                        self.handle_verified_identity_termination(reason, &message).await;
                    }
                }
                maybe_incompat = self.protocol_incompatible_rx.recv() => {
                    if let Some(message) = maybe_incompat {
                        self.handle_protocol_incompatible(&message).await;
                    }
                }
                maybe_cmd = self.cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.handle_client_command(cmd, &root_shutdown).await,
                        None => break,
                    }
                }
            }
        }

        self.graceful_shutdown_within_5s(daemon_tracker).await
    }

    /// Builds a [`RebindForwardContext`] bound to the supervisor's live handles.
    #[must_use]
    pub fn build_rebind_context(
        &self,
        rebind_feedback_tx: Option<mpsc::Sender<AppResult<()>>>,
        shutdown: &CancellationToken,
    ) -> RebindForwardContext {
        RebindForwardContext {
            runtime: Arc::clone(&self.runtime),
            platform_hooks: Arc::clone(&self.platform_hooks),
            active_wake_tx: Arc::clone(&self.active_wake_tx),
            overlay_route_installed: Arc::clone(&self.overlay_route_installed),
            agent_version: self.options.runtime_cfg.agent_version.clone(),
            rebind_feedback_tx,
            shutdown: shutdown.clone(),
        }
    }

    /// Executes clean teardown upon verified Control or Blind Relay `NodeRevoked` / `NodeKeyExpired`.
    pub async fn handle_verified_identity_termination(
        &mut self,
        reason: TerminationReason,
        message: &str,
    ) {
        let terminated_state = match reason {
            TerminationReason::NodeRevoked => DaemonState::Revoked,
            TerminationReason::NodeKeyExpired => DaemonState::ReauthRequired,
        };
        warn!(
            component = "mesh_client.session",
            event = "supervisor_identity_terminated_teardown",
            reason = ?reason,
            message = %message,
            "tearing down TUN, routes, DNS, and RelayClient after verified server termination"
        );
        {
            let mut g = self.runtime.inner.write().await;
            g.daemon_state = terminated_state;
            g.last_error = Some(message.to_owned());
        }
        if let Err(err) = self.stop_active_session_and_cleanup().await {
            warn!(
                component = "mesh_client.session",
                event = "terminated_teardown_cleanup_warning",
                error = %err,
                "platform cleanup reported warning while tearing down terminated session"
            );
        }
        let mut g = self.runtime.inner.write().await;
        g.daemon_state = terminated_state;
        g.control_connected = false;
        g.last_error = Some(message.to_owned());
    }

    /// Tears down the tunnel cleanly (`<= 5 s`), stops auto-retry, flags `protocol_incompatible`,
    /// and PRESERVES `netmap-cache.json` on disk (`mobile-system-architecture.md` §4.3).
    pub async fn handle_protocol_incompatible(&mut self, message: &str) {
        warn!(
            component = "mesh_client.session",
            event = "supervisor_protocol_incompatible_teardown",
            message = %message,
            "stopping client tunnel and disabling auto-retry after HTTP 400 ProtocolIncompatible; netmap-cache.json preserved"
        );
        {
            let mut g = self.runtime.inner.write().await;
            g.protocol_incompatible = true;
            g.control_connected = false;
            g.last_error = Some(message.to_owned());
        }
        if let Err(err) = self.stop_active_session_and_cleanup().await {
            warn!(
                component = "mesh_client.session",
                event = "protocol_incompatible_cleanup_warning",
                error = %err,
                "platform cleanup reported warning after protocol_incompatible stop"
            );
        }
        let mut g = self.runtime.inner.write().await;
        g.daemon_state = DaemonState::Stopped;
        g.control_connected = false;
        g.protocol_incompatible = true;
        g.last_error = Some(message.to_owned());
    }

    /// Attempts to resume a persisted enrolled session on startup unless key grace expired.
    pub async fn auto_resume_enrolled_session_best_effort(
        &mut self,
        root_shutdown: &CancellationToken,
    ) {
        let now_ms = self.clock.now_unix_ms();
        let (has_enrollment, key_expires_at_ms) = {
            let g = self.runtime.inner.read().await;
            (
                g.bootstrap.server_endpoint.is_some() && g.bootstrap.node_id.is_some(),
                g.key_expires_at_ms.or(g.bootstrap.key_expires_at_ms),
            )
        };
        if !has_enrollment {
            return;
        }
        if !NetmapCacheFile::is_key_usable_offline(
            key_expires_at_ms,
            now_ms,
            DEFAULT_KEY_EXPIRY_GRACE_HOURS,
        ) {
            warn!(
                component = "mesh_client.session",
                event = "auto_resume_rejected_key_expired_offline",
                key_expires_at_ms = ?key_expires_at_ms,
                now_ms,
                "skipping auto-resume: local node key offline 24h grace expired; reauthentication required"
            );
            let mut g = self.runtime.inner.write().await;
            g.daemon_state = DaemonState::ReauthRequired;
            g.control_connected = false;
            g.latest_netmap = None;
            g.last_error = Some(
                "local node key offline 24h grace expired; run `mesh up` to reauthenticate"
                    .to_owned(),
            );
            return;
        }
        if let Err(err) = self.start_enrolled_session(root_shutdown, None).await {
            warn!(
                component = "mesh_client.session",
                event = "auto_resume_failed",
                error = %err,
                "failed auto-resuming persisted overlay session on startup"
            );
            let mut g = self.runtime.inner.write().await;
            g.last_error = Some(err.to_string());
        }
    }

    async fn handle_client_command(
        &mut self,
        cmd: ClientCommand,
        root_shutdown: &CancellationToken,
    ) {
        match cmd {
            ClientCommand::Up { req, reply } => {
                send_reply(reply, self.execute_up(req, root_shutdown).await);
            }
            ClientCommand::Down { reply } => send_reply(reply, self.execute_down().await),
            ClientCommand::Cleanup { reply } => send_reply(reply, self.execute_cleanup().await),
            ClientCommand::Set { req, reply } => send_reply(reply, self.execute_set(req).await),
            ClientCommand::RotateKey { req, reply } => {
                send_reply(reply, self.execute_rotate_key(req, root_shutdown).await);
            }
            ClientCommand::EnrollOrRotate { req, reply } => {
                send_reply(reply, self.enroll_or_rotate_only(req).await);
            }
            ClientCommand::Bugreport { reply } => send_reply(reply, self.execute_bugreport().await),
        }
    }

    /// Executes zero-TUN Control enrollment or key rotation and persists trust + cached Netmap.
    pub async fn enroll_or_rotate_only(
        &mut self,
        req: EnrollOrRotateRequest,
    ) -> AppResult<EnrollOrRotateResult> {
        let (bootstrap, identity, reg) = self.perform_enrollment_or_rotation(req).await?;
        persist_bootstrap_and_runtime(&self.runtime, &bootstrap).await?;
        self.save_initial_netmap_cache_best_effort(Some(&reg.netmap), 1, reg.key_expires_at_ms);

        let mut g = self.runtime.inner.write().await;
        g.key_expires_at_ms = reg.key_expires_at_ms;
        g.latest_netmap = Some(reg.netmap.clone());
        g.overlay_cidr = Some(reg.overlay_cidr);
        g.protocol_incompatible = false;
        g.last_error = None;
        let _keep_id = identity.node_id;

        Ok(EnrollOrRotateResult {
            node_id: reg.node_id,
            node_name: reg.node_name,
            fqdn: reg.fqdn,
            overlay_ip: reg.overlay_ip,
            overlay_cidr: reg.overlay_cidr,
            key_expires_at_ms: reg.key_expires_at_ms,
            netmap: reg.netmap,
        })
    }

    /// Registers (when required) and activates the full TUN/Control/Datapath/Relay session.
    pub async fn execute_up(
        &mut self,
        req: AgentUpRequest,
        root_shutdown: &CancellationToken,
    ) -> AppResult<AgentActionResponse> {
        let endpoint = apply_port_override(&req.server_endpoint, req.port_override)?;
        let tls_auth_mode = if req.server_pin.is_some() {
            TlsAuthMode::SpkiPin
        } else {
            TlsAuthMode::SystemCa
        };
        validate_tls_trust_policy(&endpoint, tls_auth_mode, req.server_pin)?;

        self.stop_active_session_and_cleanup().await?;

        let now_ms = self.clock.now_unix_ms();
        let mut identity = self.state_store.load_or_create_identity(now_ms)?;
        let mut bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        bootstrap.server_endpoint = Some(endpoint);
        bootstrap.tls_auth_mode = tls_auth_mode;
        apply_pin_selection(&mut bootstrap, req.server_pin);

        let desired_name = resolve_desired_node_name(req.node_name.as_ref(), &bootstrap)?;
        let initial_reg = if req.preauth_key.is_some() || bootstrap.node_id.is_none() {
            let preauth_key = req.preauth_key.clone().ok_or_else(|| {
                AppError::invalid_argument(
                    "first enrollment requires --authkey-file or --authkey-stdin",
                )
            })?;
            let reg = self
                .register_identity_with_bootstrap(
                    &bootstrap,
                    &identity.node_keypair,
                    RegisterNodeRequest {
                        preauth_key,
                        node_pubkey: identity.node_keypair.public_key(),
                        disco_pubkey: identity.disco_keypair.public_key(),
                        node_name: desired_name,
                        previous_node_pubkey: None,
                    },
                )
                .await?;
            identity = self.state_store.set_identity_node_id(reg.node_id)?;
            apply_registration_to_bootstrap(&mut bootstrap, &reg);
            Some(reg)
        } else {
            None
        };

        persist_bootstrap_and_runtime(&self.runtime, &bootstrap).await?;
        self.start_enrolled_session_with_identity(root_shutdown, identity, initial_reg)
            .await?;

        let state = { self.runtime.inner.read().await.daemon_state };
        Ok(AgentActionResponse {
            state,
            message: "tunnel up".to_owned(),
        })
    }

    /// Gracefully stops the active session and cleans OS routes/TUN/DNS.
    pub async fn execute_down(&mut self) -> AppResult<AgentActionResponse> {
        self.stop_active_session_and_cleanup().await?;
        Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "tunnel stopped and platform resources cleaned".to_owned(),
        })
    }

    /// Runs idempotent cleanup without stopping if already stopped.
    pub async fn execute_cleanup(&mut self) -> AppResult<AgentActionResponse> {
        self.stop_active_session_and_cleanup().await?;
        Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "platform resource cleanup completed idempotently".to_owned(),
        })
    }

    /// Updates Control endpoint & pins atomically and wakes active Control / Relay tasks.
    pub async fn execute_set(&mut self, req: AgentSetRequest) -> AppResult<AgentActionResponse> {
        let tls_auth_mode = if req.server_pin.is_some() {
            TlsAuthMode::SpkiPin
        } else {
            TlsAuthMode::SystemCa
        };
        validate_tls_trust_policy(&req.server_endpoint, tls_auth_mode, req.server_pin)?;

        let (updated_bootstrap, relay_update) = {
            let mut g = self.runtime.inner.write().await;
            let prev_server_ep = g.bootstrap.server_endpoint.clone();
            g.bootstrap.server_endpoint = Some(req.server_endpoint.clone());
            g.bootstrap.tls_auth_mode = tls_auth_mode;
            apply_pin_selection(&mut g.bootstrap, req.server_pin);
            g.migration_pending_endpoint = None;
            g.protocol_incompatible = false;
            g.state_store.save_bootstrap(&g.bootstrap)?;

            let relay_target = match g.latest_netmap.as_ref() {
                Some(nm)
                    if Some(nm.relay_map.relay_tcp_endpoint.as_str())
                        != prev_server_ep.as_deref() =>
                {
                    nm.relay_map.relay_tcp_endpoint.clone()
                }
                _ => req.server_endpoint.clone(),
            };
            let relay_update = g.relay_handle.as_ref().and_then(|rh| {
                build_relay_client_config_for_runtime(
                    &g.bootstrap,
                    relay_target,
                    (g.underlay_if_index, g.linux_fwmark),
                    self.options.runtime_cfg.agent_version.clone(),
                )
                .ok()
                .map(|cfg| (rh.clone(), cfg))
            });
            (g.bootstrap.clone(), relay_update)
        };
        if let Some((relay_handle, relay_cfg)) = relay_update {
            relay_handle.update_config(relay_cfg);
        }
        if let Some(ref session) = self.active_session
            && let Err(err) = session.wake_tx.try_send(ControlWakeSignal::ConfigUpdated)
        {
            debug!(
                component = "mesh_client.session",
                event = "control_wake_try_send_skipped",
                error = %err,
                "control wake signal skipped after bootstrap update"
            );
        }
        let state = { self.runtime.inner.read().await.daemon_state };
        Ok(AgentActionResponse {
            state,
            message: format!(
                "updated control endpoint to {}",
                updated_bootstrap.server_endpoint.as_deref().unwrap_or("")
            ),
        })
    }

    /// Generates new WireGuard & Disco keypairs, registers with `previous_node_pubkey`, and restarts.
    pub async fn execute_rotate_key(
        &mut self,
        req: AgentRotateKeyRequest,
        root_shutdown: &CancellationToken,
    ) -> AppResult<AgentActionResponse> {
        let (updated_bootstrap, new_identity, reg) = self
            .perform_rotation_with_existing(req.preauth_key.clone())
            .await?;
        persist_bootstrap_and_runtime(&self.runtime, &updated_bootstrap).await?;

        self.stop_active_session_and_cleanup().await?;
        self.start_enrolled_session_with_identity(root_shutdown, new_identity, Some(reg))
            .await?;

        let state = { self.runtime.inner.read().await.daemon_state };
        Ok(AgentActionResponse {
            state,
            message: "node WireGuard identity key rotated cleanly".to_owned(),
        })
    }

    /// Builds a scrubbed streaming POSIX ustar bugreport `.tar` bounded to `max_bugreport_bytes`.
    pub async fn execute_bugreport(&self) -> AppResult<BugreportResponse> {
        let status = self.runtime.build_status_response().await;
        let bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        let protector = self.platform_hooks.socket_protector();

        let netcheck_res = tokio::time::timeout(
            BUGREPORT_NETCHECK_TIMEOUT,
            PingProbe::execute_netcheck_with_protector(&self.runtime, protector),
        )
        .await;
        let netcheck_storage = match netcheck_res {
            Ok(Ok(nc)) => Ok(nc),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err("netcheck timed out during bugreport collection".to_owned()),
        };

        let opts = BugreportBuildOptions {
            output_dir: &self.options.bugreport_dir,
            max_total_bytes: self.options.runtime_cfg.max_bugreport_bytes,
            binary_name: &self.options.bugreport_binary_name,
            agent_version: &self.options.runtime_cfg.agent_version,
            bootstrap: &bootstrap,
            status: &status,
            netcheck: match &netcheck_storage {
                Ok(nc) => Ok(nc),
                Err(msg) => Err(msg.as_str()),
            },
            platform_hooks: self.platform_hooks.as_ref(),
            log_dirs: &self.options.log_dirs,
            in_memory_logs: self.options.in_memory_logs.as_deref(),
            now_unix_ms: self.clock.now_unix_ms(),
        };
        create_bugreport_tar_bundle(opts)
    }

    /// Starts an already-enrolled tunnel session using persisted keystore identity.
    pub async fn start_enrolled_session(
        &mut self,
        root_shutdown: &CancellationToken,
        initial_reg: Option<RegisterNodeResponse>,
    ) -> AppResult<()> {
        let identity = self
            .state_store
            .load_existing_identity()?
            .ok_or_else(|| AppError::invalid_argument("node identity missing; run enrollment"))?;
        self.start_enrolled_session_with_identity(root_shutdown, identity, initial_reg)
            .await
    }

    /// Starts Control, Datapath, Blind Relay, and platform TUN/routes from explicit identity.
    pub async fn start_enrolled_session_with_identity(
        &mut self,
        root_shutdown: &CancellationToken,
        identity: StoredNodeIdentity,
        initial_reg: Option<RegisterNodeResponse>,
    ) -> AppResult<()> {
        let now_ms = self.clock.now_unix_ms();
        let params = self
            .prepare_session_launch_params(&identity, initial_reg.as_ref())
            .await?;

        let tun_cfg = TunConfig::new(
            self.options.default_tun_ifname.clone(),
            params.overlay_ip,
            params.overlay_cidr,
            self.options.runtime_cfg.tun_mtu,
        )?;
        let domain_suffix = params
            .initial_netmap
            .as_ref()
            .map(|n| n.domain_suffix.as_str());
        let tun_outcome = self
            .platform_hooks
            .activate_tun_and_routes(
                tun_cfg,
                params.overlay_cidr,
                params.overlay_dns_ip,
                domain_suffix,
                now_ms,
            )
            .await?;
        self.overlay_route_installed
            .store(tun_outcome.route_installed, Ordering::SeqCst);
        let actual_ifname = tun_outcome.tun.interface_name().to_owned();

        let (underlay_if_index, linux_fwmark, nat64_prefix, timer_mode) =
            self.refresh_underlay_before_bind().await;
        let protector = self
            .platform_hooks
            .socket_protector()
            .unwrap_or_else(|| Arc::new(NoopSocketProtector));

        let (relay_client, relay_handle, engine) = self
            .build_datapath_and_relay(TunnelBindInput {
                params: &params,
                identity: &identity,
                tun_dev: tun_outcome.tun.clone(),
                underlay: (underlay_if_index, linux_fwmark),
                nat64_prefix,
                timer_mode,
                protector,
            })
            .await?;

        let dp_handle = engine.handle();
        let bound_udp_port = engine.local_udp_addr().map_or(0, |a| a.port());
        self.save_initial_netmap_cache_best_effort(
            params.initial_netmap.as_ref(),
            bound_udp_port,
            params.effective_key_expires_at_ms,
        );

        let (session_rebind_handle, session_rebind_rx) = RebindHandle::channel();
        self.record_connecting_state(ConnectingStateRecord {
            params: &params,
            tun_outcome: &tun_outcome,
            actual_ifname,
            bound_udp_port,
            dp_handle: dp_handle.clone(),
            session_rebind_handle,
            relay_handle,
        })
        .await;

        self.spawn_session_tasks(SessionSpawnInput {
            root_shutdown,
            identity,
            initial_netmap: params.initial_netmap,
            relay_client,
            engine,
            apply_dp_handle: dp_handle,
            session_rebind_rx,
        })
        .await;
        Ok(())
    }

    /// Stops any active session cleanly (`WS Close <= 1 s`, platform cleanup `<= 4 s`).
    pub async fn stop_active_session_and_cleanup(&mut self) -> AppResult<()> {
        if let Ok(mut guard) = self.active_wake_tx.lock() {
            *guard = None;
        }
        self.overlay_route_installed.store(false, Ordering::SeqCst);
        self.runtime.notify_ws_close();

        if let Some(session) = self.active_session.take() {
            if let Err(err) = session
                .wake_tx
                .try_send(ControlWakeSignal::GracefulShutdown)
            {
                debug!(
                    component = "mesh_client.session",
                    event = "shutdown_wake_try_send_skipped",
                    error = %err,
                    "control wake channel already closed or full during shutdown"
                );
            }
            tokio::time::sleep(WS_CLOSE_PHASE_WAIT).await;
            session.cancel.cancel();
            session.tracker.close();
            if tokio::time::timeout(SESSION_JOIN_TIMEOUT, session.tracker.wait())
                .await
                .is_err()
            {
                warn!(
                    component = "mesh_client.session",
                    event = "session_tasks_wait_timeout",
                    "timed out waiting for tunnel session tasks during shutdown"
                );
            }
        }

        let dns_clear_res = tokio::time::timeout(
            Duration::from_millis(500),
            self.platform_hooks.dns_hook().clear_mesh_dns(),
        )
        .await;
        if let Ok(Err(err)) = dns_clear_res {
            debug!(
                component = "mesh_client.session",
                event = "dns_clear_warning",
                error = %err,
                "non-fatal warning clearing DNS entries during teardown"
            );
        }

        let cleanup_res = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            self.platform_hooks.deactivate_and_cleanup(),
        )
        .await;

        {
            let mut g = self.runtime.inner.write().await;
            if !matches!(
                g.daemon_state,
                DaemonState::Revoked | DaemonState::ReauthRequired
            ) {
                g.daemon_state = DaemonState::Stopped;
            }
            g.control_connected = false;
            g.datapath_handle = None;
            g.rebind_handle = None;
            g.relay_handle = None;
            g.tun_interface_name = None;
            g.overlay_conflict_warning = None;
            g.lockdown_warning = None;
        }

        match cleanup_res {
            Ok(inner) => inner,
            Err(_) => Err(AppError::unavailable(
                "timed out waiting for platform TUN/route cleanup",
            )),
        }
    }

    async fn graceful_shutdown_within_5s(&mut self, daemon_tracker: TaskTracker) -> AppResult<()> {
        info!(
            component = "mesh_client.session",
            event = "graceful_shutdown_started",
            "starting bounded Graceful Shutdown (<= 5s)"
        );
        if let Err(err) = self.stop_active_session_and_cleanup().await {
            warn!(
                component = "mesh_client.session",
                event = "graceful_shutdown_cleanup_warning",
                error = %err,
                "platform cleanup reported non-fatal warning during shutdown"
            );
        }
        daemon_tracker.close();
        let budget = Duration::from_millis(GRACEFUL_SHUTDOWN_BUDGET_MS);
        if tokio::time::timeout(budget, daemon_tracker.wait())
            .await
            .is_err()
        {
            warn!(
                component = "mesh_client.session",
                event = "graceful_shutdown_tracker_timeout",
                "background task tracker wait exceeded 5s budget"
            );
        }
        info!(
            component = "mesh_client.session",
            event = "graceful_shutdown_completed",
            "client session supervisor shutdown completed cleanly"
        );
        Ok(())
    }

    async fn perform_enrollment_or_rotation(
        &mut self,
        mut req: EnrollOrRotateRequest,
    ) -> AppResult<(BootstrapConfig, StoredNodeIdentity, RegisterNodeResponse)> {
        let endpoint = apply_port_override(&req.server_endpoint, req.port_override)?;
        let tls_auth_mode = if req.server_pin.is_some() {
            TlsAuthMode::SpkiPin
        } else {
            TlsAuthMode::SystemCa
        };
        validate_tls_trust_policy(&endpoint, tls_auth_mode, req.server_pin)?;

        let mut bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        bootstrap.server_endpoint = Some(endpoint);
        bootstrap.tls_auth_mode = tls_auth_mode;
        apply_pin_selection(&mut bootstrap, req.server_pin);

        let preauth_key = req.preauth_key.take().ok_or_else(|| {
            AppError::invalid_argument("enrollment or rotation requires pre-authentication key")
        })?;
        let requested_name = req.node_name.take();
        if req.rotate_existing_keypair {
            let (updated, identity, reg) = self
                .perform_rotation_with_bootstrap(bootstrap, preauth_key, requested_name)
                .await?;
            return Ok((updated, identity, reg));
        }

        let now_ms = self.clock.now_unix_ms();
        let mut identity = self.state_store.load_or_create_identity(now_ms)?;
        let node_name = resolve_desired_node_name(requested_name.as_ref(), &bootstrap)?;
        let reg = self
            .register_identity_with_bootstrap(
                &bootstrap,
                &identity.node_keypair,
                RegisterNodeRequest {
                    preauth_key,
                    node_pubkey: identity.node_keypair.public_key(),
                    disco_pubkey: identity.disco_keypair.public_key(),
                    node_name,
                    previous_node_pubkey: None,
                },
            )
            .await?;
        identity = self.state_store.set_identity_node_id(reg.node_id)?;
        apply_registration_to_bootstrap(&mut bootstrap, &reg);
        Ok((bootstrap, identity, reg))
    }

    async fn perform_rotation_with_existing(
        &self,
        preauth_key: String,
    ) -> AppResult<(BootstrapConfig, StoredNodeIdentity, RegisterNodeResponse)> {
        let bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        self.perform_rotation_with_bootstrap(bootstrap, preauth_key, None)
            .await
    }

    async fn perform_rotation_with_bootstrap(
        &self,
        mut bootstrap: BootstrapConfig,
        preauth_key: String,
        requested_name: Option<NodeName>,
    ) -> AppResult<(BootstrapConfig, StoredNodeIdentity, RegisterNodeResponse)> {
        let now_ms = self.clock.now_unix_ms();
        let old_identity = self.state_store.load_existing_identity()?.ok_or_else(|| {
            AppError::invalid_argument("cannot rotate identity before initial enrollment")
        })?;
        let new_node_kp = NodeKeypair::generate();
        let new_disco_kp = DiscoKeypair::generate();
        let node_name = resolve_desired_node_name(requested_name.as_ref(), &bootstrap)?;

        let reg = self
            .register_identity_with_bootstrap(
                &bootstrap,
                &new_node_kp,
                RegisterNodeRequest {
                    preauth_key,
                    node_pubkey: new_node_kp.public_key(),
                    disco_pubkey: new_disco_kp.public_key(),
                    node_name,
                    previous_node_pubkey: Some(old_identity.node_keypair.public_key()),
                },
            )
            .await?;

        let new_identity = StoredNodeIdentity {
            node_id: Some(reg.node_id),
            node_keypair: new_node_kp,
            disco_keypair: new_disco_kp,
            created_at_ms: now_ms,
        };
        self.state_store.save_rotated_identity(&new_identity)?;
        apply_registration_to_bootstrap(&mut bootstrap, &reg);
        Ok((bootstrap, new_identity, reg))
    }

    async fn register_identity_with_bootstrap(
        &self,
        bootstrap: &BootstrapConfig,
        signing_kp: &NodeKeypair,
        req: RegisterNodeRequest,
    ) -> AppResult<RegisterNodeResponse> {
        let (underlay, nat64_prefix) = {
            let g = self.runtime.inner.read().await;
            (
                (g.underlay_if_index, g.linux_fwmark),
                g.nat64_prefix
                    .or_else(|| self.platform_hooks.nat64_prefix()),
            )
        };
        let protector = self
            .platform_hooks
            .socket_protector()
            .unwrap_or_else(|| Arc::new(NoopSocketProtector));

        match ControlLoop::register_node_protected(
            bootstrap,
            signing_kp,
            &req,
            &self.options.runtime_cfg.agent_version,
            ControlDialOptions {
                underlay,
                nat64_prefix,
                protector: protector.as_ref(),
            },
        )
        .await
        {
            Ok(reg) => Ok(reg),
            Err(err) => {
                if is_protocol_incompatible_error(&err) {
                    let mut g = self.runtime.inner.write().await;
                    g.protocol_incompatible = true;
                    g.last_error = Some(err.to_string());
                }
                Err(err)
            }
        }
    }

    async fn prepare_session_launch_params(
        &self,
        identity: &StoredNodeIdentity,
        initial_reg: Option<&RegisterNodeResponse>,
    ) -> AppResult<SessionLaunchParams> {
        let g = self.runtime.inner.read().await;
        let bootstrap = g.bootstrap.clone();
        let endpoint = bootstrap.server_endpoint.clone().ok_or_else(|| {
            AppError::invalid_argument("cannot start session without server_endpoint")
        })?;
        let node_id = identity
            .node_id
            .or(bootstrap.node_id)
            .ok_or_else(|| AppError::invalid_argument("node_id missing prior to tunnel start"))?;
        let initial_netmap = initial_reg
            .map(|r| r.netmap.clone())
            .or_else(|| g.latest_netmap.clone());
        let overlay_cidr = match initial_netmap.as_ref() {
            Some(n) => n.overlay_cidr,
            None => OverlayCidr::parse(DEFAULT_OVERLAY_CIDR)?,
        };
        let overlay_ip = initial_reg
            .map(|r| r.overlay_ip)
            .or(bootstrap.overlay_ip)
            .ok_or_else(|| {
                AppError::invalid_argument("overlay_ip missing; run `mesh up` with auth key")
            })?;
        let preferred_udp_port = Port::from_u16(g.local_udp_port).ok();
        let effective_key_expires_at_ms = initial_reg
            .and_then(|r| r.key_expires_at_ms)
            .or(bootstrap.key_expires_at_ms)
            .or_else(|| {
                initial_netmap.as_ref().and_then(|snap| {
                    snap.peers
                        .iter()
                        .find(|p| p.node_id == node_id)
                        .and_then(|p| p.key_expires_at_ms)
                })
            });
        let peers = initial_netmap
            .as_ref()
            .map_or(&[][..], |n| n.peers.as_slice());
        let overlay_dns_ip = derive_overlay_dns_ip(
            overlay_cidr,
            Some(overlay_ip),
            peers,
            &g.underlay_dns_servers,
        )
        .ok();
        let fqdn = initial_reg
            .map(|r| r.fqdn.clone())
            .or(bootstrap.fqdn.clone());

        Ok(SessionLaunchParams {
            bootstrap,
            endpoint,
            node_id,
            overlay_ip,
            overlay_cidr,
            overlay_dns_ip,
            preferred_udp_port,
            effective_key_expires_at_ms,
            initial_netmap,
            fqdn,
        })
    }

    async fn refresh_underlay_before_bind(
        &self,
    ) -> (
        Option<u32>,
        Option<u32>,
        Option<mesh_net::nat64::Nat64Prefix>,
        mesh_datapath::TimerMode,
    ) {
        let probed_primary = self
            .platform_hooks
            .network_probe()
            .query_primary_interface()
            .ok();
        let hook_nat64 = self.platform_hooks.nat64_prefix();
        let hook_dns = self.platform_hooks.underlay_dns_servers();

        let mut g = self.runtime.inner.write().await;
        if g.underlay_if_index.is_none()
            && let Some(ref primary) = probed_primary
        {
            if primary.if_index != 0 {
                g.underlay_if_index = Some(primary.if_index);
            }
            if g.bound_physical_interface.is_none() {
                g.bound_physical_interface = Some(primary.name.clone());
            }
        }
        if hook_nat64.is_some() {
            g.nat64_prefix = hook_nat64;
        }
        if !hook_dns.is_empty() {
            g.underlay_dns_servers = hook_dns;
        }
        (
            g.underlay_if_index
                .or(self.options.underlay_if_index)
                .filter(|&id| id != 0),
            g.linux_fwmark.or(self.options.linux_fwmark),
            g.nat64_prefix,
            g.timer_mode,
        )
    }

    async fn build_datapath_and_relay(
        &self,
        input: TunnelBindInput<'_>,
    ) -> AppResult<(
        RelayClient,
        mesh_datapath::RelayClientHandle,
        DatapathEngine,
    )> {
        let params = input.params;
        let identity = input.identity;
        let tun_dev = input.tun_dev;
        let underlay = input.underlay;
        let nat64_prefix = input.nat64_prefix;
        let timer_mode = input.timer_mode;
        let protector = input.protector;
        let mut socket_cfg = MagicSocketConfig::default()
            .with_mtu(self.options.runtime_cfg.tun_mtu)?
            .with_underlay(underlay.0, underlay.1)
            .with_nat64_prefix(nat64_prefix)
            .with_socket_protector(Arc::clone(&protector));
        if let Some(port) = params.preferred_udp_port {
            socket_cfg = socket_cfg.with_preferred_port(port);
        }

        let relay_ep = params.initial_netmap.as_ref().map_or_else(
            || params.endpoint.clone(),
            |n| n.relay_map.relay_tcp_endpoint.clone(),
        );
        let (relay_host, _) = split_host_port(&params.endpoint)?;
        let relay_cfg = RelayClientConfig {
            endpoint: relay_ep,
            server_name_override: Some(relay_host),
            pin_set: params.bootstrap.pin_set(),
            underlay_if_index: underlay.0,
            linux_fwmark: underlay.1,
            require_challenge_auth: true,
            agent_version: self.options.runtime_cfg.agent_version.clone(),
        };
        let relay_opts = RelayClientOptions::default()
            .with_socket_protector(Arc::clone(&protector))
            .with_nat64_prefix(nat64_prefix)
            .with_timer_mode(timer_mode);
        let relay_client = RelayClient::with_options(
            relay_cfg,
            identity.node_keypair.clone_keypair(),
            identity.disco_keypair.clone_keypair(),
            relay_opts,
        );
        let relay_handle = relay_client.handle();
        let control_tcp_endpoint = resolve_control_tcp_endpoint(&params.endpoint).await;

        let stun_config = StunClientConfig::default()
            .with_nat64_prefix(nat64_prefix)
            .with_socket_protector(protector);
        let dp_cfg = DatapathConfig {
            local_node_id: params.node_id,
            local_overlay_ip: params.overlay_ip,
            overlay_cidr: params.overlay_cidr,
            node_keypair: identity.node_keypair.clone_keypair(),
            disco_keypair: identity.disco_keypair.clone_keypair(),
            socket_config: socket_cfg,
            stun_config,
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };
        let mut dp_opts = DatapathEngineOptions::default()
            .with_timer_mode(timer_mode)
            .with_idle_entry_window_ms(self.options.runtime_cfg.idle_entry_window_ms);
        if let Some(ref interceptor) = self.options.dns_interceptor {
            dp_opts = dp_opts.with_dns_interceptor(Arc::clone(interceptor));
        }

        let engine = DatapathEngine::bind_with_options(
            dp_cfg,
            tun_dev,
            Arc::clone(&self.clock),
            Some(relay_handle.clone()),
            dp_opts,
        )
        .await?;
        Ok((relay_client, relay_handle, engine))
    }

    fn save_initial_netmap_cache_best_effort(
        &self,
        snapshot_opt: Option<&NetmapSnapshot>,
        bound_udp_port: u16,
        effective_key_expires_at_ms: Option<u64>,
    ) {
        if let Some(snap) = snapshot_opt
            && let Ok(port) = Port::from_u16(bound_udp_port.max(1))
            && let Ok(record) = NetmapCacheFile::new_signed(
                port,
                snap.clone(),
                self.clock.now_unix_ms(),
                effective_key_expires_at_ms,
            )
            && let Err(err) = self.state_store.save_netmap_cache(&record)
        {
            warn!(
                component = "mesh_client.session",
                event = "initial_netmap_cache_save_failed",
                error = %err,
                "failed persisting initial netmap-cache.json"
            );
        }
    }

    async fn record_connecting_state(&self, rec: ConnectingStateRecord<'_>) {
        self.runtime.reset_ws_close();
        let mut g = self.runtime.inner.write().await;
        g.daemon_state = DaemonState::Connecting;
        g.node_id = Some(rec.params.node_id);
        g.node_name = rec.params.bootstrap.node_name.clone();
        g.fqdn = rec.params.fqdn.clone();
        g.overlay_ip = Some(rec.params.overlay_ip);
        g.overlay_cidr = Some(rec.params.overlay_cidr);
        g.overlay_dns_ip = rec.params.overlay_dns_ip;
        g.key_expires_at_ms = rec.params.effective_key_expires_at_ms;
        g.tun_interface_name = Some(rec.actual_ifname);
        g.local_udp_port = rec.bound_udp_port;
        g.latest_netmap = rec.params.initial_netmap.clone();
        g.datapath_handle = Some(rec.dp_handle);
        g.rebind_handle = Some(rec.session_rebind_handle);
        g.relay_handle = Some(rec.relay_handle);
        g.overlay_conflict_warning = rec.tun_outcome.conflict_warning.clone();
        g.lockdown_warning = rec.tun_outcome.lockdown_warning.clone();
        g.private_dns_warning = rec.tun_outcome.private_dns_warning.clone();
        if self.platform_hooks.is_private_dns_strict() && g.private_dns_warning.is_none() {
            g.private_dns_warning = Some(
                "strict private DNS active on physical network; split-DNS overrides may be bypassed"
                    .to_owned(),
            );
        }
        g.protocol_incompatible = false;
        g.last_error = None;
    }

    async fn spawn_session_tasks(&mut self, input: SessionSpawnInput<'_>) {
        let SessionSpawnInput {
            root_shutdown,
            identity,
            initial_netmap,
            relay_client,
            engine,
            apply_dp_handle,
            session_rebind_rx,
        } = input;
        let session_cancel = root_shutdown.child_token();
        let session_tracker = TaskTracker::new();
        let (raw_relay_tx, raw_relay_rx) = mpsc::channel::<RelayEvent>(RELAY_EVENT_CAPACITY);
        let (dp_relay_tx, dp_relay_rx) = mpsc::channel::<RelayEvent>(RELAY_EVENT_CAPACITY);
        let (wake_tx, wake_rx) = mpsc::channel::<ControlWakeSignal>(8);
        if let Ok(mut guard) = self.active_wake_tx.lock() {
            *guard = Some(wake_tx.clone());
        }

        session_tracker.spawn(relay_client.run(
            Arc::clone(&self.clock),
            raw_relay_tx,
            session_cancel.clone(),
        ));
        session_tracker.spawn(relay_event_tee_loop(
            raw_relay_rx,
            dp_relay_tx,
            self.termination_tx.clone(),
            self.protocol_incompatible_tx.clone(),
            session_cancel.clone(),
        ));

        let dp_cancel = session_cancel.clone();
        session_tracker.spawn(async move {
            if let Err(err) = engine.run(dp_relay_rx, session_rebind_rx, dp_cancel).await {
                warn!(
                    component = "mesh_client.session",
                    event = "datapath_engine_exited_error",
                    error = %err,
                    "DatapathEngine exited with error"
                );
            }
        });

        // Apply initial/cached netmap only AFTER `relay_client.run` and `engine.run` are spawned
        // so `ApplyNetmap`'s command reply is serviced without startup deadlock (`BLK-W21-01`).
        if let Some(snap) = initial_netmap
            && let Err(err) = apply_dp_handle.apply_netmap(snap).await
        {
            warn!(
                component = "mesh_client.session",
                event = "initial_netmap_apply_failed",
                error = %err,
                "failed applying initial netmap snapshot to datapath"
            );
        }
        if let Some(filter_spec) = self.platform_hooks.inbound_filter_spec()
            && let Err(err) = apply_dp_handle
                .try_reload_packet_filter_spec(&filter_spec)
                .await
        {
            warn!(
                component = "mesh_client.session",
                event = "inbound_packet_filter_apply_failed",
                error = %err,
                "failed loading inbound overlay packet filter specification"
            );
        }

        session_tracker.spawn(ControlLoop::run(ControlLoopContext {
            state: Arc::clone(&self.runtime),
            clock: Arc::clone(&self.clock),
            node_keypair: identity.node_keypair,
            disco_pubkey: identity.disco_keypair.public_key(),
            runtime_cfg: self.options.runtime_cfg.clone(),
            platform_hooks: Arc::clone(&self.platform_hooks),
            roaming_rx: Arc::clone(&self.roaming_control_rx),
            wake_rx,
            termination_tx: Some(self.termination_tx.clone()),
            protocol_incompatible_tx: Some(self.protocol_incompatible_tx.clone()),
            shutdown: session_cancel.clone(),
        }));

        self.active_session = Some(ActiveTunnelSession {
            cancel: session_cancel,
            tracker: session_tracker,
            wake_tx,
        });
    }
}

struct NetmapCacheStoreLabel;
impl NetmapCacheStoreLabel {
    const LABEL: &'static str = "netmap_cache:ready";
}

struct TunnelBindInput<'a> {
    params: &'a SessionLaunchParams,
    identity: &'a StoredNodeIdentity,
    tun_dev: Arc<dyn mesh_net::tun::TunDevice>,
    underlay: (Option<u32>, Option<u32>),
    nat64_prefix: Option<mesh_net::nat64::Nat64Prefix>,
    timer_mode: mesh_datapath::TimerMode,
    protector: Arc<dyn SocketProtector>,
}

struct ConnectingStateRecord<'a> {
    params: &'a SessionLaunchParams,
    tun_outcome: &'a crate::hooks::TunActivationOutcome,
    actual_ifname: String,
    bound_udp_port: u16,
    dp_handle: DatapathHandle,
    session_rebind_handle: RebindHandle,
    relay_handle: mesh_datapath::RelayClientHandle,
}

struct SessionSpawnInput<'a> {
    root_shutdown: &'a CancellationToken,
    identity: StoredNodeIdentity,
    initial_netmap: Option<NetmapSnapshot>,
    relay_client: RelayClient,
    engine: DatapathEngine,
    apply_dp_handle: DatapathHandle,
    session_rebind_rx: mpsc::Receiver<RebindCommand>,
}

struct SessionLaunchParams {
    bootstrap: BootstrapConfig,
    endpoint: String,
    node_id: NodeId,
    overlay_ip: OverlayIp,
    overlay_cidr: OverlayCidr,
    overlay_dns_ip: Option<OverlayIp>,
    preferred_udp_port: Option<Port>,
    effective_key_expires_at_ms: Option<u64>,
    initial_netmap: Option<NetmapSnapshot>,
    fqdn: Option<String>,
}

async fn relay_event_tee_loop(
    mut raw_rx: mpsc::Receiver<RelayEvent>,
    dp_tx: mpsc::Sender<RelayEvent>,
    termination_tx: mpsc::Sender<(TerminationReason, String)>,
    protocol_incompatible_tx: mpsc::Sender<String>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            maybe_event = raw_rx.recv() => {
                let Some(event) = maybe_event else {
                    break;
                };
                if let RelayEvent::StateChanged(RelayConnectionState::Terminated(kind)) = event {
                    notify_relay_termination(kind, &termination_tx, &protocol_incompatible_tx);
                }
                if dp_tx.send(event).await.is_err() {
                    break;
                }
            }
        }
    }
}

fn notify_relay_termination(
    kind: ErrorKind,
    termination_tx: &mpsc::Sender<(TerminationReason, String)>,
    protocol_incompatible_tx: &mpsc::Sender<String>,
) {
    match kind {
        ErrorKind::NodeRevoked => {
            if let Err(err) = termination_tx.try_send((
                TerminationReason::NodeRevoked,
                "blind relay reported node revoked".to_owned(),
            )) {
                debug!(
                    component = "mesh_client.session",
                    event = "relay_termination_signal_skipped",
                    error = %err,
                    "node_revoked termination notification skipped"
                );
            }
        }
        ErrorKind::NodeKeyExpired => {
            if let Err(err) = termination_tx.try_send((
                TerminationReason::NodeKeyExpired,
                "blind relay reported node key expired".to_owned(),
            )) {
                debug!(
                    component = "mesh_client.session",
                    event = "relay_termination_signal_skipped",
                    error = %err,
                    "node_key_expired termination notification skipped"
                );
            }
        }
        ErrorKind::InvalidArgument => {
            if let Err(err) =
                protocol_incompatible_tx.try_send(PROTOCOL_INCOMPATIBLE_RELAY_MSG.to_owned())
            {
                debug!(
                    component = "mesh_client.session",
                    event = "relay_protocol_incompatible_signal_skipped",
                    error = %err,
                    "protocol_incompatible relay notification skipped"
                );
            }
        }
        _ => {}
    }
}

fn load_valid_netmap_cache(store: &dyn ClientStateStore, now_ms: u64) -> Option<NetmapCacheFile> {
    match store.load_netmap_cache() {
        Ok(Some(cf)) if !cf.is_within_offline_grace(now_ms) => {
            warn!(
                component = "mesh_client.session",
                event = "netmap_cache_expired",
                cached_at_ms = cf.cached_at_ms,
                offline_grace_hours = cf.offline_grace_hours,
                "ignored cached netmap-cache.json beyond offline grace window"
            );
            None
        }
        Ok(opt) => opt,
        Err(err) => {
            warn!(
                component = "mesh_client.session",
                event = "netmap_cache_rejected",
                error = %err,
                "ignored tampered or corrupt netmap-cache.json (fail-closed)"
            );
            None
        }
    }
}

fn hydrate_initial_underlay_metadata(
    runtime: &ClientRuntimeState,
    options: &ClientSessionOptions,
    hooks: &dyn ClientPlatformHooks,
) {
    let probed_primary = hooks.network_probe().query_primary_interface().ok();
    let hook_nat64 = hooks.nat64_prefix();
    let hook_dns = hooks.underlay_dns_servers();
    let strict_dns = hooks.is_private_dns_strict();

    if let Ok(mut g) = runtime.inner.try_write() {
        g.underlay_if_index = options
            .underlay_if_index
            .or_else(|| {
                probed_primary
                    .as_ref()
                    .map(|p| p.if_index)
                    .filter(|&id| id != 0)
            })
            .filter(|&id| id != 0);
        g.linux_fwmark = options.linux_fwmark;
        if let Some(ref primary) = probed_primary {
            g.bound_physical_interface = Some(primary.name.clone());
        }
        g.nat64_prefix = hook_nat64;
        g.underlay_dns_servers = hook_dns;
        if strict_dns {
            g.private_dns_warning = Some(
                "strict private DNS active on physical network; split-DNS overrides may be bypassed"
                    .to_owned(),
            );
        }
    }
}

async fn resolve_control_tcp_endpoint(endpoint: &str) -> Option<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Some(addr);
    }
    let (host, port) = split_host_port(endpoint).ok()?;
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::lookup_host((host.as_str(), port.get())),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .and_then(|mut addrs| addrs.next())
}

/// Shared state passed into the sequential roam / interface-rebind forwarder (`HR-W21-08`).
pub struct RebindForwardContext {
    /// Shared non-secret client runtime state.
    pub runtime: Arc<ClientRuntimeState>,
    /// Platform hooks driving OS route reconciliation, firewall, and NAT64 discovery.
    pub platform_hooks: Arc<dyn ClientPlatformHooks>,
    /// Active Control loop wake channel slot.
    pub active_wake_tx: Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>>,
    /// Tracks whether an overlay route is currently active on the TUN device.
    pub overlay_route_installed: Arc<AtomicBool>,
    /// Agent version tag forwarded into Relay client updates.
    pub agent_version: String,
    /// Optional feedback channel unblocking `RoamingLoop` after rebind completes.
    pub rebind_feedback_tx: Option<mpsc::Sender<AppResult<()>>>,
    /// Shutdown cancellation token.
    pub shutdown: CancellationToken,
}

impl std::fmt::Debug for RebindForwardContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RebindForwardContext")
            .field("agent_version", &self.agent_version)
            .finish_non_exhaustive()
    }
}

/// Receives [`RebindCommand`] items and dispatches them sequentially (`HR-W21-08`).
pub async fn forward_rebind_loop(
    ctx: RebindForwardContext,
    rx: &mut mpsc::Receiver<RebindCommand>,
) {
    loop {
        tokio::select! {
            () = ctx.shutdown.cancelled() => break,
            maybe_cmd = rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break;
                };
                handle_rebind_command(&ctx, cmd).await;
            }
        }
    }
}

/// Executes a single [`RebindCommand`] in strict sequence before re-probing STUN / Disco / Relay.
pub async fn handle_rebind_command(ctx: &RebindForwardContext, cmd: RebindCommand) {
    let RebindCommand::RebindInterface {
        ref interface_name,
        if_index,
        is_ipv6,
    } = cmd
    else {
        forward_non_interface_rebind(ctx, cmd).await;
        return;
    };

    let effective_if_index = if_index.filter(|&id| id != 0);
    let snapshot = capture_rebind_snapshot(ctx, interface_name, effective_if_index).await;

    if let Some(ref dp) = snapshot.dp_handle
        && let Err(err) = dp.begin_rebind().await
    {
        debug!(
            component = "mesh_client.session",
            event = "datapath_begin_rebind_skipped",
            error = %err,
            "failed marking datapath rebinding before route reconciliation"
        );
    }

    if let (Some(cidr), Some(tun_if)) = (snapshot.overlay_cidr, snapshot.tun_ifname.as_deref()) {
        reconcile_overlay_on_roam(
            ctx,
            cidr,
            tun_if,
            snapshot.overlay_dns_ip,
            snapshot.domain_suffix.as_deref(),
        )
        .await;
        if let Err(err) = ctx.platform_hooks.reconcile_firewall_on_roam(tun_if, cidr) {
            warn!(
                component = "mesh_client.session",
                event = "firewall_roam_reconcile_warning",
                interface = %tun_if,
                error = %err,
                "failed reconciling OS overlay firewall rule after roam"
            );
        }
    }

    let (reprobe_ready, feedback) = execute_datapath_rebind(
        ctx,
        &snapshot,
        &cmd,
        interface_name,
        effective_if_index,
        is_ipv6,
    )
    .await;

    if reprobe_ready {
        post_rebind_refresh(ctx, &snapshot, effective_if_index).await;
    }

    if let Some(ref tx) = ctx.rebind_feedback_tx
        && let Err(err) = tx.try_send(feedback)
    {
        debug!(
            component = "mesh_client.session",
            event = "rebind_feedback_send_skipped",
            error = %err,
            "failed delivering rebind feedback to roaming loop"
        );
    }
}

struct RebindRuntimeSnapshot {
    bootstrap: BootstrapConfig,
    overlay_cidr: Option<OverlayCidr>,
    overlay_dns_ip: Option<OverlayIp>,
    domain_suffix: Option<String>,
    tun_ifname: Option<String>,
    underlay: (Option<u32>, Option<u32>),
    nat64_prefix: Option<mesh_net::nat64::Nat64Prefix>,
    rebind_handle: Option<RebindHandle>,
    relay_handle: Option<mesh_datapath::RelayClientHandle>,
    dp_handle: Option<DatapathHandle>,
    peer_ids: Vec<NodeId>,
    relay_endpoint: Option<String>,
}

async fn forward_non_interface_rebind(ctx: &RebindForwardContext, cmd: RebindCommand) {
    let (rebind_handle, relay_handle) = {
        let g = ctx.runtime.inner.read().await;
        (g.rebind_handle.clone(), g.relay_handle.clone())
    };
    if matches!(cmd, RebindCommand::WakeRelay)
        && let Some(relay) = relay_handle
    {
        relay.wake_reconnect();
    }
    if let Some(handle) = rebind_handle
        && let Err(err) = handle.try_send(cmd)
    {
        debug!(
            component = "mesh_client.session",
            event = "rebind_forward_skipped",
            error = %err,
            "failed forwarding datapath rebind command"
        );
    }
}

async fn capture_rebind_snapshot(
    ctx: &RebindForwardContext,
    interface_name: &str,
    effective_if_index: Option<u32>,
) -> RebindRuntimeSnapshot {
    let latest_nat64 = ctx.platform_hooks.nat64_prefix();
    let latest_dns = ctx.platform_hooks.underlay_dns_servers();
    let strict_dns = ctx.platform_hooks.is_private_dns_strict();

    let mut g = ctx.runtime.inner.write().await;
    g.bound_physical_interface = Some(interface_name.to_owned());
    if let Some(idx) = effective_if_index {
        g.underlay_if_index = Some(idx);
    }
    g.nat64_prefix = latest_nat64;
    if !latest_dns.is_empty() {
        g.underlay_dns_servers = latest_dns;
    }
    g.private_dns_warning = if strict_dns {
        Some(
            "strict private DNS active on physical network; split-DNS overrides may be bypassed"
                .to_owned(),
        )
    } else {
        None
    };

    if !matches!(
        g.daemon_state,
        DaemonState::Stopped | DaemonState::Revoked | DaemonState::ReauthRequired
    ) && !g.protocol_incompatible
    {
        g.daemon_state = DaemonState::Connecting;
        g.control_connected = false;
        g.last_error = Some("rebinding network interface".to_owned());
    }
    let relay_endpoint = g
        .latest_netmap
        .as_ref()
        .map(|n| n.relay_map.relay_tcp_endpoint.clone())
        .or_else(|| g.bootstrap.server_endpoint.clone());
    let peer_ids = g
        .latest_netmap
        .as_ref()
        .map(|n| n.peers.iter().map(|p| p.node_id).collect::<Vec<_>>())
        .unwrap_or_default();
    let domain_suffix = g.latest_netmap.as_ref().map(|n| n.domain_suffix.clone());

    RebindRuntimeSnapshot {
        bootstrap: g.bootstrap.clone(),
        overlay_cidr: g.overlay_cidr,
        overlay_dns_ip: g.overlay_dns_ip,
        domain_suffix,
        tun_ifname: g.tun_interface_name.clone(),
        underlay: (g.underlay_if_index, g.linux_fwmark),
        nat64_prefix: g.nat64_prefix,
        rebind_handle: g.rebind_handle.clone(),
        relay_handle: g.relay_handle.clone(),
        dp_handle: g.datapath_handle.clone(),
        peer_ids,
        relay_endpoint,
    }
}

async fn execute_datapath_rebind(
    ctx: &RebindForwardContext,
    snap: &RebindRuntimeSnapshot,
    raw_cmd: &RebindCommand,
    interface_name: &str,
    effective_if_index: Option<u32>,
    is_ipv6: bool,
) -> (bool, AppResult<()>) {
    if let Some(ref dp) = snap.dp_handle {
        if let Err(err) = dp.set_nat64_prefix(snap.nat64_prefix).await {
            debug!(
                component = "mesh_client.session",
                event = "datapath_nat64_update_skipped",
                error = %err,
                "failed pushing updated NAT64 prefix prior to underlay rebind"
            );
        }
        return match dp
            .rebind_underlay(interface_name.to_owned(), effective_if_index, is_ipv6)
            .await
        {
            Ok(bound_port) => {
                let mut g = ctx.runtime.inner.write().await;
                g.local_udp_port = bound_port;
                (true, Ok(()))
            }
            Err(err) => {
                warn!(
                    component = "mesh_client.session",
                    event = "datapath_rebind_underlay_failed",
                    interface = %interface_name,
                    if_index = ?effective_if_index,
                    error = %err,
                    "underlay UDP socket rebind failed; retaining direct-UDP block until retry"
                );
                let mut g = ctx.runtime.inner.write().await;
                g.last_error = Some(format!("rebinding network interface failed: {err}"));
                (false, Err(err))
            }
        };
    }

    if let Some(ref handle) = snap.rebind_handle
        && let Err(err) = handle.try_send(raw_cmd.clone())
    {
        debug!(
            component = "mesh_client.session",
            event = "rebind_forward_skipped",
            error = %err,
            "failed forwarding network-change rebind command to datapath"
        );
    }
    (true, Ok(()))
}

async fn post_rebind_refresh(
    ctx: &RebindForwardContext,
    snap: &RebindRuntimeSnapshot,
    effective_if_index: Option<u32>,
) {
    if snap.dp_handle.is_some()
        && let Some(ref handle) = snap.rebind_handle
        && let Err(err) = handle.try_send(RebindCommand::RefreshCandidates)
    {
        debug!(
            component = "mesh_client.session",
            event = "refresh_candidates_forward_skipped",
            error = %err,
            "failed forwarding candidate refresh after successful rebind"
        );
    }
    if let Some(ref relay_h) = snap.relay_handle {
        relay_h.set_nat64_prefix(snap.nat64_prefix);
        if let Some(ref ep) = snap.relay_endpoint {
            match build_relay_client_config_for_runtime(
                &snap.bootstrap,
                ep.clone(),
                (effective_if_index.or(snap.underlay.0), snap.underlay.1),
                ctx.agent_version.clone(),
            ) {
                Ok(next_cfg) => {
                    relay_h.update_config(next_cfg);
                    relay_h.wake_reconnect();
                }
                Err(err) => {
                    warn!(
                        component = "mesh_client.session",
                        event = "relay_reconfig_build_failed",
                        error = %err,
                        "failed rebuilding RelayClient config on roam"
                    );
                }
            }
        }
    }
    dispatch_datapath_reprobe_and_wake_control(ctx, snap.dp_handle.clone(), &snap.peer_ids).await;
}

async fn reconcile_overlay_on_roam(
    ctx: &RebindForwardContext,
    overlay_cidr: OverlayCidr,
    tun_ifname: &str,
    dns_server_ip: Option<OverlayIp>,
    domain_suffix: Option<&str>,
) {
    let conflict = ctx
        .platform_hooks
        .network_probe()
        .list_interface_subnets()
        .ok()
        .and_then(|subnets| detect_overlay_subnet_conflict(&subnets, overlay_cidr));

    match ctx
        .platform_hooks
        .reconcile_on_roam_or_netmap(tun_ifname, overlay_cidr, dns_server_ip, domain_suffix)
        .await
    {
        Ok(hook_warning) => {
            let effective_warning = hook_warning.or_else(|| conflict.map(|c| c.format_warning()));
            ctx.overlay_route_installed
                .store(effective_warning.is_none(), Ordering::SeqCst);
            let mut g = ctx.runtime.inner.write().await;
            let cleared = g.overlay_conflict_warning.is_some() && effective_warning.is_none();
            g.overlay_conflict_warning = effective_warning;
            if cleared {
                info!(
                    component = "mesh_client.session",
                    event = "overlay_subnet_conflict_cleared",
                    overlay_cidr = %overlay_cidr,
                    "physical subnet no longer overlaps overlay CIDR; warning cleared"
                );
            }
        }
        Err(err) => {
            warn!(
                component = "mesh_client.session",
                event = "roam_route_reconcile_failed",
                error = %err,
                "failed reconciling overlay route during roam"
            );
        }
    }
}

async fn dispatch_datapath_reprobe_and_wake_control(
    ctx: &RebindForwardContext,
    dp_handle: Option<DatapathHandle>,
    peer_ids: &[NodeId],
) {
    if let Some(dp) = dp_handle {
        tokio::task::yield_now().await;
        match tokio::time::timeout(
            Duration::from_millis(150),
            dp.send(DatapathCommand::TriggerStunProbe),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => debug!(
                component = "mesh_client.session",
                event = "roam_stun_probe_skipped",
                error = %err,
                "datapath skipped STUN probe dispatch on roam"
            ),
            Err(_) => debug!(
                component = "mesh_client.session",
                event = "roam_stun_probe_timeout",
                "timed out queuing STUN probe on roam"
            ),
        }
        for &peer_id in peer_ids {
            match tokio::time::timeout(
                Duration::from_millis(100),
                dp.send(DatapathCommand::InitiateHolePunch(peer_id)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => debug!(
                    component = "mesh_client.session",
                    event = "roam_disco_probe_skipped",
                    peer_id = %peer_id,
                    error = %err,
                    "datapath skipped peer Disco probe dispatch on roam"
                ),
                Err(_) => debug!(
                    component = "mesh_client.session",
                    event = "roam_disco_probe_timeout",
                    peer_id = %peer_id,
                    "timed out queuing peer Disco probe on roam"
                ),
            }
        }
    }

    let wake_opt = ctx.active_wake_tx.lock().ok().and_then(|g| g.clone());
    if let Some(wake_tx) = wake_opt
        && let Err(err) = wake_tx.try_send(ControlWakeSignal::ConfigUpdated)
    {
        debug!(
            component = "mesh_client.session",
            event = "roaming_control_wake_skipped",
            error = %err,
            "control wake signal skipped after rebind"
        );
    }
}

/// Applies an optional explicit port override onto an existing `host:port` Control endpoint string.
pub fn apply_port_override(endpoint: &str, port_override: Option<Port>) -> AppResult<String> {
    let (host, current_port) = split_host_port(endpoint)?;
    let chosen_port = port_override.unwrap_or(current_port);
    if host.contains(':') {
        Ok(format!("[{host}]:{}", chosen_port.get()))
    } else {
        Ok(format!("{host}:{}", chosen_port.get()))
    }
}

/// Applies Control registration response fields into [`BootstrapConfig`] cleanly.
pub fn apply_registration_to_bootstrap(
    bootstrap: &mut BootstrapConfig,
    reg: &RegisterNodeResponse,
) {
    bootstrap.node_id = Some(reg.node_id);
    bootstrap.node_name = Some(reg.node_name.clone());
    bootstrap.overlay_ip = Some(reg.overlay_ip);
    bootstrap.fqdn = Some(reg.fqdn.clone());
    bootstrap.key_expires_at_ms = reg.key_expires_at_ms;
    bootstrap.apply_netmap_pins(reg.netmap.pin_set.active_pin, reg.netmap.pin_set.next_pin);
    bootstrap.acked_endpoint_version = reg.netmap.relay_map.endpoint_version;
}

/// Atomically persists `bootstrap` through `state_store` and updates non-secret runtime mirrors.
pub async fn persist_bootstrap_and_runtime(
    runtime: &ClientRuntimeState,
    bootstrap: &BootstrapConfig,
) -> AppResult<()> {
    let mut g = runtime.inner.write().await;
    g.state_store.save_bootstrap(bootstrap)?;
    g.bootstrap = bootstrap.clone();
    g.node_id = bootstrap.node_id;
    g.node_name = bootstrap.node_name.clone();
    g.overlay_ip = bootstrap.overlay_ip;
    g.fqdn = bootstrap.fqdn.clone();
    Ok(())
}

fn apply_pin_selection(bootstrap: &mut BootstrapConfig, pin: Option<mesh_core::SpkiPin>) {
    match pin {
        Some(p) => {
            bootstrap.active_pin = Some(p);
            bootstrap.next_pin = None;
        }
        None => {
            bootstrap.active_pin = None;
            bootstrap.next_pin = None;
        }
    }
}

fn send_reply<T>(reply: oneshot::Sender<AppResult<T>>, res: AppResult<T>) {
    if reply.send(res).is_err() {
        debug!(
            component = "mesh_client.session",
            event = "command_reply_receiver_dropped",
            "caller dropped supervisor command reply receiver"
        );
    }
}

fn resolve_desired_node_name(
    requested: Option<&NodeName>,
    bootstrap: &BootstrapConfig,
) -> AppResult<NodeName> {
    if let Some(n) = requested {
        return Ok(n.clone());
    }
    if let Some(ref existing) = bootstrap.node_name {
        return Ok(existing.clone());
    }
    detect_default_node_name()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio_util::sync::CancellationToken;

    use mesh_core::clock::SystemClock;
    use mesh_core::{NodeId, NodeName, OverlayIp, SpkiPin};
    use mesh_crypto::{DiscoKeypair, NodeKeypair};
    use mesh_net::keystore::StoredNodeIdentity;
    use mesh_net::netmon::{FakeNetMonitor, NetworkChangeEvent};
    use mesh_proto::agent_ipc::{AgentSetRequest, DaemonState, TlsAuthMode};
    use mesh_proto::control::{RegisterNodeResponse, TerminationReason};
    use mesh_proto::netmap::{NetmapSnapshot, PeerEntry, PinSetDto, RelayMap};

    use super::{
        ClientPlatformHooks, ClientRuntimeConfig, ClientSessionOptions, ClientSessionSupervisor,
        apply_registration_to_bootstrap,
    };
    use crate::config::BootstrapConfig;
    use crate::hooks::{ClientStateStore, InMemoryClientPlatformHooks, InMemoryClientStateStore};
    use crate::netmap_cache::NetmapCacheFile;

    fn build_enrolled_in_memory_supervisor(
        hooks: &Arc<InMemoryClientPlatformHooks>,
        store: &Arc<InMemoryClientStateStore>,
        mobile: bool,
    ) -> ClientSessionSupervisor {
        let t0 = 1_700_000_000_000_u64;
        let node_id = NodeId::new_v7(t0);
        let identity = StoredNodeIdentity {
            node_id: Some(node_id),
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: t0,
        };
        assert!(store.save_rotated_identity(&identity).is_ok());

        let bootstrap = BootstrapConfig {
            node_id: Some(node_id),
            node_name: "alpha".parse::<NodeName>().ok(),
            overlay_ip: "100.115.0.10".parse::<OverlayIp>().ok(),
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(SpkiPin::from_sha256_bytes([2; 32])),
            ..BootstrapConfig::default()
        };
        assert!(store.save_bootstrap(&bootstrap).is_ok());

        let runtime_cfg = if mobile {
            ClientRuntimeConfig::for_mobile()
        } else {
            ClientRuntimeConfig::for_desktop()
        };
        ClientSessionSupervisor::boot(
            ClientSessionOptions::new(runtime_cfg),
            Arc::new(SystemClock::new()),
            Arc::clone(hooks) as Arc<dyn ClientPlatformHooks>,
            Arc::clone(store) as Arc<dyn crate::hooks::ClientStateStore>,
        )
        .expect("boot in-memory supervisor")
    }

    #[tokio::test]
    async fn test_client_supervisor_graceful_shutdown_completes_under_5s_and_clears_dns() {
        // Arrange
        let hooks = Arc::new(InMemoryClientPlatformHooks::default());
        let store = Arc::new(InMemoryClientStateStore::new());
        let supervisor = build_enrolled_in_memory_supervisor(&hooks, &store, true);
        let runtime = supervisor.runtime_state();
        let monitor = Arc::new(FakeNetMonitor::new());
        let shutdown = CancellationToken::new();
        let started = Instant::now();

        let task = tokio::spawn(supervisor.run(monitor, shutdown.clone()));
        tokio::time::sleep(Duration::from_millis(40)).await;

        // Act
        shutdown.cancel();
        let join = tokio::time::timeout(Duration::from_secs(5), task).await;

        // Assert
        assert!(matches!(join, Ok(Ok(Ok(())))));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(hooks.deactivate_count() >= 1);
        assert!(hooks.recording_dns().clear_count() >= 1);
        let status = runtime.build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::Stopped);
    }

    #[tokio::test]
    async fn test_client_supervisor_protocol_incompatible_stops_without_clearing_netmap_cache() {
        // Arrange
        let hooks = Arc::new(InMemoryClientPlatformHooks::default());
        let store = Arc::new(InMemoryClientStateStore::new());
        let t0 = 1_700_000_000_100_u64;
        let overlay_cidr = "100.115.0.0/16".parse().expect("valid cidr");
        let self_ip: OverlayIp = "100.115.0.10".parse().expect("valid ip");
        let snap = NetmapSnapshot {
            netmap_version: 7,
            generated_at_ms: t0,
            overlay_cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec![],
            },
            pin_set: PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([2; 32]),
                next_pin: None,
            },
            peers: vec![PeerEntry {
                node_id: NodeId::new_v7(t0 + 1),
                name: "peer-1".parse().expect("name"),
                fqdn: "peer-1.mesh.internal".to_owned(),
                overlay_ip: "100.115.0.20".parse().expect("peer ip"),
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: vec![],
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }],
        };
        let port = mesh_core::Port::from_u16(41641).expect("port");
        let cache = NetmapCacheFile::new_signed(port, snap.clone(), t0, None).expect("cache");
        assert!(store.save_netmap_cache(&cache).is_ok());

        let mut supervisor = build_enrolled_in_memory_supervisor(&hooks, &store, true);
        let root_shutdown = CancellationToken::new();
        assert!(
            supervisor
                .start_enrolled_session(&root_shutdown, None)
                .await
                .is_ok()
        );
        assert!(supervisor.has_active_session());

        // Act
        supervisor
            .handle_protocol_incompatible("protocol incompatible: unknown variant Android")
            .await;

        // Assert
        assert!(!supervisor.has_active_session());
        assert!(store.has_netmap_cache());
        assert!(supervisor.runtime_state().is_protocol_incompatible().await);
        assert!(hooks.deactivate_count() >= 1);
        let status = supervisor.runtime_state().build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::Stopped);
        let _ignored = (self_ip, TerminationReason::NodeRevoked, snap);
    }

    #[tokio::test]
    async fn test_client_supervisor_roam_and_execute_set_keep_state_consistent() {
        // Arrange
        let hooks = Arc::new(InMemoryClientPlatformHooks::default());
        let store = Arc::new(InMemoryClientStateStore::new());
        let mut supervisor = build_enrolled_in_memory_supervisor(&hooks, &store, false);
        let root_shutdown = CancellationToken::new();

        assert!(
            supervisor
                .start_enrolled_session(&root_shutdown, None)
                .await
                .is_ok()
        );

        // Act
        let set_resp = supervisor
            .execute_set(AgentSetRequest {
                server_endpoint: "vpn.example.com:8443".to_owned(),
                server_pin: None,
            })
            .await;
        let send_res = supervisor
            .roaming_control_sender()
            .send(NetworkChangeEvent::AddressChanged {
                interface: "wlan0".to_owned(),
            })
            .await;

        // Assert
        assert!(set_resp.is_ok());
        assert!(send_res.is_ok());
        let mut bootstrap = BootstrapConfig::default();
        let fake_reg = RegisterNodeResponse {
            node_id: NodeId::new_v7(1_700_000_000_200),
            node_name: "beta".parse().expect("node name"),
            fqdn: "beta.mesh.internal".to_owned(),
            overlay_ip: "100.115.0.15".parse().expect("ip"),
            overlay_cidr: "100.115.0.0/16".parse().expect("cidr"),
            key_expires_at_ms: Some(1_700_000_999_000),
            netmap: NetmapSnapshot {
                netmap_version: 2,
                generated_at_ms: 1_700_000_000_200,
                overlay_cidr: "100.115.0.0/16".parse().expect("cidr"),
                domain_suffix: "mesh.internal".to_owned(),
                relay_map: RelayMap {
                    endpoint_version: 3,
                    control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                    relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                    stun_udp_endpoints: vec![],
                },
                pin_set: PinSetDto {
                    active_pin: SpkiPin::from_sha256_bytes([9; 32]),
                    next_pin: None,
                },
                peers: vec![],
            },
        };
        apply_registration_to_bootstrap(&mut bootstrap, &fake_reg);
        assert_eq!(bootstrap.acked_endpoint_version, 3);
        assert!(supervisor.stop_active_session_and_cleanup().await.is_ok());
    }
}
