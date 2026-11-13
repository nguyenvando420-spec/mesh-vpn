//! Daemon lifecycle supervisor: startup `ResourceLedger` crash recovery, dual IPC/Roaming/
//! Control/Datapath orchestration, and bounded Graceful Shutdown (`<= 5 s`, `US-055`, `REL-08`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use mesh_core::clock::Clock;
use mesh_core::defaults::{DEFAULT_OVERLAY_CIDR, GRACEFUL_SHUTDOWN_BUDGET_MS};
use mesh_core::{AppError, AppResult, OverlayCidr, Port};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_datapath::{
    DatapathConfig, DatapathEngine, DiscoConfig, MagicSocketConfig, RebindCommand, RebindHandle,
    RelayClient, RelayClientConfig, RelayEvent, StunClientConfig,
};
use mesh_net::hosts::{FileHostsEditor, HostsEditor};
use mesh_net::keystore::{KeysFileStore, StoredNodeIdentity};
use mesh_net::ledger::{LedgerCleanupOps, ResourceLedger};
use mesh_net::netmon::{NetMonitor, NetworkChangeEvent};
use mesh_net::route::RouteSpec;
#[cfg(any(
    test,
    not(any(target_os = "windows", target_os = "macos", target_os = "linux"))
))]
use mesh_net::tun::FakeTunDevice;
use mesh_net::tun::{TunConfig, TunDevice};
use mesh_proto::agent_ipc::{
    AgentActionResponse, AgentRotateKeyRequest, AgentSetRequest, AgentUpRequest, BugreportResponse,
    DaemonState, TlsAuthMode,
};
use mesh_proto::control::{RegisterNodeRequest, RegisterNodeResponse, TerminationReason};

use crate::config::{
    BootstrapConfig, BootstrapStore, DaemonRuntimePaths, detect_default_node_name, split_host_port,
    validate_tls_trust_policy, write_private_file_atomic,
};
use crate::control_loop::{
    ControlLoop, ControlLoopContext, ControlWakeSignal, DaemonRuntimeState,
    build_relay_client_config_for_runtime,
};
use crate::ipc_service::{IpcRouterState, IpcService};
use crate::netmap_cache::{NetmapCacheFile, NetmapCacheStore};
use crate::ping_probe::PingProbe;
use crate::roaming_loop::{NETWORK_CHANGE_CHANNEL_CAPACITY, RoamingLoop};

const SUPERVISOR_CMD_CAPACITY: usize = 32;
const WS_CLOSE_PHASE_WAIT: Duration = Duration::from_millis(600);
const SESSION_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
const LEDGER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const RELAY_EVENT_CAPACITY: usize = 128;

/// Commands routed from `meshd-admin` IPC endpoints to the supervisor lifecycle owner.
#[derive(Debug)]
pub(crate) enum SupervisorCommand {
    /// Registers (if needed) and starts the overlay tunnel session (`POST /v1/agent/up`).
    Up {
        req: AgentUpRequest,
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Gracefully stops the active tunnel session (`POST /v1/agent/down`).
    Down {
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Forces idempotent `ResourceLedger::cleanup_all` recovery (`POST /v1/agent/cleanup`).
    Cleanup {
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Updates Control server endpoint / pins cleanly (`POST /v1/agent/set`).
    Set {
        req: AgentSetRequest,
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Rotates WireGuard identity keypair with `previous_node_pubkey` (`POST /v1/agent/rotate-key`).
    RotateKey {
        req: AgentRotateKeyRequest,
        reply: oneshot::Sender<AppResult<AgentActionResponse>>,
    },
    /// Generates a redacted non-secret diagnostic bundle (`POST /v1/agent/bugreport`).
    Bugreport {
        reply: oneshot::Sender<AppResult<BugreportResponse>>,
    },
}

/// Platform resource provisioning and cleanup abstraction (`G4` / test isolation).
pub(crate) trait PlatformAdapters: Send + Sync {
    /// Returns the OS-specific `ResourceLedger` cleanup handler.
    fn cleanup_ops(&self) -> &dyn LedgerCleanupOps;

    /// Records the TUN interface and overlay route in `ledger` **before** activating OS state.
    fn setup_tun_and_route(
        &self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
        now_ms: u64,
    ) -> AppResult<Arc<dyn TunDevice>>;

    /// Starts real IPC Unix/Pipe listeners when `true`; skipped when an external test harness drives routers.
    fn bind_ipc_listeners(&self) -> bool {
        true
    }

    /// Enforces fail-closed macOS root-ownership verification at daemon startup (`US-073 AC2`).
    fn enforce_macos_startup_path_security(&self) -> bool {
        true
    }
}

/// Production OS adapters using Linux/macOS/Windows kernel TUN, routes, firewall, and ledger ops.
#[derive(Debug)]
pub(crate) struct ProductionPlatformAdapters {
    wintun_sha256: Option<String>,
    #[cfg(target_os = "windows")]
    cleanup: mesh_net::route_windows::WindowsCleanupOps,
    #[cfg(target_os = "macos")]
    cleanup: mesh_net::route_macos::MacOsCleanupOps,
    #[cfg(target_os = "linux")]
    cleanup: mesh_net::route_linux::LinuxCleanupOps,
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    cleanup: mesh_net::ledger::FakeLedgerCleanupOps,
}

impl ProductionPlatformAdapters {
    /// Creates production OS resource adapters using optional Wintun SHA-256 verification hash.
    #[must_use]
    pub(crate) fn new(wintun_sha256: Option<String>) -> Self {
        Self {
            wintun_sha256,
            #[cfg(target_os = "windows")]
            cleanup: mesh_net::route_windows::WindowsCleanupOps::new(),
            #[cfg(target_os = "macos")]
            cleanup: mesh_net::route_macos::MacOsCleanupOps::new(),
            #[cfg(target_os = "linux")]
            cleanup: mesh_net::route_linux::LinuxCleanupOps::new(),
            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            cleanup: mesh_net::ledger::FakeLedgerCleanupOps::new(),
        }
    }
}

impl PlatformAdapters for ProductionPlatformAdapters {
    fn cleanup_ops(&self) -> &dyn LedgerCleanupOps {
        &self.cleanup
    }

    fn setup_tun_and_route(
        &self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
        now_ms: u64,
    ) -> AppResult<Arc<dyn TunDevice>> {
        setup_os_tun_and_route(
            self.wintun_sha256.as_deref(),
            tun_cfg,
            overlay_cidr,
            ledger,
            now_ms,
        )
    }
}

#[cfg(target_os = "windows")]
fn setup_os_tun_and_route(
    wintun_sha256: Option<&str>,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    _now_ms: u64,
) -> AppResult<Arc<dyn TunDevice>> {
    let sha = wintun_sha256.ok_or_else(|| {
        AppError::permission_denied(
            "wintun.dll SHA-256 pin is required at compile time (MESH_WINTUN_SHA256)",
        )
    })?;
    let spec = mesh_net::tun_windows::WindowsTunOpenSpec::app_local(sha)?;
    let tun = mesh_net::tun_windows::WindowsTunDevice::open_verified(
        tun_cfg.clone(),
        &spec,
        Some(ledger),
        None,
    )?;
    let route_spec = RouteSpec::new(
        overlay_cidr,
        overlay_cidr,
        tun.interface_name().to_owned(),
        None,
    )?;
    mesh_net::route_windows::WindowsRouteManager::new()
        .apply_overlay_route_with_ledger(&route_spec, ledger)?;
    mesh_net::firewall_windows::configure_overlay_firewall_profile_for_cidr(
        tun.interface_name(),
        overlay_cidr,
        Some(ledger),
    )?;
    Ok(Arc::new(tun))
}

#[cfg(target_os = "macos")]
fn setup_os_tun_and_route(
    _wintun_sha256: Option<&str>,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    now_ms: u64,
) -> AppResult<Arc<dyn TunDevice>> {
    let exec = mesh_net::sysexec::StdCommandExecutor::new();
    let tun = mesh_net::tun_macos::MacOsTunDevice::open(tun_cfg)?;
    tun.configure_with_ledger(&exec, ledger, now_ms)?;
    let route_spec = RouteSpec::new(
        overlay_cidr,
        overlay_cidr,
        tun.interface_name().to_owned(),
        None,
    )?;
    mesh_net::route_macos::MacOsRouteManager::new()
        .apply_overlay_route_with_ledger(&route_spec, ledger)?;
    Ok(Arc::new(tun))
}

#[cfg(target_os = "linux")]
fn setup_os_tun_and_route(
    _wintun_sha256: Option<&str>,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    now_ms: u64,
) -> AppResult<Arc<dyn TunDevice>> {
    let exec = mesh_net::sysexec::StdCommandExecutor::new();
    let tun = mesh_net::tun_linux::LinuxTunDevice::open(tun_cfg)?;
    tun.configure_with_ledger(&exec, ledger, now_ms)?;
    let route_mgr = mesh_net::route_linux::LinuxRouteManager::new();
    let policy = mesh_net::route::LinuxPolicyRoutingSpec::default();
    route_mgr.apply_linux_policy_with_ledger(&policy, ledger)?;
    let route_spec = RouteSpec::new(
        overlay_cidr,
        overlay_cidr,
        tun.interface_name().to_owned(),
        Some(policy.table),
    )?;
    route_mgr.apply_overlay_route_with_ledger(&route_spec, ledger)?;
    Ok(Arc::new(tun))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn setup_os_tun_and_route(
    _wintun_sha256: Option<&str>,
    tun_cfg: TunConfig,
    _overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    now_ms: u64,
) -> AppResult<Arc<dyn TunDevice>> {
    ledger.record_tun_before_create(
        tun_cfg.interface_name.clone(),
        None,
        std::process::id(),
        now_ms,
    )?;
    Ok(Arc::new(FakeTunDevice::new(tun_cfg)))
}

/// In-memory non-privileged platform adapters for deterministic tests without root/Admin.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct InMemoryPlatformAdapters {
    pub(crate) cleanup: mesh_net::ledger::FakeLedgerCleanupOps,
    pub(crate) bind_ipc: bool,
}

#[cfg(test)]
impl PlatformAdapters for InMemoryPlatformAdapters {
    fn cleanup_ops(&self) -> &dyn LedgerCleanupOps {
        &self.cleanup
    }

    fn setup_tun_and_route(
        &self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
        now_ms: u64,
    ) -> AppResult<Arc<dyn TunDevice>> {
        ledger.record_tun_before_create(
            tun_cfg.interface_name.clone(),
            None,
            std::process::id(),
            now_ms,
        )?;
        ledger.record_route_before_add(mesh_net::ledger::LedgerRouteEntry {
            destination_cidr: overlay_cidr.to_string(),
            interface_name: tun_cfg.interface_name.clone(),
            table: None,
        })?;
        Ok(Arc::new(FakeTunDevice::new(tun_cfg)))
    }

    fn bind_ipc_listeners(&self) -> bool {
        self.bind_ipc
    }

    fn enforce_macos_startup_path_security(&self) -> bool {
        false
    }
}

struct ActiveTunnelSession {
    cancel: CancellationToken,
    tracker: TaskTracker,
    wake_tx: mpsc::Sender<ControlWakeSignal>,
}

/// Top-level daemon orchestrator owning `TaskTracker`, hierarchical cancellation, and `ResourceLedger`.
pub(crate) struct DaemonSupervisor {
    paths: DaemonRuntimePaths,
    clock: Arc<dyn Clock>,
    adapters: Arc<dyn PlatformAdapters>,
    ledger: Arc<Mutex<ResourceLedger>>,
    runtime: Arc<DaemonRuntimeState>,
    roaming_control_tx: mpsc::Sender<NetworkChangeEvent>,
    roaming_control_rx: Arc<Mutex<mpsc::Receiver<NetworkChangeEvent>>>,
    termination_tx: mpsc::Sender<(TerminationReason, String)>,
    termination_rx: mpsc::Receiver<(TerminationReason, String)>,
    cmd_tx: mpsc::Sender<SupervisorCommand>,
    cmd_rx: mpsc::Receiver<SupervisorCommand>,
    active_session: Option<ActiveTunnelSession>,
}

impl std::fmt::Debug for DaemonSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonSupervisor")
            .field("bootstrap_path", &self.paths.bootstrap_path)
            .field("ledger_path", &self.paths.ledger_path)
            .finish_non_exhaustive()
    }
}

impl DaemonSupervisor {
    /// Returns diagnostic subsystem label (`status_label`).
    #[must_use]
    pub(crate) fn status_label() -> String {
        format!(
            "supervisor:ready({}, {}, {}, {}, {})",
            NetmapCacheStore::status_label(),
            ControlLoop::status_label(),
            RoamingLoop::status_label(),
            IpcService::status_label(),
            PingProbe::status_label(),
        )
    }

    /// Initializes the daemon supervisor and IMMEDIATELY executes startup crash recovery
    /// against `ledger.json` BEFORE allocating any TUN or route resources (`US-055 AC5`).
    pub(crate) fn boot(
        paths: DaemonRuntimePaths,
        clock: Arc<dyn Clock>,
        adapters: Arc<dyn PlatformAdapters>,
    ) -> AppResult<Self> {
        verify_startup_path_security(&paths, adapters.as_ref())?;

        let mut ledger = ResourceLedger::load_or_init(paths.ledger_path.clone())?;
        if ledger.needs_stale_recovery() {
            info!(
                component = "meshd.supervisor",
                event = "crash_recovery_cleanup_started",
                ledger = %paths.ledger_path.display(),
                "previous daemon exit was unclean; running ledger-scoped crash recovery"
            );
            ledger.cleanup_all(adapters.cleanup_ops())?;
            info!(
                component = "meshd.supervisor",
                event = "crash_recovery_cleanup_completed",
                "stale overlay resources cleaned strictly from ledger"
            );
        }

        let bootstrap_store = BootstrapStore::new(paths.bootstrap_path.clone());
        let bootstrap = bootstrap_store.load_or_default()?;

        let netmap_cache = NetmapCacheStore::new(paths.netmap_cache_path.clone());
        let cached_file: Option<NetmapCacheFile> = match netmap_cache.load_verified() {
            Ok(Some(cf)) if !cf.is_within_offline_grace(clock.now_unix_ms()) => {
                warn!(
                    component = "meshd.supervisor",
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
                    component = "meshd.supervisor",
                    event = "netmap_cache_rejected",
                    error = %err,
                    "ignored tampered or corrupt netmap-cache.json (fail-closed)"
                );
                None
            }
        };

        let runtime = Arc::new(DaemonRuntimeState::new(
            bootstrap,
            bootstrap_store,
            netmap_cache,
            cached_file.as_ref(),
            paths.tun_mtu,
        ));
        if let Ok(mut g) = runtime.inner.try_write() {
            g.underlay_if_index = paths.underlay_if_index;
            g.linux_fwmark = paths.linux_fwmark;
        }
        let (roaming_control_tx, roaming_control_rx) =
            mpsc::channel(NETWORK_CHANGE_CHANNEL_CAPACITY);
        let (termination_tx, termination_rx) = mpsc::channel(4);
        let (cmd_tx, cmd_rx) = mpsc::channel(SUPERVISOR_CMD_CAPACITY);

        Ok(Self {
            paths,
            clock,
            adapters,
            ledger: Arc::new(Mutex::new(ledger)),
            runtime,
            roaming_control_tx,
            roaming_control_rx: Arc::new(Mutex::new(roaming_control_rx)),
            termination_tx,
            termination_rx,
            cmd_tx,
            cmd_rx,
            active_session: None,
        })
    }

    /// Returns a cloned shared runtime state handle for shutdown/status inspection tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn runtime_state(&self) -> Arc<DaemonRuntimeState> {
        Arc::clone(&self.runtime)
    }

    /// Runs IPC listeners, roaming loop, optional auto-resume tunnel, and command handling
    /// until `root_shutdown` fires, guaranteeing teardown completes in `<= 5 s` (`US-055`).
    pub(crate) async fn run(
        mut self,
        monitor: Arc<dyn NetMonitor>,
        root_shutdown: CancellationToken,
    ) -> AppResult<()> {
        let daemon_tracker = TaskTracker::new();

        if self.adapters.bind_ipc_listeners() {
            let router_state = IpcRouterState {
                runtime: Arc::clone(&self.runtime),
                cmd_tx: self.cmd_tx.clone(),
            };
            IpcService::start_listeners(
                &self.paths.ro_ipc_endpoint,
                &self.paths.admin_ipc_endpoint,
                router_state,
                &daemon_tracker,
                &root_shutdown,
            )
            .await?;
        }

        let (roam_rebind_handle, mut roam_rebind_rx) = RebindHandle::channel();
        let forward_runtime = Arc::clone(&self.runtime);
        let forward_shutdown = root_shutdown.clone();
        daemon_tracker.spawn(async move {
            forward_rebind_loop(forward_runtime, &mut roam_rebind_rx, forward_shutdown).await;
        });

        let roaming = RoamingLoop::new(
            monitor,
            Arc::clone(&self.clock),
            roam_rebind_handle,
            self.roaming_control_tx.clone(),
        );
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
                maybe_cmd = self.cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.handle_supervisor_command(cmd, &root_shutdown).await,
                        None => break,
                    }
                }
            }
        }

        self.graceful_shutdown_within_5s(daemon_tracker).await
    }

    async fn handle_verified_identity_termination(
        &mut self,
        reason: TerminationReason,
        message: &str,
    ) {
        let terminated_state = match reason {
            TerminationReason::NodeRevoked => DaemonState::Revoked,
            TerminationReason::NodeKeyExpired => DaemonState::ReauthRequired,
        };
        warn!(
            component = "meshd.supervisor",
            event = "supervisor_identity_terminated_teardown",
            reason = ?reason,
            message = %message,
            "tearing down TUN, routes, hosts, and RelayClient after verified server termination"
        );
        {
            let mut g = self.runtime.inner.write().await;
            g.daemon_state = terminated_state;
            g.last_error = Some(message.to_owned());
        }
        if let Err(err) = self.stop_active_session_and_cleanup().await {
            warn!(
                component = "meshd.supervisor",
                event = "terminated_teardown_cleanup_warning",
                error = %err,
                "ledger cleanup reported warning while tearing down terminated session"
            );
        }
        let mut g = self.runtime.inner.write().await;
        g.daemon_state = terminated_state;
        g.control_connected = false;
        g.last_error = Some(message.to_owned());
    }

    async fn auto_resume_enrolled_session_best_effort(
        &mut self,
        root_shutdown: &CancellationToken,
    ) {
        let bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        if bootstrap.server_endpoint.is_some()
            && bootstrap.node_id.is_some()
            && let Err(err) = self.start_enrolled_session(root_shutdown, None).await
        {
            warn!(
                component = "meshd.supervisor",
                event = "auto_resume_failed",
                error = %err,
                "failed auto-resuming persisted overlay session on daemon startup"
            );
            let mut g = self.runtime.inner.write().await;
            g.last_error = Some(err.to_string());
        }
    }

    async fn handle_supervisor_command(
        &mut self,
        cmd: SupervisorCommand,
        root_shutdown: &CancellationToken,
    ) {
        match cmd {
            SupervisorCommand::Up { req, reply } => {
                let res = self.execute_up(req, root_shutdown).await;
                let _ignored = reply.send(res);
            }
            SupervisorCommand::Down { reply } => {
                let res = self.execute_down().await;
                let _ignored = reply.send(res);
            }
            SupervisorCommand::Cleanup { reply } => {
                let res = self.execute_cleanup().await;
                let _ignored = reply.send(res);
            }
            SupervisorCommand::Set { req, reply } => {
                let res = self.execute_set(req).await;
                let _ignored = reply.send(res);
            }
            SupervisorCommand::RotateKey { req, reply } => {
                let res = self.execute_rotate_key(req, root_shutdown).await;
                let _ignored = reply.send(res);
            }
            SupervisorCommand::Bugreport { reply } => {
                let res = self.execute_bugreport().await;
                let _ignored = reply.send(res);
            }
        }
    }

    async fn execute_up(
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
        let key_store = KeysFileStore::new(self.paths.keystore_path.clone());
        let mut identity = key_store.load_or_create(now_ms)?;

        let underlay = {
            let g = self.runtime.inner.read().await;
            (g.underlay_if_index, g.linux_fwmark)
        };
        let mut bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        bootstrap.server_endpoint = Some(endpoint);
        bootstrap.tls_auth_mode = tls_auth_mode;
        match req.server_pin {
            Some(pin) => {
                bootstrap.active_pin = Some(pin);
                bootstrap.next_pin = None;
            }
            None => {
                bootstrap.active_pin = None;
                bootstrap.next_pin = None;
            }
        }

        let desired_name = match &req.node_name {
            Some(n) => n.clone(),
            None => match bootstrap.node_name.clone() {
                Some(existing) => existing,
                None => detect_default_node_name()?,
            },
        };

        let mut initial_reg: Option<RegisterNodeResponse> = None;
        if req.preauth_key.is_some() || bootstrap.node_id.is_none() {
            let preauth_key = req.preauth_key.clone().ok_or_else(|| {
                AppError::invalid_argument(
                    "first enrollment requires --authkey-file or --authkey-stdin",
                )
            })?;
            let reg_req = RegisterNodeRequest {
                preauth_key,
                node_pubkey: identity.node_keypair.public_key(),
                disco_pubkey: identity.disco_keypair.public_key(),
                node_name: desired_name,
                previous_node_pubkey: None,
            };
            let reg = ControlLoop::register_node(
                &bootstrap,
                &identity.node_keypair,
                &reg_req,
                &self.paths.agent_version,
                underlay,
            )
            .await?;
            identity = key_store.set_node_id(reg.node_id)?;
            apply_registration_to_bootstrap(&mut bootstrap, &reg);
            initial_reg = Some(reg);
        }

        persist_bootstrap_and_runtime(&self.runtime, &bootstrap).await?;
        self.start_enrolled_session_with_identity(root_shutdown, identity, initial_reg)
            .await?;

        let state = { self.runtime.inner.read().await.daemon_state };
        Ok(AgentActionResponse {
            state,
            message: "tunnel up".to_owned(),
        })
    }

    async fn execute_down(&mut self) -> AppResult<AgentActionResponse> {
        self.stop_active_session_and_cleanup().await?;
        Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "tunnel stopped and ledger resources cleaned".to_owned(),
        })
    }

    async fn execute_cleanup(&mut self) -> AppResult<AgentActionResponse> {
        self.stop_active_session_and_cleanup().await?;
        Ok(AgentActionResponse {
            state: DaemonState::Stopped,
            message: "ledger cleanup completed idempotently".to_owned(),
        })
    }

    async fn execute_set(&mut self, req: AgentSetRequest) -> AppResult<AgentActionResponse> {
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
            if let Some(pin) = req.server_pin {
                g.bootstrap.active_pin = Some(pin);
                g.bootstrap.next_pin = None;
            } else {
                g.bootstrap.active_pin = None;
                g.bootstrap.next_pin = None;
            }
            g.migration_pending_endpoint = None;
            g.bootstrap_store.save_atomic(&g.bootstrap)?;

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
                    self.paths.agent_version.clone(),
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
                component = "meshd.supervisor",
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

    async fn execute_rotate_key(
        &mut self,
        req: AgentRotateKeyRequest,
        root_shutdown: &CancellationToken,
    ) -> AppResult<AgentActionResponse> {
        let now_ms = self.clock.now_unix_ms();
        let key_store = KeysFileStore::new(self.paths.keystore_path.clone());
        let old_identity = key_store.load_existing()?;
        let new_node_kp = NodeKeypair::generate();
        let new_disco_kp = DiscoKeypair::generate();

        let (bootstrap, underlay) = {
            let g = self.runtime.inner.read().await;
            (g.bootstrap.clone(), (g.underlay_if_index, g.linux_fwmark))
        };
        let node_name = match bootstrap.node_name.clone() {
            Some(existing) => existing,
            None => detect_default_node_name()?,
        };
        let reg_req = RegisterNodeRequest {
            preauth_key: req.preauth_key.clone(),
            node_pubkey: new_node_kp.public_key(),
            disco_pubkey: new_disco_kp.public_key(),
            node_name,
            previous_node_pubkey: Some(old_identity.node_keypair.public_key()),
        };
        let reg = ControlLoop::register_node(
            &bootstrap,
            &new_node_kp,
            &reg_req,
            &self.paths.agent_version,
            underlay,
        )
        .await?;

        let new_identity = StoredNodeIdentity {
            node_id: Some(reg.node_id),
            node_keypair: new_node_kp,
            disco_keypair: new_disco_kp,
            created_at_ms: now_ms,
        };
        key_store.save_rotated(&new_identity)?;

        let mut updated_bootstrap = bootstrap;
        apply_registration_to_bootstrap(&mut updated_bootstrap, &reg);
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

    /// Generates a redacted non-secret diagnostic snapshot file (`IMP-W12-01`).
    ///
    /// Sprint 1 writes a redacted `.json` diagnostics file for `POST /v1/agent/bugreport`; full
    /// `.tar.gz`/`.zip` bundling of logs and OS route tables is scheduled for Sprint 2 (`US-041`).
    async fn execute_bugreport(&self) -> AppResult<BugreportResponse> {
        let status = self.runtime.build_status_response().await;
        let payload = serde_json::to_vec_pretty(&status).map_err(|err| {
            AppError::internal(format!("failed serializing bugreport payload: {err}"))
        })?;
        let text = String::from_utf8_lossy(&payload);
        let (scrubbed, scrubbed_items) = scrub_diagnostic_text(&text);

        let ts = self.clock.now_unix_ms();
        let file_name = format!("mesh-bugreport-{ts}.json");
        let target = self.paths.bugreport_dir.join(file_name);
        write_private_file_atomic(&target, scrubbed.as_bytes())?;

        Ok(BugreportResponse {
            bundle_path: target.display().to_string(),
            size_bytes: u64::try_from(scrubbed.len()).unwrap_or(0),
            scrubbed_items,
        })
    }

    async fn start_enrolled_session(
        &mut self,
        root_shutdown: &CancellationToken,
        initial_reg: Option<RegisterNodeResponse>,
    ) -> AppResult<()> {
        let key_store = KeysFileStore::new(self.paths.keystore_path.clone());
        let identity = key_store.load_existing()?;
        self.start_enrolled_session_with_identity(root_shutdown, identity, initial_reg)
            .await
    }

    async fn start_enrolled_session_with_identity(
        &mut self,
        root_shutdown: &CancellationToken,
        identity: StoredNodeIdentity,
        initial_reg: Option<RegisterNodeResponse>,
    ) -> AppResult<()> {
        let now_ms = self.clock.now_unix_ms();
        let bootstrap = { self.runtime.inner.read().await.bootstrap.clone() };
        let endpoint = bootstrap.server_endpoint.clone().ok_or_else(|| {
            AppError::invalid_argument("cannot start session without server_endpoint")
        })?;
        let node_id = identity
            .node_id
            .or(bootstrap.node_id)
            .ok_or_else(|| AppError::invalid_argument("node_id missing prior to tunnel start"))?;

        let cached = self.runtime.inner.read().await.latest_netmap.clone();
        let initial_netmap = initial_reg.as_ref().map(|r| r.netmap.clone()).or(cached);
        let overlay_cidr = match initial_netmap.as_ref() {
            Some(n) => n.overlay_cidr,
            None => OverlayCidr::parse(DEFAULT_OVERLAY_CIDR)?,
        };
        let overlay_ip = initial_reg
            .as_ref()
            .map(|r| r.overlay_ip)
            .or(bootstrap.overlay_ip)
            .ok_or_else(|| {
                AppError::invalid_argument("overlay_ip missing; run `mesh up` with auth key")
            })?;

        let preferred_udp_port = {
            let p = self.runtime.inner.read().await.local_udp_port;
            Port::from_u16(p).ok()
        };
        let desired_ifname = default_tun_interface_hint();
        let tun_cfg = TunConfig::new(desired_ifname, overlay_ip, overlay_cidr, self.paths.tun_mtu)?;

        let tun_dev = {
            let mut ledger = self.ledger.lock().await;
            self.adapters
                .setup_tun_and_route(tun_cfg, overlay_cidr, &mut ledger, now_ms)?
        };
        let actual_ifname = tun_dev.interface_name().to_owned();

        let (underlay_if_index, linux_fwmark) = {
            let g = self.runtime.inner.read().await;
            (
                g.underlay_if_index.or(self.paths.underlay_if_index),
                g.linux_fwmark.or(self.paths.linux_fwmark),
            )
        };
        let socket_cfg = MagicSocketConfig::default()
            .with_mtu(self.paths.tun_mtu)?
            .with_underlay(underlay_if_index, linux_fwmark);
        let socket_cfg = match preferred_udp_port {
            Some(port) => socket_cfg.with_preferred_port(port),
            None => socket_cfg,
        };

        let relay_ep = initial_netmap
            .as_ref()
            .map(|n| n.relay_map.relay_tcp_endpoint.clone())
            .unwrap_or_else(|| endpoint.clone());
        let (relay_host, _) = split_host_port(&endpoint)?;
        let relay_cfg = RelayClientConfig {
            endpoint: relay_ep,
            server_name_override: Some(relay_host),
            pin_set: bootstrap.pin_set(),
            underlay_if_index,
            linux_fwmark,
            require_challenge_auth: true,
            agent_version: self.paths.agent_version.clone(),
        };
        let relay_client = RelayClient::new(
            relay_cfg,
            identity.node_keypair.clone_keypair(),
            identity.disco_keypair.clone_keypair(),
        );
        let relay_handle = relay_client.handle();
        let control_tcp_endpoint = resolve_control_tcp_endpoint(&endpoint).await;

        let dp_cfg = DatapathConfig {
            local_node_id: node_id,
            local_overlay_ip: overlay_ip,
            overlay_cidr,
            node_keypair: identity.node_keypair.clone_keypair(),
            disco_keypair: identity.disco_keypair.clone_keypair(),
            socket_config: socket_cfg,
            stun_config: StunClientConfig::default(),
            disco_config: DiscoConfig::default(),
            control_tcp_endpoint,
            wg_timer_interval: Duration::from_millis(250),
            disco_tick_interval: Duration::from_millis(250),
        };
        let engine = DatapathEngine::bind(
            dp_cfg,
            tun_dev,
            Arc::clone(&self.clock),
            Some(relay_handle.clone()),
        )
        .await?;
        let dp_handle = engine.handle();
        let bound_udp_port = engine.local_udp_addr().map_or(0, |a| a.port());

        if let Some(ref snap) = initial_netmap {
            if let Err(err) = dp_handle.apply_netmap(snap.clone()).await {
                warn!(
                    component = "meshd.supervisor",
                    event = "initial_netmap_apply_failed",
                    error = %err,
                    "failed applying initial netmap snapshot to datapath"
                );
            }
            if let Ok(port) = Port::from_u16(bound_udp_port.max(1)) {
                let cache = { self.runtime.inner.read().await.netmap_cache.clone() };
                if let Err(err) = cache.save_atomic(port, snap, now_ms) {
                    warn!(
                        component = "meshd.supervisor",
                        event = "initial_netmap_cache_save_failed",
                        error = %err,
                        "failed persisting initial netmap-cache.json"
                    );
                }
            }
        }

        let (session_rebind_handle, session_rebind_rx) = RebindHandle::channel();
        {
            self.runtime.reset_ws_close();
            let mut g = self.runtime.inner.write().await;
            g.daemon_state = DaemonState::Connecting;
            g.node_id = Some(node_id);
            g.node_name = bootstrap.node_name.clone();
            g.fqdn = initial_reg
                .as_ref()
                .map(|r| r.fqdn.clone())
                .or(bootstrap.fqdn.clone());
            g.overlay_ip = Some(overlay_ip);
            g.overlay_cidr = Some(overlay_cidr);
            g.key_expires_at_ms = initial_reg.as_ref().and_then(|r| r.key_expires_at_ms);
            g.tun_interface_name = Some(actual_ifname);
            g.local_udp_port = bound_udp_port;
            g.latest_netmap = initial_netmap;
            g.datapath_handle = Some(dp_handle);
            g.rebind_handle = Some(session_rebind_handle);
            g.relay_handle = Some(relay_handle);
            g.last_error = None;
        }

        let session_cancel = root_shutdown.child_token();
        let session_tracker = TaskTracker::new();
        let (relay_events_tx, relay_events_rx) = mpsc::channel::<RelayEvent>(RELAY_EVENT_CAPACITY);
        let (wake_tx, wake_rx) = mpsc::channel::<ControlWakeSignal>(8);

        let roaming_rx = Arc::clone(&self.roaming_control_rx);

        session_tracker.spawn(relay_client.run(
            Arc::clone(&self.clock),
            relay_events_tx,
            session_cancel.clone(),
        ));
        let dp_cancel = session_cancel.clone();
        session_tracker.spawn(async move {
            if let Err(err) = engine
                .run(relay_events_rx, session_rebind_rx, dp_cancel)
                .await
            {
                warn!(
                    component = "meshd.supervisor",
                    event = "datapath_engine_exited_error",
                    error = %err,
                    "DatapathEngine exited with error"
                );
            }
        });
        session_tracker.spawn(ControlLoop::run(ControlLoopContext {
            state: Arc::clone(&self.runtime),
            clock: Arc::clone(&self.clock),
            node_keypair: identity.node_keypair,
            disco_pubkey: identity.disco_keypair.public_key(),
            agent_version: self.paths.agent_version.clone(),
            hosts_override: self.paths.hosts_path_override.clone(),
            ledger: Arc::clone(&self.ledger),
            roaming_rx,
            wake_rx,
            termination_tx: Some(self.termination_tx.clone()),
            shutdown: session_cancel.clone(),
        }));

        self.active_session = Some(ActiveTunnelSession {
            cancel: session_cancel,
            tracker: session_tracker,
            wake_tx,
        });
        Ok(())
    }

    /// Stops any active session cleanly (`WS Close <= 1 s`, `cleanup_all <= 4 s`) idempotently.
    pub(crate) async fn stop_active_session_and_cleanup(&mut self) -> AppResult<()> {
        self.runtime.notify_ws_close();
        if let Some(session) = self.active_session.take() {
            if let Err(err) = session
                .wake_tx
                .try_send(ControlWakeSignal::GracefulShutdown)
            {
                debug!(
                    component = "meshd.supervisor",
                    event = "shutdown_wake_try_send_skipped",
                    error = %err,
                    "control wake channel already closed or full during shutdown"
                );
            }
            tokio::time::sleep(WS_CLOSE_PHASE_WAIT.min(Duration::from_millis(50))).await;
            session.cancel.cancel();
            session.tracker.close();
            if tokio::time::timeout(SESSION_JOIN_TIMEOUT, session.tracker.wait())
                .await
                .is_err()
            {
                warn!(
                    component = "meshd.supervisor",
                    event = "session_tasks_wait_timeout",
                    "timed out waiting for tunnel session tasks during shutdown"
                );
            }
        }

        let cleanup_res = tokio::time::timeout(LEDGER_CLEANUP_TIMEOUT, async {
            let mut ledger = self.ledger.lock().await;
            ledger.cleanup_all(self.adapters.cleanup_ops())
        })
        .await;

        clear_override_hosts_best_effort(self.paths.hosts_path_override.as_ref());

        {
            let mut g = self.runtime.inner.write().await;
            if g.daemon_state != DaemonState::Revoked
                && g.daemon_state != DaemonState::ReauthRequired
            {
                g.daemon_state = DaemonState::Stopped;
            }
            g.control_connected = false;
            g.datapath_handle = None;
            g.rebind_handle = None;
            g.relay_handle = None;
            g.tun_interface_name = None;
        }

        match cleanup_res {
            Ok(inner) => inner,
            Err(_) => Err(AppError::unavailable(
                "timed out waiting for ResourceLedger cleanup",
            )),
        }
    }

    async fn graceful_shutdown_within_5s(&mut self, daemon_tracker: TaskTracker) -> AppResult<()> {
        info!(
            component = "meshd.supervisor",
            event = "graceful_shutdown_started",
            "starting bounded Graceful Shutdown (<= 5s)"
        );
        if let Err(err) = self.stop_active_session_and_cleanup().await {
            warn!(
                component = "meshd.supervisor",
                event = "graceful_shutdown_cleanup_warning",
                error = %err,
                "ledger cleanup reported a non-fatal warning during shutdown"
            );
        }

        daemon_tracker.close();
        let budget = Duration::from_millis(GRACEFUL_SHUTDOWN_BUDGET_MS);
        if tokio::time::timeout(budget, daemon_tracker.wait())
            .await
            .is_err()
        {
            warn!(
                component = "meshd.supervisor",
                event = "graceful_shutdown_tracker_timeout",
                "background task tracker wait exceeded 5s budget"
            );
        }
        info!(
            component = "meshd.supervisor",
            event = "graceful_shutdown_completed",
            "meshd supervisor shutdown completed cleanly"
        );
        Ok(())
    }
}

async fn resolve_control_tcp_endpoint(endpoint: &str) -> Option<std::net::SocketAddr> {
    if let Ok(addr) = endpoint.parse::<std::net::SocketAddr>() {
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

async fn forward_rebind_loop(
    runtime: Arc<DaemonRuntimeState>,
    rx: &mut mpsc::Receiver<RebindCommand>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            maybe_cmd = rx.recv() => {
                let Some(cmd) = maybe_cmd else {
                    break;
                };
                if let RebindCommand::RebindInterface {
                    ref interface_name,
                    if_index,
                    ..
                } = cmd
                {
                    let mut g = runtime.inner.write().await;
                    g.bound_physical_interface = Some(interface_name.clone());
                    if let Some(idx) = if_index {
                        g.underlay_if_index = Some(idx);
                    }
                }
                let handle_opt = { runtime.inner.read().await.rebind_handle.clone() };
                if let Some(handle) = handle_opt
                    && let Err(err) = handle.try_send(cmd)
                {
                    debug!(
                        component = "meshd.supervisor",
                        event = "rebind_forward_skipped",
                        error = %err,
                        "failed forwarding network-change rebind command to datapath"
                    );
                }
            }
        }
    }
}

fn apply_port_override(endpoint: &str, port_override: Option<Port>) -> AppResult<String> {
    let (host, current_port) = split_host_port(endpoint)?;
    let chosen_port = port_override.unwrap_or(current_port);
    if host.contains(':') {
        Ok(format!("[{host}]:{}", chosen_port.get()))
    } else {
        Ok(format!("{host}:{}", chosen_port.get()))
    }
}

fn apply_registration_to_bootstrap(bootstrap: &mut BootstrapConfig, reg: &RegisterNodeResponse) {
    bootstrap.node_id = Some(reg.node_id);
    bootstrap.node_name = Some(reg.node_name.clone());
    bootstrap.overlay_ip = Some(reg.overlay_ip);
    bootstrap.fqdn = Some(reg.fqdn.clone());
    bootstrap.apply_netmap_pins(reg.netmap.pin_set.active_pin, reg.netmap.pin_set.next_pin);
    bootstrap.acked_endpoint_version = reg.netmap.relay_map.endpoint_version;
}

async fn persist_bootstrap_and_runtime(
    runtime: &DaemonRuntimeState,
    bootstrap: &BootstrapConfig,
) -> AppResult<()> {
    let mut g = runtime.inner.write().await;
    g.bootstrap_store.save_atomic(bootstrap)?;
    g.bootstrap = bootstrap.clone();
    g.node_id = bootstrap.node_id;
    g.node_name = bootstrap.node_name.clone();
    g.overlay_ip = bootstrap.overlay_ip;
    g.fqdn = bootstrap.fqdn.clone();
    Ok(())
}

fn scrub_diagnostic_text(raw: &str) -> (String, u32) {
    let mut count: u32 = 0;
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("mpk_") || lower.contains("privkey") || lower.contains("preauth") {
            count = count.saturating_add(1);
            out.push_str("  \"[REDACTED]\"\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    (out, count)
}

fn clear_override_hosts_best_effort(path: Option<&PathBuf>) {
    if let Some(p) = path
        && p.exists()
        && let Err(err) = FileHostsEditor::new(p.clone()).clear()
    {
        debug!(
            component = "meshd.supervisor",
            event = "hosts_override_clear_warning",
            error = %err,
            "failed clearing test hosts file override"
        );
    }
}

const fn default_tun_interface_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "utun"
    } else if cfg!(target_os = "windows") {
        "MeshVPN"
    } else {
        "mesh0"
    }
}

fn enforce_macos_startup_security_check<F>(
    enforce: bool,
    installed_paths_present: bool,
    verifier: F,
) -> AppResult<()>
where
    F: FnOnce() -> AppResult<()>,
{
    if enforce && installed_paths_present {
        return verifier();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_startup_path_security(
    _paths: &DaemonRuntimePaths,
    adapters: &dyn PlatformAdapters,
) -> AppResult<()> {
    use mesh_net::ipc_macos::{
        MACOS_DAEMON_BINARY_PATH, MACOS_LAUNCHD_PLIST_PATH, MACOS_STATE_DIR_PATH,
        verify_macos_daemon_startup_paths,
    };
    use std::path::Path;
    let bin = Path::new(MACOS_DAEMON_BINARY_PATH);
    let plist = Path::new(MACOS_LAUNCHD_PLIST_PATH);
    let installed_present = bin.exists() && plist.exists();
    enforce_macos_startup_security_check(
        adapters.enforce_macos_startup_path_security(),
        installed_present,
        || {
            let state = Path::new(MACOS_STATE_DIR_PATH);
            let runtime = Path::new(mesh_core::defaults::UNIX_RUN_DAEMON_DIR);
            verify_macos_daemon_startup_paths(bin, plist, state, runtime)
        },
    )
}

#[cfg(not(target_os = "macos"))]
fn verify_startup_path_security(
    _paths: &DaemonRuntimePaths,
    adapters: &dyn PlatformAdapters,
) -> AppResult<()> {
    enforce_macos_startup_security_check(
        adapters.enforce_macos_startup_path_security(),
        false,
        || Ok(()),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio_util::sync::CancellationToken;

    use mesh_core::clock::SystemClock;
    use mesh_core::{AppError, ErrorKind, NodeId, NodeName, OverlayIp, SpkiPin};
    use mesh_crypto::{DiscoKeypair, NodeKeypair};
    use mesh_net::keystore::{KeysFileStore, StoredNodeIdentity};
    use mesh_net::ledger::{LedgerRouteEntry, ResourceLedger};
    use mesh_net::netmon::{FakeNetMonitor, NetworkChangeEvent};
    use mesh_proto::agent_ipc::{AgentSetRequest, DaemonState, TlsAuthMode};
    use mesh_proto::control::TerminationReason;
    use tempfile::tempdir;

    use super::{DaemonSupervisor, InMemoryPlatformAdapters, enforce_macos_startup_security_check};
    use crate::config::DaemonRuntimePaths;

    #[test]
    fn test_supervisor_startup_crash_recovery_cleans_only_ledger_resources() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let paths = DaemonRuntimePaths::for_temp_dir(dir.path(), "crash");
        let Ok(mut stale_ledger) = ResourceLedger::load_or_init(paths.ledger_path.clone()) else {
            return;
        };
        assert!(
            stale_ledger
                .record_tun_before_create("utun9".to_owned(), None, 4242, 1_700_000_000_000)
                .is_ok()
        );
        assert!(
            stale_ledger
                .record_route_before_add(LedgerRouteEntry {
                    destination_cidr: "100.115.0.0/16".to_owned(),
                    interface_name: "utun9".to_owned(),
                    table: Some(51820),
                })
                .is_ok()
        );
        assert!(
            stale_ledger
                .record_firewall_before_apply(
                    Some("com.internal.mesh".to_owned()),
                    vec!["mesh_overlay".to_owned()],
                )
                .is_ok()
        );
        assert!(stale_ledger.needs_stale_recovery());

        let adapters = Arc::new(InMemoryPlatformAdapters::default());

        // Act
        let _supervisor = DaemonSupervisor::boot(
            paths.clone(),
            Arc::new(SystemClock::new()),
            Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
        )
        .ok();

        let Ok(reloaded) = ResourceLedger::load_or_init(paths.ledger_path) else {
            return;
        };
        let Ok(steps) = adapters.cleanup.recorded_steps() else {
            return;
        };

        // Assert
        assert!(!reloaded.needs_stale_recovery());
        assert!(steps.iter().any(|s| s.contains("utun9")));
        assert!(steps.iter().any(|s| s.contains("100.115.0.0/16")));
        assert!(steps.iter().any(|s| s.contains("com.internal.mesh")));
        assert!(!steps.iter().any(|s| s.contains("utun0")));
    }

    #[tokio::test]
    async fn test_supervisor_graceful_shutdown_completes_under_5s_budget() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let paths = DaemonRuntimePaths::for_temp_dir(dir.path(), "shutdown");
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let Ok(supervisor) = DaemonSupervisor::boot(
            paths,
            Arc::new(SystemClock::new()),
            Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
        ) else {
            return;
        };
        let runtime = supervisor.runtime_state();
        {
            let mut g = runtime.inner.write().await;
            g.bootstrap.node_id = Some(NodeId::new_v7(1_700_000_000_000));
            g.bootstrap.node_name = "alpha".parse::<NodeName>().ok();
            g.bootstrap.overlay_ip = "100.115.0.10".parse::<OverlayIp>().ok();
            g.bootstrap.server_endpoint = Some("203.0.113.10:8443".to_owned());
            g.bootstrap.active_pin = Some(SpkiPin::from_sha256_bytes([1; 32]));
        }

        let monitor = Arc::new(FakeNetMonitor::new());
        let shutdown = CancellationToken::new();
        let run_shutdown = shutdown.clone();
        let started = Instant::now();

        let task = tokio::spawn(supervisor.run(monitor, run_shutdown));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Act
        shutdown.cancel();
        let Ok(Ok(res)) = tokio::time::timeout(Duration::from_secs(5), task).await else {
            return;
        };

        // Assert
        assert!(res.is_ok());
        assert!(started.elapsed() < Duration::from_secs(5));
        let status = runtime.build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::Stopped);
    }

    async fn setup_enrolled_supervisor_in_tempdir(
        dir: &std::path::Path,
        label: &str,
        adapters: &Arc<InMemoryPlatformAdapters>,
    ) -> Option<DaemonSupervisor> {
        let paths = DaemonRuntimePaths::for_temp_dir(dir, label);
        let node_id = NodeId::new_v7(1_700_000_000_100);
        let key_store = KeysFileStore::new(paths.keystore_path.clone());
        let identity = StoredNodeIdentity {
            node_id: Some(node_id),
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: 1_700_000_000_100,
        };
        if key_store.save_rotated(&identity).is_err() {
            return None;
        }
        let Ok(supervisor) = DaemonSupervisor::boot(
            paths,
            Arc::new(SystemClock::new()),
            Arc::clone(adapters) as Arc<dyn super::PlatformAdapters>,
        ) else {
            return None;
        };
        {
            let mut g = supervisor.runtime.inner.write().await;
            g.bootstrap.node_id = Some(node_id);
            g.bootstrap.node_name = "alpha".parse::<NodeName>().ok();
            g.bootstrap.overlay_ip = "100.115.0.10".parse::<OverlayIp>().ok();
            g.bootstrap.server_endpoint = Some("203.0.113.10:8443".to_owned());
            g.bootstrap.tls_auth_mode = TlsAuthMode::SpkiPin;
            g.bootstrap.active_pin = Some(SpkiPin::from_sha256_bytes([2; 32]));
        }
        Some(supervisor)
    }

    #[tokio::test]
    async fn test_supervisor_roaming_channel_persists_across_multiple_sessions() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let Some(mut supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "roaming", &adapters).await
        else {
            return;
        };
        let root_shutdown = CancellationToken::new();

        // Act: start session #1, stop it cleanly, then start session #2 (`HR-W12-03`).
        assert!(
            supervisor
                .start_enrolled_session(&root_shutdown, None)
                .await
                .is_ok()
        );
        assert!(supervisor.stop_active_session_and_cleanup().await.is_ok());
        assert!(
            supervisor
                .start_enrolled_session(&root_shutdown, None)
                .await
                .is_ok()
        );

        // Roaming event sender remains connected across session restarts.
        let send_res = supervisor
            .roaming_control_tx
            .send(NetworkChangeEvent::AddressChanged {
                interface: "en0".to_owned(),
            })
            .await;
        assert!(send_res.is_ok());

        assert!(supervisor.stop_active_session_and_cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_supervisor_identity_termination_stops_session_and_cleans_ledger() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let Some(mut supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "revoked", &adapters).await
        else {
            return;
        };
        let root_shutdown = CancellationToken::new();
        assert!(
            supervisor
                .start_enrolled_session(&root_shutdown, None)
                .await
                .is_ok()
        );
        assert!(supervisor.active_session.is_some());

        // Act (`HR-W12-02`)
        supervisor
            .handle_verified_identity_termination(
                TerminationReason::NodeRevoked,
                "revoked by control",
            )
            .await;

        // Assert
        assert!(supervisor.active_session.is_none());
        let status = supervisor.runtime.build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::Revoked);
        assert_eq!(
            status
                .server_connection
                .as_ref()
                .and_then(|s| s.last_error.as_deref()),
            Some("revoked by control")
        );
        let Ok(steps) = adapters.cleanup.recorded_steps() else {
            return;
        };
        assert!(!steps.is_empty());
        let g = supervisor.runtime.inner.read().await;
        assert!(g.relay_handle.is_none());
        assert!(g.datapath_handle.is_none());
    }

    #[tokio::test]
    async fn test_supervisor_execute_set_clears_pins_on_system_ca_mode() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let Some(mut supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "set_ca", &adapters).await
        else {
            return;
        };
        {
            let mut g = supervisor.runtime.inner.write().await;
            g.bootstrap.next_pin = Some(SpkiPin::from_sha256_bytes([3; 32]));
        }

        // Act (`HR-W12-01`)
        let resp = supervisor
            .execute_set(AgentSetRequest {
                server_endpoint: "vpn.example.com:8443".to_owned(),
                server_pin: None,
            })
            .await;

        // Assert
        assert!(resp.is_ok());
        let g = supervisor.runtime.inner.read().await;
        assert_eq!(g.bootstrap.tls_auth_mode, TlsAuthMode::SystemCa);
        assert!(g.bootstrap.active_pin.is_none());
        assert!(g.bootstrap.next_pin.is_none());
        assert_eq!(
            g.bootstrap.server_endpoint.as_deref(),
            Some("vpn.example.com:8443")
        );
    }

    #[test]
    fn test_verify_startup_path_security_fails_closed_on_macos_error() {
        // Arrange & Act & Assert (`HR-W12-04`)
        let enforced = enforce_macos_startup_security_check(true, true, || {
            Err(AppError::permission_denied("group-writable daemon binary"))
        });
        assert!(matches!(enforced, Err(err) if err.kind() == ErrorKind::PermissionDenied));

        let unconfigured = enforce_macos_startup_security_check(true, false, || {
            Err(AppError::permission_denied("should not run"))
        });
        assert!(unconfigured.is_ok());

        let test_bypass = enforce_macos_startup_security_check(false, true, || {
            Err(AppError::permission_denied(
                "skipped under InMemoryPlatformAdapters",
            ))
        });
        assert!(test_bypass.is_ok());
    }
}
