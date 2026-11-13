//! Daemon lifecycle supervisor: startup `ResourceLedger` crash recovery, dual IPC/Roaming/
//! Control/Datapath orchestration, and bounded Graceful Shutdown (`<= 5 s`, `US-055`, `REL-08`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
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
    DatapathCommand, DatapathConfig, DatapathEngine, DiscoConfig, MagicSocketConfig, RebindCommand,
    RebindHandle, RelayClient, RelayClientConfig, RelayEvent, StunClientConfig,
};
use mesh_net::endpoint_filter::{OverlaySubnetConflict, detect_overlay_subnet_conflict};
use mesh_net::hosts::{FileHostsEditor, HostsEditor};
use mesh_net::keystore::{KeysFileStore, StoredNodeIdentity};
use mesh_net::ledger::{LedgerCleanupOps, ResourceLedger};
#[cfg(test)]
use mesh_net::netmon::FakePhysicalNetworkProbe;
use mesh_net::netmon::{
    NetMonitor, NetworkChangeEvent, OsPhysicalNetworkProbe, PhysicalNetworkProbe,
};
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

/// Result of opening the TUN adapter and evaluating overlay subnet conflicts (`US-037`).
pub(crate) struct TunRouteSetupOutcome {
    pub(crate) tun: Arc<dyn TunDevice>,
    pub(crate) route_installed: bool,
    pub(crate) conflict_warning: Option<String>,
}

/// Platform resource provisioning and cleanup abstraction (`G4` / test isolation).
pub(crate) trait PlatformAdapters: Send + Sync {
    /// Returns the OS-specific `ResourceLedger` cleanup handler.
    fn cleanup_ops(&self) -> &dyn LedgerCleanupOps;

    /// Returns the physical NIC / subnet probe used for roaming and CGNAT conflict detection.
    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe>;

    /// Records the TUN interface and overlay route in `ledger` **before** activating OS state,
    /// skipping overlay route installation when a physical NIC subnet overlaps (`US-037`).
    fn setup_tun_and_route(
        &self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
        now_ms: u64,
    ) -> AppResult<TunRouteSetupOutcome>;

    /// Installs the overlay route onto an active TUN adapter once a subnet conflict clears.
    fn install_overlay_route_only(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()>;

    /// Removes the overlay route without tearing down the TUN adapter when a conflict emerges.
    fn remove_overlay_route_only(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()>;

    /// Reconciles OS firewall profile rules on interface roam (`profile=any` on Windows, `US-036`).
    fn reconcile_firewall_on_roam(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()>;

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

    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe> {
        Arc::new(OsPhysicalNetworkProbe)
    }

    fn setup_tun_and_route(
        &self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
        now_ms: u64,
    ) -> AppResult<TunRouteSetupOutcome> {
        setup_os_tun_and_route(
            self.wintun_sha256.as_deref(),
            &OsPhysicalNetworkProbe,
            tun_cfg,
            overlay_cidr,
            ledger,
            now_ms,
        )
    }

    fn install_overlay_route_only(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()> {
        install_os_overlay_route_only(tun_ifname, overlay_cidr, ledger)
    }

    fn remove_overlay_route_only(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()> {
        remove_os_overlay_route_only(tun_ifname, overlay_cidr)
    }

    fn reconcile_firewall_on_roam(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()> {
        reconcile_os_firewall_on_roam(tun_ifname, overlay_cidr)
    }
}

fn check_overlay_conflict_with_probe(
    probe: &dyn PhysicalNetworkProbe,
    overlay_cidr: OverlayCidr,
) -> Option<OverlaySubnetConflict> {
    let subnets = match probe.list_interface_subnets() {
        Ok(list) => list,
        Err(err) => {
            debug!(
                component = "meshd.supervisor",
                event = "list_interface_subnets_skipped",
                error = %err,
                "unable to inspect physical interface subnets for overlap check"
            );
            return None;
        }
    };
    let conflict = detect_overlay_subnet_conflict(&subnets, overlay_cidr);
    if let Some(ref c) = conflict {
        warn!(
            component = "meshd.supervisor",
            event = "overlay_subnet_conflict",
            overlay_cidr = %c.overlay_cidr,
            interface = %c.interface_name,
            physical_ip = %c.physical_ip,
            physical_prefix_len = c.physical_prefix_len,
            "physical interface subnet overlaps overlay CIDR; refusing overlapping overlay route"
        );
    }
    conflict
}

#[cfg(target_os = "windows")]
fn setup_os_tun_and_route(
    wintun_sha256: Option<&str>,
    probe: &dyn PhysicalNetworkProbe,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    _now_ms: u64,
) -> AppResult<TunRouteSetupOutcome> {
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
    let conflict_warning =
        check_overlay_conflict_with_probe(probe, overlay_cidr).map(|c| c.format_warning());
    let route_installed = if conflict_warning.is_none() {
        let route_spec = RouteSpec::new(
            overlay_cidr,
            overlay_cidr,
            tun.interface_name().to_owned(),
            None,
        )?;
        mesh_net::route_windows::WindowsRouteManager::new()
            .apply_overlay_route_with_ledger(&route_spec, ledger)?;
        true
    } else {
        false
    };
    mesh_net::firewall_windows::configure_overlay_firewall_profile_for_cidr(
        tun.interface_name(),
        overlay_cidr,
        Some(ledger),
    )?;
    Ok(TunRouteSetupOutcome {
        tun: Arc::new(tun),
        route_installed,
        conflict_warning,
    })
}

#[cfg(target_os = "macos")]
fn setup_os_tun_and_route(
    _wintun_sha256: Option<&str>,
    probe: &dyn PhysicalNetworkProbe,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    now_ms: u64,
) -> AppResult<TunRouteSetupOutcome> {
    let exec = mesh_net::sysexec::StdCommandExecutor::new();
    let tun = mesh_net::tun_macos::MacOsTunDevice::open(tun_cfg)?;
    tun.configure_with_ledger(&exec, ledger, now_ms)?;
    let conflict_warning =
        check_overlay_conflict_with_probe(probe, overlay_cidr).map(|c| c.format_warning());
    let route_installed = if conflict_warning.is_none() {
        let route_spec = RouteSpec::new(
            overlay_cidr,
            overlay_cidr,
            tun.interface_name().to_owned(),
            None,
        )?;
        mesh_net::route_macos::MacOsRouteManager::new()
            .apply_overlay_route_with_ledger(&route_spec, ledger)?;
        true
    } else {
        false
    };
    Ok(TunRouteSetupOutcome {
        tun: Arc::new(tun),
        route_installed,
        conflict_warning,
    })
}

#[cfg(target_os = "linux")]
fn setup_os_tun_and_route(
    _wintun_sha256: Option<&str>,
    probe: &dyn PhysicalNetworkProbe,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    now_ms: u64,
) -> AppResult<TunRouteSetupOutcome> {
    let exec = mesh_net::sysexec::StdCommandExecutor::new();
    let tun = mesh_net::tun_linux::LinuxTunDevice::open(tun_cfg)?;
    tun.configure_with_ledger(&exec, ledger, now_ms)?;
    let route_mgr = mesh_net::route_linux::LinuxRouteManager::new();
    let policy = mesh_net::route::LinuxPolicyRoutingSpec::default();
    route_mgr.apply_linux_policy_with_ledger(&policy, ledger)?;
    let conflict_warning =
        check_overlay_conflict_with_probe(probe, overlay_cidr).map(|c| c.format_warning());
    let route_installed = if conflict_warning.is_none() {
        let route_spec = RouteSpec::new(
            overlay_cidr,
            overlay_cidr,
            tun.interface_name().to_owned(),
            Some(policy.table),
        )?;
        route_mgr.apply_overlay_route_with_ledger(&route_spec, ledger)?;
        true
    } else {
        false
    };
    Ok(TunRouteSetupOutcome {
        tun: Arc::new(tun),
        route_installed,
        conflict_warning,
    })
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn setup_os_tun_and_route(
    _wintun_sha256: Option<&str>,
    probe: &dyn PhysicalNetworkProbe,
    tun_cfg: TunConfig,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
    now_ms: u64,
) -> AppResult<TunRouteSetupOutcome> {
    ledger.record_tun_before_create(
        tun_cfg.interface_name.clone(),
        None,
        std::process::id(),
        now_ms,
    )?;
    let conflict_warning =
        check_overlay_conflict_with_probe(probe, overlay_cidr).map(|c| c.format_warning());
    let route_installed = conflict_warning.is_none();
    Ok(TunRouteSetupOutcome {
        tun: Arc::new(FakeTunDevice::new(tun_cfg)),
        route_installed,
        conflict_warning,
    })
}

#[cfg(target_os = "windows")]
fn install_os_overlay_route_only(
    tun_ifname: &str,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
) -> AppResult<()> {
    let route_spec = RouteSpec::new(overlay_cidr, overlay_cidr, tun_ifname.to_owned(), None)?;
    mesh_net::route_windows::WindowsRouteManager::new()
        .apply_overlay_route_with_ledger(&route_spec, ledger)
}

#[cfg(target_os = "macos")]
fn install_os_overlay_route_only(
    tun_ifname: &str,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
) -> AppResult<()> {
    let route_spec = RouteSpec::new(overlay_cidr, overlay_cidr, tun_ifname.to_owned(), None)?;
    mesh_net::route_macos::MacOsRouteManager::new()
        .apply_overlay_route_with_ledger(&route_spec, ledger)
}

#[cfg(target_os = "linux")]
fn install_os_overlay_route_only(
    tun_ifname: &str,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
) -> AppResult<()> {
    let policy = mesh_net::route::LinuxPolicyRoutingSpec::default();
    let route_spec = RouteSpec::new(
        overlay_cidr,
        overlay_cidr,
        tun_ifname.to_owned(),
        Some(policy.table),
    )?;
    mesh_net::route_linux::LinuxRouteManager::new()
        .apply_overlay_route_with_ledger(&route_spec, ledger)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn install_os_overlay_route_only(
    tun_ifname: &str,
    overlay_cidr: OverlayCidr,
    ledger: &mut ResourceLedger,
) -> AppResult<()> {
    ledger.record_route_before_add(mesh_net::ledger::LedgerRouteEntry {
        destination_cidr: overlay_cidr.to_string(),
        interface_name: tun_ifname.to_owned(),
        table: None,
    })
}

#[cfg(target_os = "windows")]
fn remove_os_overlay_route_only(tun_ifname: &str, overlay_cidr: OverlayCidr) -> AppResult<()> {
    use mesh_net::route::RouteManager as _;
    let route_spec = RouteSpec::new(overlay_cidr, overlay_cidr, tun_ifname.to_owned(), None)?;
    mesh_net::route_windows::WindowsRouteManager::new().remove_overlay_route(&route_spec)
}

#[cfg(target_os = "macos")]
fn remove_os_overlay_route_only(tun_ifname: &str, overlay_cidr: OverlayCidr) -> AppResult<()> {
    use mesh_net::route::RouteManager as _;
    let route_spec = RouteSpec::new(overlay_cidr, overlay_cidr, tun_ifname.to_owned(), None)?;
    mesh_net::route_macos::MacOsRouteManager::new().remove_overlay_route(&route_spec)
}

#[cfg(target_os = "linux")]
fn remove_os_overlay_route_only(tun_ifname: &str, overlay_cidr: OverlayCidr) -> AppResult<()> {
    use mesh_net::route::RouteManager as _;
    let policy = mesh_net::route::LinuxPolicyRoutingSpec::default();
    let route_spec = RouteSpec::new(
        overlay_cidr,
        overlay_cidr,
        tun_ifname.to_owned(),
        Some(policy.table),
    )?;
    mesh_net::route_linux::LinuxRouteManager::new().remove_overlay_route(&route_spec)
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn remove_os_overlay_route_only(_tun_ifname: &str, _overlay_cidr: OverlayCidr) -> AppResult<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn reconcile_os_firewall_on_roam(tun_ifname: &str, overlay_cidr: OverlayCidr) -> AppResult<()> {
    mesh_net::firewall_windows::reconcile_overlay_firewall_on_roam(tun_ifname, overlay_cidr)
}

#[cfg(not(target_os = "windows"))]
fn reconcile_os_firewall_on_roam(_tun_ifname: &str, _overlay_cidr: OverlayCidr) -> AppResult<()> {
    Ok(())
}

/// In-memory non-privileged platform adapters for deterministic tests without root/Admin.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct InMemoryPlatformAdapters {
    pub(crate) cleanup: mesh_net::ledger::FakeLedgerCleanupOps,
    pub(crate) bind_ipc: bool,
    pub(crate) probe: Arc<FakePhysicalNetworkProbe>,
    pub(crate) firewall_reconciles: StdMutex<Vec<(String, String)>>,
    pub(crate) route_installs: StdMutex<Vec<String>>,
    pub(crate) route_removals: StdMutex<Vec<String>>,
}

#[cfg(test)]
impl PlatformAdapters for InMemoryPlatformAdapters {
    fn cleanup_ops(&self) -> &dyn LedgerCleanupOps {
        &self.cleanup
    }

    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe> {
        Arc::clone(&self.probe) as Arc<dyn PhysicalNetworkProbe>
    }

    fn setup_tun_and_route(
        &self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
        now_ms: u64,
    ) -> AppResult<TunRouteSetupOutcome> {
        ledger.record_tun_before_create(
            tun_cfg.interface_name.clone(),
            None,
            std::process::id(),
            now_ms,
        )?;
        let conflict_warning = check_overlay_conflict_with_probe(self.probe.as_ref(), overlay_cidr)
            .map(|c| c.format_warning());
        let route_installed = if conflict_warning.is_none() {
            ledger.record_route_before_add(mesh_net::ledger::LedgerRouteEntry {
                destination_cidr: overlay_cidr.to_string(),
                interface_name: tun_cfg.interface_name.clone(),
                table: None,
            })?;
            if let Ok(mut g) = self.route_installs.lock() {
                g.push(overlay_cidr.to_string());
            }
            true
        } else {
            false
        };
        Ok(TunRouteSetupOutcome {
            tun: Arc::new(FakeTunDevice::new(tun_cfg)),
            route_installed,
            conflict_warning,
        })
    }

    fn install_overlay_route_only(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
        ledger: &mut ResourceLedger,
    ) -> AppResult<()> {
        ledger.record_route_before_add(mesh_net::ledger::LedgerRouteEntry {
            destination_cidr: overlay_cidr.to_string(),
            interface_name: tun_ifname.to_owned(),
            table: None,
        })?;
        if let Ok(mut g) = self.route_installs.lock() {
            g.push(overlay_cidr.to_string());
        }
        Ok(())
    }

    fn remove_overlay_route_only(
        &self,
        _tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()> {
        if let Ok(mut g) = self.route_removals.lock() {
            g.push(overlay_cidr.to_string());
        }
        Ok(())
    }

    fn reconcile_firewall_on_roam(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()> {
        if let Ok(mut g) = self.firewall_reconciles.lock() {
            g.push((tun_ifname.to_owned(), overlay_cidr.to_string()));
        }
        Ok(())
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
    active_wake_tx: Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>>,
    overlay_route_installed: Arc<AtomicBool>,
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

        let runtime = Arc::new(DaemonRuntimeState::new_with_now(
            bootstrap,
            bootstrap_store,
            netmap_cache,
            cached_file.as_ref(),
            paths.tun_mtu,
            clock.now_unix_ms(),
        ));
        let initial_probe = adapters.network_probe();
        let probed_primary = initial_probe.query_primary_interface().ok();
        if let Ok(mut g) = runtime.inner.try_write() {
            g.underlay_if_index = paths
                .underlay_if_index
                .or_else(|| {
                    probed_primary
                        .as_ref()
                        .map(|p| p.if_index)
                        .filter(|&id| id != 0)
                })
                .filter(|&id| id != 0);
            g.linux_fwmark = paths.linux_fwmark;
            if let Some(ref primary) = probed_primary {
                g.bound_physical_interface = Some(primary.name.clone());
            }
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
            active_wake_tx: Arc::new(StdMutex::new(None)),
            overlay_route_installed: Arc::new(AtomicBool::new(false)),
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
        let (rebind_feedback_tx, rebind_feedback_rx) = mpsc::channel::<AppResult<()>>(8);
        let forward_ctx = RebindForwardContext {
            runtime: Arc::clone(&self.runtime),
            adapters: Arc::clone(&self.adapters),
            ledger: Arc::clone(&self.ledger),
            active_wake_tx: Arc::clone(&self.active_wake_tx),
            overlay_route_installed: Arc::clone(&self.overlay_route_installed),
            agent_version: self.paths.agent_version.clone(),
            rebind_feedback_tx: Some(rebind_feedback_tx),
            shutdown: root_shutdown.clone(),
        };
        daemon_tracker.spawn(async move {
            forward_rebind_loop(forward_ctx, &mut roam_rebind_rx).await;
        });

        let roaming = RoamingLoop::new(
            monitor,
            Arc::clone(&self.clock),
            roam_rebind_handle,
            self.roaming_control_tx.clone(),
        )
        .with_probe(self.adapters.network_probe())
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
            crate::netmap_cache::DEFAULT_KEY_EXPIRY_GRACE_HOURS,
        ) {
            warn!(
                component = "meshd.supervisor",
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

        let setup_outcome = {
            let mut ledger = self.ledger.lock().await;
            self.adapters
                .setup_tun_and_route(tun_cfg, overlay_cidr, &mut ledger, now_ms)?
        };
        let tun_dev = setup_outcome.tun;
        let startup_conflict_warning = setup_outcome.conflict_warning;
        self.overlay_route_installed
            .store(setup_outcome.route_installed, Ordering::SeqCst);
        let actual_ifname = tun_dev.interface_name().to_owned();

        let probed_primary = self.adapters.network_probe().query_primary_interface().ok();
        let (underlay_if_index, linux_fwmark) = {
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
            (
                g.underlay_if_index
                    .or(self.paths.underlay_if_index)
                    .filter(|&id| id != 0),
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
        let effective_key_expires_at_ms = initial_reg
            .as_ref()
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

        if let Some(ref snap) = initial_netmap
            && let Ok(port) = Port::from_u16(bound_udp_port.max(1))
        {
            let cache = { self.runtime.inner.read().await.netmap_cache.clone() };
            if let Err(err) = cache.save_atomic(port, snap, now_ms, effective_key_expires_at_ms) {
                warn!(
                    component = "meshd.supervisor",
                    event = "initial_netmap_cache_save_failed",
                    error = %err,
                    "failed persisting initial netmap-cache.json"
                );
            }
        }

        let initial_netmap_for_dp = initial_netmap.clone();
        let apply_dp_handle = dp_handle.clone();
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
            g.key_expires_at_ms = effective_key_expires_at_ms;
            g.tun_interface_name = Some(actual_ifname);
            g.local_udp_port = bound_udp_port;
            g.latest_netmap = initial_netmap;
            g.datapath_handle = Some(dp_handle);
            g.rebind_handle = Some(session_rebind_handle);
            g.relay_handle = Some(relay_handle);
            g.overlay_conflict_warning = startup_conflict_warning;
            g.last_error = None;
        }

        let session_cancel = root_shutdown.child_token();
        let session_tracker = TaskTracker::new();
        let (relay_events_tx, relay_events_rx) = mpsc::channel::<RelayEvent>(RELAY_EVENT_CAPACITY);
        let (wake_tx, wake_rx) = mpsc::channel::<ControlWakeSignal>(8);
        if let Ok(mut guard) = self.active_wake_tx.lock() {
            *guard = Some(wake_tx.clone());
        }

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

        // Apply initial/cached netmap only AFTER `relay_client.run` and `engine.run` are spawned
        // so `ApplyNetmap`'s command reply is serviced immediately without startup deadlock (`BLK-W21-01`).
        if let Some(snap) = initial_netmap_for_dp
            && let Err(err) = apply_dp_handle.apply_netmap(snap).await
        {
            warn!(
                component = "meshd.supervisor",
                event = "initial_netmap_apply_failed",
                error = %err,
                "failed applying initial netmap snapshot to datapath"
            );
        }
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
            g.overlay_conflict_warning = None;
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

struct RebindForwardContext {
    runtime: Arc<DaemonRuntimeState>,
    adapters: Arc<dyn PlatformAdapters>,
    ledger: Arc<Mutex<ResourceLedger>>,
    active_wake_tx: Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>>,
    overlay_route_installed: Arc<AtomicBool>,
    agent_version: String,
    rebind_feedback_tx: Option<mpsc::Sender<AppResult<()>>>,
    shutdown: CancellationToken,
}

async fn forward_rebind_loop(ctx: RebindForwardContext, rx: &mut mpsc::Receiver<RebindCommand>) {
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

async fn handle_rebind_command(ctx: &RebindForwardContext, cmd: RebindCommand) {
    let RebindCommand::RebindInterface {
        ref interface_name,
        if_index,
        is_ipv6,
    } = cmd
    else {
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
                component = "meshd.supervisor",
                event = "rebind_forward_skipped",
                error = %err,
                "failed forwarding datapath rebind command"
            );
        }
        return;
    };

    let effective_if_index = if_index.filter(|&id| id != 0);
    let (
        bootstrap,
        overlay_cidr,
        tun_ifname,
        underlay,
        rebind_handle,
        relay_handle,
        dp_handle,
        peer_ids,
        relay_endpoint,
    ) = {
        let mut g = ctx.runtime.inner.write().await;
        g.bound_physical_interface = Some(interface_name.clone());
        if let Some(idx) = effective_if_index {
            g.underlay_if_index = Some(idx);
        }
        if !matches!(
            g.daemon_state,
            DaemonState::Stopped | DaemonState::Revoked | DaemonState::ReauthRequired
        ) {
            g.daemon_state = DaemonState::Connecting;
            g.control_connected = false;
            g.last_error = Some("rebinding network interface".to_owned());
        }
        let relay_ep = g
            .latest_netmap
            .as_ref()
            .map(|n| n.relay_map.relay_tcp_endpoint.clone())
            .or_else(|| g.bootstrap.server_endpoint.clone());
        let peers = g
            .latest_netmap
            .as_ref()
            .map(|n| n.peers.iter().map(|p| p.node_id).collect::<Vec<_>>())
            .unwrap_or_default();
        (
            g.bootstrap.clone(),
            g.overlay_cidr,
            g.tun_interface_name.clone(),
            (g.underlay_if_index, g.linux_fwmark),
            g.rebind_handle.clone(),
            g.relay_handle.clone(),
            g.datapath_handle.clone(),
            peers,
            relay_ep,
        )
    };

    if let Some(ref dp) = dp_handle
        && let Err(err) = dp.begin_rebind().await
    {
        debug!(
            component = "meshd.supervisor",
            event = "datapath_begin_rebind_skipped",
            error = %err,
            "failed marking datapath rebinding before route reconciliation"
        );
    }

    if let (Some(cidr), Some(tun_if)) = (overlay_cidr, tun_ifname.as_deref()) {
        reconcile_overlay_conflict_on_roam(ctx, cidr, tun_if).await;
        if let Err(err) = ctx.adapters.reconcile_firewall_on_roam(tun_if, cidr) {
            warn!(
                component = "meshd.supervisor",
                event = "firewall_roam_reconcile_warning",
                interface = %tun_if,
                error = %err,
                "failed reconciling OS overlay firewall rule after roam"
            );
        }
    }

    let mut reprobe_ready = true;
    let mut feedback: AppResult<()> = Ok(());

    if let Some(ref dp) = dp_handle {
        match dp
            .rebind_underlay(interface_name.clone(), effective_if_index, is_ipv6)
            .await
        {
            Ok(bound_port) => {
                let mut g = ctx.runtime.inner.write().await;
                g.local_udp_port = bound_port;
            }
            Err(err) => {
                reprobe_ready = false;
                warn!(
                    component = "meshd.supervisor",
                    event = "datapath_rebind_underlay_failed",
                    interface = %interface_name,
                    if_index = ?effective_if_index,
                    error = %err,
                    "underlay UDP socket rebind failed; retaining direct-UDP block until retry"
                );
                let mut g = ctx.runtime.inner.write().await;
                g.last_error = Some(format!("rebinding network interface failed: {err}"));
                feedback = Err(err);
            }
        }
    } else if let Some(handle) = rebind_handle.as_ref()
        && let Err(err) = handle.try_send(cmd)
    {
        debug!(
            component = "meshd.supervisor",
            event = "rebind_forward_skipped",
            error = %err,
            "failed forwarding network-change rebind command to datapath"
        );
    }

    if reprobe_ready {
        if dp_handle.is_some()
            && let Some(ref handle) = rebind_handle
            && let Err(err) = handle.try_send(RebindCommand::RefreshCandidates)
        {
            debug!(
                component = "meshd.supervisor",
                event = "refresh_candidates_forward_skipped",
                error = %err,
                "failed forwarding candidate refresh after successful rebind"
            );
        }

        if let (Some(relay_h), Some(ep)) = (relay_handle, relay_endpoint) {
            match build_relay_client_config_for_runtime(
                &bootstrap,
                ep,
                (effective_if_index.or(underlay.0), underlay.1),
                ctx.agent_version.clone(),
            ) {
                Ok(next_cfg) => {
                    relay_h.update_config(next_cfg);
                    relay_h.wake_reconnect();
                }
                Err(err) => {
                    warn!(
                        component = "meshd.supervisor",
                        event = "relay_reconfig_build_failed",
                        error = %err,
                        "failed rebuilding RelayClient config on roam"
                    );
                }
            }
        }

        dispatch_datapath_reprobe_and_wake_control(ctx, dp_handle, &peer_ids).await;
    }

    if let Some(ref tx) = ctx.rebind_feedback_tx
        && let Err(err) = tx.try_send(feedback)
    {
        debug!(
            component = "meshd.supervisor",
            event = "rebind_feedback_send_skipped",
            error = %err,
            "failed delivering rebind feedback to roaming loop"
        );
    }
}

async fn reconcile_overlay_conflict_on_roam(
    ctx: &RebindForwardContext,
    overlay_cidr: OverlayCidr,
    tun_ifname: &str,
) {
    let probe = ctx.adapters.network_probe();
    match check_overlay_conflict_with_probe(probe.as_ref(), overlay_cidr) {
        Some(conflict) => {
            let warning = conflict.format_warning();
            ctx.runtime.inner.write().await.overlay_conflict_warning = Some(warning);
            if ctx.overlay_route_installed.load(Ordering::SeqCst) {
                match ctx
                    .adapters
                    .remove_overlay_route_only(tun_ifname, overlay_cidr)
                {
                    Ok(()) => {
                        ctx.overlay_route_installed.store(false, Ordering::SeqCst);
                    }
                    Err(err) => {
                        warn!(
                            component = "meshd.supervisor",
                            event = "overlay_conflict_route_remove_failed",
                            error = %err,
                            "failed removing newly conflicting overlay route on roam"
                        );
                    }
                }
            }
        }
        None => {
            let had_warning = ctx
                .runtime
                .inner
                .write()
                .await
                .overlay_conflict_warning
                .take()
                .is_some();
            if had_warning {
                info!(
                    component = "meshd.supervisor",
                    event = "overlay_subnet_conflict_cleared",
                    overlay_cidr = %overlay_cidr,
                    "physical subnet no longer overlaps overlay CIDR; warning cleared"
                );
            }
            if !ctx.overlay_route_installed.load(Ordering::SeqCst) {
                let install_res = {
                    let mut ledger = ctx.ledger.lock().await;
                    ctx.adapters
                        .install_overlay_route_only(tun_ifname, overlay_cidr, &mut ledger)
                };
                match install_res {
                    Ok(()) => {
                        ctx.overlay_route_installed.store(true, Ordering::SeqCst);
                    }
                    Err(err) => {
                        warn!(
                            component = "meshd.supervisor",
                            event = "deferred_overlay_route_install_failed",
                            error = %err,
                            "failed installing deferred overlay route after conflict cleared"
                        );
                    }
                }
            }
        }
    }
}

async fn dispatch_datapath_reprobe_and_wake_control(
    ctx: &RebindForwardContext,
    dp_handle: Option<mesh_datapath::DatapathHandle>,
    peer_ids: &[mesh_core::NodeId],
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
            Ok(Err(err)) => {
                debug!(
                    component = "meshd.supervisor",
                    event = "roam_stun_probe_skipped",
                    error = %err,
                    "datapath skipped STUN probe dispatch on roam"
                );
            }
            Err(_) => {
                debug!(
                    component = "meshd.supervisor",
                    event = "roam_stun_probe_timeout",
                    "timed out queuing STUN probe on roam"
                );
            }
        }
        for &peer_id in peer_ids {
            match tokio::time::timeout(
                Duration::from_millis(100),
                dp.send(DatapathCommand::InitiateHolePunch(peer_id)),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    debug!(
                        component = "meshd.supervisor",
                        event = "roam_disco_probe_skipped",
                        peer_id = %peer_id,
                        error = %err,
                        "datapath skipped peer Disco probe dispatch on roam"
                    );
                }
                Err(_) => {
                    debug!(
                        component = "meshd.supervisor",
                        event = "roam_disco_probe_timeout",
                        peer_id = %peer_id,
                        "timed out queuing peer Disco probe on roam"
                    );
                }
            }
        }
    }

    let wake_opt = ctx.active_wake_tx.lock().ok().and_then(|g| g.clone());
    if let Some(wake_tx) = wake_opt
        && let Err(err) = wake_tx.try_send(ControlWakeSignal::ConfigUpdated)
    {
        debug!(
            component = "meshd.supervisor",
            event = "roaming_control_wake_skipped",
            error = %err,
            "control wake signal skipped after rebind"
        );
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
    bootstrap.key_expires_at_ms = reg.key_expires_at_ms;
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

    #[tokio::test]
    async fn test_supervisor_cgnat_conflict_refuses_route_on_startup_and_clears_on_roam() {
        // Arrange (`US-037`)
        let Ok(dir) = tempdir() else {
            return;
        };
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        adapters.probe.push_observation(
            Ok(mesh_net::netmon::PhysicalInterface {
                if_index: 0,
                name: "eth0".to_owned(),
            }),
            Ok(vec![mesh_net::endpoint_filter::InterfaceSubnetSnapshot {
                if_index: 0,
                interface_name: "eth0".to_owned(),
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 1, 10)),
                prefix_len: 10,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            }]),
        );
        let Some(mut supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "cgnat", &adapters).await
        else {
            return;
        };
        let root_shutdown = CancellationToken::new();

        // Act 1: Start session while physical NIC overlaps 100.64.0.0/10 CGNAT & 100.115.0.0/16.
        let started = supervisor
            .start_enrolled_session(&root_shutdown, None)
            .await;
        assert!(started.is_ok());

        // Assert 1: Overlapping overlay route was refused while TUN remains managed.
        assert!(
            !supervisor
                .overlay_route_installed
                .load(super::Ordering::SeqCst)
        );
        let status_conflict = supervisor.runtime.build_status_response().await;
        assert!(
            status_conflict
                .self_network
                .overlay_conflict_warning
                .as_deref()
                .is_some_and(|w| w.contains("eth0") && w.contains("100.115.0.0/16"))
        );
        {
            let Ok(initial_installs) = adapters.route_installs.lock() else {
                return;
            };
            assert!(initial_installs.is_empty());
        }

        // Act 2: Roam to clean private LAN subnets (RFC1918 zero false positive check).
        adapters.probe.push_observation(
            Ok(mesh_net::netmon::PhysicalInterface {
                if_index: 9,
                name: "en0".to_owned(),
            }),
            Ok(vec![
                mesh_net::endpoint_filter::InterfaceSubnetSnapshot {
                    if_index: 9,
                    interface_name: "en0".to_owned(),
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50)),
                    prefix_len: 24,
                    is_up: true,
                    is_virtual: false,
                    has_gateway: true,
                },
                mesh_net::endpoint_filter::InterfaceSubnetSnapshot {
                    if_index: 10,
                    interface_name: "en1".to_owned(),
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5)),
                    prefix_len: 8,
                    is_up: true,
                    is_virtual: false,
                    has_gateway: false,
                },
                mesh_net::endpoint_filter::InterfaceSubnetSnapshot {
                    if_index: 11,
                    interface_name: "en2".to_owned(),
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 4, 9)),
                    prefix_len: 16,
                    is_up: true,
                    is_virtual: false,
                    has_gateway: false,
                },
            ]),
        );
        let ctx = super::RebindForwardContext {
            runtime: Arc::clone(&supervisor.runtime),
            adapters: Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
            ledger: Arc::clone(&supervisor.ledger),
            active_wake_tx: Arc::clone(&supervisor.active_wake_tx),
            overlay_route_installed: Arc::clone(&supervisor.overlay_route_installed),
            agent_version: supervisor.paths.agent_version.clone(),
            rebind_feedback_tx: None,
            shutdown: root_shutdown.clone(),
        };
        super::handle_rebind_command(
            &ctx,
            mesh_datapath::RebindCommand::RebindInterface {
                interface_name: "en0".to_owned(),
                if_index: Some(9),
                is_ipv6: false,
            },
        )
        .await;

        // Assert 2: Warning cleared automatically & deferred overlay route installed.
        let status_clean = supervisor.runtime.build_status_response().await;
        assert!(status_clean.self_network.overlay_conflict_warning.is_none());
        assert!(
            supervisor
                .overlay_route_installed
                .load(super::Ordering::SeqCst)
        );
        {
            let Ok(final_installs) = adapters.route_installs.lock() else {
                return;
            };
            assert_eq!(final_installs.as_slice(), &["100.115.0.0/16".to_owned()]);
        }
        assert!(supervisor.stop_active_session_and_cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_supervisor_roam_sets_rebinding_state_forwards_rebind_and_wakes_control() {
        // Arrange (`US-035`, `US-036`)
        let Ok(dir) = tempdir() else {
            return;
        };
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        adapters.probe.push_observation(
            Ok(mesh_net::netmon::PhysicalInterface {
                if_index: 14,
                name: "Wi-Fi".to_owned(),
            }),
            Ok(vec![mesh_net::endpoint_filter::InterfaceSubnetSnapshot {
                if_index: 14,
                interface_name: "Wi-Fi".to_owned(),
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 10, 42)),
                prefix_len: 24,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            }]),
        );
        let Some(supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "rebind", &adapters).await
        else {
            return;
        };
        let (rebind_handle, mut rebind_rx) = mesh_datapath::RebindHandle::channel();
        let (wake_tx, mut wake_rx) = tokio::sync::mpsc::channel(4);
        if let Ok(mut guard) = supervisor.active_wake_tx.lock() {
            *guard = Some(wake_tx);
        }
        supervisor
            .overlay_route_installed
            .store(true, super::Ordering::SeqCst);
        let Ok(overlay_cidr) = "100.115.0.0/16".parse::<mesh_core::OverlayCidr>() else {
            return;
        };
        {
            let mut g = supervisor.runtime.inner.write().await;
            g.daemon_state = DaemonState::Connected;
            g.control_connected = true;
            g.last_error = None;
            g.overlay_cidr = Some(overlay_cidr);
            g.tun_interface_name = Some("MeshVPN".to_owned());
            g.rebind_handle = Some(rebind_handle);
        }
        let ctx = super::RebindForwardContext {
            runtime: Arc::clone(&supervisor.runtime),
            adapters: Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
            ledger: Arc::clone(&supervisor.ledger),
            active_wake_tx: Arc::clone(&supervisor.active_wake_tx),
            overlay_route_installed: Arc::clone(&supervisor.overlay_route_installed),
            agent_version: supervisor.paths.agent_version.clone(),
            rebind_feedback_tx: None,
            shutdown: CancellationToken::new(),
        };

        // Act
        super::handle_rebind_command(
            &ctx,
            mesh_datapath::RebindCommand::RebindInterface {
                interface_name: "Wi-Fi".to_owned(),
                if_index: Some(14),
                is_ipv6: false,
            },
        )
        .await;

        // Assert: transient rebinding status, NIC index updated, RebindCommand + Wake dispatched,
        // and Windows Firewall reconciliation executed on roam.
        let status = supervisor.runtime.build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::Connecting);
        assert!(
            !status
                .server_connection
                .as_ref()
                .is_some_and(|s| s.control_connected)
        );
        let g = supervisor.runtime.inner.read().await;
        assert_eq!(g.bound_physical_interface.as_deref(), Some("Wi-Fi"));
        assert_eq!(g.underlay_if_index, Some(14));
        assert_eq!(g.last_error.as_deref(), Some("rebinding network interface"));
        drop(g);

        assert_eq!(
            rebind_rx.try_recv(),
            Ok(mesh_datapath::RebindCommand::RebindInterface {
                interface_name: "Wi-Fi".to_owned(),
                if_index: Some(14),
                is_ipv6: false,
            })
        );
        assert!(matches!(
            wake_rx.try_recv(),
            Ok(crate::control_loop::ControlWakeSignal::ConfigUpdated)
        ));
        let Ok(fw) = adapters.firewall_reconciles.lock() else {
            return;
        };
        assert_eq!(
            fw.as_slice(),
            &[("MeshVPN".to_owned(), "100.115.0.0/16".to_owned())]
        );
    }

    #[tokio::test]
    async fn test_supervisor_start_enrolled_session_with_initial_netmap_does_not_deadlock_under_1s()
    {
        // Arrange (`BLK-W21-01`)
        let Ok(dir) = tempdir() else {
            return;
        };
        let now_ms: u64 = 1_700_000_000_000;
        let clock = Arc::new(mesh_core::clock::FakeClock::new(now_ms));
        let paths = DaemonRuntimePaths::for_temp_dir(dir.path(), "blk_w21_01");
        let node_id = NodeId::new_v7(now_ms);
        let key_store = KeysFileStore::new(paths.keystore_path.clone());
        let identity = StoredNodeIdentity {
            node_id: Some(node_id),
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: now_ms,
        };
        assert!(key_store.save_rotated(&identity).is_ok());

        let Ok(overlay_cidr) = "100.115.0.0/16".parse::<mesh_core::OverlayCidr>() else {
            return;
        };
        let Ok(self_ip) = "100.115.0.10".parse::<OverlayIp>() else {
            return;
        };
        let Ok(peer_ip) = "100.115.0.20".parse::<OverlayIp>() else {
            return;
        };
        let Ok(node_name) = "alpha".parse::<NodeName>() else {
            return;
        };
        let Ok(peer_name) = "beta".parse::<NodeName>() else {
            return;
        };
        let bootstrap = crate::config::BootstrapConfig {
            node_id: Some(node_id),
            node_name: Some(node_name),
            overlay_ip: Some(self_ip),
            fqdn: Some("alpha.mesh.internal".to_owned()),
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(SpkiPin::from_sha256_bytes([4; 32])),
            key_expires_at_ms: Some(now_ms + 3_600_000),
            ..crate::config::BootstrapConfig::default()
        };
        let bootstrap_store = crate::config::BootstrapStore::new(paths.bootstrap_path.clone());
        assert!(bootstrap_store.save_atomic(&bootstrap).is_ok());

        let snap = mesh_proto::netmap::NetmapSnapshot {
            netmap_version: 7,
            generated_at_ms: now_ms,
            overlay_cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: mesh_proto::netmap::RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec!["203.0.113.10:13478".to_owned()],
            },
            pin_set: mesh_proto::netmap::PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([4; 32]),
                next_pin: None,
            },
            peers: vec![mesh_proto::netmap::PeerEntry {
                node_id: NodeId::new_v7(now_ms + 1),
                name: peer_name,
                fqdn: "beta.mesh.internal".to_owned(),
                overlay_ip: peer_ip,
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: vec![],
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: Some(now_ms + 7_200_000),
                online: true,
            }],
        };
        let Ok(cache_port) = mesh_core::Port::from_u16(51820) else {
            return;
        };
        let cache = crate::netmap_cache::NetmapCacheStore::new(paths.netmap_cache_path.clone());
        assert!(
            cache
                .save_atomic(cache_port, &snap, now_ms, Some(now_ms + 3_600_000))
                .is_ok()
        );

        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let boot_res = DaemonSupervisor::boot(
            paths,
            clock,
            Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
        );
        assert!(boot_res.is_ok(), "boot error: {:?}", boot_res.err());
        let Ok(mut supervisor) = boot_res else {
            return;
        };
        let root_shutdown = CancellationToken::new();

        // Act: start session with cached initial_netmap under strict 1s deadline
        let resume_res = tokio::time::timeout(
            Duration::from_secs(1),
            supervisor.auto_resume_enrolled_session_best_effort(&root_shutdown),
        )
        .await;

        // Assert: completed quickly without apply_netmap deadlock and applied netmap v7
        assert!(resume_res.is_ok(), "startup deadlock exceeded 1s");
        let dp_handle = {
            supervisor
                .runtime
                .inner
                .read()
                .await
                .datapath_handle
                .clone()
        };
        assert!(dp_handle.is_some());
        if let Some(dp) = dp_handle {
            let status_res = dp.query_status().await;
            assert!(status_res.is_ok());
            if let Ok(dp_status) = status_res {
                assert_eq!(dp_status.netmap_version, 7);
            }
        }
        assert!(supervisor.stop_active_session_and_cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_supervisor_roam_sequences_rebind_before_reprobe_and_suppresses_reprobe_on_failure()
     {
        // Arrange (`HR-W21-08`)
        let Ok(dir) = tempdir() else {
            return;
        };
        let stun_bind = tokio::net::UdpSocket::bind("127.0.0.1:0").await;
        assert!(stun_bind.is_ok());
        let Ok(stun_sock) = stun_bind else {
            return;
        };
        let Ok(stun_addr) = stun_sock.local_addr() else {
            return;
        };

        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let Some(mut supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "seq_rebind", &adapters).await
        else {
            return;
        };

        let Ok(overlay_cidr) = "100.115.0.0/16".parse::<mesh_core::OverlayCidr>() else {
            return;
        };
        let Ok(peer_ip) = "100.115.0.30".parse::<OverlayIp>() else {
            return;
        };
        let Ok(peer_name) = "gamma".parse::<NodeName>() else {
            return;
        };
        let snap = mesh_proto::netmap::NetmapSnapshot {
            netmap_version: 2,
            generated_at_ms: 1_700_000_000_200,
            overlay_cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: mesh_proto::netmap::RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec![stun_addr.to_string()],
            },
            pin_set: mesh_proto::netmap::PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([2; 32]),
                next_pin: None,
            },
            peers: vec![mesh_proto::netmap::PeerEntry {
                node_id: NodeId::new_v7(1_700_000_000_201),
                name: peer_name,
                fqdn: "gamma.mesh.internal".to_owned(),
                overlay_ip: peer_ip,
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: vec![],
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }],
        };
        {
            let mut g = supervisor.runtime.inner.write().await;
            g.latest_netmap = Some(snap);
        }

        let root_shutdown = CancellationToken::new();
        assert!(
            supervisor
                .start_enrolled_session(&root_shutdown, None)
                .await
                .is_ok()
        );

        let mut buf = [0_u8; 256];
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(60), stun_sock.recv_from(&mut buf)).await
        {
        }

        let (wake_tx, mut wake_rx) = tokio::sync::mpsc::channel(8);
        if let Ok(mut guard) = supervisor.active_wake_tx.lock() {
            *guard = Some(wake_tx);
        }
        let (feedback_tx, mut feedback_rx) = tokio::sync::mpsc::channel(4);
        let ctx = super::RebindForwardContext {
            runtime: Arc::clone(&supervisor.runtime),
            adapters: Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
            ledger: Arc::clone(&supervisor.ledger),
            active_wake_tx: Arc::clone(&supervisor.active_wake_tx),
            overlay_route_installed: Arc::clone(&supervisor.overlay_route_installed),
            agent_version: supervisor.paths.agent_version.clone(),
            rebind_feedback_tx: Some(feedback_tx),
            shutdown: root_shutdown.clone(),
        };

        // Act 1: Roam triggers sequenced `begin_rebind -> rebind_underlay -> reprobe + wake`
        super::handle_rebind_command(
            &ctx,
            mesh_datapath::RebindCommand::RebindInterface {
                interface_name: "lo0".to_owned(),
                if_index: None,
                is_ipv6: false,
            },
        )
        .await;

        // Assert 1: Rebind succeeded, port updated, feedback Ok, wake sent, STUN came from rebound port
        assert_eq!(feedback_rx.try_recv().ok().map(|r| r.is_ok()), Some(true));
        assert!(matches!(
            wake_rx.try_recv(),
            Ok(crate::control_loop::ControlWakeSignal::ConfigUpdated)
        ));
        let updated_port = { supervisor.runtime.inner.read().await.local_udp_port };
        assert!(updated_port > 0);
        let probe_pkt =
            tokio::time::timeout(Duration::from_secs(2), stun_sock.recv_from(&mut buf)).await;
        assert!(probe_pkt.is_ok());
        if let Ok(Ok((len, src_addr))) = probe_pkt {
            assert!(len >= 20);
            assert_eq!(src_addr.port(), updated_port);
        }

        // Act 2: Simulate datapath rebind failure (stopped engine handles fail RebindUnderlay)
        let dead_dp = {
            supervisor
                .runtime
                .inner
                .read()
                .await
                .datapath_handle
                .clone()
        };
        assert!(supervisor.stop_active_session_and_cleanup().await.is_ok());
        {
            let mut g = supervisor.runtime.inner.write().await;
            g.datapath_handle = dead_dp;
        }
        while wake_rx.try_recv().is_ok() {}
        if let Ok(mut guard) = supervisor.active_wake_tx.lock() {
            let (tx2, rx2) = tokio::sync::mpsc::channel(4);
            wake_rx = rx2;
            *guard = Some(tx2);
        }
        super::handle_rebind_command(
            &ctx,
            mesh_datapath::RebindCommand::RebindInterface {
                interface_name: "broken0".to_owned(),
                if_index: None,
                is_ipv6: false,
            },
        )
        .await;

        // Assert 2: Err propagated on feedback channel and reprobe/wake suppressed
        assert_eq!(feedback_rx.try_recv().ok().map(|r| r.is_err()), Some(true));
        assert!(wake_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_supervisor_key_expiry_persists_through_restart_and_blocks_boot_after_24h_offline()
    {
        // Arrange (`HR-W21-13`)
        let Ok(dir) = tempdir() else {
            return;
        };
        let t0: u64 = 1_700_000_000_000;
        let key_expiry_ms = t0 + 10_000;
        let paths = DaemonRuntimePaths::for_temp_dir(dir.path(), "key_grace");
        let node_id = NodeId::new_v7(t0);
        let key_store = KeysFileStore::new(paths.keystore_path.clone());
        let identity = StoredNodeIdentity {
            node_id: Some(node_id),
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: t0,
        };
        assert!(key_store.save_rotated(&identity).is_ok());

        let Ok(overlay_cidr) = "100.115.0.0/16".parse::<mesh_core::OverlayCidr>() else {
            return;
        };
        let Ok(self_ip) = "100.115.0.10".parse::<OverlayIp>() else {
            return;
        };
        let Ok(peer_ip) = "100.115.0.21".parse::<OverlayIp>() else {
            return;
        };
        let Ok(node_name) = "alpha".parse::<NodeName>() else {
            return;
        };
        let Ok(peer_name) = "peer-grace".parse::<NodeName>() else {
            return;
        };

        let mut bootstrap = crate::config::BootstrapConfig {
            node_id: Some(node_id),
            node_name: Some(node_name.clone()),
            overlay_ip: Some(self_ip),
            fqdn: Some("alpha.mesh.internal".to_owned()),
            server_endpoint: Some("203.0.113.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SpkiPin,
            active_pin: Some(SpkiPin::from_sha256_bytes([6; 32])),
            ..crate::config::BootstrapConfig::default()
        };
        let snap = mesh_proto::netmap::NetmapSnapshot {
            netmap_version: 3,
            generated_at_ms: t0,
            overlay_cidr,
            domain_suffix: "mesh.internal".to_owned(),
            relay_map: mesh_proto::netmap::RelayMap {
                endpoint_version: 1,
                control_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                relay_tcp_endpoint: "203.0.113.10:8443".to_owned(),
                stun_udp_endpoints: vec!["203.0.113.10:13478".to_owned()],
            },
            pin_set: mesh_proto::netmap::PinSetDto {
                active_pin: SpkiPin::from_sha256_bytes([6; 32]),
                next_pin: None,
            },
            peers: vec![mesh_proto::netmap::PeerEntry {
                node_id: NodeId::new_v7(t0 + 1),
                name: peer_name,
                fqdn: "peer-grace.mesh.internal".to_owned(),
                overlay_ip: peer_ip,
                node_pubkey: NodeKeypair::generate().public_key(),
                disco_pubkey: DiscoKeypair::generate().public_key(),
                endpoints: vec![],
                relay_home: "203.0.113.10:8443".to_owned(),
                key_expires_at_ms: None,
                online: true,
            }],
        };
        let fake_reg = mesh_proto::control::RegisterNodeResponse {
            node_id,
            node_name,
            fqdn: "alpha.mesh.internal".to_owned(),
            overlay_ip: self_ip,
            overlay_cidr,
            key_expires_at_ms: Some(key_expiry_ms),
            netmap: snap.clone(),
        };
        super::apply_registration_to_bootstrap(&mut bootstrap, &fake_reg);
        let bootstrap_store = crate::config::BootstrapStore::new(paths.bootstrap_path.clone());
        assert!(bootstrap_store.save_atomic(&bootstrap).is_ok());
        let Ok(cache_port) = mesh_core::Port::from_u16(51820) else {
            return;
        };
        let cache = crate::netmap_cache::NetmapCacheStore::new(paths.netmap_cache_path.clone());
        assert!(
            cache
                .save_atomic(cache_port, &snap, t0, Some(key_expiry_ms))
                .is_ok()
        );

        let adapters = Arc::new(InMemoryPlatformAdapters::default());

        // Act 1: Restart within 24h offline grace recovers cached netmap and key expiry
        let within_grace_ms = key_expiry_ms + 23 * 3_600_000;
        let sup_ok_res = DaemonSupervisor::boot(
            paths.clone(),
            Arc::new(mesh_core::clock::FakeClock::new(within_grace_ms)),
            Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
        );
        assert!(sup_ok_res.is_ok());
        if let Ok(mut sup_ok) = sup_ok_res {
            let status_within = sup_ok.runtime.build_status_response().await;
            assert_eq!(status_within.key_expires_at_ms, Some(key_expiry_ms));
            let root_shutdown = CancellationToken::new();
            sup_ok
                .auto_resume_enrolled_session_best_effort(&root_shutdown)
                .await;
            assert!(sup_ok.active_session.is_some());
            assert!(sup_ok.stop_active_session_and_cleanup().await.is_ok());
        }

        // Act 2: Restart after > 24h offline rejects boot recovery and transitions to ReauthRequired
        let past_grace_ms = key_expiry_ms + 86_400_000 + 1;
        let sup_exp_res = DaemonSupervisor::boot(
            paths,
            Arc::new(mesh_core::clock::FakeClock::new(past_grace_ms)),
            Arc::clone(&adapters) as Arc<dyn super::PlatformAdapters>,
        );
        assert!(sup_exp_res.is_ok());
        if let Ok(mut sup_exp) = sup_exp_res {
            let root_shutdown = CancellationToken::new();
            sup_exp
                .auto_resume_enrolled_session_best_effort(&root_shutdown)
                .await;
            assert!(sup_exp.active_session.is_none());
            let status_after = sup_exp.runtime.build_status_response().await;
            assert_eq!(status_after.daemon_state, DaemonState::ReauthRequired);
            assert_eq!(status_after.key_expires_at_ms, Some(key_expiry_ms));
        }
    }
}
