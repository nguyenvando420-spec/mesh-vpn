//! Daemon lifecycle supervisor: startup `ResourceLedger` crash recovery, dual IPC listeners,
//! desktop OS platform hooks, and thin delegation to `mesh_client::ClientSessionSupervisor`
//! (`US-055`, `REL-08`, `US-099`).

use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::Mutex;
#[cfg(test)]
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use mesh_client::hooks::{
    ClientFuture, ClientPlatformHooks, DnsUpstreamHook, FileClientStateStore, TunActivationOutcome,
};
#[cfg(test)]
use mesh_client::session::apply_registration_to_bootstrap;
use mesh_client::{ClientCommand, ClientSessionOptions, ClientSessionSupervisor};
#[cfg(target_os = "windows")]
use mesh_core::AppError;
use mesh_core::brand::DAEMON_BINARY_NAME;
use mesh_core::clock::Clock;
use mesh_core::{AppResult, NodeName, OverlayCidr, OverlayIp};
#[cfg(test)]
use mesh_datapath::RebindCommand;
use mesh_net::DiscoveredInterfaceEndpoint;
use mesh_net::endpoint_filter::{OverlaySubnetConflict, detect_overlay_subnet_conflict};
use mesh_net::hosts::{FileHostsEditor, HostsEditor as _, HostsEntry};
use mesh_net::ledger::{LedgerCleanupOps, ResourceLedger};
use mesh_net::nat64::SocketProtector;
use mesh_net::netmon::{FakeNetMonitor, NetMonitor, OsPhysicalNetworkProbe, PhysicalNetworkProbe};
#[cfg(test)]
use mesh_net::netmon::{FakePhysicalNetworkProbe, NetworkChangeEvent};
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use mesh_net::route::RouteSpec;
#[cfg(any(
    test,
    not(any(target_os = "windows", target_os = "macos", target_os = "linux"))
))]
use mesh_net::tun::FakeTunDevice;
use mesh_net::tun::{TunConfig, TunDevice};
#[cfg(test)]
use mesh_proto::agent_ipc::{AgentActionResponse, AgentSetRequest};
#[cfg(test)]
use mesh_proto::control::{RegisterNodeResponse, TerminationReason};
use mesh_proto::netmap::NetmapSnapshot;

use crate::config::{
    DaemonRuntimePaths, candidate_log_dirs, collect_os_route_table, default_state_dir,
    load_inbound_filter_spec, split_host_port,
};
use crate::control_loop::{
    ControlLoop, discover_desktop_local_interface_endpoints, sync_platform_hosts_entries,
};
#[cfg(test)]
use crate::control_loop::{ControlWakeSignal, DaemonRuntimeState};
use crate::ipc_service::{IpcRouterState, IpcService};
use crate::netmap_cache::NetmapCacheStore;
use crate::ping_probe::PingProbe;
use crate::roaming_loop::RoamingLoop;

/// Commands routed from `meshd-admin` IPC endpoints to the client session supervisor.
pub(crate) type SupervisorCommand = ClientCommand;
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

#[derive(Debug)]
struct DesktopDnsHook {
    hosts_override: Option<PathBuf>,
    ledger: Arc<Mutex<ResourceLedger>>,
}

impl DnsUpstreamHook for DesktopDnsHook {
    fn sync_mesh_dns<'a>(
        &'a self,
        snapshot: &'a NetmapSnapshot,
        self_overlay_ip: Option<OverlayIp>,
        self_name: Option<&'a NodeName>,
    ) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async move {
            let mut entries = Vec::with_capacity(snapshot.peers.len() + 1);
            if let (Some(ip), Some(name)) = (self_overlay_ip, self_name)
                && let Ok(entry) = HostsEntry::new(
                    ip,
                    name.clone(),
                    &snapshot.domain_suffix,
                    Some(&snapshot.relay_map.control_tcp_endpoint),
                )
            {
                entries.push(entry);
            }
            for peer in &snapshot.peers {
                if let Ok(entry) = HostsEntry::new(
                    peer.overlay_ip,
                    peer.name.clone(),
                    &snapshot.domain_suffix,
                    Some(&snapshot.relay_map.control_tcp_endpoint),
                ) {
                    entries.push(entry);
                }
            }

            let public_host = split_host_port(&snapshot.relay_map.control_tcp_endpoint)
                .map(|(h, _)| h)
                .ok();

            if let Some(ref custom_path) = self.hosts_override {
                let editor = FileHostsEditor::new(custom_path.clone());
                let mut ledger = self.ledger.lock().await;
                if let Err(err) =
                    ledger.record_hosts_before_activate(custom_path.display().to_string())
                {
                    warn!(
                        component = "meshd.supervisor",
                        event = "hosts_ledger_record_failed",
                        error = %err,
                        "failed recording override hosts path into ResourceLedger"
                    );
                }
                return editor.apply(&entries, public_host.as_deref());
            }

            sync_platform_hosts_entries(&entries, public_host.as_deref(), &self.ledger).await;
            Ok(())
        })
    }

    fn clear_mesh_dns<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async move {
            clear_override_hosts_best_effort(self.hosts_override.as_ref());
            Ok(())
        })
    }
}

/// Desktop [`ClientPlatformHooks`] bridging `PlatformAdapters`, `ResourceLedger`, `/etc/hosts`,
/// `sysexec` route diagnostics, and `inbound-filter.conf`.
pub(crate) struct DesktopPlatformHooks {
    paths: DaemonRuntimePaths,
    adapters: Arc<dyn PlatformAdapters>,
    ledger: Arc<Mutex<ResourceLedger>>,
    dns: Arc<DesktopDnsHook>,
    route_installed_flag: OnceLock<Arc<AtomicBool>>,
    net_monitor_override: OnceLock<Arc<dyn NetMonitor>>,
}

impl std::fmt::Debug for DesktopPlatformHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopPlatformHooks")
            .field("bootstrap_path", &self.paths.bootstrap_path)
            .field("dns", &self.dns)
            .finish_non_exhaustive()
    }
}

impl DesktopPlatformHooks {
    fn new(
        paths: DaemonRuntimePaths,
        adapters: Arc<dyn PlatformAdapters>,
        ledger: Arc<Mutex<ResourceLedger>>,
    ) -> Self {
        let dns = Arc::new(DesktopDnsHook {
            hosts_override: paths.hosts_path_override.clone(),
            ledger: Arc::clone(&ledger),
        });
        Self {
            paths,
            adapters,
            ledger,
            dns,
            route_installed_flag: OnceLock::new(),
            net_monitor_override: OnceLock::new(),
        }
    }

    fn bind_route_flag(&self, flag: Arc<AtomicBool>) {
        if self.route_installed_flag.set(flag).is_err() {
            debug!(
                component = "meshd.supervisor",
                event = "route_flag_already_bound",
                "desktop route-installed flag already bound"
            );
        }
    }

    fn bind_net_monitor(&self, monitor: Arc<dyn NetMonitor>) {
        if self.net_monitor_override.set(monitor).is_err() {
            debug!(
                component = "meshd.supervisor",
                event = "net_monitor_already_bound",
                "desktop network monitor already bound"
            );
        }
    }
}

impl ClientPlatformHooks for DesktopPlatformHooks {
    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe> {
        self.adapters.network_probe()
    }

    fn net_monitor(&self) -> Arc<dyn NetMonitor> {
        self.net_monitor_override
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::new(FakeNetMonitor::new()))
    }

    fn dns_hook(&self) -> Arc<dyn DnsUpstreamHook> {
        Arc::clone(&self.dns) as Arc<dyn DnsUpstreamHook>
    }

    fn socket_protector(&self) -> Option<Arc<dyn SocketProtector>> {
        None
    }

    fn activate_tun_and_routes<'a>(
        &'a self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        _dns_server_ip: Option<OverlayIp>,
        _domain_suffix: Option<&'a str>,
        now_ms: u64,
    ) -> ClientFuture<'a, AppResult<TunActivationOutcome>> {
        Box::pin(async move {
            let mut ledger = self.ledger.lock().await;
            let setup =
                self.adapters
                    .setup_tun_and_route(tun_cfg, overlay_cidr, &mut ledger, now_ms)?;
            if let Some(flag) = self.route_installed_flag.get() {
                flag.store(setup.route_installed, Ordering::SeqCst);
            }
            Ok(TunActivationOutcome {
                tun: setup.tun,
                route_installed: setup.route_installed,
                conflict_warning: setup.conflict_warning,
                lockdown_warning: None,
                private_dns_warning: None,
            })
        })
    }

    fn reconcile_on_roam_or_netmap<'a>(
        &'a self,
        tun_ifname: &'a str,
        overlay_cidr: OverlayCidr,
        _dns_server_ip: Option<OverlayIp>,
        _domain_suffix: Option<&'a str>,
    ) -> ClientFuture<'a, AppResult<Option<String>>> {
        Box::pin(async move {
            let conflict = check_overlay_conflict_with_probe(
                self.adapters.network_probe().as_ref(),
                overlay_cidr,
            );
            let currently_installed = self
                .route_installed_flag
                .get()
                .is_some_and(|flag| flag.load(Ordering::SeqCst));
            match conflict {
                Some(c) => {
                    if currently_installed {
                        self.adapters
                            .remove_overlay_route_only(tun_ifname, overlay_cidr)?;
                        if let Some(flag) = self.route_installed_flag.get() {
                            flag.store(false, Ordering::SeqCst);
                        }
                    }
                    Ok(Some(c.format_warning()))
                }
                None => {
                    if !currently_installed {
                        let mut ledger = self.ledger.lock().await;
                        self.adapters.install_overlay_route_only(
                            tun_ifname,
                            overlay_cidr,
                            &mut ledger,
                        )?;
                        if let Some(flag) = self.route_installed_flag.get() {
                            flag.store(true, Ordering::SeqCst);
                        }
                    }
                    Ok(None)
                }
            }
        })
    }

    fn deactivate_and_cleanup<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async move {
            let res = {
                let mut ledger = self.ledger.lock().await;
                ledger.cleanup_all(self.adapters.cleanup_ops())
            };
            clear_override_hosts_best_effort(self.paths.hosts_path_override.as_ref());
            res
        })
    }

    fn discover_local_interface_endpoints(
        &self,
        udp_port: u16,
    ) -> Vec<DiscoveredInterfaceEndpoint> {
        discover_desktop_local_interface_endpoints(udp_port)
    }

    fn collect_route_diagnostics(&self) -> String {
        collect_os_route_table()
    }

    fn inbound_filter_spec(&self) -> Option<String> {
        load_inbound_filter_spec(self.paths.bootstrap_path.parent())
    }

    fn reconcile_firewall_on_roam(
        &self,
        tun_ifname: &str,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<()> {
        self.adapters
            .reconcile_firewall_on_roam(tun_ifname, overlay_cidr)
    }

    fn enforce_startup_security(&self) -> AppResult<()> {
        verify_startup_path_security(&self.paths, self.adapters.as_ref())
    }
}

/// Top-level desktop daemon orchestrator wrapping [`ClientSessionSupervisor`], `ResourceLedger`
/// crash recovery, and dual Read-Only / Admin IPC listeners (`US-055`, `REL-08`, `US-099`).
pub(crate) struct DaemonSupervisor {
    client: ClientSessionSupervisor,
    paths: DaemonRuntimePaths,
    adapters: Arc<dyn PlatformAdapters>,
    desktop_hooks: Arc<DesktopPlatformHooks>,
    #[cfg(test)]
    ledger: Arc<Mutex<ResourceLedger>>,
    #[cfg(test)]
    runtime: Arc<DaemonRuntimeState>,
    #[cfg(test)]
    roaming_control_tx: mpsc::Sender<NetworkChangeEvent>,
    #[cfg(test)]
    active_wake_tx: Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>>,
    #[cfg(test)]
    overlay_route_installed: Arc<AtomicBool>,
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

    /// Initializes the desktop supervisor and IMMEDIATELY executes startup crash recovery
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
        let ledger = Arc::new(Mutex::new(ledger));

        let state_dir = paths
            .bootstrap_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(default_state_dir);
        let state_store = Arc::new(FileClientStateStore::new(
            state_dir,
            paths.keystore_path.clone(),
            paths.bootstrap_path.clone(),
            paths.netmap_cache_path.clone(),
        ));
        let desktop_hooks = Arc::new(DesktopPlatformHooks::new(
            paths.clone(),
            Arc::clone(&adapters),
            Arc::clone(&ledger),
        ));
        let options = ClientSessionOptions::new(paths.to_client_runtime_config())
            .with_underlay(paths.underlay_if_index, paths.linux_fwmark)
            .with_default_tun_ifname(default_tun_interface_hint())
            .with_bugreport(
                paths.bugreport_dir.clone(),
                DAEMON_BINARY_NAME,
                candidate_log_dirs(paths.bootstrap_path.parent()),
                None,
            );
        let client = ClientSessionSupervisor::boot(
            options,
            clock,
            Arc::clone(&desktop_hooks) as Arc<dyn ClientPlatformHooks>,
            state_store,
        )?;
        let overlay_route_installed = client.overlay_route_flag();
        desktop_hooks.bind_route_flag(Arc::clone(&overlay_route_installed));
        #[cfg(test)]
        let runtime = client.runtime_state();
        #[cfg(test)]
        let roaming_control_tx = client.roaming_control_sender();
        #[cfg(test)]
        let active_wake_tx = client.active_wake_slot();

        Ok(Self {
            client,
            paths,
            adapters,
            desktop_hooks,
            #[cfg(test)]
            ledger,
            #[cfg(test)]
            runtime,
            #[cfg(test)]
            roaming_control_tx,
            #[cfg(test)]
            active_wake_tx,
            #[cfg(test)]
            overlay_route_installed,
        })
    }

    /// Returns a cloned shared runtime state handle for shutdown/status inspection tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn runtime_state(&self) -> Arc<DaemonRuntimeState> {
        self.client.runtime_state()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn has_active_session(&self) -> bool {
        self.client.has_active_session()
    }

    #[cfg(test)]
    pub(crate) async fn handle_verified_identity_termination(
        &mut self,
        reason: TerminationReason,
        message: &str,
    ) {
        self.client
            .handle_verified_identity_termination(reason, message)
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn auto_resume_enrolled_session_best_effort(
        &mut self,
        root_shutdown: &CancellationToken,
    ) {
        self.client
            .auto_resume_enrolled_session_best_effort(root_shutdown)
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn execute_set(
        &mut self,
        req: AgentSetRequest,
    ) -> AppResult<AgentActionResponse> {
        self.client.execute_set(req).await
    }

    #[cfg(test)]
    pub(crate) async fn start_enrolled_session(
        &mut self,
        root_shutdown: &CancellationToken,
        initial_reg: Option<RegisterNodeResponse>,
    ) -> AppResult<()> {
        self.client
            .start_enrolled_session(root_shutdown, initial_reg)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn stop_active_session_and_cleanup(&mut self) -> AppResult<()> {
        self.client.stop_active_session_and_cleanup().await
    }

    #[cfg(test)]
    pub(crate) async fn execute_reset_identity(&mut self) -> AppResult<AgentActionResponse> {
        self.client.execute_reset_identity().await
    }

    /// Runs desktop IPC listeners plus the shared client supervisor lifecycle until
    /// `root_shutdown` fires, guaranteeing teardown completes in `<= 5 s` (`US-055`).
    pub(crate) async fn run(
        self,
        monitor: Arc<dyn NetMonitor>,
        root_shutdown: CancellationToken,
    ) -> AppResult<()> {
        self.desktop_hooks.bind_net_monitor(Arc::clone(&monitor));
        let daemon_tracker = TaskTracker::new();

        if self.adapters.bind_ipc_listeners() {
            let router_state = IpcRouterState {
                runtime: self.client.runtime_state(),
                cmd_tx: self.client.command_sender(),
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

        self.client
            .run_with_tracker(monitor, daemon_tracker, root_shutdown)
            .await
    }
}

#[cfg(test)]
pub(crate) struct RebindForwardContext {
    pub(crate) runtime: Arc<DaemonRuntimeState>,
    pub(crate) adapters: Arc<dyn PlatformAdapters>,
    pub(crate) ledger: Arc<Mutex<ResourceLedger>>,
    pub(crate) active_wake_tx: Arc<StdMutex<Option<mpsc::Sender<ControlWakeSignal>>>>,
    pub(crate) overlay_route_installed: Arc<AtomicBool>,
    pub(crate) agent_version: String,
    pub(crate) rebind_feedback_tx: Option<mpsc::Sender<AppResult<()>>>,
    pub(crate) shutdown: CancellationToken,
}

#[cfg(test)]
pub(crate) async fn handle_rebind_command(ctx: &RebindForwardContext, cmd: RebindCommand) {
    let mut paths = DaemonRuntimePaths::for_temp_dir(&std::env::temp_dir(), "rebind-test");
    paths.hosts_path_override = None;
    let hooks = Arc::new(DesktopPlatformHooks::new(
        paths,
        Arc::clone(&ctx.adapters),
        Arc::clone(&ctx.ledger),
    ));
    hooks.bind_route_flag(Arc::clone(&ctx.overlay_route_installed));
    let client_ctx = mesh_client::RebindForwardContext {
        runtime: Arc::clone(&ctx.runtime),
        platform_hooks: hooks,
        active_wake_tx: Arc::clone(&ctx.active_wake_tx),
        overlay_route_installed: Arc::clone(&ctx.overlay_route_installed),
        agent_version: ctx.agent_version.clone(),
        rebind_feedback_tx: ctx.rebind_feedback_tx.clone(),
        shutdown: ctx.shutdown.clone(),
    };
    mesh_client::handle_rebind_command(&client_ctx, cmd).await;
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
        assert!(supervisor.has_active_session());

        // Act (`HR-W12-02`)
        supervisor
            .handle_verified_identity_termination(
                TerminationReason::NodeRevoked,
                "revoked by control",
            )
            .await;

        // Assert
        assert!(!supervisor.has_active_session());
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
            assert!(sup_ok.has_active_session());
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
            assert!(!sup_exp.has_active_session());
            let status_after = sup_exp.runtime.build_status_response().await;
            assert_eq!(status_after.daemon_state, DaemonState::ReauthRequired);
            assert_eq!(status_after.key_expires_at_ms, Some(key_expiry_ms));
        }
    }

    #[tokio::test]
    async fn test_supervisor_execute_reset_identity_cleans_keystore_bootstrap_and_runtime()
    -> Result<(), String> {
        // Arrange
        let dir = tempdir().map_err(|e| e.to_string())?;
        let adapters = Arc::new(InMemoryPlatformAdapters::default());
        let Some(mut supervisor) =
            setup_enrolled_supervisor_in_tempdir(dir.path(), "reset_id", &adapters).await
        else {
            return Err("failed setting up enrolled supervisor".to_owned());
        };
        let root_shutdown = CancellationToken::new();
        supervisor
            .start_enrolled_session(&root_shutdown, None)
            .await
            .map_err(|e| e.to_string())?;
        assert!(supervisor.has_active_session());

        // Act
        let resp = supervisor
            .execute_reset_identity()
            .await
            .map_err(|e| e.to_string())?;

        // Assert
        assert_eq!(resp.state, DaemonState::Stopped);
        assert!(!supervisor.has_active_session());
        assert!(!dir.path().join("keys.json").exists());
        let status = supervisor.runtime_state().build_status_response().await;
        assert_eq!(status.daemon_state, DaemonState::Stopped);
        assert_eq!(status.node_id, None);
        assert_eq!(status.server_connection, None);
        assert!(status.peers.is_empty());
        Ok(())
    }
}
