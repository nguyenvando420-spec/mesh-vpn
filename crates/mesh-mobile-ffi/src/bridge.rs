//! OS-neutral bridges adapting `mesh_client` storage and platform hooks to Android & iOS.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Duration;

use mesh_client::{
    BootstrapConfig, ClientFuture, ClientPlatformHooks, ClientStateStore, DnsUpstreamHook,
    NetmapCacheFile, TunActivationOutcome, compute_split_tunnel_routes, derive_overlay_dns_ip,
};
use mesh_core::{AppError, AppResult, NodeId, NodeName, OverlayCidr, OverlayIp};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_net::{
    DiscoveredInterfaceEndpoint, FakeNetMonitor, InterfaceSubnetSnapshot, Nat64Prefix, NetEvent,
    NetMonitor, PhysicalInterface, PhysicalNetworkProbe, SocketProtector, StoredNodeIdentity,
    TunConfig, TunDevice, detect_overlay_subnet_conflict,
};
use mesh_proto::netmap::{NetmapSnapshot, PeerEntry};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::dns_responder::MobileSplitDnsInterceptor;
use crate::tun_bridge::{AndroidTunDevice, PacketFlowAdapter};
use crate::types::{
    MobileError, MobileNetEventKind, MobilePlatformKind, MobilePlatformWarning,
    MobileStatusSnapshot, MobileTunnelNetworkConfig, MobileUnderlayState, MobileWarningKind,
    PlatformNetworkBridge,
};

const SEALED_IDENTITY_FILENAME: &str = "identity.sealed.bin";
const BOOTSTRAP_FILENAME: &str = "bootstrap.toml";
const NETMAP_CACHE_FILENAME: &str = "netmap-cache.json";
const STATUS_IPC_FILENAME: &str = "status-snapshot.json";
const DEFAULT_SEARCH_DOMAIN: &str = "mesh.internal";
const ROUTE_CHANGE_TIMEOUT_MS: u64 = 10_000;
const RFC7050_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Fail-closed mobile state store sealing identity material with a platform Keychain/Keystore DEK
/// (`SEC-01`, `IG-MOB-G2-02`, `HR-MOB-G2-03`).
pub(crate) struct FfiStateStore {
    bridge: Arc<dyn PlatformNetworkBridge>,
    state_dir: Option<PathBuf>,
}

impl std::fmt::Debug for FfiStateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiStateStore")
            .field("state_dir", &self.state_dir)
            .finish_non_exhaustive()
    }
}

impl FfiStateStore {
    /// Creates a state store delegating DEK and private file persistence to `bridge`.
    #[must_use]
    pub(crate) fn new(bridge: Arc<dyn PlatformNetworkBridge>, state_dir: Option<PathBuf>) -> Self {
        Self { bridge, state_dir }
    }

    /// Runs a blocking Keychain/Keystore or file bridge FFI call without stalling an async
    /// `MultiThread` worker pool (critical on iOS `worker_threads(1)`, `HIGH-MOB-WA-04`).
    fn run_bridge_io<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&dyn PlatformNetworkBridge) -> T,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| f(self.bridge.as_ref()))
            }
            _ => f(self.bridge.as_ref()),
        }
    }

    /// Atomically persists the compact `<= 4096 B` status snapshot JSON for iOS App Group IPC.
    pub(crate) fn write_status_snapshot_ipc(
        &self,
        snapshot: &MobileStatusSnapshot,
    ) -> AppResult<()> {
        let json_bytes = snapshot
            .to_bounded_ipc_json()
            .map_err(|err| err.to_app_error())?;
        self.run_bridge_io(|bridge| {
            bridge.save_state_file(STATUS_IPC_FILENAME.to_owned(), json_bytes)
        })
        .map_err(|err| err.to_app_error())
    }

    /// Reads and unseals the identity if present, or fails closed on missing DEK/corruption.
    fn load_dek_32(&self) -> AppResult<Zeroizing<[u8; 32]>> {
        let mut raw = self
            .run_bridge_io(|bridge| bridge.load_or_create_platform_dek())
            .map_err(|err| err.to_app_error())?;
        let wrapped = Zeroizing::new(std::mem::take(&mut raw));
        if wrapped.len() != 32 {
            return Err(AppError::invalid_argument(format!(
                "platform DEK must be 32 bytes, got {}",
                wrapped.len()
            )));
        }
        let mut dek = Zeroizing::new([0_u8; 32]);
        dek.copy_from_slice(&wrapped);
        Ok(dek)
    }

    fn read_sealed_identity(&self) -> AppResult<Option<StoredNodeIdentity>> {
        let maybe_blob = self
            .run_bridge_io(|bridge| bridge.load_state_file(SEALED_IDENTITY_FILENAME.to_owned()))
            .map_err(|err| err.to_app_error())?;
        let Some(blob) = maybe_blob else {
            return Ok(None);
        };
        let dek = self.load_dek_32()?;
        StoredNodeIdentity::unseal_with_dek(&blob, &dek)
            .map(Some)
            .map_err(|err| {
                AppError::internal(
                    "keystore_invalidated: sealed identity decryption failed with platform DEK",
                )
                .with_internal_detail(format!("keystore_invalidated: {err}"))
            })
    }

    fn write_sealed_identity(&self, identity: &StoredNodeIdentity) -> AppResult<()> {
        let dek = self.load_dek_32()?;
        let sealed = identity.seal_with_dek(&dek)?;
        self.run_bridge_io(|bridge| {
            bridge.save_state_file(SEALED_IDENTITY_FILENAME.to_owned(), sealed)
        })
        .map_err(|err| err.to_app_error())
    }
}

impl ClientStateStore for FfiStateStore {
    fn load_or_create_identity(&self, now_ms: u64) -> AppResult<StoredNodeIdentity> {
        if let Some(existing) = self.read_sealed_identity()? {
            return Ok(existing);
        }
        let fresh = StoredNodeIdentity {
            node_id: None,
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: now_ms,
        };
        self.write_sealed_identity(&fresh)?;
        Ok(fresh)
    }

    fn load_existing_identity(&self) -> AppResult<Option<StoredNodeIdentity>> {
        self.read_sealed_identity()
    }

    fn save_rotated_identity(&self, identity: &StoredNodeIdentity) -> AppResult<()> {
        self.write_sealed_identity(identity)
    }

    fn set_identity_node_id(&self, node_id: NodeId) -> AppResult<StoredNodeIdentity> {
        let mut current = self.read_sealed_identity()?.ok_or_else(|| {
            AppError::not_found("cannot attach node_id before local sealed identity is initialized")
        })?;
        current.node_id = Some(node_id);
        self.write_sealed_identity(&current)?;
        Ok(current)
    }

    fn load_bootstrap(&self) -> AppResult<BootstrapConfig> {
        let maybe_bytes = self
            .run_bridge_io(|bridge| bridge.load_state_file(BOOTSTRAP_FILENAME.to_owned()))
            .map_err(|err| err.to_app_error())?;
        let Some(bytes) = maybe_bytes else {
            return Ok(BootstrapConfig::default());
        };
        let text = std::str::from_utf8(&bytes).map_err(|err| {
            AppError::invalid_argument(format!("invalid UTF-8 in bootstrap config: {err}"))
        })?;
        let cfg: BootstrapConfig = toml::from_str(text)
            .map_err(|err| AppError::invalid_argument(format!("corrupt bootstrap TOML: {err}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn save_bootstrap(&self, config: &BootstrapConfig) -> AppResult<()> {
        config.validate()?;
        let encoded = toml::to_string_pretty(config)
            .map_err(|err| AppError::internal(format!("failed serializing bootstrap: {err}")))?;
        self.run_bridge_io(|bridge| {
            bridge.save_state_file(BOOTSTRAP_FILENAME.to_owned(), encoded.into_bytes())
        })
        .map_err(|err| err.to_app_error())
    }

    fn load_netmap_cache(&self) -> AppResult<Option<NetmapCacheFile>> {
        let maybe_bytes = self
            .run_bridge_io(|bridge| bridge.load_state_file(NETMAP_CACHE_FILENAME.to_owned()))
            .map_err(|err| err.to_app_error())?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let parsed: NetmapCacheFile = serde_json::from_slice(&bytes).map_err(|err| {
            AppError::invalid_argument(format!("corrupt netmap cache JSON: {err}"))
        })?;
        parsed.verify_integrity()?;
        Ok(Some(parsed))
    }

    fn save_netmap_cache(&self, cache: &NetmapCacheFile) -> AppResult<()> {
        cache.verify_integrity()?;
        let encoded = serde_json::to_vec_pretty(cache)
            .map_err(|err| AppError::internal(format!("failed serializing netmap cache: {err}")))?;
        self.run_bridge_io(|bridge| {
            bridge.save_state_file(NETMAP_CACHE_FILENAME.to_owned(), encoded)
        })
        .map_err(|err| err.to_app_error())
    }

    fn clear_netmap_cache(&self) -> AppResult<()> {
        self.run_bridge_io(|bridge| bridge.delete_state_file(NETMAP_CACHE_FILENAME.to_owned()))
            .map_err(|err| err.to_app_error())
    }

    fn delete_identity(&self) -> AppResult<()> {
        self.run_bridge_io(|bridge| bridge.delete_state_file(SEALED_IDENTITY_FILENAME.to_owned()))
            .map_err(|err| err.to_app_error())
    }

    fn state_dir(&self) -> Option<&Path> {
        self.state_dir.as_deref()
    }
}

/// Zero-lock synchronous `VpnService.protect(fd)` forwarder (`HR-MOB-G2-01`).
pub(crate) struct FfiSocketProtector {
    bridge: Arc<dyn PlatformNetworkBridge>,
}

impl std::fmt::Debug for FfiSocketProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiSocketProtector").finish_non_exhaustive()
    }
}

impl SocketProtector for FfiSocketProtector {
    fn protect_socket(&self, raw_fd: i32) -> AppResult<()> {
        let allowed = self
            .bridge
            .protect_socket(raw_fd)
            .map_err(|err| err.to_app_error())?;
        if !allowed {
            return Err(AppError::permission_denied(format!(
                "VpnService.protect({raw_fd}) returned false; socket traffic would loop"
            )));
        }
        Ok(())
    }
}

/// Normalized underlay state stored inside [`FfiPhysicalNetworkProbe`].
#[derive(Debug, Clone)]
pub(crate) struct ParsedUnderlaySnapshot {
    /// Whether an underlay path exists.
    pub(crate) network_available: bool,
    /// Primary active physical OS interface.
    pub(crate) primary_interface: PhysicalInterface,
    /// Configured physical adapter subnets for overlap detection.
    pub(crate) subnets: Vec<InterfaceSubnetSnapshot>,
    /// Physical DNS server IPs from link properties.
    pub(crate) dns_servers: Vec<IpAddr>,
    /// Synthesizable DNS64/NAT64 prefix when IPv6-only cellular underlay is active.
    pub(crate) nat64_prefix: Option<Nat64Prefix>,
    /// Whether Android "Block connections without VPN" Lockdown mode is active.
    pub(crate) lockdown_active: bool,
    /// Whether Android Strict Private DNS is active.
    pub(crate) private_dns_strict: bool,
    /// Optional Android Private DNS hostname.
    pub(crate) private_dns_server_name: Option<String>,
}

impl Default for ParsedUnderlaySnapshot {
    fn default() -> Self {
        Self {
            network_available: true,
            primary_interface: PhysicalInterface {
                if_index: 1,
                name: "mobile0".to_owned(),
            },
            subnets: Vec::new(),
            dns_servers: Vec::new(),
            nat64_prefix: None,
            lockdown_active: false,
            private_dns_strict: false,
            private_dns_server_name: None,
        }
    }
}

/// Parses OS-reported [`MobileUnderlayState`] into strongly typed network metadata.
#[must_use]
pub(crate) fn parse_underlay_state(state: &MobileUnderlayState) -> ParsedUnderlaySnapshot {
    let if_index = state.physical_if_index.unwrap_or(1);
    let if_name = state
        .active_interface_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("mobile0")
        .to_owned();

    let dns_servers = state
        .underlay_dns_servers
        .iter()
        .filter_map(|s| IpAddr::from_str(s.trim()).ok())
        .collect();

    // NAT64/DNS64 is strictly for IPv6-only underlays (`!has_ipv4 && has_ipv6`).
    // Dual-stack and IPv4-only networks must keep NAT64 disabled (`HIGH-MOB-WA-05`).
    let ipv6_only = !state.has_ipv4 && state.has_ipv6;
    let nat64_prefix = if ipv6_only {
        state
            .os_nat64_prefix
            .as_deref()
            .and_then(|raw| Nat64Prefix::from_cidr(raw.trim()).ok())
    } else {
        None
    };

    let mut subnets = Vec::new();
    for raw_cidr in &state.physical_subnets {
        if let Some((ip_part, prefix_part)) = raw_cidr.trim().split_once('/')
            && let (Ok(ip), Ok(prefix_len)) = (IpAddr::from_str(ip_part), prefix_part.parse::<u8>())
        {
            subnets.push(InterfaceSubnetSnapshot {
                if_index,
                interface_name: if_name.clone(),
                ip,
                prefix_len,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            });
        }
    }

    ParsedUnderlaySnapshot {
        network_available: state.has_ipv4 || state.has_ipv6,
        primary_interface: PhysicalInterface {
            if_index,
            name: if_name,
        },
        subnets,
        dns_servers,
        nat64_prefix,
        lockdown_active: state.is_android_lockdown_enabled,
        private_dns_strict: state.is_android_private_dns_strict,
        private_dns_server_name: state.private_dns_server_name.clone(),
    }
}

/// Live-updatable [`PhysicalNetworkProbe`] driven by host OS path callbacks.
#[derive(Debug, Default)]
pub(crate) struct FfiPhysicalNetworkProbe {
    snapshot: StdRwLock<ParsedUnderlaySnapshot>,
}

impl FfiPhysicalNetworkProbe {
    /// Atomically replaces the active underlay metadata snapshot.
    pub(crate) fn update(&self, next: ParsedUnderlaySnapshot) {
        if let Ok(mut guard) = self.snapshot.write() {
            *guard = next;
        }
    }

    /// Reads current underlay snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> ParsedUnderlaySnapshot {
        self.snapshot.read().map(|g| g.clone()).unwrap_or_default()
    }
}

impl PhysicalNetworkProbe for FfiPhysicalNetworkProbe {
    fn query_primary_interface(&self) -> AppResult<PhysicalInterface> {
        Ok(self.snapshot().primary_interface)
    }

    fn list_interface_subnets(&self) -> AppResult<Vec<InterfaceSubnetSnapshot>> {
        Ok(self.snapshot().subnets)
    }
}

/// [`DnsUpstreamHook`] synchronizing Split-DNS state and retained peer routes.
#[derive(Debug)]
pub(crate) struct FfiDnsUpstreamHook {
    dns_interceptor: Arc<MobileSplitDnsInterceptor>,
    probe: Arc<FfiPhysicalNetworkProbe>,
    latest_peers: StdRwLock<Vec<PeerEntry>>,
    latest_overlay_dns_ip: StdRwLock<Option<String>>,
}

impl FfiDnsUpstreamHook {
    /// Creates a DNS hook bound to `dns_interceptor` and `probe`.
    #[must_use]
    pub(crate) fn new(
        dns_interceptor: Arc<MobileSplitDnsInterceptor>,
        probe: Arc<FfiPhysicalNetworkProbe>,
    ) -> Self {
        Self {
            dns_interceptor,
            probe,
            latest_peers: StdRwLock::new(Vec::new()),
            latest_overlay_dns_ip: StdRwLock::new(None),
        }
    }

    /// Returns latest active Netmap peer list for split-tunnel route calculation.
    #[must_use]
    pub(crate) fn latest_peers(&self) -> Vec<PeerEntry> {
        self.latest_peers
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns most recently derived overlay DNS IP string.
    #[must_use]
    pub(crate) fn latest_overlay_dns_ip(&self) -> Option<String> {
        self.latest_overlay_dns_ip
            .read()
            .ok()
            .and_then(|g| g.clone())
    }
}

impl DnsUpstreamHook for FfiDnsUpstreamHook {
    fn sync_mesh_dns<'a>(
        &'a self,
        snapshot: &'a NetmapSnapshot,
        self_overlay_ip: Option<OverlayIp>,
        self_name: Option<&'a NodeName>,
    ) -> ClientFuture<'a, AppResult<()>> {
        let underlay = self.probe.snapshot();
        if let Ok(mut guard) = self.latest_peers.write() {
            *guard = snapshot.peers.clone();
        }
        let overlay_dns_ip = derive_overlay_dns_ip(
            snapshot.overlay_cidr,
            self_overlay_ip,
            &snapshot.peers,
            &underlay.dns_servers,
        )
        .ok();
        if let Ok(mut guard) = self.latest_overlay_dns_ip.write() {
            *guard = overlay_dns_ip.map(|ip| ip.to_string());
        }
        self.dns_interceptor
            .update_netmap(snapshot, self_overlay_ip, self_name, overlay_dns_ip);
        Box::pin(async { Ok(()) })
    }

    fn clear_mesh_dns<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        self.dns_interceptor.clear();
        if let Ok(mut guard) = self.latest_peers.write() {
            guard.clear();
        }
        if let Ok(mut guard) = self.latest_overlay_dns_ip.write() {
            *guard = None;
        }
        Box::pin(async { Ok(()) })
    }
}

/// Safely closes a detached Android TUN descriptor that was never transferred into an
/// [`AndroidTunDevice`] (for example, on failure, waiter timeout, stale `op_id`, or shutdown).
pub(crate) fn close_unused_android_tun_fd(raw_fd: Option<i32>) {
    #[cfg(target_os = "android")]
    {
        if let Some(fd) = raw_fd
            && fd >= 0
        {
            // Dropping the returned `OwnedFd` closes the descriptor via RAII with zero
            // hand-written `unsafe` inside `mesh-mobile-ffi`.
            drop(mesh_sys::tun_android::adopt_raw_tun_fd(fd));
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _unused = raw_fd;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteOpKind {
    InitialEstablish,
    Reconcile,
}

type PendingRouteOps = StdMutex<
    HashMap<
        u64,
        (
            RouteOpKind,
            oneshot::Sender<Result<Option<i32>, MobileError>>,
        ),
    >,
>;
type Rfc7050LookupFn = Arc<dyn Fn() -> Vec<Ipv6Addr> + Send + Sync>;

/// Returns `true` when RFC 7050 `ipv4only.arpa` discovery should run (`!has_ipv4 && has_ipv6`
/// without a usable OS-supplied prefix, `HIGH-MOB-WA-05`).
#[must_use]
fn needs_rfc7050_nat64_discovery(
    state: &MobileUnderlayState,
    parsed: &ParsedUnderlaySnapshot,
) -> bool {
    !state.has_ipv4 && state.has_ipv6 && parsed.nat64_prefix.is_none()
}

fn lookup_ipv4only_arpa_system() -> Vec<Ipv6Addr> {
    let Ok(iter) = ("ipv4only.arpa", 80).to_socket_addrs() else {
        return Vec::new();
    };
    iter.filter_map(|sa| match sa {
        SocketAddr::V6(v6) => Some(*v6.ip()),
        SocketAddr::V4(_) => None,
    })
    .collect()
}

/// Complete [`ClientPlatformHooks`] implementation driving Android `VpnService` and iOS
/// `NEPacketTunnelProvider` without subprocess execution or blocking locks across FFI.
pub(crate) struct FfiPlatformHooks {
    platform: MobilePlatformKind,
    bridge: Arc<dyn PlatformNetworkBridge>,
    probe: Arc<FfiPhysicalNetworkProbe>,
    monitor: Arc<FakeNetMonitor>,
    dns_interceptor: Arc<MobileSplitDnsInterceptor>,
    dns_hook: Arc<FfiDnsUpstreamHook>,
    protector: Arc<FfiSocketProtector>,
    requested_tun_ifname: StdMutex<Option<String>>,
    initial_android_tun_fd: StdMutex<Option<i32>>,
    active_android_tun: StdMutex<Option<Arc<AndroidTunDevice>>>,
    active_ios_flow: StdMutex<Option<Arc<PacketFlowAdapter>>>,
    active_tun_cfg: StdMutex<Option<TunConfig>>,
    last_applied_route_cfg: StdMutex<Option<MobileTunnelNetworkConfig>>,
    ios_pump_handle: StdMutex<Option<(CancellationToken, JoinHandle<()>)>>,
    forwarder_handle: StdMutex<Option<(CancellationToken, JoinHandle<()>)>>,
    next_op_id: AtomicU64,
    pending_route_ops: PendingRouteOps,
    route_active: AtomicBool,
    active_warnings: StdRwLock<Vec<MobilePlatformWarning>>,
    memory_override_bytes: AtomicU64,
    use_memory_override: AtomicBool,
    rfc7050_lookup: StdRwLock<Option<Rfc7050LookupFn>>,
    #[cfg(test)]
    closed_unused_fds: StdMutex<Vec<i32>>,
    #[cfg(test)]
    complete_route_tokio_runtime_ids: StdMutex<Vec<Option<tokio::runtime::Id>>>,
}

impl std::fmt::Debug for FfiPlatformHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiPlatformHooks")
            .field("platform", &self.platform)
            .field("route_active", &self.route_active.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl FfiPlatformHooks {
    /// Constructs platform hooks for Android/iOS extensions.
    #[must_use]
    pub(crate) fn new(
        platform: MobilePlatformKind,
        bridge: Arc<dyn PlatformNetworkBridge>,
        dns_interceptor: Arc<MobileSplitDnsInterceptor>,
    ) -> Self {
        let probe = Arc::new(FfiPhysicalNetworkProbe::default());
        let dns_hook = Arc::new(FfiDnsUpstreamHook::new(
            Arc::clone(&dns_interceptor),
            Arc::clone(&probe),
        ));
        let protector = Arc::new(FfiSocketProtector {
            bridge: Arc::clone(&bridge),
        });
        Self {
            platform,
            bridge,
            probe,
            monitor: Arc::new(FakeNetMonitor::new()),
            dns_interceptor,
            dns_hook,
            protector,
            requested_tun_ifname: StdMutex::new(None),
            initial_android_tun_fd: StdMutex::new(None),
            active_android_tun: StdMutex::new(None),
            active_ios_flow: StdMutex::new(None),
            active_tun_cfg: StdMutex::new(None),
            last_applied_route_cfg: StdMutex::new(None),
            ios_pump_handle: StdMutex::new(None),
            forwarder_handle: StdMutex::new(None),
            next_op_id: AtomicU64::new(1),
            pending_route_ops: StdMutex::new(HashMap::new()),
            route_active: AtomicBool::new(false),
            active_warnings: StdRwLock::new(Vec::new()),
            memory_override_bytes: AtomicU64::new(0),
            use_memory_override: AtomicBool::new(false),
            rfc7050_lookup: StdRwLock::new(None),
            #[cfg(test)]
            closed_unused_fds: StdMutex::new(Vec::new()),
            #[cfg(test)]
            complete_route_tokio_runtime_ids: StdMutex::new(Vec::new()),
        }
    }

    /// Stores a preferred TUN interface name override from [`crate::types::MobileUpConfig`].
    pub(crate) fn set_requested_tun_ifname(&self, ifname: Option<String>) {
        if let Ok(mut guard) = self.requested_tun_ifname.lock() {
            *guard = ifname
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());
        }
    }

    /// Configures an optional initial Android TUN descriptor before `start_tunnel`.
    pub(crate) fn set_initial_android_tun_fd(&self, raw_fd: Option<i32>) {
        let prev = self
            .initial_android_tun_fd
            .lock()
            .ok()
            .and_then(|mut guard| {
                let old = guard.take();
                *guard = raw_fd;
                old
            });
        if prev != raw_fd {
            self.discard_unused_android_tun_fd(prev);
        }
    }

    /// Closes an unused Android TUN descriptor (and records it in unit tests).
    pub(crate) fn discard_unused_android_tun_fd(&self, raw_fd: Option<i32>) {
        #[cfg(test)]
        if let Some(fd) = raw_fd
            && fd >= 0
            && let Ok(mut guard) = self.closed_unused_fds.lock()
        {
            guard.push(fd);
        }
        close_unused_android_tun_fd(raw_fd);
    }

    /// Injects an L3 packet batch from iOS `NEPacketTunnelFlow` into active [`PacketFlowAdapter`].
    #[must_use]
    pub(crate) fn push_ios_tun_packets(&self, packets: Vec<Vec<u8>>) -> u32 {
        let adapter = self.active_ios_flow.lock().ok().and_then(|g| g.clone());
        match adapter {
            Some(flow) => flow.push_packets(packets),
            None => 0,
        }
    }

    /// Overrides reported `available_memory_bytes` in deterministic Jetsam tests.
    #[cfg(test)]
    pub(crate) fn set_test_available_memory_bytes(&self, bytes: Option<u64>) {
        match bytes {
            Some(v) => {
                self.memory_override_bytes.store(v, Ordering::SeqCst);
                self.use_memory_override.store(true, Ordering::SeqCst);
            }
            None => self.use_memory_override.store(false, Ordering::SeqCst),
        }
    }

    /// Overrides RFC 7050 `ipv4only.arpa` resolver in deterministic NAT64 tests.
    #[cfg(test)]
    pub(crate) fn set_test_rfc7050_lookup(&self, lookup: Option<Rfc7050LookupFn>) {
        if let Ok(mut guard) = self.rfc7050_lookup.write() {
            *guard = lookup;
        }
    }

    /// Inserts a pending route operation for deterministic callback tests.
    #[cfg(test)]
    pub(crate) fn insert_test_pending_route_op(
        &self,
        op_id: u64,
        kind: RouteOpKind,
    ) -> oneshot::Receiver<Result<Option<i32>, MobileError>> {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut ops) = self.pending_route_ops.lock() {
            ops.insert(op_id, (kind, tx));
        }
        rx
    }

    /// Drains recorded unused Android TUN FD discards in unit tests.
    #[cfg(test)]
    pub(crate) fn take_test_closed_unused_fds(&self) -> Vec<i32> {
        self.closed_unused_fds
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    /// Drains recorded Tokio runtime IDs seen inside `complete_route_change` in unit tests.
    #[cfg(test)]
    pub(crate) fn take_test_route_complete_runtime_ids(&self) -> Vec<Option<tokio::runtime::Id>> {
        self.complete_route_tokio_runtime_ids
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    /// Returns current active warnings surfaced by platform probes/pressure watchers.
    #[must_use]
    pub(crate) fn snapshot_warnings(&self) -> Vec<MobilePlatformWarning> {
        self.active_warnings
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns latest derived Split-DNS IPv4 listener string when active.
    #[must_use]
    pub(crate) fn latest_overlay_dns_ip(&self) -> Option<String> {
        self.dns_hook.latest_overlay_dns_ip()
    }

    /// Records or removes a categorized platform warning and emits `on_platform_warning`.
    pub(crate) fn set_warning(&self, kind: MobileWarningKind, maybe_message: Option<String>) {
        let Ok(mut guard) = self.active_warnings.write() else {
            return;
        };
        guard.retain(|w| w.kind != kind);
        if let Some(msg) = maybe_message {
            let warn = MobilePlatformWarning { kind, message: msg };
            guard.push(warn.clone());
            drop(guard);
            self.bridge.on_platform_warning(warn);
        }
    }

    /// Pulls underlay state off-thread via `spawn_blocking` and triggers RFC 7050 discovery when
    /// running on an IPv6-only underlay without an OS-supplied NAT64 prefix (`HIGH-MOB-WA-04/05`).
    pub(crate) async fn refresh_underlay_from_bridge_async(&self) -> ParsedUnderlaySnapshot {
        let bridge = Arc::clone(&self.bridge);
        let query_res = tokio::task::spawn_blocking(move || bridge.query_underlay_state()).await;
        match query_res {
            Ok(Ok(raw)) => {
                let mut parsed = parse_underlay_state(&raw);
                if needs_rfc7050_nat64_discovery(&raw, &parsed) {
                    parsed.nat64_prefix = self.discover_nat64_prefix_rfc7050().await;
                }
                self.apply_underlay_snapshot(parsed.clone());
                parsed
            }
            Ok(Err(err)) => {
                debug!(
                    component = "mesh_mobile_ffi.bridge",
                    event = "query_underlay_state_unavailable",
                    error = %err,
                    "host bridge did not supply initial underlay state"
                );
                self.probe.snapshot()
            }
            Err(join_err) => {
                debug!(
                    component = "mesh_mobile_ffi.bridge",
                    event = "query_underlay_state_panicked",
                    error = %join_err,
                    "underlay query task aborted"
                );
                self.probe.snapshot()
            }
        }
    }

    async fn discover_nat64_prefix_rfc7050(&self) -> Option<Nat64Prefix> {
        let custom_lookup = self.rfc7050_lookup.read().ok().and_then(|g| g.clone());
        let res = tokio::time::timeout(
            RFC7050_DISCOVERY_TIMEOUT,
            tokio::task::spawn_blocking(move || match custom_lookup {
                Some(f) => f(),
                None => lookup_ipv4only_arpa_system(),
            }),
        )
        .await;
        match res {
            Ok(Ok(addrs)) => Nat64Prefix::from_ipv4only_arpa_addrs(&addrs),
            Ok(Err(_join_err)) => None,
            Err(_elapsed) => {
                debug!(
                    component = "mesh_mobile_ffi.bridge",
                    event = "rfc7050_ipv4only_arpa_timeout",
                    timeout_ms = RFC7050_DISCOVERY_TIMEOUT.as_millis(),
                    "RFC 7050 ipv4only.arpa lookup timed out after 2s"
                );
                None
            }
        }
    }

    /// Resolves a pending `on_route_changed` callback invoked by Android/iOS host code.
    pub(crate) fn complete_route_change(
        &self,
        op_id: u64,
        success: bool,
        new_android_tun_fd: Option<i32>,
        error_message: Option<String>,
    ) -> Result<(), MobileError> {
        #[cfg(test)]
        if let Ok(mut guard) = self.complete_route_tokio_runtime_ids.lock() {
            guard.push(tokio::runtime::Handle::try_current().ok().map(|h| h.id()));
        }

        let maybe_op = match self.pending_route_ops.lock() {
            Ok(mut ops) => ops.remove(&op_id),
            Err(_) => {
                self.discard_unused_android_tun_fd(new_android_tun_fd);
                return Err(MobileError::internal("pending_route_ops lock poisoned"));
            }
        };

        if !success {
            self.discard_unused_android_tun_fd(new_android_tun_fd);
            if let Some((_kind, tx)) = maybe_op
                && tx
                    .send(Err(MobileError::unavailable(error_message.unwrap_or_else(
                        || "host rejected tunnel route configuration".to_owned(),
                    ))))
                    .is_err()
            {
                debug!(
                    component = "mesh_mobile_ffi.bridge",
                    event = "route_change_waiter_dropped",
                    op_id,
                    "route change waiter already timed out or dropped"
                );
            }
            return Ok(());
        }

        match maybe_op {
            Some((RouteOpKind::InitialEstablish, tx)) => {
                // Hand raw FD directly to `activate_tun_and_routes` so `from_raw_fd` adopts it once.
                if let Err(returned) = tx.send(Ok(new_android_tun_fd)) {
                    if let Ok(unused_fd) = returned {
                        self.discard_unused_android_tun_fd(unused_fd);
                    }
                    debug!(
                        component = "mesh_mobile_ffi.bridge",
                        event = "route_change_waiter_dropped",
                        op_id,
                        "initial establish route waiter dropped before completion"
                    );
                }
                Ok(())
            }
            Some((RouteOpKind::Reconcile, tx)) => {
                self.complete_reconcile_route_op(op_id, tx, new_android_tun_fd)
            }
            None => {
                self.discard_unused_android_tun_fd(new_android_tun_fd);
                debug!(
                    component = "mesh_mobile_ffi.bridge",
                    event = "route_change_waiter_dropped",
                    op_id,
                    has_android_tun_fd = new_android_tun_fd.is_some(),
                    "ignoring stale or timed-out route change completion"
                );
                Ok(())
            }
        }
    }

    fn complete_reconcile_route_op(
        &self,
        op_id: u64,
        tx: oneshot::Sender<Result<Option<i32>, MobileError>>,
        new_android_tun_fd: Option<i32>,
    ) -> Result<(), MobileError> {
        let swap_res = if let Some(fd) = new_android_tun_fd {
            let existing = self
                .active_android_tun
                .lock()
                .ok()
                .and_then(|guard| guard.clone());
            match existing {
                Some(existing_tun) => existing_tun.swap_raw_fd(fd).map_err(MobileError::from),
                None => {
                    self.discard_unused_android_tun_fd(Some(fd));
                    Err(MobileError::unavailable(
                        "cannot apply Android TUN FD reconcile without active TUN device",
                    ))
                }
            }
        } else {
            Ok(())
        };
        let return_res = swap_res.as_ref().map(|()| None).map_err(Clone::clone);
        if tx.send(return_res).is_err() {
            debug!(
                component = "mesh_mobile_ffi.bridge",
                event = "route_change_waiter_dropped",
                op_id,
                "reconcile route waiter already timed out or dropped"
            );
        }
        swap_res
    }

    /// Dispatches an underlay transition event into the supervised session `NetMonitor`.
    pub(crate) async fn notify_network_change(
        &self,
        event_kind: MobileNetEventKind,
        underlay: MobileUnderlayState,
    ) {
        let mut parsed = parse_underlay_state(&underlay);
        if needs_rfc7050_nat64_discovery(&underlay, &parsed) {
            parsed.nat64_prefix = self.discover_nat64_prefix_rfc7050().await;
        }
        self.apply_underlay_snapshot(parsed.clone());

        let event = match event_kind {
            MobileNetEventKind::InterfaceChanged | MobileNetEventKind::DnsServersChanged => {
                NetEvent::RouteChanged
            }
            MobileNetEventKind::AddressChanged => NetEvent::AddressChanged {
                interface: parsed.primary_interface.name,
            },
            MobileNetEventKind::ConnectivityLost => NetEvent::InterfaceDown {
                interface: parsed.primary_interface.name,
            },
            MobileNetEventKind::ConnectivityRestored => NetEvent::InterfaceUp {
                interface: parsed.primary_interface.name,
            },
        };
        self.monitor.push_event(event).await;
    }

    fn apply_underlay_snapshot(&self, parsed: ParsedUnderlaySnapshot) {
        let if_idx =
            (parsed.primary_interface.if_index != 0).then_some(parsed.primary_interface.if_index);
        self.dns_interceptor.update_underlay(
            parsed.dns_servers.clone(),
            parsed.nat64_prefix,
            if_idx,
            None,
        );
        self.set_warning(
            MobileWarningKind::AndroidLockdownActive,
            parsed.lockdown_active.then(|| {
                "Android 'Block connections without VPN' Lockdown mode is active; control plane probes may fail if excluded".to_owned()
            }),
        );
        self.set_warning(
            MobileWarningKind::AndroidPrivateDnsStrict,
            parsed.private_dns_strict.then(|| {
                let target = parsed
                    .private_dns_server_name
                    .as_deref()
                    .unwrap_or("private-dns");
                format!("Android Strict Private DNS ({target}) is active; DoT :853 fails fast and split-DNS fallback applies")
            }),
        );
        self.probe.update(parsed);
    }

    async fn dispatch_route_update(
        &self,
        op_id: u64,
        kind: RouteOpKind,
        cfg: MobileTunnelNetworkConfig,
    ) -> AppResult<Option<i32>> {
        let (tx, rx) = oneshot::channel();
        {
            let mut ops = self
                .pending_route_ops
                .lock()
                .map_err(|_| AppError::internal("pending_route_ops lock poisoned"))?;
            ops.insert(op_id, (kind, tx));
        }

        let bridge = Arc::clone(&self.bridge);
        tokio::task::spawn_blocking(move || bridge.on_route_changed(op_id, cfg))
            .await
            .map_err(|err| AppError::internal(format!("route callback task panicked: {err}")))?;

        match tokio::time::timeout(Duration::from_millis(ROUTE_CHANGE_TIMEOUT_MS), rx).await {
            Ok(Ok(Ok(maybe_fd))) => Ok(maybe_fd),
            Ok(Ok(Err(mobile_err))) => Err(mobile_err.to_app_error()),
            Ok(Err(_closed)) => Err(AppError::unavailable(
                "host dropped route change completion channel",
            )),
            Err(_elapsed) => {
                if let Ok(mut ops) = self.pending_route_ops.lock() {
                    let _removed = ops.remove(&op_id);
                }
                Err(AppError::unavailable(format!(
                    "host did not complete route change op {op_id} within {ROUTE_CHANGE_TIMEOUT_MS} ms"
                )))
            }
        }
    }

    fn build_route_config(
        &self,
        overlay_ip: OverlayIp,
        overlay_cidr: OverlayCidr,
        dns_server_ip: Option<OverlayIp>,
        domain_suffix: Option<&str>,
        mtu: u16,
    ) -> AppResult<(MobileTunnelNetworkConfig, bool, Option<String>)> {
        let underlay = self.probe.snapshot();
        let underlay_ips: Vec<IpAddr> = underlay.subnets.iter().map(|s| s.ip).collect();
        let conflict = detect_overlay_subnet_conflict(&underlay.subnets, overlay_cidr);
        let peers = self.dns_hook.latest_peers();
        let dns_ip = match dns_server_ip {
            Some(ip) => ip,
            None => derive_overlay_dns_ip(
                overlay_cidr,
                Some(overlay_ip),
                &peers,
                &underlay.dns_servers,
            )?,
        };
        let plan = compute_split_tunnel_routes(
            overlay_cidr,
            overlay_ip,
            dns_ip,
            &peers,
            &underlay_ips,
            conflict.is_some(),
        )?;
        let search_domain = domain_suffix
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_SEARCH_DOMAIN)
            .to_owned();

        let mask = prefix_len_to_ipv4_mask(overlay_cidr.prefix_len());
        let cfg = MobileTunnelNetworkConfig {
            overlay_ip: overlay_ip.to_string(),
            tun_interface_prefix_len: 32,
            overlay_cidr: overlay_cidr.to_string(),
            overlay_subnet_mask: mask.to_string(),
            overlay_dns_ip: plan.overlay_dns_ip.to_string(),
            domain_suffix: search_domain,
            tun_mtu: mtu,
            included_routes_cidr: plan
                .included_routes
                .into_iter()
                .map(mesh_client::SplitTunnelCidr::to_cidr_string)
                .collect(),
        };
        Ok((
            cfg,
            conflict.is_some(),
            conflict.map(|c| c.format_warning()),
        ))
    }

    fn stop_background_tun_helpers(&self) {
        if let Some((token, handle)) = self.forwarder_handle.lock().ok().and_then(|mut g| g.take())
        {
            token.cancel();
            handle.abort();
        }
        if let Some((token, handle)) = self.ios_pump_handle.lock().ok().and_then(|mut g| g.take()) {
            token.cancel();
            handle.abort();
        }
    }
}

impl ClientPlatformHooks for FfiPlatformHooks {
    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe> {
        self.probe.clone()
    }

    fn net_monitor(&self) -> Arc<dyn NetMonitor> {
        self.monitor.clone()
    }

    fn dns_hook(&self) -> Arc<dyn DnsUpstreamHook> {
        self.dns_hook.clone()
    }

    fn socket_protector(&self) -> Option<Arc<dyn SocketProtector>> {
        match self.platform {
            MobilePlatformKind::Android => Some(self.protector.clone()),
            MobilePlatformKind::Ios => None,
        }
    }

    fn activate_tun_and_routes<'a>(
        &'a self,
        mut tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        dns_server_ip: Option<OverlayIp>,
        domain_suffix: Option<&'a str>,
        _now_ms: u64,
    ) -> ClientFuture<'a, AppResult<TunActivationOutcome>> {
        let domain_owned = domain_suffix.map(ToOwned::to_owned);
        Box::pin(async move {
            self.stop_background_tun_helpers();
            let prev_ios = self.active_ios_flow.lock().ok().and_then(|mut g| g.take());
            if let Some(flow) = prev_ios {
                let _ignored = flow.close().await;
            }
            let prev_android = self
                .active_android_tun
                .lock()
                .ok()
                .and_then(|mut g| g.take());
            if let Some(tun) = prev_android {
                let _ignored = tun.close().await;
            }
            if let Ok(mut g) = self.active_tun_cfg.lock() {
                *g = None;
            }
            if let Ok(mut g) = self.last_applied_route_cfg.lock() {
                *g = None;
            }

            if let Some(custom_ifname) = self
                .requested_tun_ifname
                .lock()
                .ok()
                .and_then(|mut g| g.take())
            {
                tun_cfg.interface_name = custom_ifname;
            }

            let underlay = self.refresh_underlay_from_bridge_async().await;
            let (route_cfg, _had_conflict, conflict_warning) = self.build_route_config(
                tun_cfg.overlay_ip,
                overlay_cidr,
                dns_server_ip,
                domain_owned.as_deref(),
                tun_cfg.mtu,
            )?;
            self.set_warning(
                MobileWarningKind::OverlaySubnetConflict,
                conflict_warning.clone(),
            );

            if let Ok(mut guard) = self.dns_hook.latest_overlay_dns_ip.write() {
                *guard = Some(route_cfg.overlay_dns_ip.clone());
            }

            let op_id = self.next_op_id.fetch_add(1, Ordering::SeqCst);
            let tun: Arc<dyn TunDevice> = match self.platform {
                MobilePlatformKind::Ios => {
                    let (adapter, pump) =
                        PacketFlowAdapter::new(tun_cfg.clone(), Arc::clone(&self.bridge));
                    if let Ok(mut guard) = self.active_ios_flow.lock() {
                        *guard = Some(Arc::clone(&adapter));
                    }
                    let pump_cancel = CancellationToken::new();
                    let pump_join = tokio::spawn(pump.run(pump_cancel.clone()));
                    if let Ok(mut guard) = self.ios_pump_handle.lock() {
                        *guard = Some((pump_cancel, pump_join));
                    }
                    match self
                        .dispatch_route_update(
                            op_id,
                            RouteOpKind::InitialEstablish,
                            route_cfg.clone(),
                        )
                        .await
                    {
                        Ok(_ios_no_tun_fd) => adapter,
                        Err(err) => {
                            self.stop_background_tun_helpers();
                            if let Some(flow) =
                                self.active_ios_flow.lock().ok().and_then(|mut g| g.take())
                            {
                                let _ignored = flow.close().await;
                            }
                            return Err(err);
                        }
                    }
                }
                MobilePlatformKind::Android => {
                    let callback_fd = match self
                        .dispatch_route_update(
                            op_id,
                            RouteOpKind::InitialEstablish,
                            route_cfg.clone(),
                        )
                        .await
                    {
                        Ok(fd) => fd,
                        Err(err) => {
                            let leftover_initial = self
                                .initial_android_tun_fd
                                .lock()
                                .ok()
                                .and_then(|mut g| g.take());
                            self.discard_unused_android_tun_fd(leftover_initial);
                            return Err(err);
                        }
                    };
                    let initial_fd = self
                        .initial_android_tun_fd
                        .lock()
                        .ok()
                        .and_then(|mut g| g.take());
                    let chosen_fd = match (callback_fd, initial_fd) {
                        (Some(cb_fd), Some(init_fd)) => {
                            if init_fd != cb_fd {
                                self.discard_unused_android_tun_fd(Some(init_fd));
                            }
                            cb_fd
                        }
                        (Some(cb_fd), None) => cb_fd,
                        (None, Some(init_fd)) => init_fd,
                        (None, None) => {
                            return Err(AppError::unavailable(
                                "Android VpnService.Builder.establish() did not provide a TUN FD",
                            ));
                        }
                    };
                    let android_tun =
                        Arc::new(AndroidTunDevice::from_raw_fd(tun_cfg.clone(), chosen_fd)?);
                    if let Ok(mut guard) = self.active_android_tun.lock() {
                        *guard = Some(Arc::clone(&android_tun));
                    }
                    android_tun
                }
            };

            if let Ok(mut g) = self.active_tun_cfg.lock() {
                *g = Some(tun_cfg);
            }
            if let Ok(mut g) = self.last_applied_route_cfg.lock() {
                *g = Some(route_cfg);
            }
            self.route_active.store(true, Ordering::SeqCst);

            let forwarder_cancel = CancellationToken::new();
            let forwarder_join = self.dns_interceptor.start_upstream_forwarder(
                Some(Arc::clone(&tun)),
                self.socket_protector(),
                forwarder_cancel.clone(),
            );
            if let Ok(mut guard) = self.forwarder_handle.lock() {
                *guard = Some((forwarder_cancel, forwarder_join));
            }

            let lockdown_warning = underlay.lockdown_active.then(|| {
                "Android 'Block connections without VPN' Lockdown mode is active".to_owned()
            });
            let private_dns_warning = underlay.private_dns_strict.then(|| {
                "Android Strict Private DNS is active; .mesh.internal queries may bypass split-DNS"
                    .to_owned()
            });

            Ok(TunActivationOutcome {
                tun,
                route_installed: true,
                conflict_warning,
                lockdown_warning,
                private_dns_warning,
            })
        })
    }

    fn reconcile_on_roam_or_netmap<'a>(
        &'a self,
        _tun_ifname: &'a str,
        overlay_cidr: OverlayCidr,
        dns_server_ip: Option<OverlayIp>,
        domain_suffix: Option<&'a str>,
    ) -> ClientFuture<'a, AppResult<Option<String>>> {
        let domain_owned = domain_suffix.map(ToOwned::to_owned);
        Box::pin(async move {
            let Some(active_tun) = self.active_tun_cfg.lock().ok().and_then(|g| g.clone()) else {
                return Ok(None);
            };
            let (route_cfg, _had_conflict, conflict_warning) = self.build_route_config(
                active_tun.overlay_ip,
                overlay_cidr,
                dns_server_ip,
                domain_owned.as_deref(),
                active_tun.mtu,
            )?;
            self.set_warning(
                MobileWarningKind::OverlaySubnetConflict,
                conflict_warning.clone(),
            );
            let unchanged = self
                .last_applied_route_cfg
                .lock()
                .ok()
                .is_some_and(|g| g.as_ref() == Some(&route_cfg));
            if unchanged {
                return Ok(conflict_warning);
            }
            let op_id = self.next_op_id.fetch_add(1, Ordering::SeqCst);
            let _reconciled_tun_fd = self
                .dispatch_route_update(op_id, RouteOpKind::Reconcile, route_cfg.clone())
                .await?;
            if let Ok(mut g) = self.last_applied_route_cfg.lock() {
                *g = Some(route_cfg);
            }
            Ok(conflict_warning)
        })
    }

    fn deactivate_and_cleanup<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async move {
            self.route_active.store(false, Ordering::SeqCst);
            self.stop_background_tun_helpers();
            self.dns_interceptor.clear();

            if let Ok(mut g) = self.active_tun_cfg.lock() {
                *g = None;
            }
            if let Ok(mut g) = self.last_applied_route_cfg.lock() {
                *g = None;
            }
            if let Ok(mut g) = self.requested_tun_ifname.lock() {
                *g = None;
            }

            let ios_flow = self
                .active_ios_flow
                .lock()
                .ok()
                .and_then(|mut guard| guard.take());
            if let Some(flow) = ios_flow {
                let _ignored = flow.close().await;
            }
            let android_tun = self
                .active_android_tun
                .lock()
                .ok()
                .and_then(|mut guard| guard.take());
            if let Some(tun) = android_tun {
                let _ignored = tun.close().await;
            }
            let leftover_initial = self
                .initial_android_tun_fd
                .lock()
                .ok()
                .and_then(|mut guard| guard.take());
            self.discard_unused_android_tun_fd(leftover_initial);
            if let Ok(mut ops) = self.pending_route_ops.lock() {
                for (_, (_kind, tx)) in ops.drain() {
                    let _ignored = tx.send(Err(MobileError::unavailable("tunnel shutting down")));
                }
            }
            info!(
                component = "mesh_mobile_ffi.bridge",
                event = "mobile_platform_deactivated",
                "cleared mobile Split-DNS, TUN adapters, and pending route ops"
            );
            Ok(())
        })
    }

    fn discover_local_interface_endpoints(
        &self,
        _udp_port: u16,
    ) -> Vec<DiscoveredInterfaceEndpoint> {
        Vec::new()
    }

    fn collect_route_diagnostics(&self) -> String {
        let underlay = self.probe.snapshot();
        format!(
            "platform={:?} network_available={} primary_if={}#{} dns_servers={:?} nat64={} route_active={}\n",
            self.platform,
            underlay.network_available,
            underlay.primary_interface.name,
            underlay.primary_interface.if_index,
            underlay.dns_servers,
            underlay.nat64_prefix.map_or_else(
                || "none".to_owned(),
                |p| format!("{}/{}", p.prefix_addr(), p.prefix_len().as_u8()),
            ),
            self.route_active.load(Ordering::Relaxed)
        )
    }

    fn available_memory_bytes(&self) -> Option<u64> {
        if self.use_memory_override.load(Ordering::SeqCst) {
            return Some(self.memory_override_bytes.load(Ordering::SeqCst));
        }
        #[cfg(target_os = "ios")]
        {
            Some(u64::try_from(mesh_sys::memory_ios::available_memory_bytes()).unwrap_or(u64::MAX))
        }
        #[cfg(not(target_os = "ios"))]
        {
            None
        }
    }

    fn nat64_prefix(&self) -> Option<Nat64Prefix> {
        self.probe.snapshot().nat64_prefix
    }

    fn underlay_dns_servers(&self) -> Vec<IpAddr> {
        self.probe.snapshot().dns_servers
    }

    fn is_private_dns_strict(&self) -> bool {
        self.probe.snapshot().private_dns_strict
    }
}

const fn prefix_len_to_ipv4_mask(prefix_len: u8) -> Ipv4Addr {
    let raw = if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let [a, b, c, d] = raw.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex as StdMutex};

    use mesh_client::{BootstrapConfig, ClientPlatformHooks, ClientStateStore};
    use mesh_core::{FakeClock, OverlayCidr, OverlayIp};
    use mesh_crypto::random_bytes;
    use mesh_net::{Nat64Prefix, Nat64Synthesizer, TunConfig};
    use mesh_proto::agent_ipc::TlsAuthMode;

    use super::{
        FfiPlatformHooks, FfiStateStore, RouteOpKind, close_unused_android_tun_fd,
        parse_underlay_state,
    };
    use crate::dns_responder::MobileSplitDnsInterceptor;
    use crate::types::{
        MobileError, MobileNetEventKind, MobilePlatformKind, MobilePlatformWarning,
        MobileStatusSnapshot, MobileTunnelNetworkConfig, MobileUnderlayState,
        PlatformNetworkBridge,
    };

    #[derive(Debug, Default)]
    struct FakeBridge {
        dek: StdMutex<Option<Vec<u8>>>,
        files: StdMutex<HashMap<String, Vec<u8>>>,
        protected_fds: StdMutex<Vec<i32>>,
        route_updates: StdMutex<Vec<(u64, MobileTunnelNetworkConfig)>>,
    }

    impl PlatformNetworkBridge for FakeBridge {
        fn protect_socket(&self, raw_fd: i32) -> Result<bool, MobileError> {
            if let Ok(mut g) = self.protected_fds.lock() {
                g.push(raw_fd);
            }
            Ok(true)
        }

        fn on_tun_packets(&self, _packets: Vec<Vec<u8>>) {}

        fn on_route_changed(&self, op_id: u64, config: MobileTunnelNetworkConfig) {
            if let Ok(mut g) = self.route_updates.lock() {
                g.push((op_id, config));
            }
        }

        fn on_status_changed(&self, _status: MobileStatusSnapshot) {}

        fn on_platform_warning(&self, _warning: MobilePlatformWarning) {}

        fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError> {
            Ok(MobileUnderlayState::default())
        }

        fn load_or_create_platform_dek(&self) -> Result<Vec<u8>, MobileError> {
            let Ok(mut guard) = self.dek.lock() else {
                return Err(MobileError::internal("dek mutex poisoned"));
            };
            if let Some(ref existing) = *guard {
                return Ok(existing.clone());
            }
            let fresh = random_bytes::<32>().to_vec();
            *guard = Some(fresh.clone());
            Ok(fresh)
        }

        fn load_state_file(&self, file_name: String) -> Result<Option<Vec<u8>>, MobileError> {
            Ok(self
                .files
                .lock()
                .ok()
                .and_then(|g| g.get(&file_name).cloned()))
        }

        fn save_state_file(&self, file_name: String, content: Vec<u8>) -> Result<(), MobileError> {
            if let Ok(mut g) = self.files.lock() {
                g.insert(file_name, content);
            }
            Ok(())
        }

        fn delete_state_file(&self, file_name: String) -> Result<(), MobileError> {
            if let Ok(mut g) = self.files.lock() {
                let _removed = g.remove(&file_name);
            }
            Ok(())
        }
    }

    #[test]
    fn test_sealed_identity_store_uses_dek_and_fails_closed_when_dek_rotates_away()
    -> Result<(), String> {
        // Arrange
        let bridge = Arc::new(FakeBridge::default());
        let store = FfiStateStore::new(bridge.clone(), None);

        // Act 1: Generate and seal identity.
        let created = store
            .load_or_create_identity(1_700_000_000_000)
            .map_err(|e| e.to_string())?;
        let sealed_blob = bridge
            .files
            .lock()
            .map_err(|_| "lock poisoned".to_owned())?
            .get("identity.sealed.bin")
            .cloned()
            .ok_or("missing sealed identity")?;
        let reloaded = store
            .load_existing_identity()
            .map_err(|e| e.to_string())?
            .ok_or("missing reloaded identity")?;

        // Assert 1: Sealed file starts with magic "MSH1", contains zero plaintext JSON keys.
        assert!(sealed_blob.starts_with(b"MSH1"));
        assert!(!String::from_utf8_lossy(&sealed_blob).contains("node_privkey_hex"));
        assert_eq!(
            reloaded.node_keypair.public_key(),
            created.node_keypair.public_key()
        );

        // Act 2: Simulate Keychain/Keystore invalidation by rotating away DEK.
        if let Ok(mut g) = bridge.dek.lock() {
            *g = Some(vec![0x99_u8; 32]);
        }
        let Err(wrong_dek_err) = store.load_existing_identity() else {
            return Err("wrong DEK must fail closed instead of regenerating".to_owned());
        };

        // Assert 2: Converts cleanly into KeystoreInvalidated mobile error.
        let mobile_err = MobileError::from(wrong_dek_err);
        assert!(mobile_err.is_keystore_invalidated());
        Ok(())
    }

    #[test]
    fn test_ffi_state_store_delete_identity_removes_sealed_identity_only() -> Result<(), String> {
        // Arrange
        let bridge = Arc::new(FakeBridge::default());
        let store = FfiStateStore::new(bridge.clone(), None);
        let _created = store
            .load_or_create_identity(1_700_000_000_000)
            .map_err(|e| e.to_string())?;
        store
            .save_bootstrap(&BootstrapConfig::default())
            .map_err(|e| e.to_string())?;

        // Act
        store.delete_identity().map_err(|e| e.to_string())?;
        store.delete_identity().map_err(|e| e.to_string())?;

        // Assert
        let files = bridge
            .files
            .lock()
            .map_err(|_| "lock poisoned".to_owned())?;
        assert!(!files.contains_key("identity.sealed.bin"));
        assert!(files.contains_key("bootstrap.toml"));
        drop(files);
        assert!(
            store
                .load_existing_identity()
                .map_err(|e| e.to_string())?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn test_ffi_state_store_bootstrap_validation_rejects_ip_literal_system_ca() -> Result<(), String>
    {
        // Arrange
        let bridge = Arc::new(FakeBridge::default());
        let store = FfiStateStore::new(bridge.clone(), None);
        let invalid_cfg = BootstrapConfig {
            server_endpoint: Some("198.51.100.10:8443".to_owned()),
            tls_auth_mode: TlsAuthMode::SystemCa,
            active_pin: None,
            ..BootstrapConfig::default()
        };

        // Act
        let save_res = store.save_bootstrap(&invalid_cfg);
        if let Ok(mut g) = bridge.files.lock() {
            g.insert(
                "bootstrap.toml".to_owned(),
                b"schema_version = 1\nserver_endpoint = \"198.51.100.10:8443\"\ntls_auth_mode = \"system_ca\"\n".to_vec(),
            );
        }
        let load_res = store.load_bootstrap();

        // Assert
        assert!(save_res.is_err());
        assert!(load_res.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_reconcile_on_roam_preserves_overlay_ip_mtu_and_dedups_noop_routes()
    -> Result<(), String> {
        // Arrange
        #[derive(Debug)]
        struct CompletingBridge {
            inner: FakeBridge,
            hooks: StdMutex<Option<Arc<FfiPlatformHooks>>>,
        }
        impl PlatformNetworkBridge for CompletingBridge {
            fn protect_socket(&self, raw_fd: i32) -> Result<bool, MobileError> {
                self.inner.protect_socket(raw_fd)
            }
            fn on_tun_packets(&self, packets: Vec<Vec<u8>>) {
                self.inner.on_tun_packets(packets);
            }
            fn on_route_changed(&self, op_id: u64, config: MobileTunnelNetworkConfig) {
                self.inner.on_route_changed(op_id, config);
                if let Ok(g) = self.hooks.lock()
                    && let Some(ref h) = *g
                {
                    let _res = h.complete_route_change(op_id, true, None, None);
                }
            }
            fn on_status_changed(&self, status: MobileStatusSnapshot) {
                self.inner.on_status_changed(status);
            }
            fn on_platform_warning(&self, warning: MobilePlatformWarning) {
                self.inner.on_platform_warning(warning);
            }
            fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError> {
                self.inner.query_underlay_state()
            }
            fn load_or_create_platform_dek(&self) -> Result<Vec<u8>, MobileError> {
                self.inner.load_or_create_platform_dek()
            }
            fn load_state_file(&self, file_name: String) -> Result<Option<Vec<u8>>, MobileError> {
                self.inner.load_state_file(file_name)
            }
            fn save_state_file(
                &self,
                file_name: String,
                content: Vec<u8>,
            ) -> Result<(), MobileError> {
                self.inner.save_state_file(file_name, content)
            }
            fn delete_state_file(&self, file_name: String) -> Result<(), MobileError> {
                self.inner.delete_state_file(file_name)
            }
        }

        let bridge = Arc::new(CompletingBridge {
            inner: FakeBridge::default(),
            hooks: StdMutex::new(None),
        });
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let dns = Arc::new(MobileSplitDnsInterceptor::new(clock));
        let hooks = Arc::new(FfiPlatformHooks::new(
            MobilePlatformKind::Ios,
            bridge.clone(),
            dns,
        ));
        if let Ok(mut g) = bridge.hooks.lock() {
            *g = Some(Arc::clone(&hooks));
        }
        let cidr = OverlayCidr::parse("100.64.0.0/16").map_err(|e| e.to_string())?;
        let real_ip =
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 9, 42)).map_err(|e| e.to_string())?;
        let tun_cfg = TunConfig::new("utun9", real_ip, cidr, 1400).map_err(|e| e.to_string())?;

        // Act
        let _outcome = hooks
            .activate_tun_and_routes(tun_cfg, cidr, None, Some("mesh.internal"), 1_000)
            .await
            .map_err(|e| e.to_string())?;
        let updates_after_activate = bridge
            .inner
            .route_updates
            .lock()
            .map_err(|_| "lock".to_owned())?
            .len();
        let _reconcile_same = hooks
            .reconcile_on_roam_or_netmap("utun9", cidr, None, Some("mesh.internal"))
            .await
            .map_err(|e| e.to_string())?;
        let updates_after_noop_reconcile = bridge
            .inner
            .route_updates
            .lock()
            .map_err(|_| "lock".to_owned())?
            .len();
        let updated_dns =
            OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 200)).map_err(|e| e.to_string())?;
        let _reconcile_changed = hooks
            .reconcile_on_roam_or_netmap("utun9", cidr, Some(updated_dns), Some("mesh.internal"))
            .await
            .map_err(|e| e.to_string())?;
        let recorded = bridge
            .inner
            .route_updates
            .lock()
            .map_err(|_| "lock".to_owned())?
            .clone();
        hooks
            .deactivate_and_cleanup()
            .await
            .map_err(|e| e.to_string())?;
        let reconcile_when_inactive = hooks
            .reconcile_on_roam_or_netmap("utun9", cidr, None, Some("mesh.internal"))
            .await
            .map_err(|e| e.to_string())?;

        // Assert
        assert_eq!(updates_after_activate, 1);
        assert_eq!(updates_after_noop_reconcile, 1);
        assert_eq!(recorded.len(), 2);
        let second_cfg = recorded
            .get(1)
            .map(|(_, c)| c)
            .ok_or("missing second route config")?;
        assert_eq!(second_cfg.overlay_ip, "100.64.9.42");
        assert_eq!(second_cfg.tun_mtu, 1400);
        assert_eq!(reconcile_when_inactive, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_underlay_nat64_disabled_on_dual_stack_and_discovers_rfc7050() -> Result<(), String>
    {
        // Arrange
        let dual_stack = MobileUnderlayState {
            has_ipv4: true,
            has_ipv6: true,
            os_nat64_prefix: Some("64:ff9b::/96".to_owned()),
            ..MobileUnderlayState::default()
        };
        let bridge = Arc::new(FakeBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let dns = Arc::new(MobileSplitDnsInterceptor::new(clock));
        let hooks = Arc::new(FfiPlatformHooks::new(
            MobilePlatformKind::Android,
            bridge,
            dns,
        ));
        let expected_prefix =
            Nat64Prefix::from_cidr("2001:db8:40::/64").map_err(|e| e.to_string())?;
        let synth = Nat64Synthesizer::new(expected_prefix);
        let arpa_a = synth.synthesize_ip(Ipv4Addr::new(192, 0, 0, 170));
        let arpa_b = synth.synthesize_ip(Ipv4Addr::new(192, 0, 0, 171));
        hooks.set_test_rfc7050_lookup(Some(Arc::new(move || vec![arpa_a, arpa_b])));

        // Act
        let dual_parsed = parse_underlay_state(&dual_stack);
        hooks
            .notify_network_change(
                MobileNetEventKind::InterfaceChanged,
                MobileUnderlayState {
                    has_ipv4: false,
                    has_ipv6: true,
                    os_nat64_prefix: None,
                    active_interface_name: Some("rmnet0".to_owned()),
                    ..MobileUnderlayState::default()
                },
            )
            .await;
        let discovered = hooks.nat64_prefix();

        hooks
            .notify_network_change(MobileNetEventKind::InterfaceChanged, dual_stack)
            .await;
        let cleared_on_dual_stack = hooks.nat64_prefix();

        // Assert
        assert_eq!(dual_parsed.nat64_prefix, None);
        assert_eq!(discovered, Some(expected_prefix));
        assert_eq!(cleared_on_dual_stack, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_complete_route_change_closes_unused_android_tun_fd_on_all_drop_paths()
    -> Result<(), String> {
        // Arrange
        let bridge = Arc::new(FakeBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let dns = Arc::new(MobileSplitDnsInterceptor::new(clock));
        let hooks = Arc::new(FfiPlatformHooks::new(
            MobilePlatformKind::Android,
            bridge,
            dns,
        ));

        // Act 1: `!success` with pending op and `Some(fd)` must notify waiter and discard FD.
        let rx_fail = hooks.insert_test_pending_route_op(1, RouteOpKind::InitialEstablish);
        hooks
            .complete_route_change(1, false, Some(101), Some("host denied".to_owned()))
            .map_err(|e| e.to_string())?;
        let fail_outcome = rx_fail.await.map_err(|e| e.to_string())?;
        assert!(matches!(fail_outcome, Err(MobileError::Unavailable { .. })));

        // Act 2: `!success` with unknown op_id and `Some(fd)` must still discard FD.
        hooks
            .complete_route_change(999, false, Some(102), None)
            .map_err(|e| e.to_string())?;

        // Act 3: `success = true` with unknown/expired op_id and `Some(fd)` must discard FD.
        hooks
            .complete_route_change(888, true, Some(103), None)
            .map_err(|e| e.to_string())?;

        // Act 4: `InitialEstablish` where waiter timed out / dropped before completion.
        let rx_dropped = hooks.insert_test_pending_route_op(2, RouteOpKind::InitialEstablish);
        drop(rx_dropped);
        hooks
            .complete_route_change(2, true, Some(104), None)
            .map_err(|e| e.to_string())?;

        // Act 5: `Reconcile` with `active_android_tun == None` must discard FD and error.
        let rx_reconcile = hooks.insert_test_pending_route_op(3, RouteOpKind::Reconcile);
        let reconcile_res = hooks.complete_route_change(3, true, Some(105), None);
        assert!(matches!(
            reconcile_res,
            Err(MobileError::Unavailable { .. })
        ));
        let reconcile_waiter_res = rx_reconcile.await.map_err(|e| e.to_string())?;
        assert!(matches!(
            reconcile_waiter_res,
            Err(MobileError::Unavailable { .. })
        ));

        // Act 6: overwriting & cleaning up unused `initial_android_tun_fd` discards old FD.
        hooks.set_initial_android_tun_fd(Some(106));
        hooks.set_initial_android_tun_fd(Some(107));
        hooks
            .deactivate_and_cleanup()
            .await
            .map_err(|e| e.to_string())?;

        // Act 7: `close_unused_android_tun_fd` accepts `None` and negative sentinel cleanly.
        close_unused_android_tun_fd(None);
        close_unused_android_tun_fd(Some(-1));
        hooks.discard_unused_android_tun_fd(None);
        hooks.discard_unused_android_tun_fd(Some(-1));

        // Assert
        let discarded = hooks.take_test_closed_unused_fds();
        assert_eq!(discarded, vec![101, 102, 103, 104, 105, 106, 107]);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unknown_route_op_does_not_swap_active_android_tun_and_discards_fd()
    -> Result<(), String> {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;

        use crate::tun_bridge::AndroidTunDevice;

        // Arrange
        let bridge = Arc::new(FakeBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let dns = Arc::new(MobileSplitDnsInterceptor::new(clock));
        let hooks = Arc::new(FfiPlatformHooks::new(
            MobilePlatformKind::Android,
            bridge,
            dns,
        ));
        let (_k1, a1) = UnixDatagram::pair().map_err(|e| e.to_string())?;
        a1.set_nonblocking(true).map_err(|e| e.to_string())?;
        let cidr = OverlayCidr::parse("100.64.0.0/16").map_err(|e| e.to_string())?;
        let ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 7)).map_err(|e| e.to_string())?;
        let cfg = TunConfig::with_default_mtu("tun0", ip, cidr).map_err(|e| e.to_string())?;
        let dev = Arc::new(
            AndroidTunDevice::from_owned_fd(cfg, OwnedFd::from(a1)).map_err(|e| e.to_string())?,
        );
        if let Ok(mut guard) = hooks.active_android_tun.lock() {
            *guard = Some(Arc::clone(&dev));
        }

        // Act: unknown op_id with Some(201) must NOT swap into active_android_tun; must discard.
        hooks
            .complete_route_change(77_777, true, Some(201), None)
            .map_err(|e| e.to_string())?;

        // Assert
        assert_eq!(hooks.take_test_closed_unused_fds(), vec![201]);
        hooks
            .deactivate_and_cleanup()
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
