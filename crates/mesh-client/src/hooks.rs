//! Platform, DNS, and persistent state trait boundaries shared across Desktop (`meshd`) and
//! Mobile (`mesh-mobile-ffi`) runtimes (`ADR-012`, `US-099`).

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use mesh_core::{AppError, AppResult, ErrorKind, NodeId, NodeName, OverlayCidr, OverlayIp};
use mesh_crypto::{DiscoKeypair, NodeKeypair};
use mesh_net::endpoint_filter::{
    DiscoveredInterfaceEndpoint, InterfaceSubnetSnapshot, detect_overlay_subnet_conflict,
};
use mesh_net::keystore::{KeysFileStore, StoredNodeIdentity};
use mesh_net::nat64::{Nat64Prefix, NoopSocketProtector, SocketProtector};
use mesh_net::netmon::{
    FakeNetMonitor, FakePhysicalNetworkProbe, NetMonitor, PhysicalInterface, PhysicalNetworkProbe,
};
use mesh_net::tun::{BoxFuture, FakeTunDevice, TunConfig, TunDevice};
use mesh_proto::netmap::NetmapSnapshot;

use crate::config::{BootstrapConfig, BootstrapStore};
use crate::netmap_cache::{NetmapCacheFile, NetmapCacheStore};

/// Boxed `Send` future alias used across async client hook traits (`mobile-system-architecture.md` §3.2).
pub type ClientFuture<'a, T> = BoxFuture<'a, T>;

/// Outcome produced when activating the platform TUN interface and split-tunnel/overlay routes.
#[derive(Debug, Clone)]
pub struct TunActivationOutcome {
    /// Active TUN packet device consumed by [`mesh_datapath::DatapathEngine`].
    pub tun: Arc<dyn TunDevice>,
    /// Whether the overlay subnet route is installed on the host/VPN builder.
    pub route_installed: bool,
    /// Warning emitted when a physical NIC / CGNAT subnet overlaps the overlay CIDR (`US-037`).
    pub conflict_warning: Option<String>,
    /// Warning emitted when mobile OS VPN Lockdown ("Block connections without VPN") is active.
    pub lockdown_warning: Option<String>,
    /// Warning emitted when mobile Strict Private DNS prevents opportunistic `.mesh.internal` override.
    pub private_dns_warning: Option<String>,
}

/// Platform network/OS abstraction boundary isolating `mesh-client` from Desktop & Mobile specifics.
pub trait ClientPlatformHooks: Send + Sync + std::fmt::Debug {
    /// Returns the OS physical interface and subnet probe used for roaming and CGNAT checks.
    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe>;

    /// Returns the OS network & sleep/wake event monitor.
    fn net_monitor(&self) -> Arc<dyn NetMonitor>;

    /// Returns the platform DNS upstream / hosts synchronization hook.
    fn dns_hook(&self) -> Arc<dyn DnsUpstreamHook>;

    /// Returns `Some(...)` on Android (`VpnService.protect(fd)`), or `None` when not needed.
    fn socket_protector(&self) -> Option<Arc<dyn SocketProtector>>;

    /// Activates the TUN device and installs overlay / split-tunnel routes (`OQ-MOB-04`).
    fn activate_tun_and_routes<'a>(
        &'a self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        dns_server_ip: Option<OverlayIp>,
        domain_suffix: Option<&'a str>,
        now_ms: u64,
    ) -> ClientFuture<'a, AppResult<TunActivationOutcome>>;

    /// Reconciles overlay routes, DNS settings, and OS firewall profile on Netmap/roam updates.
    fn reconcile_on_roam_or_netmap<'a>(
        &'a self,
        tun_ifname: &'a str,
        overlay_cidr: OverlayCidr,
        dns_server_ip: Option<OverlayIp>,
        domain_suffix: Option<&'a str>,
    ) -> ClientFuture<'a, AppResult<Option<String>>>;

    /// Tears down active routes, TUN, and DNS entries cleanly within the `<= 5 s` shutdown budget.
    fn deactivate_and_cleanup<'a>(&'a self) -> ClientFuture<'a, AppResult<()>>;

    /// Enumerates physical interface UDP endpoint candidates bound to `udp_port`.
    fn discover_local_interface_endpoints(&self, udp_port: u16)
    -> Vec<DiscoveredInterfaceEndpoint>;

    /// Captures a scrubbed route & underlay diagnostic snapshot (in-memory JSON on Mobile, 0 `sysexec`).
    fn collect_route_diagnostics(&self) -> String;

    /// Reports remaining process memory headroom in bytes (`Some(...)` on iOS Jetsam targets).
    fn available_memory_bytes(&self) -> Option<u64> {
        None
    }

    /// Returns the active RFC 6052 NAT64 synthesis prefix observed on the physical underlay.
    fn nat64_prefix(&self) -> Option<Nat64Prefix> {
        None
    }

    /// Returns current underlay DNS resolver IPs to exclude from `overlay_dns_ip` collisions.
    fn underlay_dns_servers(&self) -> Vec<IpAddr> {
        Vec::new()
    }

    /// Returns `true` when Android Strict Private DNS is active on the current underlay network.
    fn is_private_dns_strict(&self) -> bool {
        false
    }

    /// Returns an optional comma-separated inbound overlay packet filter rule specification.
    fn inbound_filter_spec(&self) -> Option<String> {
        None
    }

    /// Reconciles desktop OS firewall state on interface roam (no-op on Mobile).
    fn reconcile_firewall_on_roam(
        &self,
        _tun_ifname: &str,
        _overlay_cidr: OverlayCidr,
    ) -> AppResult<()> {
        Ok(())
    }

    /// Runs fail-closed startup platform security validation (e.g. macOS root-owned paths).
    fn enforce_startup_security(&self) -> AppResult<()> {
        Ok(())
    }
}

/// Platform synchronization boundary for `.mesh.internal` name resolution (`hosts` vs Split-DNS).
pub trait DnsUpstreamHook: Send + Sync + std::fmt::Debug {
    /// Synchronizes peer overlay hostnames and FQDNs from `snapshot`.
    fn sync_mesh_dns<'a>(
        &'a self,
        snapshot: &'a NetmapSnapshot,
        self_overlay_ip: Option<OverlayIp>,
        self_name: Option<&'a NodeName>,
    ) -> ClientFuture<'a, AppResult<()>>;

    /// Clears previously installed mesh DNS entries when shutting down or leaving the network.
    fn clear_mesh_dns<'a>(&'a self) -> ClientFuture<'a, AppResult<()>>;
}

/// OS-neutral identity, bootstrap, and Netmap cache storage boundary (`SEC-01`, `HR-MOB-G2-03`).
pub trait ClientStateStore: Send + Sync + std::fmt::Debug {
    /// Loads the existing node identity or generates and persists a new one if absent.
    fn load_or_create_identity(&self, now_ms: u64) -> AppResult<StoredNodeIdentity>;

    /// Loads an existing node identity without generating new keys; returns `Ok(None)` only if absent.
    fn load_existing_identity(&self) -> AppResult<Option<StoredNodeIdentity>>;

    /// Atomically replaces the persisted identity after explicit key rotation.
    fn save_rotated_identity(&self, identity: &StoredNodeIdentity) -> AppResult<()>;

    /// Records the control-assigned [`NodeId`] on the persisted identity.
    fn set_identity_node_id(&self, node_id: NodeId) -> AppResult<StoredNodeIdentity>;

    /// Loads validated bootstrap config, or [`BootstrapConfig::default`] when absent.
    fn load_bootstrap(&self) -> AppResult<BootstrapConfig>;

    /// Validates and atomically persists `bootstrap.toml` material.
    fn save_bootstrap(&self, config: &BootstrapConfig) -> AppResult<()>;

    /// Loads and SHA-256 verifies the cached Netmap snapshot (`Ok(None)` if absent).
    fn load_netmap_cache(&self) -> AppResult<Option<NetmapCacheFile>>;

    /// Atomically persists a signed Netmap cache entry.
    fn save_netmap_cache(&self, cache: &NetmapCacheFile) -> AppResult<()>;

    /// Removes any persisted Netmap cache entry.
    fn clear_netmap_cache(&self) -> AppResult<()>;

    /// Optional filesystem state directory used for desktop diagnostics log discovery.
    fn state_dir(&self) -> Option<&Path> {
        None
    }
}

/// Standard file-backed [`ClientStateStore`] wrapping `KeysFileStore`, `BootstrapStore`, and `NetmapCacheStore`.
#[derive(Debug, Clone)]
pub struct FileClientStateStore {
    state_dir: PathBuf,
    keys: KeysFileStore,
    bootstrap: BootstrapStore,
    netmap_cache: NetmapCacheStore,
}

impl FileClientStateStore {
    /// Builds a file-backed store rooted inside `state_dir`.
    #[must_use]
    pub fn from_dir(state_dir: PathBuf) -> Self {
        let keys = KeysFileStore::new(state_dir.join("keys.json"));
        let bootstrap = BootstrapStore::new(state_dir.join("bootstrap.toml"));
        let netmap_cache = NetmapCacheStore::new(state_dir.join("netmap-cache.json"));
        Self {
            state_dir,
            keys,
            bootstrap,
            netmap_cache,
        }
    }

    /// Builds a store from explicit `keys.json`, `bootstrap.toml`, and `netmap-cache.json` paths.
    #[must_use]
    pub fn new(
        state_dir: PathBuf,
        keys_path: PathBuf,
        bootstrap_path: PathBuf,
        netmap_cache_path: PathBuf,
    ) -> Self {
        Self {
            state_dir,
            keys: KeysFileStore::new(keys_path),
            bootstrap: BootstrapStore::new(bootstrap_path),
            netmap_cache: NetmapCacheStore::new(netmap_cache_path),
        }
    }
}

impl ClientStateStore for FileClientStateStore {
    fn load_or_create_identity(&self, now_ms: u64) -> AppResult<StoredNodeIdentity> {
        self.keys.load_or_create(now_ms)
    }

    fn load_existing_identity(&self) -> AppResult<Option<StoredNodeIdentity>> {
        match self.keys.load_existing() {
            Ok(id) => Ok(Some(id)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn save_rotated_identity(&self, identity: &StoredNodeIdentity) -> AppResult<()> {
        self.keys.save_rotated(identity)
    }

    fn set_identity_node_id(&self, node_id: NodeId) -> AppResult<StoredNodeIdentity> {
        self.keys.set_node_id(node_id)
    }

    fn load_bootstrap(&self) -> AppResult<BootstrapConfig> {
        self.bootstrap.load_or_default()
    }

    fn save_bootstrap(&self, config: &BootstrapConfig) -> AppResult<()> {
        self.bootstrap.save_atomic(config)
    }

    fn load_netmap_cache(&self) -> AppResult<Option<NetmapCacheFile>> {
        self.netmap_cache.load_verified()
    }

    fn save_netmap_cache(&self, cache: &NetmapCacheFile) -> AppResult<()> {
        self.netmap_cache.write_verified(cache)
    }

    fn clear_netmap_cache(&self) -> AppResult<()> {
        self.netmap_cache.clear()
    }

    fn state_dir(&self) -> Option<&Path> {
        Some(&self.state_dir)
    }
}

/// No-op [`DnsUpstreamHook`] used when platform DNS integration is managed externally.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDnsUpstreamHook;

impl DnsUpstreamHook for NoopDnsUpstreamHook {
    fn sync_mesh_dns<'a>(
        &'a self,
        _snapshot: &'a NetmapSnapshot,
        _self_overlay_ip: Option<OverlayIp>,
        _self_name: Option<&'a NodeName>,
    ) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn clear_mesh_dns<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// In-memory [`DnsUpstreamHook`] recording sync/clear calls for unit & integration tests.
#[derive(Debug, Default)]
pub struct InMemoryDnsUpstreamHook {
    synced_snapshots: StdMutex<Vec<NetmapSnapshot>>,
    clear_calls: StdMutex<usize>,
}

impl InMemoryDnsUpstreamHook {
    /// Creates an empty recording DNS hook.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns all synced [`NetmapSnapshot`] revisions captured in order.
    #[must_use]
    pub fn synced_snapshots(&self) -> Vec<NetmapSnapshot> {
        self.synced_snapshots
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns how many times `clear_mesh_dns` was called.
    #[must_use]
    pub fn clear_count(&self) -> usize {
        self.clear_calls.lock().map(|g| *g).unwrap_or(0)
    }
}

impl DnsUpstreamHook for InMemoryDnsUpstreamHook {
    fn sync_mesh_dns<'a>(
        &'a self,
        snapshot: &'a NetmapSnapshot,
        _self_overlay_ip: Option<OverlayIp>,
        _self_name: Option<&'a NodeName>,
    ) -> ClientFuture<'a, AppResult<()>> {
        if let Ok(mut g) = self.synced_snapshots.lock() {
            g.push(snapshot.clone());
        }
        Box::pin(async { Ok(()) })
    }

    fn clear_mesh_dns<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        if let Ok(mut g) = self.clear_calls.lock() {
            *g = g.saturating_add(1);
        }
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
struct InMemoryHooksInner {
    active_tun: Option<Arc<FakeTunDevice>>,
    route_installed: bool,
    discovered_endpoints: Vec<DiscoveredInterfaceEndpoint>,
    route_diagnostics: String,
    available_memory_bytes: Option<u64>,
    nat64_prefix: Option<Nat64Prefix>,
    underlay_dns_servers: Vec<IpAddr>,
    private_dns_strict: bool,
    lockdown_warning: Option<String>,
    inbound_filter_spec: Option<String>,
    deactivate_calls: usize,
}

/// In-memory [`ClientPlatformHooks`] implementation backed by `FakeTunDevice`, `FakeNetMonitor`,
/// and `FakePhysicalNetworkProbe` (`cargo test` green with 0 OS privileges).
pub struct InMemoryClientPlatformHooks {
    probe: Arc<FakePhysicalNetworkProbe>,
    monitor: Arc<FakeNetMonitor>,
    dns: Arc<InMemoryDnsUpstreamHook>,
    protector: StdMutex<Option<Arc<dyn SocketProtector>>>,
    inner: StdMutex<InMemoryHooksInner>,
}

impl std::fmt::Debug for InMemoryClientPlatformHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryClientPlatformHooks")
            .field("probe", &self.probe)
            .field("dns", &self.dns)
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryClientPlatformHooks {
    fn default() -> Self {
        let primary = PhysicalInterface {
            if_index: 1,
            name: "eth0".to_owned(),
        };
        let subnets = vec![InterfaceSubnetSnapshot {
            if_index: 1,
            interface_name: "eth0".to_owned(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            prefix_len: 24,
            is_up: true,
            is_virtual: false,
            has_gateway: true,
        }];
        Self {
            probe: Arc::new(FakePhysicalNetworkProbe::with_snapshot(primary, subnets)),
            monitor: Arc::new(FakeNetMonitor::new()),
            dns: Arc::new(InMemoryDnsUpstreamHook::new()),
            protector: StdMutex::new(Some(Arc::new(NoopSocketProtector))),
            inner: StdMutex::new(InMemoryHooksInner {
                active_tun: None,
                route_installed: false,
                discovered_endpoints: Vec::new(),
                route_diagnostics: "fake-in-memory-route-table\n".to_owned(),
                available_memory_bytes: None,
                nat64_prefix: None,
                underlay_dns_servers: Vec::new(),
                private_dns_strict: false,
                lockdown_warning: None,
                inbound_filter_spec: None,
                deactivate_calls: 0,
            }),
        }
    }
}

impl InMemoryClientPlatformHooks {
    /// Creates an in-memory platform hook harness with explicit `probe` and `monitor`.
    #[must_use]
    pub fn with_net(probe: Arc<FakePhysicalNetworkProbe>, monitor: Arc<FakeNetMonitor>) -> Self {
        Self {
            probe,
            monitor,
            ..Self::default()
        }
    }

    /// Configures the `SocketProtector` returned by [`ClientPlatformHooks::socket_protector`].
    pub fn set_socket_protector(&self, protector: Option<Arc<dyn SocketProtector>>) {
        if let Ok(mut g) = self.protector.lock() {
            *g = protector;
        }
    }

    /// Configures synthesized NAT64 prefix reported by [`ClientPlatformHooks::nat64_prefix`].
    pub fn set_nat64_prefix(&self, prefix: Option<Nat64Prefix>) {
        if let Ok(mut g) = self.inner.lock() {
            g.nat64_prefix = prefix;
        }
    }

    /// Configures underlay DNS servers returned by [`ClientPlatformHooks::underlay_dns_servers`].
    pub fn set_underlay_dns_servers(&self, servers: Vec<IpAddr>) {
        if let Ok(mut g) = self.inner.lock() {
            g.underlay_dns_servers = servers;
        }
    }

    /// Configures mock `available_memory_bytes` (for iOS Jetsam pressure simulation).
    pub fn set_available_memory_bytes(&self, bytes: Option<u64>) {
        if let Ok(mut g) = self.inner.lock() {
            g.available_memory_bytes = bytes;
        }
    }

    /// Configures Strict Private DNS warning state for tests.
    pub fn set_private_dns_strict(&self, strict: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.private_dns_strict = strict;
        }
    }

    /// Configures an optional inbound firewall filter spec string.
    pub fn set_inbound_filter_spec(&self, spec: Option<String>) {
        if let Ok(mut g) = self.inner.lock() {
            g.inbound_filter_spec = spec;
        }
    }

    /// Returns the most recently activated [`FakeTunDevice`].
    #[must_use]
    pub fn active_tun(&self) -> Option<Arc<FakeTunDevice>> {
        self.inner.lock().ok().and_then(|g| g.active_tun.clone())
    }

    /// Returns the fake network monitor for injecting synthetic roam/wake events.
    #[must_use]
    pub fn fake_monitor(&self) -> Arc<FakeNetMonitor> {
        Arc::clone(&self.monitor)
    }

    /// Returns the fake network probe for scripting subnet changes.
    #[must_use]
    pub fn fake_probe(&self) -> Arc<FakePhysicalNetworkProbe> {
        Arc::clone(&self.probe)
    }

    /// Returns the recording DNS hook.
    #[must_use]
    pub fn recording_dns(&self) -> Arc<InMemoryDnsUpstreamHook> {
        Arc::clone(&self.dns)
    }

    /// Returns how many times [`ClientPlatformHooks::deactivate_and_cleanup`] was invoked.
    #[must_use]
    pub fn deactivate_count(&self) -> usize {
        self.inner.lock().map(|g| g.deactivate_calls).unwrap_or(0)
    }

    /// Returns whether an overlay route is currently active in the harness.
    #[must_use]
    pub fn is_route_installed(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.route_installed)
            .unwrap_or(false)
    }
}

impl ClientPlatformHooks for InMemoryClientPlatformHooks {
    fn network_probe(&self) -> Arc<dyn PhysicalNetworkProbe> {
        self.probe.clone()
    }

    fn net_monitor(&self) -> Arc<dyn NetMonitor> {
        self.monitor.clone()
    }

    fn dns_hook(&self) -> Arc<dyn DnsUpstreamHook> {
        self.dns.clone()
    }

    fn socket_protector(&self) -> Option<Arc<dyn SocketProtector>> {
        self.protector.lock().ok().and_then(|g| g.clone())
    }

    fn activate_tun_and_routes<'a>(
        &'a self,
        tun_cfg: TunConfig,
        overlay_cidr: OverlayCidr,
        _dns_server_ip: Option<OverlayIp>,
        _domain_suffix: Option<&'a str>,
        _now_ms: u64,
    ) -> ClientFuture<'a, AppResult<TunActivationOutcome>> {
        let subnets = self.probe.list_interface_subnets().unwrap_or_default();
        let conflict = detect_overlay_subnet_conflict(&subnets, overlay_cidr);
        let route_installed = conflict.is_none();
        let conflict_warning = conflict.map(|c| c.format_warning());
        let tun = Arc::new(FakeTunDevice::new(tun_cfg));
        let mut lockdown_warning = None;
        let mut private_dns_warning = None;
        if let Ok(mut g) = self.inner.lock() {
            g.active_tun = Some(Arc::clone(&tun));
            g.route_installed = route_installed;
            lockdown_warning = g.lockdown_warning.clone();
            if g.private_dns_strict {
                private_dns_warning = Some(
                    "Android Strict Private DNS is active; .mesh.internal queries may bypass split-DNS"
                        .to_owned(),
                );
            }
        }
        Box::pin(async move {
            Ok(TunActivationOutcome {
                tun,
                route_installed,
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
        _dns_server_ip: Option<OverlayIp>,
        _domain_suffix: Option<&'a str>,
    ) -> ClientFuture<'a, AppResult<Option<String>>> {
        let subnets = self.probe.list_interface_subnets().unwrap_or_default();
        let conflict = detect_overlay_subnet_conflict(&subnets, overlay_cidr);
        let route_installed = conflict.is_none();
        if let Ok(mut g) = self.inner.lock() {
            g.route_installed = route_installed;
        }
        let warning = conflict.map(|c| c.format_warning());
        Box::pin(async move { Ok(warning) })
    }

    fn deactivate_and_cleanup<'a>(&'a self) -> ClientFuture<'a, AppResult<()>> {
        if let Ok(mut g) = self.inner.lock() {
            g.active_tun = None;
            g.route_installed = false;
            g.deactivate_calls = g.deactivate_calls.saturating_add(1);
        }
        Box::pin(async { Ok(()) })
    }

    fn discover_local_interface_endpoints(
        &self,
        _udp_port: u16,
    ) -> Vec<DiscoveredInterfaceEndpoint> {
        self.inner
            .lock()
            .map(|g| g.discovered_endpoints.clone())
            .unwrap_or_default()
    }

    fn collect_route_diagnostics(&self) -> String {
        self.inner
            .lock()
            .map(|g| g.route_diagnostics.clone())
            .unwrap_or_default()
    }

    fn available_memory_bytes(&self) -> Option<u64> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.available_memory_bytes)
    }

    fn nat64_prefix(&self) -> Option<Nat64Prefix> {
        self.inner.lock().ok().and_then(|g| g.nat64_prefix)
    }

    fn underlay_dns_servers(&self) -> Vec<IpAddr> {
        self.inner
            .lock()
            .map(|g| g.underlay_dns_servers.clone())
            .unwrap_or_default()
    }

    fn is_private_dns_strict(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.private_dns_strict)
            .unwrap_or(false)
    }

    fn inbound_filter_spec(&self) -> Option<String> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.inbound_filter_spec.clone())
    }
}

#[derive(Debug, Default)]
struct InMemoryStateInner {
    identity: Option<StoredNodeIdentity>,
    bootstrap: BootstrapConfig,
    netmap_cache: Option<NetmapCacheFile>,
}

/// Pure RAM [`ClientStateStore`] implementation for zero-disk unit and integration testing.
#[derive(Debug, Default)]
pub struct InMemoryClientStateStore {
    inner: StdMutex<InMemoryStateInner>,
    state_dir: Option<PathBuf>,
}

impl InMemoryClientStateStore {
    /// Creates an empty in-memory state store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an in-memory store advertising an optional `state_dir` for diagnostic lookups.
    #[must_use]
    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        Self {
            inner: StdMutex::new(InMemoryStateInner::default()),
            state_dir: Some(state_dir),
        }
    }

    /// Returns whether an encrypted/in-memory Netmap cache currently exists.
    #[must_use]
    pub fn has_netmap_cache(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.netmap_cache.is_some())
            .unwrap_or(false)
    }
}

fn clone_stored_identity(id: &StoredNodeIdentity) -> StoredNodeIdentity {
    StoredNodeIdentity {
        node_id: id.node_id,
        node_keypair: id.node_keypair.clone_keypair(),
        disco_keypair: id.disco_keypair.clone_keypair(),
        created_at_ms: id.created_at_ms,
    }
}

impl ClientStateStore for InMemoryClientStateStore {
    fn load_or_create_identity(&self, now_ms: u64) -> AppResult<StoredNodeIdentity> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        if let Some(ref existing) = g.identity {
            return Ok(clone_stored_identity(existing));
        }
        let created = StoredNodeIdentity {
            node_id: None,
            node_keypair: NodeKeypair::generate(),
            disco_keypair: DiscoKeypair::generate(),
            created_at_ms: now_ms,
        };
        g.identity = Some(clone_stored_identity(&created));
        Ok(created)
    }

    fn load_existing_identity(&self) -> AppResult<Option<StoredNodeIdentity>> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        Ok(g.identity.as_ref().map(clone_stored_identity))
    }

    fn save_rotated_identity(&self, identity: &StoredNodeIdentity) -> AppResult<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        g.identity = Some(clone_stored_identity(identity));
        Ok(())
    }

    fn set_identity_node_id(&self, node_id: NodeId) -> AppResult<StoredNodeIdentity> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        let Some(ref mut id) = g.identity else {
            return Err(AppError::not_found("in-memory identity not initialized"));
        };
        id.node_id = Some(node_id);
        Ok(clone_stored_identity(id))
    }

    fn load_bootstrap(&self) -> AppResult<BootstrapConfig> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        Ok(g.bootstrap.clone())
    }

    fn save_bootstrap(&self, config: &BootstrapConfig) -> AppResult<()> {
        config.validate()?;
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        g.bootstrap = config.clone();
        Ok(())
    }

    fn load_netmap_cache(&self) -> AppResult<Option<NetmapCacheFile>> {
        let g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        if let Some(ref entry) = g.netmap_cache {
            entry.verify_integrity()?;
            return Ok(Some(entry.clone()));
        }
        Ok(None)
    }

    fn save_netmap_cache(&self, cache: &NetmapCacheFile) -> AppResult<()> {
        cache.verify_integrity()?;
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        g.netmap_cache = Some(cache.clone());
        Ok(())
    }

    fn clear_netmap_cache(&self) -> AppResult<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("InMemoryClientStateStore lock poisoned"))?;
        g.netmap_cache = None;
        Ok(())
    }

    fn state_dir(&self) -> Option<&Path> {
        self.state_dir.as_deref()
    }
}
