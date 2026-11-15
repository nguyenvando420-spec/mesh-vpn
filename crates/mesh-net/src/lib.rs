//! OS-neutral networking traits, in-memory fakes, fail-closed keystore, NAT64 synthesis,
//! endpoint filtering, and feature-gated desktop/mobile OS adapters.

pub mod endpoint_filter;
#[cfg(all(feature = "desktop-os", target_os = "linux"))]
pub mod firewall_linux;
#[cfg(all(feature = "desktop-os", target_os = "macos"))]
pub mod firewall_macos;
#[cfg(all(feature = "desktop-os", target_os = "windows"))]
pub mod firewall_windows;
#[cfg(feature = "desktop-os")]
pub mod hosts;
#[cfg(all(feature = "desktop-os", target_os = "linux"))]
pub mod hosts_linux;
#[cfg(all(feature = "desktop-os", target_os = "macos"))]
pub mod hosts_macos;
#[cfg(all(feature = "desktop-os", target_os = "windows"))]
pub mod hosts_windows;
#[cfg(feature = "desktop-ipc")]
pub mod ipc;
#[cfg(all(feature = "desktop-ipc", target_os = "linux"))]
pub mod ipc_linux;
#[cfg(all(feature = "desktop-ipc", target_os = "macos"))]
pub mod ipc_macos;
#[cfg(all(feature = "desktop-ipc", target_os = "windows"))]
pub mod ipc_windows;
pub mod keystore;
#[cfg(feature = "desktop-os")]
pub mod ledger;
pub mod nat64;
pub mod netmon;
#[cfg(target_os = "linux")]
pub mod netmon_linux;
#[cfg(target_os = "macos")]
pub mod netmon_macos;
#[cfg(target_os = "windows")]
pub mod netmon_windows;
pub mod route;
#[cfg(all(feature = "desktop-os", target_os = "linux"))]
pub mod route_linux;
#[cfg(all(feature = "desktop-os", target_os = "macos"))]
pub mod route_macos;
#[cfg(all(feature = "desktop-os", target_os = "windows"))]
pub mod route_windows;
#[cfg(feature = "desktop-os")]
pub mod sysexec;
pub mod tun;
#[cfg(all(feature = "desktop-os", target_os = "linux"))]
pub mod tun_linux;
#[cfg(all(feature = "desktop-os", target_os = "macos"))]
pub mod tun_macos;
#[cfg(all(feature = "desktop-os", target_os = "windows"))]
pub mod tun_windows;

pub use endpoint_filter::{
    CandidateFilterContext, DiscoveredInterfaceEndpoint, InterfaceSubnetSnapshot,
    OverlaySubnetConflict, detect_overlay_subnet_conflict, filter_candidate_endpoints,
    ipv4_subnets_overlap, is_usable_dhcp_ip, is_valid_candidate_endpoint, is_valid_candidate_ip,
    is_virtual_interface_name,
};
#[cfg(feature = "desktop-os")]
pub use hosts::{
    FakeHostsEditor, FileHostsEditor, HostsEditor, HostsEntry, remove_hosts_block,
    render_hosts_block, render_hosts_with_block,
};
#[cfg(feature = "desktop-ipc")]
pub use ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, FakeIpcPeerVerifier, FakePrivilegeIpc, IpcChannelKind,
    IpcPeerVerifier, PeerIdentity, PrivilegeIpc, UnixSocketAuthPolicy, send_ipc_json_request,
    serve_ipc_http_connection,
};
pub use keystore::{KeysFileStore, StoredNodeIdentity};
#[cfg(feature = "desktop-os")]
pub use ledger::{
    FakeLedgerCleanupOps, LedgerCleanupOps, LedgerIpRuleEntry, LedgerRouteEntry, ResourceLedger,
    ResourceLedgerData,
};
pub use nat64::{
    Nat64Prefix, Nat64PrefixLen, Nat64Synthesizer, NoopSocketProtector, SocketProtector,
};
pub use netmon::{
    DEFAULT_DHCP_INITIAL_DELAY_MS, DEFAULT_DHCP_MAX_DELAY_MS, DEFAULT_DHCP_WAIT_TIMEOUT_MS,
    Debouncer, DhcpWaitConfig, FakeNetMonitor, FakePhysicalNetworkProbe, NetEvent, NetMonitor,
    NetworkChangeEvent, OsPhysicalNetworkProbe, PhysicalInterface, PhysicalNetworkProbe,
    check_clock_jump, has_usable_ip_on_interface, list_os_interface_subnets,
    probe_ready_primary_interface, query_os_primary_physical_interface,
    wait_for_usable_ip_with_backoff,
};
pub use route::{
    FakeRouteManager, LinuxPolicyRoutingSpec, RouteManager, RouteSpec, apply_overlay_route_checked,
    bind_underlay_socket2, bind_underlay_udp_socket, disable_udp_dont_fragment,
    ensure_cidr_contained, ensure_no_overlay_subnet_conflict, reject_non_overlay_cidr,
};
#[cfg(feature = "desktop-os")]
pub use sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, FakeCommandExecutor,
    RecordedCommand, StdCommandExecutor,
};
pub use tun::{BoxFuture, FakeTunDevice, TunConfig, TunDevice};
