//! OS-neutral networking traits, in-memory fakes, fail-closed keystore, resource ledger,
//! endpoint filtering, hosts editor, and platform-gated OS adapters.

pub mod endpoint_filter;
#[cfg(target_os = "linux")]
pub mod firewall_linux;
#[cfg(target_os = "macos")]
pub mod firewall_macos;
#[cfg(target_os = "windows")]
pub mod firewall_windows;
pub mod hosts;
#[cfg(target_os = "linux")]
pub mod hosts_linux;
#[cfg(target_os = "macos")]
pub mod hosts_macos;
#[cfg(target_os = "windows")]
pub mod hosts_windows;
pub mod ipc;
#[cfg(target_os = "linux")]
pub mod ipc_linux;
#[cfg(target_os = "macos")]
pub mod ipc_macos;
#[cfg(target_os = "windows")]
pub mod ipc_windows;
pub mod keystore;
pub mod ledger;
pub mod netmon;
#[cfg(target_os = "linux")]
pub mod netmon_linux;
#[cfg(target_os = "macos")]
pub mod netmon_macos;
#[cfg(target_os = "windows")]
pub mod netmon_windows;
pub mod route;
#[cfg(target_os = "linux")]
pub mod route_linux;
#[cfg(target_os = "macos")]
pub mod route_macos;
#[cfg(target_os = "windows")]
pub mod route_windows;
pub mod sysexec;
pub mod tun;
#[cfg(target_os = "linux")]
pub mod tun_linux;
#[cfg(target_os = "macos")]
pub mod tun_macos;
#[cfg(target_os = "windows")]
pub mod tun_windows;

pub use endpoint_filter::{
    CandidateFilterContext, DiscoveredInterfaceEndpoint, InterfaceSubnetSnapshot,
    OverlaySubnetConflict, detect_overlay_subnet_conflict, filter_candidate_endpoints,
    ipv4_subnets_overlap, is_usable_dhcp_ip, is_valid_candidate_endpoint, is_valid_candidate_ip,
    is_virtual_interface_name,
};
pub use hosts::{
    FakeHostsEditor, FileHostsEditor, HostsEditor, HostsEntry, remove_hosts_block,
    render_hosts_block, render_hosts_with_block,
};
pub use ipc::{
    CallerPrivilege, DefaultPrivilegeIpc, FakeIpcPeerVerifier, FakePrivilegeIpc, IpcChannelKind,
    IpcPeerVerifier, PeerIdentity, PrivilegeIpc, UnixSocketAuthPolicy, send_ipc_json_request,
    serve_ipc_http_connection,
};
pub use keystore::{KeysFileStore, StoredNodeIdentity};
pub use ledger::{
    FakeLedgerCleanupOps, LedgerCleanupOps, LedgerIpRuleEntry, LedgerRouteEntry, ResourceLedger,
    ResourceLedgerData,
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
pub use sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, FakeCommandExecutor,
    RecordedCommand, StdCommandExecutor,
};
pub use tun::{BoxFuture, FakeTunDevice, TunConfig, TunDevice};
