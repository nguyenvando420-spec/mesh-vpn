//! Overlay-only route management abstraction and Linux anti-routing-loop policy specs (`REL-09`).

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use mesh_core::defaults::{
    LINUX_FWMARK, LINUX_ROUTING_TABLE, LINUX_RULE_PRIORITY_MAIN_SUPPRESS,
    LINUX_RULE_PRIORITY_OVERLAY,
};
use mesh_core::{AppError, AppResult, ErrorKind, OverlayCidr};

use crate::endpoint_filter::{
    InterfaceSubnetSnapshot, OverlaySubnetConflict, detect_overlay_subnet_conflict,
};

/// Validated overlay CIDR route restricted strictly within the configured mesh overlay network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// Destination CIDR installed in OS routing table (guaranteed inside overlay CIDR).
    pub destination_cidr: OverlayCidr,
    /// Target TUN adapter / interface name.
    pub interface_name: String,
    /// Optional routing table identifier (e.g. Linux policy table `51820`).
    pub table: Option<u32>,
}

impl RouteSpec {
    /// Validates that `destination_cidr` is completely contained inside `allowed_overlay_cidr`.
    ///
    /// Prevents installing default routes (`0.0.0.0/0`) or non-overlay LAN/public routes.
    pub fn new(
        destination_cidr: OverlayCidr,
        allowed_overlay_cidr: OverlayCidr,
        interface_name: impl Into<String>,
        table: Option<u32>,
    ) -> AppResult<Self> {
        ensure_cidr_contained(destination_cidr, allowed_overlay_cidr)?;
        let iface = interface_name.into();
        if iface.trim().is_empty() || iface.len() > 64 {
            return Err(AppError::invalid_argument(
                "route interface name must be 1..=64 characters",
            ));
        }
        Ok(Self {
            destination_cidr,
            interface_name: iface,
            table,
        })
    }

    /// Validates an arbitrary raw CIDR string against `allowed_overlay_cidr` (rejecting `0.0.0.0/0`).
    pub fn parse_within_overlay(
        raw_cidr: &str,
        allowed_overlay_cidr: OverlayCidr,
        interface_name: impl Into<String>,
        table: Option<u32>,
    ) -> AppResult<Self> {
        let parsed = OverlayCidr::from_str(raw_cidr)?;
        Self::new(parsed, allowed_overlay_cidr, interface_name, table)
    }
}

/// Checks that `candidate` is equal to or a strict subnet of `parent`.
pub fn ensure_cidr_contained(candidate: OverlayCidr, parent: OverlayCidr) -> AppResult<()> {
    if candidate.prefix_len() < parent.prefix_len() {
        return Err(AppError::invalid_argument(format!(
            "route CIDR {candidate} is broader than allowed overlay CIDR {parent}"
        )));
    }
    let parent_mask = ipv4_mask(parent.prefix_len());
    let cand_net = u32::from(candidate.network());
    let parent_net = u32::from(parent.network());
    if (cand_net & parent_mask) != parent_net {
        return Err(AppError::invalid_argument(format!(
            "route CIDR {candidate} is outside allowed overlay CIDR {parent}"
        )));
    }
    Ok(())
}

/// Rejects raw arbitrary destination strings (`0.0.0.0/0`, LAN/WAN CIDRs) outside overlay scope.
pub fn reject_non_overlay_cidr(raw_cidr: &str, allowed_overlay_cidr: OverlayCidr) -> AppResult<()> {
    let trimmed = raw_cidr.trim();
    let Some((ip_part, prefix_part)) = trimmed.split_once('/') else {
        return Err(AppError::invalid_argument(
            "route destination must be CIDR notation",
        ));
    };
    let addr = Ipv4Addr::from_str(ip_part)
        .map_err(|_| AppError::invalid_argument("invalid IPv4 address in route CIDR"))?;
    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| AppError::invalid_argument("invalid prefix length in route CIDR"))?;
    if addr == Ipv4Addr::UNSPECIFIED && prefix == 0 {
        return Err(AppError::invalid_argument(
            "default route 0.0.0.0/0 is strictly forbidden in overlay-only mode",
        ));
    }
    let parsed = OverlayCidr::from_str(trimmed)?;
    ensure_cidr_contained(parsed, allowed_overlay_cidr)
}

/// Checks `physical_subnets` for an IPv4 subnet conflict against `overlay_cidr` before route
/// installation (`US-037`).
pub fn ensure_no_overlay_subnet_conflict(
    overlay_cidr: OverlayCidr,
    physical_subnets: &[InterfaceSubnetSnapshot],
) -> Result<(), OverlaySubnetConflict> {
    match detect_overlay_subnet_conflict(physical_subnets, overlay_cidr) {
        Some(conflict) => Err(conflict),
        None => Ok(()),
    }
}

/// Refuses applying `spec` via `manager` when any active physical NIC overlaps
/// `spec.destination_cidr` (`US-037`), returning [`ErrorKind::Conflict`].
pub fn apply_overlay_route_checked(
    manager: &dyn RouteManager,
    spec: &RouteSpec,
    physical_subnets: &[InterfaceSubnetSnapshot],
) -> AppResult<()> {
    if let Err(conflict) =
        ensure_no_overlay_subnet_conflict(spec.destination_cidr, physical_subnets)
    {
        return Err(AppError::new(
            ErrorKind::Conflict,
            conflict.format_warning(),
        ));
    }
    manager.apply_overlay_route(spec)
}

const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

/// Linux policy-routing rule configuration defeating underlay/overlay routing loops (`REL-09`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPolicyRoutingSpec {
    /// Dedicated routing table number (`51820`).
    pub table: u32,
    /// Socket mark excluded from overlay lookup (`0x5d56`).
    pub fwmark: u32,
    /// Rule priority for `not fwmark <fwmark> lookup <table>` (`51820`).
    pub overlay_rule_priority: u32,
    /// Rule priority for `lookup main suppress_prefixlength 0` (`51810`).
    pub main_suppress_priority: u32,
}

impl Default for LinuxPolicyRoutingSpec {
    fn default() -> Self {
        Self {
            table: LINUX_ROUTING_TABLE,
            fwmark: LINUX_FWMARK,
            overlay_rule_priority: LINUX_RULE_PRIORITY_OVERLAY,
            main_suppress_priority: LINUX_RULE_PRIORITY_MAIN_SUPPRESS,
        }
    }
}

/// Abstraction over OS routing-table installation & cleanup so tests run unprivileged.
pub trait RouteManager: Send + Sync + std::fmt::Debug {
    /// Installs an overlay-restricted route in the OS routing table.
    fn apply_overlay_route(&self, spec: &RouteSpec) -> AppResult<()>;
    /// Removes a previously installed overlay route idempotently.
    fn remove_overlay_route(&self, spec: &RouteSpec) -> AppResult<()>;
    /// Installs Linux policy rules + routing table (no-op on macOS/Windows).
    fn apply_linux_policy(&self, policy: &LinuxPolicyRoutingSpec) -> AppResult<()>;
    /// Removes Linux policy rules + routing table idempotently (no-op on macOS/Windows).
    fn remove_linux_policy(&self, policy: &LinuxPolicyRoutingSpec) -> AppResult<()>;
}

/// Thread-safe in-memory fake route manager for unit tests.
#[derive(Debug, Clone, Default)]
pub struct FakeRouteManager {
    state: Arc<Mutex<FakeRouteState>>,
}

#[derive(Debug, Default)]
struct FakeRouteState {
    routes: Vec<RouteSpec>,
    active_linux_policy: Option<LinuxPolicyRoutingSpec>,
}

impl FakeRouteManager {
    /// Creates an empty fake route manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns currently installed routes in insertion order.
    pub fn active_routes(&self) -> AppResult<Vec<RouteSpec>> {
        let guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("fake route mutex poisoned"))?;
        Ok(guard.routes.clone())
    }

    /// Returns the currently applied Linux policy config if present.
    pub fn active_linux_policy(&self) -> AppResult<Option<LinuxPolicyRoutingSpec>> {
        let guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("fake route mutex poisoned"))?;
        Ok(guard.active_linux_policy.clone())
    }
}

impl RouteManager for FakeRouteManager {
    fn apply_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("fake route mutex poisoned"))?;
        if !guard.routes.contains(spec) {
            guard.routes.push(spec.clone());
        }
        Ok(())
    }

    fn remove_overlay_route(&self, spec: &RouteSpec) -> AppResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("fake route mutex poisoned"))?;
        guard.routes.retain(|item| item != spec);
        Ok(())
    }

    fn apply_linux_policy(&self, policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("fake route mutex poisoned"))?;
        guard.active_linux_policy = Some(policy.clone());
        Ok(())
    }

    fn remove_linux_policy(&self, _policy: &LinuxPolicyRoutingSpec) -> AppResult<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| AppError::internal("fake route mutex poisoned"))?;
        guard.active_linux_policy = None;
        Ok(())
    }
}

/// Applies OS-specific anti-routing-loop underlay binding (`SO_MARK` on Linux, `IP_BOUND_IF` on macOS,
/// `IP_UNICAST_IF` on Windows) to a Tokio `UdpSocket` so `mesh-datapath` never depends directly on `mesh-sys`.
pub fn bind_underlay_udp_socket(
    socket: &tokio::net::UdpSocket,
    is_ipv6: bool,
    physical_if_index: Option<u32>,
    fwmark: Option<u32>,
) -> AppResult<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let _unused = (is_ipv6, physical_if_index);
        mesh_sys::socket_linux::set_socket_fwmark(
            socket.as_raw_fd(),
            fwmark.unwrap_or(LINUX_FWMARK),
        )
        .map_err(AppError::from)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd as _;
        let _unused = fwmark;
        let if_index = physical_if_index.ok_or_else(|| {
            AppError::invalid_argument(
                "macOS underlay socket binding requires physical interface index",
            )
        })?;
        mesh_sys::socket_macos::bind_socket_to_interface_index(
            socket.as_raw_fd(),
            is_ipv6,
            if_index,
        )
        .map_err(AppError::from)
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket as _;
        let _unused = fwmark;
        let if_index = physical_if_index.ok_or_else(|| {
            AppError::invalid_argument(
                "Windows underlay socket binding requires physical interface index",
            )
        })?;
        mesh_sys::socket_windows::bind_socket_to_interface_index(
            socket.as_raw_socket(),
            is_ipv6,
            if_index,
        )
        .map_err(AppError::from)
    }
    #[cfg(target_os = "android")]
    {
        // Android anti-routing-loop delegates socket protection to `VpnService.protect(fd)`
        // via `SocketProtector` rather than `SO_MARK`.
        let _unused = (socket, is_ipv6, physical_if_index, fwmark);
        Ok(())
    }
    #[cfg(target_os = "ios")]
    {
        use std::os::fd::AsRawFd as _;
        let _unused = fwmark;
        if let Some(if_index) = physical_if_index {
            mesh_sys::socket_ios::bind_socket_to_interface_index(
                socket.as_raw_fd(),
                is_ipv6,
                if_index,
            )
            .map_err(AppError::from)
        } else {
            Ok(())
        }
    }
}

/// Applies OS-specific anti-routing-loop underlay binding directly to a `socket2::Socket` prior
/// to wrapping inside `tokio::net::UdpSocket` (`BLK-03`).
pub fn bind_underlay_socket2(
    socket: &socket2::Socket,
    is_ipv6: bool,
    physical_if_index: Option<u32>,
    fwmark: Option<u32>,
) -> AppResult<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let _unused = (is_ipv6, physical_if_index);
        mesh_sys::socket_linux::set_socket_fwmark(
            socket.as_raw_fd(),
            fwmark.unwrap_or(LINUX_FWMARK),
        )
        .map_err(AppError::from)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd as _;
        let _unused = fwmark;
        let if_index = physical_if_index.ok_or_else(|| {
            AppError::invalid_argument(
                "macOS underlay socket binding requires physical interface index",
            )
        })?;
        mesh_sys::socket_macos::bind_socket_to_interface_index(
            socket.as_raw_fd(),
            is_ipv6,
            if_index,
        )
        .map_err(AppError::from)
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket as _;
        let _unused = fwmark;
        let if_index = physical_if_index.ok_or_else(|| {
            AppError::invalid_argument(
                "Windows underlay socket binding requires physical interface index",
            )
        })?;
        mesh_sys::socket_windows::bind_socket_to_interface_index(
            socket.as_raw_socket(),
            is_ipv6,
            if_index,
        )
        .map_err(AppError::from)
    }
    #[cfg(target_os = "android")]
    {
        let _unused = (socket, is_ipv6, physical_if_index, fwmark);
        Ok(())
    }
    #[cfg(target_os = "ios")]
    {
        use std::os::fd::AsRawFd as _;
        let _unused = fwmark;
        if let Some(if_index) = physical_if_index {
            mesh_sys::socket_ios::bind_socket_to_interface_index(
                socket.as_raw_fd(),
                is_ipv6,
                if_index,
            )
            .map_err(AppError::from)
        } else {
            Ok(())
        }
    }
}

/// Disables forced IPv4 Don't Fragment (`DF=0`) on a Tokio UDP socket via `mesh-sys` (`BLK-03`).
pub fn disable_udp_dont_fragment(socket: &tokio::net::UdpSocket) -> AppResult<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        mesh_sys::socket_linux::disable_ipv4_dont_fragment(socket.as_raw_fd())
            .map_err(AppError::from)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd as _;
        mesh_sys::socket_macos::disable_ipv4_dont_fragment(socket.as_raw_fd())
            .map_err(AppError::from)
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket as _;
        mesh_sys::socket_windows::disable_ipv4_dont_fragment(socket.as_raw_socket())
            .map_err(AppError::from)
    }
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd as _;
        mesh_sys::socket_android::disable_ipv4_dont_fragment(socket.as_raw_fd())
            .map_err(AppError::from)
    }
    #[cfg(target_os = "ios")]
    {
        use std::os::fd::AsRawFd as _;
        mesh_sys::socket_ios::disable_ipv4_dont_fragment(socket.as_raw_fd()).map_err(AppError::from)
    }
}

#[cfg(test)]
mod tests {
    use mesh_core::OverlayCidr;

    use super::{
        FakeRouteManager, LinuxPolicyRoutingSpec, RouteManager, RouteSpec,
        apply_overlay_route_checked, reject_non_overlay_cidr,
    };
    use crate::endpoint_filter::InterfaceSubnetSnapshot;

    #[test]
    fn test_route_rejects_default_and_external_cidrs_and_tracks_fake_routes() {
        // Arrange
        let overlay = match "100.115.0.0/16".parse::<OverlayCidr>() {
            Ok(c) => c,
            Err(err) => {
                assert_eq!(err.to_string(), "overlay parse failed");
                return;
            }
        };
        let mgr = FakeRouteManager::new();
        let policy = LinuxPolicyRoutingSpec::default();

        // Act / Assert rejections
        assert!(reject_non_overlay_cidr("0.0.0.0/0", overlay).is_err());
        assert!(reject_non_overlay_cidr("192.168.0.0/16", overlay).is_err());
        assert!(reject_non_overlay_cidr("100.114.0.0/15", overlay).is_err());
        assert!(reject_non_overlay_cidr("100.115.0.0/16", overlay).is_ok());

        let spec = match RouteSpec::parse_within_overlay("100.115.0.0/16", overlay, "utun7", None) {
            Ok(s) => s,
            Err(err) => {
                assert_eq!(err.to_string(), "route spec failed");
                return;
            }
        };

        assert!(mgr.apply_linux_policy(&policy).is_ok());
        assert!(mgr.apply_overlay_route(&spec).is_ok());
        assert_eq!(mgr.active_routes().unwrap_or_default().len(), 1);
        assert!(mgr.active_linux_policy().unwrap_or_default().is_some());

        assert!(mgr.remove_overlay_route(&spec).is_ok());
        assert!(mgr.remove_linux_policy(&policy).is_ok());
        assert!(mgr.active_routes().unwrap_or_default().is_empty());
        assert!(mgr.active_linux_policy().unwrap_or_default().is_none());
    }

    #[test]
    fn test_route_refuses_overlay_install_on_physical_subnet_conflict() {
        // Traces: US-037
        // Arrange
        let Ok(overlay) = "100.115.0.0/16".parse::<OverlayCidr>() else {
            return;
        };
        let Ok(spec) = RouteSpec::new(overlay, overlay, "mesh0", None) else {
            return;
        };
        let mgr = FakeRouteManager::new();
        let conflicting = vec![InterfaceSubnetSnapshot {
            if_index: 3,
            interface_name: "eth0".to_owned(),
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 115, 2, 10)),
            prefix_len: 24,
            is_up: true,
            is_virtual: false,
            has_gateway: true,
        }];
        let clean = vec![InterfaceSubnetSnapshot {
            if_index: 3,
            interface_name: "eth0".to_owned(),
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 10, 20)),
            prefix_len: 24,
            is_up: true,
            is_virtual: false,
            has_gateway: true,
        }];

        // Act & Assert: conflict refused and no route installed
        let err = apply_overlay_route_checked(&mgr, &spec, &conflicting);
        assert!(err.is_err());
        assert!(mgr.active_routes().unwrap_or_default().is_empty());

        // Switching to clean network installs route normally
        assert!(apply_overlay_route_checked(&mgr, &spec, &clean).is_ok());
        assert_eq!(mgr.active_routes().unwrap_or_default().len(), 1);
    }
}
