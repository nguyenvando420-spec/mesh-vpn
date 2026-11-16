//! Single shared non-blocking UDP socket with static receive buffers, MTU checks, and demuxing.

use std::io::ErrorKind as IoErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use mesh_core::defaults::{DEFAULT_TUN_MTU, MAX_FRAME_SIZE, MAX_TUN_MTU, MIN_TUN_MTU};
use mesh_core::{AppError, AppResult, ErrorKind, Port};
use mesh_net::{
    Nat64Prefix, Nat64Synthesizer, NoopSocketProtector, SocketProtector, bind_underlay_socket2,
    bind_underlay_udp_socket, disable_udp_dont_fragment,
};
use mesh_proto::relay::RELAY_MAX_CIPHERTEXT_BYTES;
use mesh_proto::{DemuxPacket, demux_packet};

/// Fixed packet buffer size matching the workspace frame limit (`MAX_FRAME_SIZE = 2048`).
pub const MAGIC_SOCKET_BUFFER_SIZE: usize = MAX_FRAME_SIZE;

/// WireGuard header + Poly1305 tag overhead over inner IP packet size.
const WIREGUARD_TRANSPORT_OVERHEAD_BYTES: usize = 32;
/// WireGuard zero-padding alignment boundary in bytes.
const WIREGUARD_PADDING_ALIGNMENT: usize = 16;

/// Stack- or pre-allocated hot-path UDP packet buffer (`0` heap allocations per packet).
pub type PacketBuffer = [u8; MAGIC_SOCKET_BUFFER_SIZE];

/// Configuration for binding or rebinding `MagicSocket` (`US-017`, `US-019`).
#[derive(Clone)]
pub struct MagicSocketConfig {
    /// Persisted local UDP port to try before falling back to an OS ephemeral port (`0`).
    pub preferred_port: Option<Port>,
    /// Explicit local bind address (`None` tries dual-stack `[::]` then falls back to `0.0.0.0`).
    pub bind_ip: Option<IpAddr>,
    /// Overlay TUN MTU (`576..=1420`, default `1280`).
    pub mtu: u16,
    /// Optional physical underlay interface index for routing-loop prevention (`REL-09`).
    pub underlay_if_index: Option<u32>,
    /// Optional Linux `SO_MARK` fwmark for policy routing loop prevention.
    pub linux_fwmark: Option<u32>,
    /// Optional NAT64 prefix for synthesizing IPv4 peer/STUN targets on IPv6-only networks (`US-077`).
    pub nat64_prefix: Option<Nat64Prefix>,
    /// Fail-closed socket protector hook (`VpnService.protect` / mobile bypass) (`US-077`).
    pub socket_protector: Arc<dyn SocketProtector>,
}

impl std::fmt::Debug for MagicSocketConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicSocketConfig")
            .field("preferred_port", &self.preferred_port)
            .field("bind_ip", &self.bind_ip)
            .field("mtu", &self.mtu)
            .field("underlay_if_index", &self.underlay_if_index)
            .field("linux_fwmark", &self.linux_fwmark)
            .field("nat64_prefix", &self.nat64_prefix)
            .field("socket_protector", &"<dyn SocketProtector>")
            .finish()
    }
}

impl PartialEq for MagicSocketConfig {
    fn eq(&self, other: &Self) -> bool {
        self.preferred_port == other.preferred_port
            && self.bind_ip == other.bind_ip
            && self.mtu == other.mtu
            && self.underlay_if_index == other.underlay_if_index
            && self.linux_fwmark == other.linux_fwmark
            && self.nat64_prefix == other.nat64_prefix
            && Arc::ptr_eq(&self.socket_protector, &other.socket_protector)
    }
}

impl Eq for MagicSocketConfig {}

impl Default for MagicSocketConfig {
    fn default() -> Self {
        Self {
            preferred_port: None,
            bind_ip: None,
            mtu: DEFAULT_TUN_MTU,
            underlay_if_index: None,
            linux_fwmark: None,
            nat64_prefix: None,
            socket_protector: Arc::new(NoopSocketProtector),
        }
    }
}

impl MagicSocketConfig {
    /// Creates a configuration preferring a specific local UDP port.
    #[must_use]
    pub fn with_preferred_port(mut self, port: Port) -> Self {
        self.preferred_port = Some(port);
        self
    }

    /// Creates a configuration binding a specific local IP address (useful for tests/loopback).
    #[must_use]
    pub fn with_bind_ip(mut self, bind_ip: IpAddr) -> Self {
        self.bind_ip = Some(bind_ip);
        self
    }

    /// Validates and updates the configured overlay MTU (`576..=1420`).
    pub fn with_mtu(mut self, mtu: u16) -> AppResult<Self> {
        validate_tun_mtu(mtu)?;
        self.mtu = mtu;
        Ok(self)
    }

    /// Configures physical underlay interface pinning metadata (`if_index`, Linux `fwmark`).
    #[must_use]
    pub fn with_underlay(mut self, if_index: Option<u32>, linux_fwmark: Option<u32>) -> Self {
        self.underlay_if_index = if_index;
        self.linux_fwmark = linux_fwmark;
        self
    }

    /// Configures an active NAT64 RFC 6052 prefix for IPv6-only cellular/Wi-Fi synthesis (`US-077`).
    #[must_use]
    pub fn with_nat64_prefix(mut self, nat64_prefix: Option<Nat64Prefix>) -> Self {
        self.nat64_prefix = nat64_prefix;
        self
    }

    /// Configures a fail-closed OS socket protector (`Android VpnService.protect` / iOS) (`US-077`).
    #[must_use]
    pub fn with_socket_protector(mut self, protector: Arc<dyn SocketProtector>) -> Self {
        self.socket_protector = protector;
        self
    }
}

/// Validates that `mtu` stays within `576..=1420` and its WireGuard payload fits Relay limits.
pub fn validate_tun_mtu(mtu: u16) -> AppResult<u16> {
    if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&mtu) {
        return Err(AppError::invalid_argument(format!(
            "mtu {mtu} out of allowed bounds {MIN_TUN_MTU}..={MAX_TUN_MTU}"
        )));
    }
    let mtu_usize = usize::from(mtu);
    let padded_inner = mtu_usize
        .div_ceil(WIREGUARD_PADDING_ALIGNMENT)
        .saturating_mul(WIREGUARD_PADDING_ALIGNMENT);
    let max_wg_packet = padded_inner.saturating_add(WIREGUARD_TRANSPORT_OVERHEAD_BYTES);
    if max_wg_packet > RELAY_MAX_CIPHERTEXT_BYTES || max_wg_packet > MAX_FRAME_SIZE {
        return Err(AppError::invalid_argument(format!(
            "mtu {mtu} produces WireGuard packet ({max_wg_packet} B) exceeding relay limit \
             ({RELAY_MAX_CIPHERTEXT_BYTES} B)"
        )));
    }
    Ok(mtu)
}

/// Outcome metadata produced when binding or rebinding `MagicSocket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindReport {
    /// Effective local socket address (`::ffff:` unmapped if applicable).
    pub local_addr: SocketAddr,
    /// Preferred UDP port requested by configuration (`None` if ephemeral `0`).
    pub preferred_port_requested: Option<Port>,
    /// True if binding `preferred_port` failed because it was busy and ephemeral `0` was used.
    pub used_fallback_port: bool,
    /// True if socket is bound as IPv6 dual-stack (`IPV6_V6ONLY = false`).
    pub dual_stack: bool,
    /// True if outer socket `DF=1` disabling succeeded (`US-017 AC3`).
    pub df_disabled: bool,
}

/// Shared non-blocking UDP socket carrying STUN, Authenticated Disco, and WireGuard traffic.
#[derive(Debug)]
pub struct MagicSocket {
    socket: UdpSocket,
    bind_report: BindReport,
    mtu: u16,
    config: MagicSocketConfig,
    protection_failed: bool,
}

impl MagicSocket {
    /// Validates `config`, binds the single UDP socket (preferring `preferred_port`), and clears `DF=1`.
    pub async fn bind(config: MagicSocketConfig) -> AppResult<Self> {
        Self::bind_in_runtime(config)
    }

    /// Synchronous constructor intended to be invoked inside an active Tokio runtime.
    pub fn bind_in_runtime(config: MagicSocketConfig) -> AppResult<Self> {
        let mtu = validate_tun_mtu(config.mtu)?;
        let (socket, bind_report) = open_and_bind_socket(&config)?;
        Ok(Self {
            socket,
            bind_report,
            mtu,
            config,
            protection_failed: false,
        })
    }

    /// Returns the validated overlay MTU configured for this `MagicSocket`.
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Returns metadata from the most recent bind/rebind operation.
    #[must_use]
    pub fn bind_report(&self) -> BindReport {
        self.bind_report
    }

    /// Returns the configured NAT64 prefix, if any (`US-077`).
    #[must_use]
    pub fn nat64_prefix(&self) -> Option<Nat64Prefix> {
        self.config.nat64_prefix
    }

    /// Updates the active NAT64 RFC 6052 prefix at runtime (`US-077`).
    pub fn set_nat64_prefix(&mut self, prefix: Option<Nat64Prefix>) {
        self.config.nat64_prefix = prefix;
    }

    /// Returns a reference to the configured OS [`SocketProtector`].
    #[must_use]
    pub fn socket_protector(&self) -> &Arc<dyn SocketProtector> {
        &self.config.socket_protector
    }

    /// Returns the underlying raw OS socket descriptor for external verification or STUN protection.
    pub fn raw_fd(&self) -> AppResult<i32> {
        extract_udp_raw_fd(&self.socket)
    }

    /// Returns the effective normalized local socket address.
    pub fn local_addr(&self) -> AppResult<SocketAddr> {
        let addr = self.socket.local_addr().map_err(|err| {
            AppError::unavailable(format!("failed to read magic socket addr: {err}"))
        })?;
        Ok(unmap_socket_addr(addr))
    }

    /// Returns the bound local UDP port as a validated non-zero `Port`.
    pub fn local_port(&self) -> AppResult<Port> {
        let addr = self.local_addr()?;
        Port::from_u16(addr.port())
    }

    /// Returns true if the underlying UDP socket uses an IPv6 descriptor.
    #[must_use]
    pub fn is_ipv6_socket(&self) -> bool {
        self.bind_report.local_addr.is_ipv6() || self.bind_report.dual_stack
    }

    /// Receives a raw UDP datagram into a pre-allocated `[u8; 2048]` buffer and unmaps/desynthesizes
    /// the peer address back to canonical IPv4 when a NAT64 prefix matches (`US-077`).
    pub async fn recv_from(&self, buf: &mut PacketBuffer) -> AppResult<(usize, SocketAddr)> {
        let (len, peer) = self.socket.recv_from(buf).await.map_err(|err| {
            AppError::unavailable(format!("magic socket recv_from failed: {err}"))
        })?;
        Ok((len, self.normalize_ingress_addr(peer)))
    }

    /// Receives and demultiplexes one UDP datagram without per-packet heap allocation.
    pub async fn recv_demuxed<'a>(
        &self,
        buf: &'a mut PacketBuffer,
    ) -> AppResult<(SocketAddr, DemuxPacket<'a>)> {
        let (len, peer) = self.recv_from(buf).await?;
        let packet = buf
            .get(..len)
            .ok_or_else(|| AppError::unavailable("udp recv returned length exceeding buffer"))?;
        Ok((peer, demux_packet(packet)))
    }

    /// Sends `payload` over the single UDP socket to `target`, checking frame bounds.
    pub async fn send_to(&self, payload: &[u8], target: SocketAddr) -> AppResult<usize> {
        let normalized = self.prepare_send(payload, target)?;
        self.socket
            .send_to(payload, normalized)
            .await
            .map_err(|err| AppError::unavailable(format!("magic socket send_to failed: {err}")))
    }

    /// Attempts a non-blocking UDP send without yielding across `.await`.
    pub fn try_send_to(&self, payload: &[u8], target: SocketAddr) -> AppResult<usize> {
        let normalized = self.prepare_send(payload, target)?;
        self.socket
            .try_send_to(payload, normalized)
            .map_err(|err| AppError::unavailable(format!("magic socket try_send_to failed: {err}")))
    }

    /// Re-applies [`SocketProtector`] and physical underlay socket binding (`IP_UNICAST_IF` /
    /// `IP_BOUND_IF` / `SO_MARK`) in place without closing the UDP port.
    pub fn rebind_underlay(
        &mut self,
        if_index: Option<u32>,
        linux_fwmark: Option<u32>,
    ) -> AppResult<()> {
        if let Err(err) = protect_udp_socket(self.config.socket_protector.as_ref(), &self.socket) {
            self.protection_failed = true;
            return Err(err);
        }
        self.protection_failed = false;
        self.config.underlay_if_index = if_index;
        self.config.linux_fwmark = linux_fwmark;
        if if_index.is_none() && linux_fwmark.is_none() {
            return Ok(());
        }
        apply_underlay_binding(
            &self.socket,
            self.is_ipv6_socket(),
            self.bind_report.dual_stack,
            if_index,
            linux_fwmark,
        )
    }

    /// Recreates and rebinds the underlying UDP socket onto the new underlay interface, preserving
    /// the previously bound UDP port if available (`US-019 AC1`).
    pub fn recreate_socket(
        &mut self,
        if_index: Option<u32>,
        linux_fwmark: Option<u32>,
    ) -> AppResult<BindReport> {
        let current_port = self.local_port().ok().or(self.config.preferred_port);
        let mut next_cfg = self.config.clone().with_underlay(if_index, linux_fwmark);
        next_cfg.preferred_port = current_port;

        // Release the previously bound port before trying to re-acquire the same UDP port.
        let placeholder = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        if current_port.is_some()
            && let Ok(dummy) = std::net::UdpSocket::bind(placeholder)
            && dummy.set_nonblocking(true).is_ok()
            && let Ok(tokio_dummy) = UdpSocket::from_std(dummy)
        {
            self.socket = tokio_dummy;
        }

        let (new_sock, report) = match open_and_bind_socket(&next_cfg) {
            Ok(bound) => bound,
            Err(err) => {
                // Fail-closed: prevent sending packets via any temporary placeholder socket.
                self.protection_failed = true;
                return Err(err);
            }
        };
        self.socket = new_sock;
        self.bind_report = report;
        self.config = next_cfg;
        self.protection_failed = false;
        Ok(report)
    }

    fn normalize_ingress_addr(&self, addr: SocketAddr) -> SocketAddr {
        let unmapped = unmap_socket_addr(addr);
        match (unmapped, self.config.nat64_prefix) {
            (SocketAddr::V6(v6), Some(prefix)) => {
                if let Some(v4) = Nat64Synthesizer::new(prefix).desynthesize_ip(*v6.ip()) {
                    SocketAddr::V4(SocketAddrV4::new(v4, v6.port()))
                } else {
                    SocketAddr::V6(v6)
                }
            }
            (other, _) => other,
        }
    }

    fn prepare_send(&self, payload: &[u8], target: SocketAddr) -> AppResult<SocketAddr> {
        if self.protection_failed {
            return Err(AppError::permission_denied(
                "refusing outbound udp packet over unprotected MagicSocket",
            ));
        }
        if payload.len() > MAX_FRAME_SIZE {
            return Err(AppError::invalid_argument(format!(
                "outbound udp payload ({} B) exceeds max frame size ({MAX_FRAME_SIZE} B)",
                payload.len()
            )));
        }
        if target.port() == 0 {
            return Err(AppError::invalid_argument(
                "refusing outbound udp packet to port 0",
            ));
        }
        normalize_target_for_socket(
            target,
            self.bind_report.local_addr,
            self.bind_report.dual_stack,
            self.config.nat64_prefix,
        )
    }
}

enum BindFailure {
    Protector(AppError),
    Socket(AppError),
}

impl BindFailure {
    fn into_app_error(self) -> AppError {
        match self {
            Self::Protector(err) | Self::Socket(err) => err,
        }
    }
}

fn open_and_bind_socket(config: &MagicSocketConfig) -> AppResult<(UdpSocket, BindReport)> {
    let preferred_u16 = config.preferred_port.map_or(0, Port::get);
    match try_bind_family(config, preferred_u16) {
        Ok(result) => Ok(result),
        Err(BindFailure::Protector(err)) => Err(err),
        Err(BindFailure::Socket(err)) if preferred_u16 != 0 && is_port_busy_error(&err) => {
            warn!(
                component = "datapath.magic_socket",
                event = "preferred_udp_port_busy",
                preferred_port = preferred_u16,
                error = %err,
                "preferred UDP port busy; falling back to ephemeral port 0"
            );
            let (sock, mut report) =
                try_bind_family(config, 0).map_err(BindFailure::into_app_error)?;
            report.preferred_port_requested = config.preferred_port;
            report.used_fallback_port = true;
            Ok((sock, report))
        }
        Err(BindFailure::Socket(err)) => Err(err),
    }
}

fn try_bind_family(
    config: &MagicSocketConfig,
    port: u16,
) -> Result<(UdpSocket, BindReport), BindFailure> {
    match config.bind_ip {
        Some(IpAddr::V4(v4)) => bind_single_socket(config, SocketAddr::from((v4, port)), false),
        Some(IpAddr::V6(v6)) => {
            let allow_dual_stack = v6.is_unspecified();
            bind_single_socket(config, SocketAddr::from((v6, port)), allow_dual_stack)
        }
        None => {
            let v6_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
            match bind_single_socket(config, v6_addr, true) {
                Ok(res) => Ok(res),
                Err(BindFailure::Protector(err)) => Err(BindFailure::Protector(err)),
                Err(BindFailure::Socket(v6_err)) => {
                    warn!(
                        component = "datapath.magic_socket",
                        event = "ipv6_dualstack_bind_fallback",
                        error = %v6_err,
                        "dual-stack IPv6 UDP bind unavailable; falling back to IPv4 unspecified"
                    );
                    let v4_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                    match bind_single_socket(config, v4_addr, false) {
                        Ok(res) => Ok(res),
                        Err(BindFailure::Protector(err)) => Err(BindFailure::Protector(err)),
                        Err(BindFailure::Socket(v4_err)) if config.nat64_prefix.is_some() => {
                            warn!(
                                component = "datapath.magic_socket",
                                event = "ipv6_only_nat64_bind_fallback",
                                error = %v4_err,
                                "IPv4 fallback bind unavailable under NAT64; attempting IPv6-only unspecified bind"
                            );
                            bind_single_socket(config, v6_addr, false)
                        }
                        Err(err) => Err(err),
                    }
                }
            }
        }
    }
}

fn bind_single_socket(
    config: &MagicSocketConfig,
    bind_addr: SocketAddr,
    dual_stack: bool,
) -> Result<(UdpSocket, BindReport), BindFailure> {
    let is_ipv6 = bind_addr.is_ipv6();
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|err| {
        BindFailure::Socket(AppError::unavailable(format!(
            "failed to create udp socket: {err}"
        )))
    })?;

    sock.set_nonblocking(true).map_err(|err| {
        BindFailure::Socket(AppError::unavailable(format!(
            "failed to set udp nonblocking: {err}"
        )))
    })?;

    if is_ipv6 && dual_stack {
        sock.set_only_v6(false).map_err(|err| {
            BindFailure::Socket(AppError::unavailable(format!(
                "failed to configure dual-stack IPV6_V6ONLY=false: {err}"
            )))
        })?;
    }

    // Fail-closed: protect the raw descriptor BEFORE binding or applying underlay options
    // so an unprotected socket can never transmit packets across the active tunnel interface.
    protect_socket2(config.socket_protector.as_ref(), &sock).map_err(BindFailure::Protector)?;

    if config.underlay_if_index.is_some() || config.linux_fwmark.is_some() {
        bind_underlay_socket2(
            &sock,
            is_ipv6,
            config.underlay_if_index,
            config.linux_fwmark,
        )
        .map_err(BindFailure::Socket)?;
    }

    sock.bind(&bind_addr.into()).map_err(|err| {
        if err.kind() == IoErrorKind::AddrInUse
            || err.kind() == IoErrorKind::AddrNotAvailable
            || (bind_addr.port() != 0 && err.kind() == IoErrorKind::PermissionDenied)
        {
            BindFailure::Socket(AppError::new(
                ErrorKind::Conflict,
                format!("udp bind {bind_addr} unavailable: {err}"),
            ))
        } else {
            BindFailure::Socket(AppError::unavailable(format!(
                "failed to bind udp socket {bind_addr}: {err}"
            )))
        }
    })?;

    let std_sock: std::net::UdpSocket = sock.into();
    let tokio_sock = UdpSocket::from_std(std_sock).map_err(|err| {
        BindFailure::Socket(AppError::unavailable(format!(
            "failed to adopt tokio udp socket: {err}"
        )))
    })?;

    let df_disabled = match disable_udp_dont_fragment(&tokio_sock) {
        Ok(()) => true,
        Err(err) => {
            warn!(
                component = "datapath.magic_socket",
                event = "disable_df_failed",
                error = %err,
                "failed to clear DF=1 flag on outer UDP socket"
            );
            false
        }
    };

    let bound_addr = tokio_sock
        .local_addr()
        .map(unmap_socket_addr)
        .map_err(|err| {
            BindFailure::Socket(AppError::unavailable(format!(
                "failed to read local_addr after bind: {err}"
            )))
        })?;

    info!(
        component = "datapath.magic_socket",
        event = "magic_socket_bound",
        local_addr = %bound_addr,
        dual_stack,
        df_disabled,
        mtu = config.mtu,
        nat64_active = config.nat64_prefix.is_some(),
        "bound shared MagicSocket"
    );

    Ok((
        tokio_sock,
        BindReport {
            local_addr: bound_addr,
            preferred_port_requested: config.preferred_port,
            used_fallback_port: false,
            dual_stack,
            df_disabled,
        },
    ))
}

pub(crate) fn extract_socket2_raw_fd(socket: &Socket) -> AppResult<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        Ok(socket.as_raw_fd())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;
        raw_socket_to_fd(socket.as_raw_socket())
    }
}

pub(crate) fn extract_udp_raw_fd(socket: &UdpSocket) -> AppResult<i32> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        Ok(socket.as_raw_fd())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket as _;
        raw_socket_to_fd(socket.as_raw_socket())
    }
}

#[cfg(windows)]
fn raw_socket_to_fd(raw: std::os::windows::io::RawSocket) -> AppResult<i32> {
    if raw == u64::MAX {
        return Err(AppError::unavailable("invalid OS socket descriptor"));
    }
    match i32::try_from(raw) {
        Ok(fd) => Ok(fd),
        Err(_) => {
            let masked = raw & 0x7FFF_FFFF;
            i32::try_from(masked).map_err(|_| AppError::unavailable("invalid OS socket descriptor"))
        }
    }
}

pub(crate) fn protect_socket2(protector: &dyn SocketProtector, socket: &Socket) -> AppResult<()> {
    let raw_fd = extract_socket2_raw_fd(socket)?;
    protector.protect_socket(raw_fd)
}

pub(crate) fn protect_udp_socket(
    protector: &dyn SocketProtector,
    socket: &UdpSocket,
) -> AppResult<()> {
    let raw_fd = extract_udp_raw_fd(socket)?;
    protector.protect_socket(raw_fd)
}

fn apply_underlay_binding(
    socket: &UdpSocket,
    is_ipv6_socket: bool,
    dual_stack: bool,
    if_index: Option<u32>,
    linux_fwmark: Option<u32>,
) -> AppResult<()> {
    bind_underlay_udp_socket(socket, is_ipv6_socket, if_index, linux_fwmark)?;
    if dual_stack && is_ipv6_socket && if_index.is_some() {
        // Best-effort IPv4 underlay hint on dual-stack sockets where OS expects IP_UNICAST_IF.
        if let Err(err) = bind_underlay_udp_socket(socket, false, if_index, None) {
            warn!(
                component = "datapath.magic_socket",
                event = "dualstack_v4_underlay_hint_skipped",
                error = %err,
                "skipped secondary IPv4 underlay option on dual-stack socket"
            );
        }
    }
    Ok(())
}

fn is_port_busy_error(err: &AppError) -> bool {
    err.kind() == ErrorKind::Conflict
        || err.public_message().contains("in use")
        || err.public_message().contains("Address already in use")
        || err
            .public_message()
            .contains("Only one usage of each socket address")
        || err.public_message().contains("unavailable")
}

/// Converts IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) back into canonical IPv4 addresses.
#[must_use]
pub fn unmap_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::V4(v4),
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => SocketAddr::V6(v6),
        },
    }
}

fn normalize_target_for_socket(
    target: SocketAddr,
    local_addr: SocketAddr,
    dual_stack: bool,
    nat64_prefix: Option<Nat64Prefix>,
) -> AppResult<SocketAddr> {
    if let (SocketAddr::V4(v4), Some(prefix)) = (target, nat64_prefix)
        && (local_addr.is_ipv6() || dual_stack)
        && let Some(synthesized) = Nat64Synthesizer::new(prefix).try_synthesize_sockaddr(v4)
    {
        return Ok(SocketAddr::V6(synthesized));
    }

    match (local_addr, dual_stack, target) {
        (SocketAddr::V4(_), false, SocketAddr::V4(_)) => Ok(target),
        (SocketAddr::V4(_), false, SocketAddr::V6(_)) => Err(AppError::invalid_argument(
            "cannot send to IPv6 endpoint from an IPv4-only MagicSocket",
        )),
        (_, true, SocketAddr::V4(v4)) => Ok(SocketAddr::V6(SocketAddrV6::new(
            v4.ip().to_ipv6_mapped(),
            v4.port(),
            0,
            0,
        ))),
        (SocketAddr::V6(_), false, SocketAddr::V4(_)) => Err(AppError::invalid_argument(
            "cannot send to IPv4 endpoint from an IPv6-only MagicSocket",
        )),
        (_, _, SocketAddr::V6(_)) => Ok(target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Traces: US-017
    #[test]
    fn test_mtu_validation_accepts_bounds_and_rejects_out_of_range() {
        // Arrange & Act & Assert
        assert_eq!(validate_tun_mtu(MIN_TUN_MTU).ok(), Some(576));
        assert_eq!(validate_tun_mtu(DEFAULT_TUN_MTU).ok(), Some(1280));
        assert_eq!(validate_tun_mtu(MAX_TUN_MTU).ok(), Some(1420));
        assert!(validate_tun_mtu(575).is_err());
        assert!(validate_tun_mtu(1421).is_err());
    }

    // Traces: US-019
    #[tokio::test]
    async fn test_magic_socket_falls_back_when_preferred_port_busy() {
        // Arrange
        let occupied = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("initial socket should bind");
        let busy_port = occupied.local_port().expect("valid bound port");

        // Act
        let fallback_sock = MagicSocket::bind(
            MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .with_preferred_port(busy_port),
        )
        .await
        .expect("fallback bind should succeed on ephemeral port");

        // Assert
        assert!(fallback_sock.bind_report().used_fallback_port);
        assert_ne!(
            fallback_sock.local_port().expect("fallback port"),
            busy_port
        );
    }

    // Traces: ADR-002, US-017
    #[tokio::test]
    async fn test_magic_socket_loopback_demuxes_stun_disco_and_wireguard() {
        // Arrange
        let sock_a = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("sock A binds");
        let sock_b = MagicSocket::bind(
            MagicSocketConfig::default().with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        )
        .await
        .expect("sock B binds");
        let addr_b = sock_b.local_addr().expect("addr B");
        let mut buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];

        // Act: send WireGuard-like packet (`type = 4`, minimum 32 bytes), STUN, and Disco
        let mut wg_like = [0u8; 32];
        if let Some(first) = wg_like.first_mut() {
            *first = 4;
        }
        sock_a
            .send_to(&wg_like, addr_b)
            .await
            .expect("send wireguard packet");
        let (peer, demuxed) = sock_b.recv_demuxed(&mut buf).await.expect("recv wg");
        assert_eq!(peer, sock_a.local_addr().expect("addr A"));
        assert!(matches!(demuxed, DemuxPacket::WireGuard(_)));

        let stun_pkt = mesh_proto::stun::encode_binding_request([7u8; 12]);
        sock_a
            .send_to(&stun_pkt, addr_b)
            .await
            .expect("send stun packet");
        let (_, demuxed_stun) = sock_b.recv_demuxed(&mut buf).await.expect("recv stun");
        assert!(matches!(demuxed_stun, DemuxPacket::Stun(_)));

        let mut disco_like = vec![0u8; mesh_proto::MIN_DISCO_PACKET_LEN];
        if let Some(prefix) = disco_like.get_mut(..6) {
            prefix.copy_from_slice(b"MESHDS");
        }
        if let Some(ver) = disco_like.get_mut(6) {
            *ver = mesh_crypto::DISCO_PROTOCOL_VERSION;
        }
        sock_a
            .send_to(&disco_like, addr_b)
            .await
            .expect("send disco packet");
        let (_, demuxed_disco) = sock_b.recv_demuxed(&mut buf).await.expect("recv disco");
        assert!(matches!(demuxed_disco, DemuxPacket::Disco(_)));
    }

    struct ToggleSocketProtector {
        fail_after: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
        observed_fds: std::sync::Mutex<Vec<i32>>,
    }

    impl ToggleSocketProtector {
        fn always_fail() -> Self {
            Self {
                fail_after: std::sync::atomic::AtomicUsize::new(0),
                calls: std::sync::atomic::AtomicUsize::new(0),
                observed_fds: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn fail_after(succeed_count: usize) -> Self {
            Self {
                fail_after: std::sync::atomic::AtomicUsize::new(succeed_count),
                calls: std::sync::atomic::AtomicUsize::new(0),
                observed_fds: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SocketProtector for ToggleSocketProtector {
        fn protect_socket(&self, raw_fd: i32) -> AppResult<()> {
            let idx = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Ok(mut guard) = self.observed_fds.lock() {
                guard.push(raw_fd);
            }
            if idx >= self.fail_after.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AppError::permission_denied("VpnService.protect failed"));
            }
            Ok(())
        }
    }

    // Traces: US-077, REL-09
    #[tokio::test]
    async fn test_magic_socket_fail_closed_when_protector_errors_blocks_bind_and_send() {
        // Arrange
        let failing_protector = Arc::new(ToggleSocketProtector::always_fail());
        let cfg = MagicSocketConfig::default()
            .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .with_socket_protector(failing_protector.clone());

        // Act
        let bind_res = MagicSocket::bind(cfg).await;

        // Assert
        assert!(bind_res.is_err());
        assert_eq!(failing_protector.call_count(), 1);
        assert_eq!(
            bind_res.err().map(|e| e.kind()),
            Some(ErrorKind::PermissionDenied)
        );

        // Arrange: fail protector after initial bind succeeds during rebind / recreate
        let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink udp");
        let sink_addr = sink.local_addr().expect("sink addr");
        let conditional_protector = Arc::new(ToggleSocketProtector::fail_after(1));
        let mut sock = MagicSocket::bind(
            MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .with_socket_protector(conditional_protector.clone()),
        )
        .await
        .expect("initial bind should succeed");

        // Act: rebind fails protection -> subsequent send must fail closed with 0 bytes transmitted
        let rebind_err = sock.recreate_socket(None, None);
        let send_err = sock.try_send_to(b"hello", sink_addr);
        let mut rx_buf = [0u8; 64];
        let recv_timeout =
            tokio::time::timeout(std::time::Duration::from_millis(60), sink.recv(&mut rx_buf))
                .await;

        // Assert
        assert!(rebind_err.is_err());
        assert!(send_err.is_err());
        assert!(
            recv_timeout.is_err(),
            "zero bytes must leave socket after protector failure"
        );
        assert!(conditional_protector.call_count() >= 2);
    }

    // Traces: US-077, NAT64
    #[tokio::test]
    async fn test_magic_socket_nat64_synthesizes_outbound_and_desynthesizes_ingress() {
        // Arrange: bind an IPv6 loopback MagicSocket and configure NAT64 prefix mapping 0.0.0.1 -> ::1
        let nat64 = Nat64Prefix::well_known();
        let v4_target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 51820));
        let v6_local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 51820, 0, 0));

        // Act 1: outbound normalization converts IPv4 targets into RFC 6052 IPv6
        let synthesized = normalize_target_for_socket(v4_target, v6_local, false, Some(nat64))
            .expect("NAT64 synthesis on IPv6 socket should succeed");

        // Assert 1
        assert_eq!(
            synthesized,
            SocketAddr::V6(SocketAddrV6::new(
                "64:ff9b::cb00:710a".parse::<Ipv6Addr>().expect("ipv6"),
                51820,
                0,
                0,
            ))
        );

        // Arrange 2: live loopback UDP exchange using prefix `::/96` mapping `0.0.0.1` <-> `::1`
        let loopback_nat64 = Nat64Prefix::from_prefix_and_len(Ipv6Addr::UNSPECIFIED, 96)
            .expect("::/96 prefix valid for RFC 6052 loopback test");
        let sock_sender = MagicSocket::bind(
            MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
                .with_nat64_prefix(Some(loopback_nat64)),
        )
        .await
        .expect("bind sender IPv6 MagicSocket");
        let sock_receiver = MagicSocket::bind(
            MagicSocketConfig::default()
                .with_bind_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
                .with_nat64_prefix(Some(loopback_nat64)),
        )
        .await
        .expect("bind receiver IPv6 MagicSocket");
        let rx_port = sock_receiver.local_port().expect("rx port").get();
        let tx_port = sock_sender.local_port().expect("tx port").get();

        // Act 2: send to synthetic IPv4 `0.0.0.1:rx_port` -> delivered to `[::1]:rx_port` and
        // desynthesized on ingress back to `0.0.0.1:tx_port`.
        let stun_pkt = mesh_proto::stun::encode_binding_request([9u8; 12]);
        sock_sender
            .send_to(
                &stun_pkt,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 1), rx_port)),
            )
            .await
            .expect("NAT64 synthesized send should deliver to ::1");
        let mut rx_buf: PacketBuffer = [0u8; MAGIC_SOCKET_BUFFER_SIZE];
        let (len, peer_addr) = sock_receiver.recv_from(&mut rx_buf).await.expect("recv");

        // Assert 2
        assert_eq!(len, stun_pkt.len());
        assert_eq!(
            peer_addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 1), tx_port))
        );
    }

    #[test]
    fn test_magic_socket_normalize_skips_nat64_for_rfc1918_and_link_local() {
        // Arrange
        let nat64 = Some(Nat64Prefix::well_known());
        let dual_local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 51820, 0, 0));
        let v6_only_local = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 51820, 0, 0));
        let lan_target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 51820));
        let rfc1918_ten = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51820));
        let link_local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(169, 254, 1, 2), 51820));

        // Act
        let dual_res = normalize_target_for_socket(lan_target, dual_local, true, nat64);
        let ten_res = normalize_target_for_socket(rfc1918_ten, dual_local, true, nat64);
        let v6_only_res = normalize_target_for_socket(link_local, v6_only_local, false, nat64);

        // Assert
        assert_eq!(
            dual_res.ok(),
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv4Addr::new(192, 168, 1, 50).to_ipv6_mapped(),
                51820,
                0,
                0
            )))
        );
        assert_eq!(
            ten_res.ok(),
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped(),
                51820,
                0,
                0
            )))
        );
        assert!(v6_only_res.is_err());
    }
}
