//! Single shared non-blocking UDP socket with static receive buffers, MTU checks, and demuxing.

use std::io::ErrorKind as IoErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use mesh_core::defaults::{DEFAULT_TUN_MTU, MAX_FRAME_SIZE, MAX_TUN_MTU, MIN_TUN_MTU};
use mesh_core::{AppError, AppResult, ErrorKind, Port};
use mesh_net::{bind_underlay_socket2, bind_underlay_udp_socket, disable_udp_dont_fragment};
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl Default for MagicSocketConfig {
    fn default() -> Self {
        Self {
            preferred_port: None,
            bind_ip: None,
            mtu: DEFAULT_TUN_MTU,
            underlay_if_index: None,
            linux_fwmark: None,
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

    /// Receives a raw UDP datagram into a pre-allocated `[u8; 2048]` buffer and unmaps the peer IP.
    pub async fn recv_from(&self, buf: &mut PacketBuffer) -> AppResult<(usize, SocketAddr)> {
        let (len, peer) = self.socket.recv_from(buf).await.map_err(|err| {
            AppError::unavailable(format!("magic socket recv_from failed: {err}"))
        })?;
        Ok((len, unmap_socket_addr(peer)))
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

    /// Re-applies physical underlay socket binding (`IP_UNICAST_IF` / `IP_BOUND_IF` / `SO_MARK`)
    /// in place without closing the UDP port.
    pub fn rebind_underlay(
        &mut self,
        if_index: Option<u32>,
        linux_fwmark: Option<u32>,
    ) -> AppResult<()> {
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

        let (new_sock, report) = open_and_bind_socket(&next_cfg)?;
        self.socket = new_sock;
        self.bind_report = report;
        self.config = next_cfg;
        Ok(report)
    }

    fn prepare_send(&self, payload: &[u8], target: SocketAddr) -> AppResult<SocketAddr> {
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
        )
    }
}

fn open_and_bind_socket(config: &MagicSocketConfig) -> AppResult<(UdpSocket, BindReport)> {
    let preferred_u16 = config.preferred_port.map_or(0, Port::get);
    match try_bind_family(config, preferred_u16) {
        Ok(result) => Ok(result),
        Err(err) if preferred_u16 != 0 && is_port_busy_error(&err) => {
            warn!(
                component = "datapath.magic_socket",
                event = "preferred_udp_port_busy",
                preferred_port = preferred_u16,
                error = %err,
                "preferred UDP port busy; falling back to ephemeral port 0"
            );
            let (sock, mut report) = try_bind_family(config, 0)?;
            report.preferred_port_requested = config.preferred_port;
            report.used_fallback_port = true;
            Ok((sock, report))
        }
        Err(err) => Err(err),
    }
}

fn try_bind_family(config: &MagicSocketConfig, port: u16) -> AppResult<(UdpSocket, BindReport)> {
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
                Err(v6_err) => {
                    warn!(
                        component = "datapath.magic_socket",
                        event = "ipv6_dualstack_bind_fallback",
                        error = %v6_err,
                        "dual-stack IPv6 UDP bind unavailable; falling back to IPv4 unspecified"
                    );
                    let v4_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                    bind_single_socket(config, v4_addr, false)
                }
            }
        }
    }
}

fn bind_single_socket(
    config: &MagicSocketConfig,
    bind_addr: SocketAddr,
    dual_stack: bool,
) -> AppResult<(UdpSocket, BindReport)> {
    let is_ipv6 = bind_addr.is_ipv6();
    let domain = if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|err| AppError::unavailable(format!("failed to create udp socket: {err}")))?;

    sock.set_nonblocking(true)
        .map_err(|err| AppError::unavailable(format!("failed to set udp nonblocking: {err}")))?;

    if is_ipv6 && dual_stack {
        sock.set_only_v6(false).map_err(|err| {
            AppError::unavailable(format!(
                "failed to configure dual-stack IPV6_V6ONLY=false: {err}"
            ))
        })?;
    }

    if config.underlay_if_index.is_some() || config.linux_fwmark.is_some() {
        bind_underlay_socket2(
            &sock,
            is_ipv6,
            config.underlay_if_index,
            config.linux_fwmark,
        )?;
    }

    sock.bind(&bind_addr.into()).map_err(|err| {
        if err.kind() == IoErrorKind::AddrInUse || err.kind() == IoErrorKind::AddrNotAvailable {
            AppError::new(
                ErrorKind::Conflict,
                format!("udp bind {bind_addr} unavailable: {err}"),
            )
        } else {
            AppError::unavailable(format!("failed to bind udp socket {bind_addr}: {err}"))
        }
    })?;

    let std_sock: std::net::UdpSocket = sock.into();
    let tokio_sock = UdpSocket::from_std(std_sock)
        .map_err(|err| AppError::unavailable(format!("failed to adopt tokio udp socket: {err}")))?;

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
            AppError::unavailable(format!("failed to read local_addr after bind: {err}"))
        })?;

    info!(
        component = "datapath.magic_socket",
        event = "magic_socket_bound",
        local_addr = %bound_addr,
        dual_stack,
        df_disabled,
        mtu = config.mtu,
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
) -> AppResult<SocketAddr> {
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
}
