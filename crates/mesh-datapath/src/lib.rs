//! WireGuard Sans-I/O data-plane (`defguard_boringtun`), `MagicSocket` demuxer, STUN client,
//! Disco hole-punching engine, and WebSocket Blind Relay client (`WP-S1-02`).

pub mod cryptokey;
pub mod disco_engine;
pub mod engine;
pub mod magic_socket;
pub mod peer_map;
pub mod rebind;
pub mod relay_client;
pub mod stun_client;

pub use cryptokey::{
    CryptokeyDropReason, CryptokeyMetricsSnapshot, CryptokeyValidator, FilterProtocol,
    PacketFilterPolicy, PacketFilterRule, ParsedIpv4Header, PortRange,
};
pub use disco_engine::{
    DiscoConfig, DiscoEngine, DiscoEvent, DiscoFilterContext, DiscoMetricsSnapshot,
    OutboundDiscoPacket,
};
pub use engine::{
    DatapathCommand, DatapathConfig, DatapathEngine, DatapathHandle, DatapathPeerStatus,
    DatapathStatusSnapshot,
};
pub use magic_socket::{
    BindReport, MAGIC_SOCKET_BUFFER_SIZE, MagicSocket, MagicSocketConfig, PacketBuffer,
    validate_tun_mtu,
};
pub use peer_map::{
    ApplyDiffReport, DecapsulateResult, PeerActivePath, PeerMap, PeerSendTarget, PeerSession,
};
pub use rebind::{
    REBIND_COMMAND_CHANNEL_CAPACITY, RebindCommand, RebindHandle, RebindOutcome, SocketRebinder,
};
pub use relay_client::{
    ConnectedRelayTransport, RelayClient, RelayClientConfig, RelayClientHandle,
    RelayConnectionState, RelayConnector, RelayEvent, RelayIoStream, RelayMetricsSnapshot,
    TlsRelayConnector,
};
pub use stun_client::{
    StunClient, StunClientConfig, StunObservation, StunProbeReport, collect_and_sort_candidates,
};
