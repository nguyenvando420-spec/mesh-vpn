//! Local Client CLI <-> Daemon (`meshd`) IPC DTOs (`meshd-ro` & `meshd-admin`, `api-design.md` §5).

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, Port, SpkiPin};

use crate::netmap::{CandidateEndpoint, NatMappingKind};

/// Overall lifecycle state of the `meshd` agent daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    /// Interface down or not yet configured.
    Stopped,
    /// Attempting TLS/Control/Relay handshake.
    Connecting,
    /// Tunnel active and synchronized with Control stream.
    Connected,
    /// Halted due to `ErrorKind::NodeKeyExpired`; re-auth required (`US-031`).
    ReauthRequired,
    /// Halted due to `ErrorKind::NodeRevoked`; tunnel torn down (`US-029`).
    Revoked,
    /// Control stream temporarily offline while cached P2P tunnel stays alive (`US-033`).
    Degraded,
}

/// Control TLS trust strategy currently used by `meshd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsAuthMode {
    /// Zero-TOFU leaf SPKI SHA-256 pinning.
    SpkiPin,
    /// CA-trusted certificate verification (`rustls-webpki`).
    SystemCa,
}

/// Active transport path state for an overlay peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivePathKind {
    /// Direct UDP hole-punched datapath.
    Direct,
    /// Blind Relay WebSocket datapath.
    Relay,
    /// No handshake established yet.
    None,
}

/// Status of the daemon's connection to the Control, Relay, and STUN infrastructure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConnectionStatus {
    /// Active Control HTTPS `<host_or_ip>:<port>`.
    pub control_endpoint: String,
    /// Active Relay HTTPS/WebSocket `<host_or_ip>:<port>`.
    pub relay_endpoint: String,
    /// Active STUN UDP endpoints.
    pub stun_endpoints: Vec<String>,
    /// Active TLS trust mode.
    pub tls_auth_mode: TlsAuthMode,
    /// Primary pinned SPKI fingerprint (`None` only in SystemCA mode).
    pub active_pin: Option<SpkiPin>,
    /// Secondary staged SPKI fingerprint during rotation.
    pub next_pin: Option<SpkiPin>,
    /// Whether the Control WebSocket stream is connected.
    pub control_connected: bool,
    /// Whether the Blind Relay WebSocket is connected.
    pub relay_connected: bool,
    /// Most recent measured Relay RTT in milliseconds.
    pub relay_rtt_ms: Option<u64>,
    /// Pending endpoint advertised during graceful port migration (`US-074`).
    pub migration_pending_endpoint: Option<String>,
    /// Public sanitized error description of the last failure, if any.
    pub last_error: Option<String>,
}

/// Local network interface, UDP socket, and NAT diagnostic summary for this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfNetworkStatus {
    /// Bound `MagicSocket` UDP port (`u16`).
    pub local_udp_port: u16,
    /// Bound physical egress interface name (e.g. `en0`, `eth0`, `Ethernet`).
    pub bound_physical_interface: Option<String>,
    /// Observed NAT mapping behavior.
    pub nat_type: NatMappingKind,
    /// Clarifying note explaining single-STUN-IP NAT classification scope.
    pub nat_classification_note: Option<String>,
    /// Warning if configured overlay CIDR overlaps local physical NIC subnets (`US-008 AC4`).
    pub overlay_conflict_warning: Option<String>,
    /// Warning if macOS Application Firewall may drop inbound unsolicited UDP.
    pub macos_firewall_warning: Option<String>,
    /// Current validated UDP candidate addresses.
    pub candidates: Vec<CandidateEndpoint>,
}

/// Per-peer runtime connectivity and byte counters returned by `mesh status` / `mesh peers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPeerStatus {
    /// Peer UUID.
    pub node_id: NodeId,
    /// Peer RFC 1123 node label.
    pub name: NodeName,
    /// Peer FQDN.
    pub fqdn: String,
    /// Peer overlay IPv4 address.
    pub overlay_ip: OverlayIp,
    /// Whether peer currently maintains a Control connection.
    pub online: bool,
    /// Current forwarding path (`direct`, `relay`, `none`).
    pub active_path: ActivePathKind,
    /// Established direct UDP `IP:port` if `active_path == Direct`.
    pub direct_endpoint: Option<String>,
    /// Latest measured RTT in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Latest WireGuard handshake UTC timestamp in milliseconds.
    pub last_handshake_at_ms: Option<u64>,
    /// Cumulative received transport bytes.
    pub rx_bytes: u64,
    /// Cumulative transmitted transport bytes.
    pub tx_bytes: u64,
}

/// Canonical alias for [`AgentPeerStatus`].
pub type PeerStatusDto = AgentPeerStatus;

/// Complete non-secret payload returned by `GET /v1/agent/status` and `GET /v1/agent/peers` (`US-039`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStatusResponse {
    /// Overall daemon state.
    pub daemon_state: DaemonState,
    /// Assigned local node UUID (`None` before first registration).
    pub node_id: Option<NodeId>,
    /// Assigned local node label.
    pub node_name: Option<NodeName>,
    /// Assigned local node FQDN.
    pub fqdn: Option<String>,
    /// Assigned local overlay IPv4 address.
    pub overlay_ip: Option<OverlayIp>,
    /// Overlay network CIDR block.
    pub overlay_cidr: Option<OverlayCidr>,
    /// Active TUN adapter name (`utunN`, `mesh0`, `Mesh`).
    pub tun_interface_name: Option<String>,
    /// Configured TUN MTU.
    pub tun_mtu: u16,
    /// Highest applied Netmap version.
    pub netmap_version: u64,
    /// Node identity key expiration UTC milliseconds.
    pub key_expires_at_ms: Option<u64>,
    /// Control/Relay/STUN connection summary.
    pub server_connection: Option<ServerConnectionStatus>,
    /// Local UDP & physical interface status.
    pub self_network: SelfNetworkStatus,
    /// Peer connectivity summaries.
    pub peers: Vec<AgentPeerStatus>,
}

/// Request sent to `POST /v1/agent/ping` (`api-design.md` §5.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingRequest {
    /// Target peer name, FQDN, or overlay IP.
    pub target: String,
    /// Number of Disco ping probes to send (`1..=64`).
    pub count: u16,
    /// If `true`, probe direct UDP candidates even if currently relayed.
    pub force_direct: bool,
    /// Per-probe timeout in milliseconds.
    pub timeout_ms: u64,
}

/// Canonical alias for [`PingRequest`].
pub type AgentPingRequest = PingRequest;

/// Path traversed by a single Disco ping probe sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PingVia {
    /// Delivered directly over UDP.
    Direct,
    /// Delivered over the Blind Relay WebSocket.
    Relay,
    /// Timed out waiting for a Pong.
    Timeout,
}

/// Single latency probe measurement inside [`PingResponse`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingSample {
    /// 1-based probe sequence number.
    pub seq: u16,
    /// Path taken (`direct`, `relay`, `timeout`).
    pub via: PingVia,
    /// Endpoint address queried/used for this sample (`None` on timeout).
    pub endpoint: Option<String>,
    /// Measured round-trip latency in milliseconds (`None` on timeout).
    pub rtt_ms: Option<f64>,
}

/// Response returned from `POST /v1/agent/ping`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingResponse {
    /// Resolved target peer name.
    pub target_name: NodeName,
    /// Resolved target overlay IPv4 address.
    pub target_overlay_ip: OverlayIp,
    /// Individual sequence results.
    pub samples: Vec<PingSample>,
    /// Number of probes transmitted.
    pub packets_sent: u16,
    /// Number of matching Disco Pongs received.
    pub packets_received: u16,
    /// Percentage packet loss (`0.0..=100.0`).
    pub loss_percent: f64,
    /// Minimum observed RTT in milliseconds (`None` if 100% loss).
    pub rtt_min_ms: Option<f64>,
    /// Arithmetic mean observed RTT in milliseconds.
    pub rtt_avg_ms: Option<f64>,
    /// Maximum observed RTT in milliseconds.
    pub rtt_max_ms: Option<f64>,
}

/// Canonical alias for [`PingResponse`].
pub type AgentPingResponse = PingResponse;

/// Response returned from `POST /v1/agent/netcheck` (`api-design.md` §5.2.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetcheckResponse {
    /// Whether outbound UDP traffic succeeded.
    pub udp_egress_ok: bool,
    /// Whether configured STUN server responded validly.
    pub stun_reachable: bool,
    /// STUN server `<ip>:<port>` probed.
    pub stun_endpoint_tested: Option<String>,
    /// Reflexive external IPv4 endpoint observed by STUN.
    pub reflexive_ipv4: Option<String>,
    /// Whether global IPv6 connectivity is available.
    pub ipv6_available: bool,
    /// Observed NAT mapping type.
    pub nat_mapping: NatMappingKind,
    /// Explanation note on NAT probe fidelity.
    pub nat_note: String,
    /// Whether Control/Relay HTTPS TCP endpoint is reachable.
    pub control_tcp_reachable: bool,
    /// Control TCP endpoint tested.
    pub control_tcp_endpoint_tested: Option<String>,
    /// Relay RTT measured during probe in milliseconds.
    pub relay_rtt_ms: Option<f64>,
    /// Actionable hint when non-standard ports are blocked by strict egress firewalls (`US-023 AC4`).
    pub diagnostic_hint: Option<String>,
}

/// Canonical alias for [`NetcheckResponse`].
pub type AgentNetcheckResponse = NetcheckResponse;

/// Privileged request sent to `POST /v1/agent/up` (`meshd-admin`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentUpRequest {
    /// Control server endpoint (`<host_or_ip>:<port>`).
    pub server_endpoint: String,
    /// Optional server port override validated via [`Port`].
    pub port_override: Option<Port>,
    /// Pinned TLS certificate SPKI SHA-256 fingerprint (`None` only for public CA/ACME).
    pub server_pin: Option<SpkiPin>,
    /// Optional pre-authentication key when registering or re-authenticating (`None` when resuming).
    pub preauth_key: Option<String>,
    /// Optional desired RFC 1123 device name (`None` defaults to sanitized OS hostname).
    pub node_name: Option<NodeName>,
}

impl Drop for AgentUpRequest {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preauth_key {
            key.zeroize();
        }
    }
}

impl fmt::Debug for AgentUpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentUpRequest")
            .field("server_endpoint", &self.server_endpoint)
            .field("port_override", &self.port_override)
            .field("server_pin", &self.server_pin)
            .field(
                "preauth_key",
                &self.preauth_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("node_name", &self.node_name)
            .finish()
    }
}

/// Privileged request sent to `POST /v1/agent/set` (`US-074 AC5`, `meshd-admin`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSetRequest {
    /// Updated Control server `<host_or_ip>:<port>`.
    pub server_endpoint: String,
    /// Optional updated SPKI pin.
    pub server_pin: Option<SpkiPin>,
}

/// Privileged request sent to `POST /v1/agent/rotate-key` (`US-032`, `meshd-admin`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRotateKeyRequest {
    /// Fresh pre-auth token authorizing key rotation (`--for <node>`).
    pub preauth_key: String,
}

impl Drop for AgentRotateKeyRequest {
    fn drop(&mut self) {
        self.preauth_key.zeroize();
    }
}

impl fmt::Debug for AgentRotateKeyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentRotateKeyRequest")
            .field("preauth_key", &"[REDACTED]")
            .finish()
    }
}

/// Generic acknowledgement response returned from `up`, `down`, `cleanup`, `set`, `rotate-key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentActionResponse {
    /// Resulting daemon state after action completes.
    pub state: DaemonState,
    /// Concise status summary for CLI stdout.
    pub message: String,
}

/// Response returned from `POST /v1/agent/bugreport` (`US-041`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BugreportResponse {
    /// Filesystem path of the redacted diagnostic archive (`<= 20 MB`).
    pub bundle_path: String,
    /// Byte size of the generated archive.
    pub size_bytes: u64,
    /// Number of secret patterns scrubbed/redacted during generation.
    pub scrubbed_items: u32,
}

/// Canonical alias for [`BugreportResponse`].
pub type AgentBugreportResponse = BugreportResponse;

#[cfg(test)]
mod tests {
    use super::{AgentRotateKeyRequest, AgentSetRequest};

    #[test]
    fn test_agent_ipc_dtos_reject_unknown_fields_and_redact_keys() {
        // Arrange
        let rotate = AgentRotateKeyRequest {
            preauth_key: "mpk_super_secret_value".to_owned(),
        };
        let dbg = format!("{rotate:?}");
        let raw_extra = r#"{"server_endpoint":"203.0.113.10:8443","server_pin":null,"extra":1}"#;

        // Act
        let parsed: Result<AgentSetRequest, _> = serde_json::from_str(raw_extra);

        // Assert
        assert!(!dbg.contains("mpk_super_secret_value"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(parsed.is_err());
    }
}
