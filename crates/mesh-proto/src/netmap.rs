//! Network map (`NetmapSnapshot`), peer definitions, relay routing hints, and pin distribution.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey, SpkiPin};

/// Origin class of a peer UDP endpoint candidate (`api-design.md` §1.1, §1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    /// Private LAN address discovered on physical interface.
    Lan,
    /// Global/routable IPv6 address.
    Ipv6,
    /// Public address discovered via STUN Binding response.
    Reflexive,
}

/// Validated peer UDP endpoint paired with its discovery provenance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEndpoint {
    /// Socket address (`IP:port`).
    pub addr: SocketAddr,
    /// Discovery mechanism source.
    pub source: CandidateSource,
}

/// NAT address mapping classification observed during `netcheck` / STUN probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMappingKind {
    /// Endpoint-Independent Mapping or Address-Dependent Mapping (P2P friendly).
    EimOrAdm,
    /// Port-dependent hard NAT requiring Relay fallback or birthday attack.
    PortDependent,
    /// Classification incomplete or offline.
    Unknown,
}

/// Control/Relay/STUN server topology pushed in Netmap updates (`US-074`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayMap {
    /// Monotonically incremented endpoint configuration generation (`US-074`).
    pub endpoint_version: u64,
    /// Control HTTPS endpoint formatted as `<host_or_ip>:<port>`.
    pub control_tcp_endpoint: String,
    /// Relay HTTPS/WebSocket endpoint formatted as `<host_or_ip>:<port>`.
    pub relay_tcp_endpoint: String,
    /// Configured UDP STUN endpoints (`<host_or_ip>:<port>`).
    pub stun_udp_endpoints: Vec<String>,
}

/// Wire representation of active and optional next TLS SPKI pin (`US-047 AC5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinSetDto {
    /// Primary pinned SPKI digest (`"sha256:<64hex>"`).
    pub active_pin: SpkiPin,
    /// Secondary staged SPKI digest accepted during zero-downtime key rotation.
    pub next_pin: Option<SpkiPin>,
}

/// Per-peer metadata synchronized across the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// Peer unique UUID identifier.
    pub node_id: NodeId,
    /// Peer RFC 1123 node label.
    pub name: NodeName,
    /// Peer FQDN (`<name>.<domain_suffix>`).
    pub fqdn: String,
    /// Assigned overlay IPv4 address.
    pub overlay_ip: OverlayIp,
    /// WireGuard X25519 public key.
    pub node_pubkey: PublicKey,
    /// Authenticated Disco X25519 public key.
    pub disco_pubkey: PublicKey,
    /// Current validated candidate UDP endpoints.
    pub endpoints: Vec<CandidateEndpoint>,
    /// Assigned home Blind Relay endpoint.
    pub relay_home: String,
    /// Node identity key expiry UTC ms (`None` if non-expiring).
    pub key_expires_at_ms: Option<u64>,
    /// Whether the peer currently holds an active Control stream.
    pub online: bool,
}

/// Full atomic overlay topology snapshot pushed over `/v1/nodes/register` and `/v1/netmap/stream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetmapSnapshot {
    /// Strictly monotonically increasing map version allocated by the control server.
    pub netmap_version: u64,
    /// Server generation UTC timestamp in milliseconds.
    pub generated_at_ms: u64,
    /// Overlay IPv4 CIDR block shared by the mesh.
    pub overlay_cidr: OverlayCidr,
    /// DNS suffix appended to node names inside `/etc/hosts`.
    pub domain_suffix: String,
    /// Current Control/Relay/STUN server addresses (`US-074`).
    pub relay_map: RelayMap,
    /// Current TLS SPKI pin trust material.
    pub pin_set: PinSetDto,
    /// Active peers (excluding revoked nodes and self).
    pub peers: Vec<PeerEntry>,
}

#[cfg(test)]
mod tests {
    use super::CandidateEndpoint;

    #[test]
    fn test_netmap_dto_rejects_unknown_fields() {
        // Arrange
        let raw = r#"{"addr":"192.168.1.45:51829","source":"lan","bogus":true}"#;

        // Act & Assert
        let parsed: Result<CandidateEndpoint, _> = serde_json::from_str(raw);
        assert!(parsed.is_err());
    }
}
