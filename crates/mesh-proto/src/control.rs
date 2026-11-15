//! Control-plane HTTPS REST & WebSocket `/v1/netmap/stream` DTOs (`api-design.md` §1).

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use mesh_core::{NodeId, NodeName, OverlayCidr, OverlayIp, PublicKey};

use crate::netmap::{CandidateEndpoint, NatMappingKind, NetmapSnapshot};

/// Header name carrying the single-use `challenge_id` UUID (`api-design.md` §1.3).
pub const HEADER_CHALLENGE_ID: &str = "x-mesh-challenge-id";

/// Header name carrying base64-encoded 32-byte client `node_pubkey`.
pub const HEADER_NODE_PUBKEY: &str = "x-mesh-node-pubkey";

/// Header name carrying base64-encoded 24-byte `SalsaBox` nonce.
pub const HEADER_BOX_NONCE: &str = "x-mesh-box-nonce";

/// Header name carrying base64-encoded sealed `ProofPayload`.
pub const HEADER_AUTH_PROOF: &str = "x-mesh-auth-proof";

/// Client OS tag (`OPS-10`, `US-050 AC1`, `US-075`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetOs {
    /// macOS 13+.
    Darwin,
    /// Windows 10/11.
    Windows,
    /// Linux (Ubuntu/Debian/etc.).
    Linux,
    /// Android 10+ (`API 29+`).
    Android,
    /// iOS 15+.
    Ios,
}

/// Client CPU architecture tag (`OPS-10`, `US-050 AC1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetArch {
    /// 64-bit ARM (`aarch64`).
    Arm64,
    /// 64-bit x86 (`x86_64`).
    Amd64,
}

/// Request sent to `POST /v1/auth/challenge` (`api-design.md` §1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// Client WireGuard/Control public key.
    pub node_pubkey: PublicKey,
    /// Client Disco traversal public key.
    pub disco_pubkey: PublicKey,
    /// Control protocol version (`1`).
    pub protocol_version: u16,
    /// Semantic agent version string.
    pub agent_version: String,
    /// Client operating system tag.
    pub os: TargetOs,
    /// Client CPU architecture tag.
    pub arch: TargetArch,
}

/// Server response returned from `POST /v1/auth/challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    /// Single-use challenge UUID.
    pub challenge_id: NodeId,
    /// Server ephemeral X25519 public key used to seal `ProofPayload`.
    pub server_eph_pubkey: PublicKey,
    /// Base64-encoded 32-byte random challenge nonce.
    pub challenge_nonce: String,
    /// Authoritative server UTC Unix milliseconds.
    pub server_time_at_ms: u64,
    /// Challenge expiry timestamp in UTC Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Request sent to `POST /v1/nodes/register` (`api-design.md` §1.4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterNodeRequest {
    /// Node WireGuard public key.
    pub node_pubkey: PublicKey,
    /// Node Disco public key.
    pub disco_pubkey: PublicKey,
    /// Single- or bounded-use pre-authentication key (`"mpk_..."`).
    pub preauth_key: String,
    /// Requested RFC 1123 node name.
    pub node_name: NodeName,
    /// Optional previous node key being atomically rotated out (`US-032`).
    pub previous_node_pubkey: Option<PublicKey>,
}

impl Drop for RegisterNodeRequest {
    fn drop(&mut self) {
        self.preauth_key.zeroize();
    }
}

impl fmt::Debug for RegisterNodeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterNodeRequest")
            .field("node_pubkey", &self.node_pubkey)
            .field("disco_pubkey", &self.disco_pubkey)
            .field("preauth_key", &"[REDACTED]")
            .field("node_name", &self.node_name)
            .field("previous_node_pubkey", &self.previous_node_pubkey)
            .finish()
    }
}

/// Response returned from `POST /v1/nodes/register`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterNodeResponse {
    /// Assigned node UUID.
    pub node_id: NodeId,
    /// Assigned canonical RFC 1123 node label.
    pub node_name: NodeName,
    /// Assigned FQDN (`<node_name>.<domain_suffix>`).
    pub fqdn: String,
    /// Assigned overlay IPv4 address.
    pub overlay_ip: OverlayIp,
    /// Overlay IPv4 CIDR block.
    pub overlay_cidr: OverlayCidr,
    /// Optional identity key expiry timestamp in UTC milliseconds.
    pub key_expires_at_ms: Option<u64>,
    /// Initial atomic mesh network snapshot.
    pub netmap: NetmapSnapshot,
}

/// Request sent to `POST /v1/endpoints` (`api-design.md` §1.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpointsRequest {
    /// Validated candidate UDP endpoints.
    pub endpoints: Vec<CandidateEndpoint>,
    /// Observed NAT mapping type.
    pub nat_type: NatMappingKind,
    /// Highest `endpoint_version` acknowledged by this agent (`US-074`).
    pub acked_endpoint_version: u64,
}

/// Response returned from `POST /v1/endpoints`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpointsResponse {
    /// Current Netmap version after evaluating endpoint delta.
    pub netmap_version: u64,
    /// Server update timestamp in UTC milliseconds.
    pub updated_at_ms: u64,
}

/// Request sent to `POST /v1/disco/call-me-maybe` (`api-design.md` §1.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallMeMaybeRequest {
    /// Target peer UUID.
    pub dst_node_id: NodeId,
    /// Base64-encoded complete `MESHDS` encrypted `CallMeMaybe` frame (`172..=1024` bytes decoded).
    pub disco_frame_b64: String,
}

/// Text/JSON frames pushed from `meshd` -> `mesh-server` over `/v1/netmap/stream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientControlFrame {
    /// Candidate endpoint update and listener port ack.
    EndpointUpdate {
        /// Validated UDP candidate list.
        endpoints: Vec<CandidateEndpoint>,
        /// Observed NAT behavior.
        nat_type: NatMappingKind,
        /// Acknowledged server endpoint generation.
        acked_endpoint_version: u64,
    },
    /// Relayed encrypted NAT hole-punch request.
    CallMeMaybe {
        /// Target peer UUID.
        dst_node_id: NodeId,
        /// Base64-encoded `MESHDS` frame (`0x03`).
        disco_frame_b64: String,
    },
    /// Application heartbeat keep-alive that never bumps `netmap_version`.
    Heartbeat {
        /// Client UTC timestamp in milliseconds.
        sent_at_ms: u64,
        /// Last Netmap version applied locally.
        acked_netmap_version: u64,
    },
}

/// Terminal error kind forcing an agent to halt automatic retries when received over valid TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    /// Administrator revoked this node (`ErrorKind::NodeRevoked`).
    NodeRevoked,
    /// Node identity key expired (`ErrorKind::NodeKeyExpired`).
    NodeKeyExpired,
}

/// Text/JSON frames pushed from `mesh-server` -> `meshd` over `/v1/netmap/stream`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerControlFrame {
    /// Full atomic network map snapshot.
    NetmapSnapshot {
        /// Server dispatch UTC milliseconds.
        sent_at_ms: u64,
        /// Full Netmap payload.
        netmap: Box<NetmapSnapshot>,
    },
    /// Peer-to-peer NAT traversal frame relayed from an authenticated peer (`HR-G2-04`).
    CallMeMaybeRelay {
        /// Source peer UUID.
        src_node_id: NodeId,
        /// Source peer WireGuard public key.
        src_node_pubkey: PublicKey,
        /// Base64-encoded complete `MESHDS` frame (`0x03`).
        disco_frame_b64: String,
        /// Server dispatch UTC milliseconds.
        sent_at_ms: u64,
    },
    /// Immediate session termination notification (`US-034 AC5`).
    IdentityTerminated {
        /// Specific revocation or expiry classification.
        error_kind: TerminationReason,
        /// Human-readable public reason string.
        public_msg: String,
        /// Server UTC timestamp in milliseconds.
        occurred_at_ms: u64,
    },
    /// Server application heartbeat reply.
    Heartbeat {
        /// Server UTC timestamp in milliseconds.
        sent_at_ms: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::{ChallengeRequest, TargetArch, TargetOs, UpdateEndpointsRequest};
    use mesh_core::PublicKey;

    #[test]
    fn test_control_dtos_use_u16_version_and_reject_unknown_fields() {
        // Arrange
        let (Ok(node_pubkey), Ok(disco_pubkey)) = (
            PublicKey::from_bytes([7_u8; 32]),
            PublicKey::from_bytes([8_u8; 32]),
        ) else {
            return;
        };
        let req = ChallengeRequest {
            node_pubkey,
            disco_pubkey,
            protocol_version: 1_u16,
            agent_version: "0.1.0".to_owned(),
            os: TargetOs::Linux,
            arch: TargetArch::Amd64,
        };
        let encoded = serde_json::to_string(&req);
        assert!(encoded.is_ok());

        let unknown_endpoint_json =
            r#"{"endpoints":[],"nat_type":"unknown","acked_endpoint_version":1,"extra":1}"#;

        // Act & Assert
        let parsed: Result<UpdateEndpointsRequest, _> = serde_json::from_str(unknown_endpoint_json);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_target_os_serializes_android_and_ios_lowercase() {
        // Arrange & Act
        let android_json = serde_json::to_string(&TargetOs::Android);
        let ios_json = serde_json::to_string(&TargetOs::Ios);
        let parsed_android: Result<TargetOs, _> = serde_json::from_str("\"android\"");
        let parsed_ios: Result<TargetOs, _> = serde_json::from_str("\"ios\"");

        // Assert
        assert_eq!(android_json.ok().as_deref(), Some("\"android\""));
        assert_eq!(ios_json.ok().as_deref(), Some("\"ios\""));
        assert_eq!(parsed_android.ok(), Some(TargetOs::Android));
        assert_eq!(parsed_ios.ok(), Some(TargetOs::Ios));
    }
}
