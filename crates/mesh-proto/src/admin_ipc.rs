//! Server Local Admin Unix Socket IPC DTOs (`/run/mesh-server/admin.sock`) and
//! Read-Only Observability HTTP response schemas (`/healthz`, `/readyz`) (`api-design.md` §4, §6).

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use mesh_core::{KeyId, NodeId, NodeName, OverlayIp, Port, SpkiPin};

/// Storage durability level achieved during an urgent admin revoke/expire action (`Codex R2 #2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceTier {
    /// Persisted atomically in `redb`.
    Redb,
    /// Main DB unavailable (e.g. `ENOSPC`); written to pre-reserved emergency revocation slot.
    EmergencySlot,
    /// Enforced immediately in RAM only (volatile until disk recovers).
    RamOnly,
}

/// Immediate response for `POST /v1/admin/nodes/{ref}/revoke`, `expire`, or key revoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeActionResponse {
    /// Target node or key identifier.
    pub target_id: String,
    /// Whether the revocation or expiry state was applied.
    pub revoked: bool,
    /// Whether in-memory `RevokedSet` / `ExpiredSet` and socket teardown completed immediately.
    pub ram_enforced: bool,
    /// Whether durable storage write (`redb` or `emergency_slot`) succeeded.
    pub persisted: bool,
    /// Storage durability tier achieved for restart persistence.
    pub persistence_tier: PersistenceTier,
    /// Server UTC timestamp in milliseconds when action took effect.
    pub acted_at_ms: u64,
}

/// Request sent to `POST /v1/admin/preauth-keys` (`api-design.md` §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePreAuthKeyRequest {
    /// Key lifetime in seconds from creation.
    pub ttl_secs: u64,
    /// Allow multiple devices (`true`) or single device registration (`false`).
    pub reusable: bool,
    /// Maximum allowed uses (must be `>= 1`; `1` when `!reusable`).
    pub max_uses: u32,
    /// Whether registered nodes are auto-reaped after disconnect timeout.
    pub is_ephemeral: bool,
    /// Optional offline expiry window for ephemeral nodes in seconds.
    pub ephemeral_timeout_secs: Option<u32>,
    /// Optional node UUID or name to re-authenticate exclusively (`US-031 AC5`).
    pub target_node: Option<String>,
}

/// One-time response containing the plaintext `raw_key` when creating a pre-auth token (`US-002`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAuthKeyCreatedResponse {
    /// Stored key metadata UUID.
    pub key_id: KeyId,
    /// Plaintext pre-authentication key returned once (`mpk_...`).
    pub raw_key: String,
    /// Creation timestamp in UTC milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in UTC milliseconds.
    pub expires_at_ms: u64,
    /// Reusable flag.
    pub reusable: bool,
    /// Maximum allowed registrations.
    pub max_uses: u32,
    /// Target node UUID if scoped for node key re-auth.
    pub target_node_id: Option<NodeId>,
    /// Configured Control server `<host>:<port>`.
    pub server_endpoint: String,
    /// Active SPKI pin expected on TLS handshakes.
    pub active_pin: Option<SpkiPin>,
    /// Default ready-to-run client join command hint.
    pub cli_join_command: String,
    /// Ready-to-run file-based client join command.
    pub join_command_file: String,
    /// Ready-to-run stdin-based client join command.
    pub join_command_stdin: String,
}

impl Drop for PreAuthKeyCreatedResponse {
    fn drop(&mut self) {
        self.raw_key.zeroize();
    }
}

impl fmt::Debug for PreAuthKeyCreatedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreAuthKeyCreatedResponse")
            .field("key_id", &self.key_id)
            .field("raw_key", &"[REDACTED]")
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("reusable", &self.reusable)
            .field("max_uses", &self.max_uses)
            .field("target_node_id", &self.target_node_id)
            .field("server_endpoint", &self.server_endpoint)
            .field("active_pin", &self.active_pin)
            .field("cli_join_command", &self.cli_join_command)
            .field("join_command_file", &self.join_command_file)
            .field("join_command_stdin", &self.join_command_stdin)
            .finish()
    }
}

/// Public metadata returned by `GET /v1/admin/preauth-keys` (never exposes plaintext secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAuthKeySummary {
    /// Key UUID.
    pub key_id: KeyId,
    /// Lifecycle status (`"active"`, `"exhausted"`, `"expired"`, or `"revoked"`).
    pub status: String,
    /// Creation UTC milliseconds.
    pub created_at_ms: u64,
    /// Expiration UTC milliseconds.
    pub expires_at_ms: u64,
    /// Reusable flag.
    pub reusable: bool,
    /// Remaining/consumed count.
    pub used_count: u32,
    /// Configured cap.
    pub max_uses: u32,
    /// Ephemeral node flag.
    pub is_ephemeral: bool,
    /// Optional target node UUID restriction.
    pub target_node_id: Option<NodeId>,
}

/// Administrative summary row for `GET /v1/admin/nodes` (`US-012 AC1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminNodeSummary {
    /// Node UUID.
    pub node_id: NodeId,
    /// Normalized RFC 1123 hostname.
    pub name: NodeName,
    /// Assigned overlay IPv4 address.
    pub overlay_ip: OverlayIp,
    /// Lifecycle status (`"active"`, `"expired"`, `"revoked"`).
    pub status: String,
    /// Whether a live Control stream is open.
    pub online: bool,
    /// Last seen UTC milliseconds.
    pub last_seen_at_ms: u64,
    /// Optional node identity key expiration UTC milliseconds.
    pub key_expires_at_ms: Option<u64>,
    /// Client OS tag (`"darwin"`, `"windows"`, `"linux"`).
    pub os: String,
    /// Client CPU arch tag (`"arm64"`, `"amd64"`).
    pub arch: String,
    /// Agent software version.
    pub agent_version: String,
    /// Highest `endpoint_version` acknowledged by this node (`US-074 AC7`).
    pub acked_endpoint_version: u64,
}

/// Request sent to `POST /v1/admin/nodes/{ref}/rename`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameNodeRequest {
    /// Validated replacement RFC 1123 node name.
    pub new_name: NodeName,
}

/// Request sent to `POST /v1/admin/nodes/{ref}/expire`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpireNodeRequest {
    /// If `true`, clears key expiry (`--never` for trusted VPS servers).
    pub never: bool,
}

/// Response returned from `GET /v1/admin/server/status` (`US-074 AC7`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerAdminStatusResponse {
    /// Active TCP Control/Relay bind address (`<ip>:<port>`).
    pub control_tcp_listen: String,
    /// Active UDP STUN bind address (`<ip>:<port>`).
    pub stun_udp_listen: String,
    /// Configured TLS mode (`"ip_pinned"`, `"acme"`, or `"reverse_proxy"`).
    pub tls_mode: String,
    /// Explicit TLS client trust policy tag (`"spki_pin"` or `"system_ca"`).
    pub tls_auth_mode: String,
    /// Active TLS certificate SPKI pin (`None` in CA-only mode without pinning).
    pub active_pin: Option<SpkiPin>,
    /// Secondary staged SPKI pin during certificate rotation.
    pub next_pin: Option<SpkiPin>,
    /// Leaf certificate expiration UTC milliseconds (`None` if reverse-proxy terminated).
    pub cert_expires_at_ms: Option<u64>,
    /// Current Netmap version.
    pub netmap_version: u64,
    /// Current `endpoint_version` for port-migration tracking.
    pub endpoint_version: u64,
    /// Active concurrent Blind Relay sessions on `/v1/relay`.
    pub relay_sessions_active: u64,
    /// Nodes still holding an older `acked_endpoint_version` during port migration.
    pub unacked_migration_nodes: Vec<String>,
    /// Whether main `redb` database reported disk degradation (`ENOSPC`).
    pub db_degraded: bool,
}

/// Canonical alias for [`ServerAdminStatusResponse`].
pub type ServerStatusResponse = ServerAdminStatusResponse;

/// Response returned from `POST /v1/admin/server/backup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCreatedResponse {
    /// Path of created verified atomic snapshot archive.
    pub snapshot_path: String,
    /// Lowercase SHA-256 checksum written to companion `.sha256` file.
    pub sha256_hex: String,
    /// Snapshot archive size in bytes.
    pub size_bytes: u64,
    /// Creation timestamp in UTC milliseconds.
    pub created_at_ms: u64,
}

/// Backward-compatible alias for [`BackupCreatedResponse`].
pub type BackupActionResponse = BackupCreatedResponse;

/// Request sent to `POST /v1/admin/server/restore` (`US-045`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBackupRequest {
    /// Archive path to verify and restore.
    pub snapshot_path: String,
    /// Enforce companion `.sha256` verification prior to swap.
    pub verify_sha256: bool,
}

/// Response returned from `POST /v1/admin/server/restore` (`US-045`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBackupResponse {
    /// Whether atomic database + identity restore succeeded.
    pub restored: bool,
    /// Restored Netmap version from snapshot.
    pub netmap_version: u64,
    /// Total node records loaded after restore.
    pub node_count: u64,
}

/// Request sent to `POST /v1/admin/server/migrate-endpoint` (`US-074`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateEndpointRequest {
    /// Optional updated Control/Relay host or public IP.
    pub host: Option<String>,
    /// Optional replacement Control/Relay HTTPS TCP port.
    pub tcp_port: Option<Port>,
    /// Optional replacement STUN UDP port.
    pub stun_port: Option<Port>,
    /// Optional replacement TLS mode (`"ip_pinned"`, `"acme"`, `"reverse_proxy"`).
    pub tls_mode: Option<String>,
    /// Optional dual-listener transition window duration in seconds.
    pub transition_window_secs: Option<u64>,
    /// Optional extension seconds added to the active transition window (`--extend-window`).
    pub extend_window_secs: Option<u64>,
}

/// Response returned from `POST /v1/admin/server/migrate-endpoint` (`US-074`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateEndpointResponse {
    /// Incremented `endpoint_version`.
    pub endpoint_version: u64,
    /// Incremented `netmap_version`.
    pub netmap_version: u64,
    /// Updated Control/Relay TCP endpoint string (`<host>:<port>`).
    pub control_tcp_endpoint: String,
    /// Updated STUN UDP endpoint string (`<host>:<port>`).
    pub stun_udp_endpoint: String,
    /// UTC milliseconds when legacy listener transition window shuts down (`None` if immediate).
    pub transition_deadline_at_ms: Option<u64>,
}

/// TLS key rotation subcommand action (`US-047 AC5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotateTlsKeyAction {
    /// Stage a secondary keypair (`next_pin`) and push via Netmap before switching.
    Stage,
    /// Promote staged `next_pin` to primary `active_pin` cleanly.
    Promote,
}

/// Request sent to `POST /v1/admin/server/rotate-tls-key` (`US-047 AC5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateTlsKeyRequest {
    /// Rotation stage (`stage` vs `promote`).
    pub action: RotateTlsKeyAction,
}

/// Response returned from `POST /v1/admin/server/rotate-tls-key` (`US-047 AC5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateTlsKeyResponse {
    /// Current primary certificate SPKI pin.
    pub active_pin: Option<SpkiPin>,
    /// Currently staged secondary certificate SPKI pin, if any.
    pub next_pin: Option<SpkiPin>,
    /// Resulting Netmap version pushed to connected agents.
    pub netmap_version: u64,
    /// `true` if a staged pin is now live.
    pub staged: bool,
    /// `true` if promotion completed.
    pub promoted: bool,
}

/// Single append-only security/admin audit record returned by `GET /v1/admin/audit-events` (`US-013`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventDto {
    /// Monotonic audit log sequence number.
    pub seq: u64,
    /// Event creation UTC timestamp in milliseconds.
    pub occurred_at_ms: u64,
    /// Authenticated caller / actor identity (`uid:...` or node UUID).
    pub actor: String,
    /// Canonical audit action identifier (e.g. `node_revoked`, `preauthkey_created`).
    pub action: String,
    /// Optional target node or key reference.
    pub target_id: Option<String>,
    /// Action outcome (`"ok"` or `"denied"`).
    pub outcome: String,
    /// Non-secret contextual detail.
    pub detail: Option<String>,
}

/// Response returned from `GET /v1/admin/audit-events` (`US-013`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListAuditEventsResponse {
    /// Ordered audit events matching the requested limit.
    pub events: Vec<AuditEventDto>,
}

/// Single host/server security baseline check entry (`mesh server doctor` / hardening check).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardeningCheckItem {
    /// Stable check identifier (e.g. `socket_dir_mode`, `non_root_uid`).
    pub check_id: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Actionable remediation or confirmation message.
    pub detail: String,
}

/// Aggregated response returned from server hardening self-check (`US-056`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardeningCheckResponse {
    /// `true` iff every check item passed.
    pub all_passed: bool,
    /// Individual baseline verification checks.
    pub items: Vec<HardeningCheckItem>,
}

/// JSON body for `GET /healthz` (`api-design.md` §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    /// Fixed `"alive"` status while process runs.
    pub status: String,
}

/// JSON body for `GET /readyz` (`api-design.md` §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessResponse {
    /// `"ready"` when HTTP 200, `"not_ready"` when HTTP 503.
    pub status: String,
    /// Whether `redb` is healthy and not in `ENOSPC` degraded state.
    pub db_healthy: bool,
    /// Whether the Control/Relay HTTPS TCP listener is active.
    pub control_tcp_listener_healthy: bool,
    /// Whether the embedded STUN UDP listener is active.
    pub stun_udp_listener_healthy: bool,
    /// Optional non-sensitive reason describing why readiness failed.
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::HardeningCheckResponse;

    #[test]
    fn test_admin_ipc_dtos_reject_unknown_fields() {
        // Arrange
        let raw = r#"{"all_passed":true,"items":[],"rogue_field":123}"#;

        // Act & Assert
        let parsed: Result<HardeningCheckResponse, _> = serde_json::from_str(raw);
        assert!(parsed.is_err());
    }
}
