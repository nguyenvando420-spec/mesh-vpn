//! UniFFI `0.29.5` types, error taxonomy, opaque secret session, and callback interface
//! (`ADR-014`, `mobile-ffi-and-storage-design.md` §2).

use std::fmt;
use std::sync::Mutex as StdMutex;

use mesh_client::diagnostics::scrub_diagnostic_secrets;
use mesh_core::defaults::MAX_RO_IPC_BODY_BYTES;
use mesh_core::{AppError, ErrorKind, NodeName, Port, SpkiPin, parse_join_uri};
use mesh_crypto::PreAuthToken;
use mesh_crypto::keys::mask_preauth_token;
use mesh_net::nat64::Nat64Prefix;
use mesh_proto::agent_ipc::{
    ActivePathKind, AgentStatusResponse, DaemonState, NetcheckResponse, PingResponse, PingVia,
    TlsAuthMode,
};
use mesh_proto::netmap::NatMappingKind;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, ZeroizeOnDrop, Zeroizing};

const MOBILE_IPC_HARD_LIMIT_BYTES: usize = MAX_RO_IPC_BODY_BYTES;
const FIXED_UNAUTHENTICATED_MSG: &str = "authentication failed";

/// Target mobile operating system flavor passed at engine initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobilePlatformKind {
    /// Android `VpnService` in-process engine.
    Android,
    /// iOS `NEPacketTunnelProvider` or container enrollment helper.
    Ios,
}

/// High-level lifecycle state displayed to Android and iOS clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobileDaemonState {
    /// Tunnel stopped or not yet started.
    Stopped,
    /// Connecting to Control / Relay / STUN infrastructure.
    Connecting,
    /// Tunnel active and synchronized with Control plane.
    Connected,
    /// Identity key expired; re-enrollment required.
    ReauthRequired,
    /// Node explicitly revoked by administrator.
    Revoked,
    /// Control stream degraded while P2P cached session stays alive.
    Degraded,
    /// Control server rejected mobile `TargetOs`; server upgrade needed.
    ServerUpgradeRequired,
    /// Device encrypted storage unavailable prior to first unlock.
    DeviceLocked,
}

/// Control TLS certificate trust mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobileTlsAuthMode {
    /// Fail-closed SHA-256 leaf SPKI fingerprint pinning.
    SpkiPin,
    /// Platform root store CA verification (domain names only).
    SystemCa,
}

/// Active peer transport datapath classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobileActivePathKind {
    /// Direct hole-punched UDP datapath.
    Direct,
    /// Blind Relay WebSocket datapath.
    Relay,
    /// No active datapath yet.
    None,
}

/// Observed NAT address mapping behavior from STUN probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobileNatKind {
    /// Mapping behavior unknown or offline.
    Unknown,
    /// Endpoint-independent / full-cone friendly mapping.
    EndpointIndependent,
    /// Address-dependent mapping.
    AddressDependent,
    /// Address- and port-dependent symmetric NAT.
    AddressAndPortDependent,
}

/// Transport leg traversed by an interactive ping sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobilePingVia {
    /// Direct UDP peer-to-peer probe.
    Direct,
    /// Relayed probe through Blind Relay.
    Relay,
    /// Probe timed out before receiving Disco Pong.
    Timeout,
}

/// Underlay connectivity transition emitted by platform network monitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobileNetEventKind {
    /// Active physical network interface switched (e.g. Wi-Fi to LTE).
    InterfaceChanged,
    /// Local IPv4/IPv6 addresses changed on the active physical interface.
    AddressChanged,
    /// System DNS resolvers or NAT64 discovery changed.
    DnsServersChanged,
    /// Physical connectivity lost.
    ConnectivityLost,
    /// Physical connectivity restored.
    ConnectivityRestored,
}

/// Non-fatal operational warnings surfaced to Kotlin/Swift UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum MobileWarningKind {
    /// Physical LAN/CGNAT subnet overlaps the mesh overlay CIDR (`US-037`).
    OverlaySubnetConflict,
    /// Android "Block connections without VPN" Lockdown mode is active.
    AndroidLockdownActive,
    /// Android Strict Private DNS is active and may bypass Split-DNS.
    AndroidPrivateDnsStrict,
    /// iOS Jetsam low-memory pressure triggered defensive shedding.
    IosLowMemoryPressure,
    /// Server reported HTTP 400 compatibility rejection requiring server upgrade.
    ProtocolServerUpgradeNeeded,
    /// Keystore/Keychain unavailable before first device unlock or invalidated.
    DeviceKeystoreLocked,
}

/// Standardized error enum across the UniFFI boundary preserving `SEC-05`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    /// Caller provided invalid input or state precondition failed.
    #[error("invalid argument: {message}")]
    InvalidArgument {
        /// Machine-readable wire error code (`E_INVALID_ARG`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// SEC-05 invariant: `message` is always fixed to `"authentication failed"`.
    #[error("{message}")]
    Unauthenticated {
        /// Machine-readable wire error code (`E_UNAUTHENTICATED`).
        error_code: String,
        /// Fixed constant `"authentication failed"`.
        message: String,
    },
    /// OS permission or policy denied the requested operation.
    #[error("permission denied: {message}")]
    PermissionDenied {
        /// Machine-readable wire error code (`E_PERM_DENIED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Administrator revoked this node.
    #[error("node revoked: {message}")]
    NodeRevoked {
        /// Machine-readable wire error code (`E_NODE_REVOKED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Node identity key expired and requires re-enrollment.
    #[error("node key expired: {message}")]
    NodeKeyExpired {
        /// Machine-readable wire error code (`E_NODE_KEY_EXPIRED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Requested entity was not found.
    #[error("not found: {message}")]
    NotFound {
        /// Machine-readable wire error code (`E_NOT_FOUND`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// State conflict such as colliding node name or address pool exhaustion.
    #[error("conflict: {message}")]
    Conflict {
        /// Machine-readable wire error code (`E_CONFLICT`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Rate limiter temporarily rejected the request.
    #[error("rate limited: {message}")]
    RateLimited {
        /// Machine-readable wire error code (`E_RATE_LIMITED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Control/Relay or network path is temporarily unavailable.
    #[error("unavailable: {message}")]
    Unavailable {
        /// Machine-readable wire error code (`E_UNAVAILABLE`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Device wall clock differs materially from server TLS validity window.
    #[error("clock skew detected: {message}")]
    ClockSkew {
        /// Machine-readable wire error code (`E_CLOCK_SKEW`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Server TLS leaf SPKI fingerprint mismatched configured pin (Zero-TOFU).
    #[error("SPKI pin mismatch: {message}")]
    PinMismatch {
        /// Machine-readable wire error code (`E_PIN_MISMATCH`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Server rejected mobile platform / protocol version (`v0.1.0-rc1` compatibility guard).
    #[error("server upgrade required: {message}")]
    ServerUpgradeRequired {
        /// Machine-readable error code (`E_SERVER_UPGRADE_REQUIRED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Hardware keystore KEK was invalidated or sealed identity blob corrupted; re-enroll needed.
    #[error("keystore invalidated: {message}")]
    KeystoreInvalidated {
        /// Machine-readable error code (`E_KEYSTORE_INVALIDATED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Device is still locked before first unlock (`Direct Boot` / `errSecInteractionNotAllowed`).
    #[error("device locked: {message}")]
    DeviceLocked {
        /// Machine-readable error code (`E_DEVICE_LOCKED`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
    /// Unexpected internal error.
    #[error("internal error: {message}")]
    Internal {
        /// Machine-readable wire error code (`E_INTERNAL`).
        error_code: String,
        /// Sanitized human-readable explanation.
        message: String,
    },
}

impl MobileError {
    /// Builds an [`InvalidArgument`](Self::InvalidArgument) error with scrubbed text.
    #[must_use]
    pub fn invalid_argument(message: impl AsRef<str>) -> Self {
        let (clean, _) = scrub_diagnostic_secrets(message.as_ref());
        Self::InvalidArgument {
            error_code: ErrorKind::InvalidArgument.wire_code().to_owned(),
            message: clean,
        }
    }

    /// Builds an [`Unavailable`](Self::Unavailable) error with scrubbed text.
    #[must_use]
    pub fn unavailable(message: impl AsRef<str>) -> Self {
        let (clean, _) = scrub_diagnostic_secrets(message.as_ref());
        Self::Unavailable {
            error_code: ErrorKind::Unavailable.wire_code().to_owned(),
            message: clean,
        }
    }

    /// Builds an [`Internal`](Self::Internal) error with scrubbed text.
    #[must_use]
    pub fn internal(message: impl AsRef<str>) -> Self {
        let (clean, _) = scrub_diagnostic_secrets(message.as_ref());
        Self::Internal {
            error_code: ErrorKind::Internal.wire_code().to_owned(),
            message: clean,
        }
    }

    /// Returns a constant `SEC-05` unauthenticated error.
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self::Unauthenticated {
            error_code: ErrorKind::Unauthenticated.wire_code().to_owned(),
            message: FIXED_UNAUTHENTICATED_MSG.to_owned(),
        }
    }

    /// Converts a platform-bridge [`MobileError`] into a tagged [`AppError`].
    #[must_use]
    pub fn to_app_error(&self) -> AppError {
        match self {
            Self::InvalidArgument { message, .. } => AppError::invalid_argument(message.clone()),
            Self::Unauthenticated { .. } => AppError::unauthenticated(FIXED_UNAUTHENTICATED_MSG),
            Self::PermissionDenied { message, .. } => AppError::permission_denied(message.clone()),
            Self::NodeRevoked { message, .. } => {
                AppError::new(ErrorKind::NodeRevoked, message.clone())
            }
            Self::NodeKeyExpired { message, .. } => {
                AppError::new(ErrorKind::NodeKeyExpired, message.clone())
            }
            Self::NotFound { message, .. } => AppError::not_found(message.clone()),
            Self::Conflict { message, .. } => AppError::conflict(message.clone()),
            Self::RateLimited { message, .. } => {
                AppError::new(ErrorKind::RateLimited, message.clone())
            }
            Self::Unavailable { message, .. } => AppError::unavailable(message.clone()),
            Self::ClockSkew { message, .. } => AppError::clock_skew(message.clone()),
            Self::PinMismatch { message, .. } => AppError::pin_mismatch(message.clone()),
            Self::ServerUpgradeRequired { message, .. } => {
                AppError::invalid_argument(format!("protocol_incompatible: {message}"))
            }
            Self::KeystoreInvalidated { message, .. } => {
                AppError::internal(format!("keystore_invalidated: {message}"))
            }
            Self::DeviceLocked { message, .. } => {
                AppError::unavailable(format!("device_locked: {message}"))
            }
            Self::Internal { message, .. } => AppError::internal(message.clone()),
        }
    }

    /// Returns `true` when this error represents a permanently invalidated OS keystore/DEK.
    #[must_use]
    pub const fn is_keystore_invalidated(&self) -> bool {
        matches!(self, Self::KeystoreInvalidated { .. })
    }

    /// Returns `true` when this error represents pre-unlock locked device storage.
    #[must_use]
    pub const fn is_device_locked(&self) -> bool {
        matches!(self, Self::DeviceLocked { .. })
    }
}

impl From<AppError> for MobileError {
    fn from(err: AppError) -> Self {
        let code = err.kind().wire_code().to_owned();
        if err.kind() == ErrorKind::Unauthenticated {
            return Self::Unauthenticated {
                error_code: code,
                message: FIXED_UNAUTHENTICATED_MSG.to_owned(),
            };
        }
        let (clean_msg, _) = scrub_diagnostic_secrets(err.public_message());
        let (clean_detail, _) = err
            .internal_detail()
            .map_or_else(|| (String::new(), 0), scrub_diagnostic_secrets);
        let lower = format!("{clean_msg} {clean_detail}").to_ascii_lowercase();

        if lower.contains("keystore_invalidated")
            || lower.contains("keystore invalidated")
            || lower.contains("keypermanentlyinvalidated")
            || lower.contains("aeadbadtag")
        {
            let msg = if clean_msg == "internal error" {
                "hardware keystore invalidated or sealed identity corrupted; re-enroll required"
                    .to_owned()
            } else {
                clean_msg
            };
            return Self::KeystoreInvalidated {
                error_code: "E_KEYSTORE_INVALIDATED".to_owned(),
                message: msg,
            };
        }
        if lower.contains("device_locked")
            || lower.contains("device locked")
            || lower.contains("errsecinteractionnotallowed")
            || lower.contains("-25308")
            || lower.contains("direct boot")
        {
            let msg = if clean_msg == "internal error" {
                "device credential storage locked before first unlock".to_owned()
            } else {
                clean_msg
            };
            return Self::DeviceLocked {
                error_code: "E_DEVICE_LOCKED".to_owned(),
                message: msg,
            };
        }

        if err.kind() == ErrorKind::InvalidArgument
            && (lower.contains("protocol_incompatible")
                || lower.contains("unknown variant")
                || lower.contains("protocol incompatible")
                || lower.contains("agent upgrade required")
                || lower.contains("unsupported os")
                || lower.contains("unsupported protocol"))
        {
            return Self::ServerUpgradeRequired {
                error_code: "E_SERVER_UPGRADE_REQUIRED".to_owned(),
                message: clean_msg,
            };
        }

        match err.kind() {
            ErrorKind::InvalidArgument => Self::InvalidArgument {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::Unauthenticated => Self::Unauthenticated {
                error_code: code,
                message: FIXED_UNAUTHENTICATED_MSG.to_owned(),
            },
            ErrorKind::PermissionDenied => Self::PermissionDenied {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::NodeRevoked => Self::NodeRevoked {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::NodeKeyExpired => Self::NodeKeyExpired {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::NotFound => Self::NotFound {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::Conflict => Self::Conflict {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::RateLimited => Self::RateLimited {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::Unavailable => Self::Unavailable {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::ClockSkew => Self::ClockSkew {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::PinMismatch => Self::PinMismatch {
                error_code: code,
                message: clean_msg,
            },
            ErrorKind::Internal => Self::Internal {
                error_code: code,
                message: clean_msg,
            },
        }
    }
}

/// Engine construction settings supplied by Android/iOS host wrappers.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileEngineInitConfig {
    /// Target mobile OS.
    pub platform: MobilePlatformKind,
    /// Mobile app / extension version reported to Control.
    pub agent_version: String,
    /// Optional suggested RFC 1123 node name fallback.
    pub default_node_name: Option<String>,
    /// Directory writable by extension/app for temporary diagnostics artifacts.
    pub log_dir_path: String,
}

/// Non-secret summary extracted from a `mesh://join?v=1&...` enrollment URI (`OQ-MOB-03`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileJoinUriData {
    /// Schema version (`1`).
    pub version: u8,
    /// Control endpoint formatted as `<host_or_ip>:<port>`.
    pub server_endpoint: String,
    /// TLS verification policy (`SpkiPin` or `SystemCa`).
    pub tls_auth_mode: MobileTlsAuthMode,
    /// SHA-256 SPKI pin when `tls_auth_mode == SpkiPin`.
    pub server_pin: Option<String>,
    /// Masked token preview (`"mpk_AbCd...6789"`) safe for display.
    pub preauth_key_masked: String,
    /// Optional suggested RFC 1123 device name.
    pub node_name: Option<String>,
}

/// Opaque zeroize-on-drop pre-auth token holder shared across FFI without leaking `mpk_*` strings.
#[derive(uniffi::Object)]
pub struct MobilePendingJoinSession {
    secret: StdMutex<Option<Zeroizing<String>>>,
    masked: String,
}

impl fmt::Debug for MobilePendingJoinSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active = self.secret.lock().ok().is_some_and(|g| g.is_some());
        f.debug_struct("MobilePendingJoinSession")
            .field("masked", &self.masked)
            .field("secret", &"[REDACTED]")
            .field("active", &active)
            .finish()
    }
}

impl Drop for MobilePendingJoinSession {
    fn drop(&mut self) {
        self.clear_secret();
    }
}

impl ZeroizeOnDrop for MobilePendingJoinSession {}

impl MobilePendingJoinSession {
    /// Validates and wraps a raw pre-authentication key, immediately zeroizing invalid input.
    pub(crate) fn from_raw(mut raw_key: String) -> Result<Self, MobileError> {
        let trimmed = raw_key.trim().to_owned();
        raw_key.zeroize();
        let zeroizing = Zeroizing::new(trimmed);

        if let Err(err) = PreAuthToken::parse(zeroizing.as_str()) {
            return Err(MobileError::from(err));
        }
        let masked = mask_preauth_token(zeroizing.as_str());
        Ok(Self {
            secret: StdMutex::new(Some(zeroizing)),
            masked,
        })
    }

    /// Atomically takes and consumes the underlying pre-auth secret, returning an error if already
    /// consumed or cancelled.
    pub(crate) fn take_preauth_key(&self) -> Result<Zeroizing<String>, MobileError> {
        let mut guard = self
            .secret
            .lock()
            .map_err(|_| MobileError::internal("pending join session mutex poisoned"))?;
        guard.take().ok_or_else(|| {
            MobileError::invalid_argument(
                "pending join session has already been consumed or cancelled",
            )
        })
    }

    fn clear_secret(&self) {
        if let Ok(mut guard) = self.secret.lock()
            && let Some(mut val) = guard.take()
        {
            val.zeroize();
        }
    }
}

#[uniffi::export]
impl MobilePendingJoinSession {
    /// Returns the redacted display preview (`"mpk_AbCd...6789"`).
    #[must_use]
    pub fn masked_preview(&self) -> String {
        self.masked.clone()
    }

    /// Explicitly cancels and zeroizes the buffered pre-auth token in RAM.
    pub fn cancel(&self) {
        self.clear_secret();
    }
}

/// Output of `parse_mobile_join_uri`: non-secret UI summary paired with opaque token session.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileParsedJoinUri {
    /// Non-secret connection and pin confirmation summary.
    pub summary: MobileJoinUriData,
    /// Opaque RAM-only pre-auth token session (`ZeroizeOnDrop`).
    pub session: std::sync::Arc<MobilePendingJoinSession>,
}

/// Parameters for standalone zero-TUN Control enrollment or key rotation (`ADR-014`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileEnrollConfig {
    /// Control-plane `<host_or_ip>:<port>`.
    pub server_endpoint: String,
    /// Optional port override validated against `1..=65535`.
    pub port_override: Option<u16>,
    /// Selected TLS verification policy.
    pub tls_auth_mode: MobileTlsAuthMode,
    /// Pinned SPKI SHA-256 fingerprint (`sha256:<64hex>`).
    pub server_pin: Option<String>,
    /// Opaque pre-auth token holder consumed by enrollment.
    pub pending_join: std::sync::Arc<MobilePendingJoinSession>,
    /// Optional desired RFC 1123 device label.
    pub node_name: Option<String>,
    /// `false` for initial enrollment; `true` for key rotation sending `previous_node_pubkey`.
    pub rotate_existing_identity: bool,
}

/// Parameters passed to `MobileEngine::start_tunnel`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileUpConfig {
    /// Control-plane `<host_or_ip>:<port>`.
    pub server_endpoint: String,
    /// Optional port override validated against `1..=65535`.
    pub port_override: Option<u16>,
    /// Selected TLS verification policy.
    pub tls_auth_mode: MobileTlsAuthMode,
    /// Pinned SPKI SHA-256 fingerprint (`sha256:<64hex>`).
    pub server_pin: Option<String>,
    /// Optional single-process Android enrollment secret (always `None` in iOS PacketTunnel).
    pub pending_join: Option<std::sync::Arc<MobilePendingJoinSession>>,
    /// Optional desired RFC 1123 node name.
    pub node_name: Option<String>,
    /// Optional detached Android `VpnService` TUN descriptor (`None` on iOS or pre-provision).
    pub android_tun_fd: Option<i32>,
    /// Preferred TUN interface name hint (`tun0`, `utun`).
    pub tun_interface_name: Option<String>,
}

/// Parameters passed to `MobileEngine::update_server_config`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileSetConfig {
    /// Replacement Control-plane `<host_or_ip>:<port>`.
    pub server_endpoint: String,
    /// Replacement TLS verification policy.
    pub tls_auth_mode: MobileTlsAuthMode,
    /// Replacement pinned SPKI SHA-256 fingerprint (`None` only for domain `SystemCa`).
    pub server_pin: Option<String>,
}

/// Parameters passed to `MobileEngine::rotate_key` on single-process platforms (Android).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileRotateKeyConfig {
    /// Opaque pre-auth token holder consumed during key rotation.
    pub pending_join: std::sync::Arc<MobilePendingJoinSession>,
}

/// Snapshot of physical underlay state reported by Android `ConnectivityManager` / iOS `NWPath`.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct MobileUnderlayState {
    /// Active physical interface name (`wlan0`, `rmnet_data0`, `en0`, `pdp_ip0`).
    pub active_interface_name: Option<String>,
    /// Numeric OS interface index when known.
    pub physical_if_index: Option<u32>,
    /// Whether the active underlay provides routable IPv4 connectivity.
    pub has_ipv4: bool,
    /// Whether the active underlay provides routable IPv6 connectivity.
    pub has_ipv6: bool,
    /// Underlay DNS server IPs from OS link properties.
    pub underlay_dns_servers: Vec<String>,
    /// Optional NAT64 prefix CIDR advertised by OS (`"64:ff9b::/96"`).
    pub os_nat64_prefix: Option<String>,
    /// Physical adapter IP/prefix strings (`"192.168.1.42/24"`) for conflict detection.
    pub physical_subnets: Vec<String>,
    /// Whether Android VPN Lockdown ("Block connections without VPN") is enabled.
    pub is_android_lockdown_enabled: bool,
    /// Whether Android Strict Private DNS is active on the current underlay.
    pub is_android_private_dns_strict: bool,
    /// Optional Private DNS hostname when reported by OS.
    pub private_dns_server_name: Option<String>,
}

/// Canonical alias matching external `MobileTunnelConfig` references where needed.
pub type MobileTunnelConfig = MobileTunnelNetworkConfig;

/// Dynamic L3 TUN interface, route, and Split-DNS settings pushed to OS VPN builders (`§5`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileTunnelNetworkConfig {
    /// Local overlay IPv4 address assigned to the TUN adapter.
    pub overlay_ip: String,
    /// Point-to-point TUN interface prefix length (always `32`).
    pub tun_interface_prefix_len: u8,
    /// Active overlay subnet CIDR (`"100.64.0.0/16"` or dynamic server range).
    pub overlay_cidr: String,
    /// Dotted subnet mask matching `overlay_cidr`.
    pub overlay_subnet_mask: String,
    /// Collision-free Split-DNS listener IP (`<ip>/32`).
    pub overlay_dns_ip: String,
    /// Authoritative internal DNS zone (`"mesh.internal"`).
    pub domain_suffix: String,
    /// Overlay TUN link MTU (default `1280`).
    pub tun_mtu: u16,
    /// Non-default included IPv4 split-tunnel routes (`0` `0.0.0.0/0` entries; always covers DNS IP).
    pub included_routes_cidr: Vec<String>,
}

/// Non-fatal operational warning record emitted to mobile UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MobilePlatformWarning {
    /// Categorized warning code.
    pub kind: MobileWarningKind,
    /// Sanitized human-readable warning message.
    pub message: String,
}

/// Non-secret Control/Relay connection telemetry exposed in [`MobileStatusSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MobileServerStatus {
    /// Active Control `<host_or_ip>:<port>`.
    pub control_endpoint: String,
    /// Active Blind Relay `<host_or_ip>:<port>`.
    pub relay_endpoint: String,
    /// Active UDP STUN endpoints.
    pub stun_endpoints: Vec<String>,
    /// Active TLS trust policy.
    pub tls_auth_mode: MobileTlsAuthMode,
    /// Primary pinned SPKI digest (`None` when `SystemCa`).
    pub active_pin: Option<String>,
    /// Secondary staged SPKI pin during certificate rotation.
    pub next_pin: Option<String>,
    /// Whether Control WebSocket stream is connected.
    pub control_connected: bool,
    /// Whether Blind Relay WebSocket stream is connected.
    pub relay_connected: bool,
    /// Latest measured Blind Relay RTT in milliseconds.
    pub relay_rtt_ms: Option<u64>,
    /// Latest scrubbed non-fatal connection error description.
    pub last_error: Option<String>,
}

/// Non-secret local network status exposed in [`MobileStatusSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MobileSelfNetworkStatus {
    /// Bound UDP socket port.
    pub local_udp_port: u16,
    /// Bound physical underlay interface name.
    pub bound_physical_interface: Option<String>,
    /// Observed NAT mapping kind.
    pub nat_type: MobileNatKind,
    /// Non-empty when underlay LAN/CGNAT overlaps overlay CIDR.
    pub overlay_conflict_warning: Option<String>,
    /// Active NAT64 prefix CIDR when running behind DNS64/NAT64.
    pub nat64_active_prefix: Option<String>,
    /// Local/reflexive UDP candidates (`"ip:port"`).
    pub candidates: Vec<String>,
}

/// Non-secret per-peer connectivity summary inside [`MobileStatusSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MobilePeerStatus {
    /// Peer UUID string.
    pub node_id: String,
    /// Peer RFC 1123 label.
    pub name: String,
    /// Peer internal FQDN.
    pub fqdn: String,
    /// Peer overlay IPv4.
    pub overlay_ip: String,
    /// Whether peer holds an active Control connection.
    pub online: bool,
    /// Active forwarding path (`Direct`, `Relay`, `None`).
    pub active_path: MobileActivePathKind,
    /// Active direct `IP:port` endpoint when `Direct`.
    pub direct_endpoint: Option<String>,
    /// Latest direct RTT in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Latest WireGuard handshake UTC timestamp in milliseconds.
    pub last_handshake_at_ms: Option<u64>,
    /// Cumulative received transport bytes.
    pub rx_bytes: u64,
    /// Cumulative transmitted transport bytes.
    pub tx_bytes: u64,
}

/// Bounded (`<= 4096 B` JSON-serialized) non-secret status snapshot for mobile UI & App Group IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MobileStatusSnapshot {
    /// Current lifecycle state.
    pub daemon_state: MobileDaemonState,
    /// Assigned local node UUID (`None` before registration).
    pub node_id: Option<String>,
    /// Assigned local RFC 1123 node name.
    pub node_name: Option<String>,
    /// Assigned mesh FQDN.
    pub fqdn: Option<String>,
    /// Assigned overlay IPv4.
    pub overlay_ip: Option<String>,
    /// Overlay CIDR block.
    pub overlay_cidr: Option<String>,
    /// Collision-free Split-DNS resolver IP.
    pub overlay_dns_ip: Option<String>,
    /// Active TUN interface name.
    pub tun_interface_name: Option<String>,
    /// Configured TUN MTU.
    pub tun_mtu: u16,
    /// Applied Netmap version.
    pub netmap_version: u64,
    /// Node key expiry UTC timestamp in milliseconds.
    pub key_expires_at_ms: Option<u64>,
    /// Control/Relay connection telemetry.
    pub server_connection: Option<MobileServerStatus>,
    /// Local UDP & physical underlay state.
    pub self_network: MobileSelfNetworkStatus,
    /// Peer status list (tail-trimmed when enforcing `<= 4096 B` App Group IPC budget).
    pub peers: Vec<MobilePeerStatus>,
    /// Active operational warnings.
    pub warnings: Vec<MobilePlatformWarning>,
}

/// Parameters for `MobileEngine::ping_peer`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobilePingRequest {
    /// Target peer name, FQDN, UUID, or overlay IP.
    pub target: String,
    /// Probe sample count (`1..=64`).
    pub count: u16,
    /// Whether to probe direct UDP even if peer is currently relayed.
    pub force_direct: bool,
    /// Per-probe timeout in milliseconds.
    pub timeout_ms: u64,
}

/// Single sample measurement inside [`MobilePingResponse`].
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MobilePingSample {
    /// 1-based probe sequence number.
    pub seq: u16,
    /// Transport leg traversed (`Direct`, `Relay`, `Timeout`).
    pub via: MobilePingVia,
    /// Remote endpoint string (`None` on timeout).
    pub endpoint: Option<String>,
    /// Round-trip latency in milliseconds (`None` on timeout).
    pub rtt_ms: Option<f64>,
}

/// Result returned by `MobileEngine::ping_peer`.
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct MobilePingResponse {
    /// Target peer UUID.
    pub peer_id: String,
    /// Target peer name.
    pub peer_name: String,
    /// Target peer overlay IPv4.
    pub peer_overlay_ip: String,
    /// Individual sample outcomes.
    pub samples: Vec<MobilePingSample>,
    /// Mean observed RTT in milliseconds.
    pub avg_rtt_ms: Option<f64>,
}

/// Result returned by `MobileEngine::netcheck`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileNetcheckResponse {
    /// Whether outbound protected UDP traffic succeeded.
    pub udp_reachable: bool,
    /// Whether IPv4 underlay connectivity is available.
    pub ipv4_available: bool,
    /// Whether global IPv6 connectivity is available.
    pub ipv6_available: bool,
    /// Observed NAT mapping classification.
    pub nat_type: MobileNatKind,
    /// Reflexive external endpoint discovered via STUN.
    pub mapped_endpoint: Option<String>,
    /// Whether Blind Relay TCP/TLS/WS endpoint is reachable.
    pub relay_connected: bool,
    /// Measured Blind Relay RTT in milliseconds.
    pub relay_rtt_ms: Option<u64>,
    /// Active NAT64 prefix when behind IPv6-only/DNS64 underlay.
    pub nat64_prefix: Option<String>,
}

/// Result returned by `MobileEngine::export_bugreport_to_file`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MobileBugreportResult {
    /// Path to generated `.tar` bundle (`<= DEFAULT_MOBILE_MAX_BUGREPORT_BYTES`).
    pub bundle_path: String,
    /// Actual archive byte size.
    pub size_bytes: u64,
    /// Total secret patterns scrubbed during archive assembly.
    pub scrubbed_items: u32,
}

/// UniFFI callback interface implemented by Kotlin (`MeshVpnService`) and Swift (`MeshPacketTunnel` / `MeshApp`).
#[uniffi::export(callback_interface)]
pub trait PlatformNetworkBridge: Send + Sync + fmt::Debug {
    /// Android: synchronously calls `VpnService.protect(raw_fd)` with zero Rust locks held.
    /// iOS: returns `Ok(true)`.
    fn protect_socket(&self, raw_fd: i32) -> Result<bool, MobileError>;

    /// iOS (`NEPacketTunnelFlow`): delivers decrypted L3 IP packets for `writePackets`.
    fn on_tun_packets(&self, packets: Vec<Vec<u8>>);

    /// Requests asynchronous OS VPN builder route/DNS reconfiguration for `op_id`.
    /// Must eventually invoke `MobileEngine::complete_route_change`.
    fn on_route_changed(&self, op_id: u64, config: MobileTunnelNetworkConfig);

    /// Delivers a bounded, secret-free [`MobileStatusSnapshot`] to platform UI observers.
    fn on_status_changed(&self, status: MobileStatusSnapshot);

    /// Delivers a non-fatal platform warning (`Lockdown`, `PrivateDNS`, `IosLowMemoryPressure`).
    fn on_platform_warning(&self, warning: MobilePlatformWarning);

    /// Queries current OS physical underlay DNS, NAT64, subnets, and Lockdown/PrivateDNS flags.
    fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError>;

    /// Loads or creates the hardware-protected 32-byte Master DEK (Android Keystore KEK / iOS Keychain).
    fn load_or_create_platform_dek(&self) -> Result<Vec<u8>, MobileError>;

    /// Reads an opaque state file from private app storage / iOS App Group container.
    fn load_state_file(&self, file_name: String) -> Result<Option<Vec<u8>>, MobileError>;

    /// Atomically persists an opaque state file into private app storage / iOS App Group container.
    fn save_state_file(&self, file_name: String, content: Vec<u8>) -> Result<(), MobileError>;

    /// Deletes a state file from private app storage / iOS App Group container.
    fn delete_state_file(&self, file_name: String) -> Result<(), MobileError>;
}

/// Parses and validates `mesh://join?v=1&...`, returning a redacted UI summary and opaque
/// `ZeroizeOnDrop` session holder (`OQ-MOB-03`, `HR-MOB-G2-03`).
#[uniffi::export]
pub fn parse_mobile_join_uri(raw_uri: String) -> Result<MobileParsedJoinUri, MobileError> {
    let raw_uri = Zeroizing::new(raw_uri);
    let parsed = parse_join_uri(raw_uri.as_str()).map_err(MobileError::from)?;
    let (tls_auth_mode, server_pin) = match parsed.tls_auth {
        mesh_core::MobileJoinTlsAuth::SpkiPin(pin) => {
            (MobileTlsAuthMode::SpkiPin, Some(pin.to_string()))
        }
        mesh_core::MobileJoinTlsAuth::SystemCa => (MobileTlsAuthMode::SystemCa, None),
    };
    let session = std::sync::Arc::new(MobilePendingJoinSession::from_raw(
        parsed.preauth_key().to_owned(),
    )?);
    let summary = MobileJoinUriData {
        version: parsed.version,
        server_endpoint: parsed.control_endpoint.clone(),
        tls_auth_mode,
        server_pin,
        preauth_key_masked: session.masked_preview(),
        node_name: parsed.node_name.as_ref().map(ToString::to_string),
    };
    Ok(MobileParsedJoinUri { summary, session })
}

/// Wraps a manually entered pre-auth token into an opaque [`MobilePendingJoinSession`]
/// (`ZeroizeOnDrop`), validating syntax immediately.
#[uniffi::export]
pub fn create_pending_join_session(
    raw_preauth_key: String,
) -> Result<std::sync::Arc<MobilePendingJoinSession>, MobileError> {
    Ok(std::sync::Arc::new(MobilePendingJoinSession::from_raw(
        raw_preauth_key,
    )?))
}

impl From<DaemonState> for MobileDaemonState {
    fn from(value: DaemonState) -> Self {
        match value {
            DaemonState::Stopped => Self::Stopped,
            DaemonState::Connecting => Self::Connecting,
            DaemonState::Connected => Self::Connected,
            DaemonState::ReauthRequired => Self::ReauthRequired,
            DaemonState::Revoked => Self::Revoked,
            DaemonState::Degraded => Self::Degraded,
        }
    }
}

impl From<TlsAuthMode> for MobileTlsAuthMode {
    fn from(value: TlsAuthMode) -> Self {
        match value {
            TlsAuthMode::SpkiPin => Self::SpkiPin,
            TlsAuthMode::SystemCa => Self::SystemCa,
        }
    }
}

impl From<MobileTlsAuthMode> for TlsAuthMode {
    fn from(value: MobileTlsAuthMode) -> Self {
        match value {
            MobileTlsAuthMode::SpkiPin => Self::SpkiPin,
            MobileTlsAuthMode::SystemCa => Self::SystemCa,
        }
    }
}

impl From<ActivePathKind> for MobileActivePathKind {
    fn from(value: ActivePathKind) -> Self {
        match value {
            ActivePathKind::Direct => Self::Direct,
            ActivePathKind::Relay => Self::Relay,
            ActivePathKind::None => Self::None,
        }
    }
}

impl From<NatMappingKind> for MobileNatKind {
    fn from(value: NatMappingKind) -> Self {
        match value {
            NatMappingKind::EimOrAdm => Self::EndpointIndependent,
            NatMappingKind::PortDependent => Self::AddressAndPortDependent,
            NatMappingKind::Unknown => Self::Unknown,
        }
    }
}

impl From<PingVia> for MobilePingVia {
    fn from(value: PingVia) -> Self {
        match value {
            PingVia::Direct => Self::Direct,
            PingVia::Relay => Self::Relay,
            PingVia::Timeout => Self::Timeout,
        }
    }
}

/// Validates and converts optional FFI pin/port/name inputs into strongly typed `mesh_core` values.
pub(crate) fn parse_optional_spki_pin(
    mode: MobileTlsAuthMode,
    raw_pin: Option<&str>,
) -> Result<Option<SpkiPin>, MobileError> {
    match (mode, raw_pin) {
        (MobileTlsAuthMode::SpkiPin, Some(pin)) => SpkiPin::parse(pin.trim())
            .map(Some)
            .map_err(MobileError::from),
        (MobileTlsAuthMode::SpkiPin, None) => Err(MobileError::invalid_argument(
            "server_pin is required when tls_auth_mode is SpkiPin",
        )),
        (MobileTlsAuthMode::SystemCa, Some(pin)) if !pin.trim().is_empty() => {
            Err(MobileError::invalid_argument(
                "server_pin must be omitted when tls_auth_mode is SystemCa",
            ))
        }
        (MobileTlsAuthMode::SystemCa, _) => Ok(None),
    }
}

/// Validates an optional `u16` port override into [`Port`].
pub(crate) fn parse_optional_port(port: Option<u16>) -> Result<Option<Port>, MobileError> {
    port.map(Port::from_u16)
        .transpose()
        .map_err(MobileError::from)
}

/// Validates an optional desired RFC 1123 [`NodeName`].
pub(crate) fn parse_optional_node_name(raw: Option<&str>) -> Result<Option<NodeName>, MobileError> {
    match raw {
        Some(name) if !name.trim().is_empty() => NodeName::parse(name.trim())
            .map(Some)
            .map_err(MobileError::from),
        _ => Ok(None),
    }
}

/// Converts a core [`AgentStatusResponse`] plus mobile metadata into [`MobileStatusSnapshot`],
/// scrubbing accidental secret patterns and enforcing the `<= 4096 B` IPC size cap.
#[must_use]
pub(crate) fn status_from_agent_response(
    resp: AgentStatusResponse,
    overlay_dns_ip: Option<String>,
    nat64_prefix: Option<Nat64Prefix>,
    mut warnings: Vec<MobilePlatformWarning>,
    protocol_incompatible: bool,
    override_state: Option<MobileDaemonState>,
) -> MobileStatusSnapshot {
    let mut daemon_state =
        override_state.unwrap_or_else(|| MobileDaemonState::from(resp.daemon_state));
    if protocol_incompatible && override_state.is_none() {
        daemon_state = MobileDaemonState::ServerUpgradeRequired;
    }

    let server_connection = resp.server_connection.map(|sc| {
        let cleaned_err = sc.last_error.map(|e| {
            let (scrubbed, _) = scrub_diagnostic_secrets(&e);
            scrubbed
        });
        MobileServerStatus {
            control_endpoint: sc.control_endpoint,
            relay_endpoint: sc.relay_endpoint,
            stun_endpoints: sc.stun_endpoints,
            tls_auth_mode: sc.tls_auth_mode.into(),
            active_pin: sc.active_pin.map(|p| p.to_string()),
            next_pin: sc.next_pin.map(|p| p.to_string()),
            control_connected: sc.control_connected,
            relay_connected: sc.relay_connected,
            relay_rtt_ms: sc.relay_rtt_ms,
            last_error: cleaned_err,
        }
    });

    let conflict_warning = resp.self_network.overlay_conflict_warning.map(|w| {
        let (clean, _) = scrub_diagnostic_secrets(&w);
        clean
    });
    let self_network = MobileSelfNetworkStatus {
        local_udp_port: resp.self_network.local_udp_port,
        bound_physical_interface: resp.self_network.bound_physical_interface,
        nat_type: resp.self_network.nat_type.into(),
        overlay_conflict_warning: conflict_warning,
        nat64_active_prefix: nat64_prefix
            .map(|p| format!("{}/{}", p.prefix_addr(), p.prefix_len().as_u8())),
        candidates: resp
            .self_network
            .candidates
            .into_iter()
            .map(|c| c.addr.to_string())
            .collect(),
    };

    let mut peers: Vec<MobilePeerStatus> = resp
        .peers
        .into_iter()
        .map(|p| MobilePeerStatus {
            node_id: p.node_id.to_string(),
            name: p.name.to_string(),
            fqdn: p.fqdn,
            overlay_ip: p.overlay_ip.to_string(),
            online: p.online,
            active_path: p.active_path.into(),
            direct_endpoint: p.direct_endpoint,
            rtt_ms: p.rtt_ms,
            last_handshake_at_ms: p.last_handshake_at_ms,
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
        })
        .collect();
    peers.sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name)));

    for w in &mut warnings {
        let (clean, _) = scrub_diagnostic_secrets(&w.message);
        w.message = clean;
    }

    MobileStatusSnapshot {
        daemon_state,
        node_id: resp.node_id.map(|id| id.to_string()),
        node_name: resp.node_name.map(|n| n.to_string()),
        fqdn: resp.fqdn,
        overlay_ip: resp.overlay_ip.map(|ip| ip.to_string()),
        overlay_cidr: resp.overlay_cidr.map(|c| c.to_string()),
        overlay_dns_ip,
        tun_interface_name: resp.tun_interface_name,
        tun_mtu: resp.tun_mtu,
        netmap_version: resp.netmap_version,
        key_expires_at_ms: resp.key_expires_at_ms,
        server_connection,
        self_network,
        peers,
        warnings,
    }
    .into_bounded_ipc()
}

/// Converts [`PingResponse`] from `mesh-client` into [`MobilePingResponse`].
#[must_use]
pub(crate) fn ping_response_from_core(peer_id: String, resp: PingResponse) -> MobilePingResponse {
    MobilePingResponse {
        peer_id,
        peer_name: resp.target_name.to_string(),
        peer_overlay_ip: resp.target_overlay_ip.to_string(),
        samples: resp
            .samples
            .into_iter()
            .map(|s| MobilePingSample {
                seq: s.seq,
                via: s.via.into(),
                endpoint: s.endpoint,
                rtt_ms: s.rtt_ms,
            })
            .collect(),
        avg_rtt_ms: resp.rtt_avg_ms,
    }
}

/// Converts [`NetcheckResponse`] from `mesh-client` into [`MobileNetcheckResponse`].
#[must_use]
pub(crate) fn netcheck_response_from_core(
    resp: NetcheckResponse,
    nat64_prefix: Option<Nat64Prefix>,
) -> MobileNetcheckResponse {
    MobileNetcheckResponse {
        udp_reachable: resp.udp_egress_ok && resp.stun_reachable,
        ipv4_available: resp.udp_egress_ok || resp.control_tcp_reachable,
        ipv6_available: resp.ipv6_available,
        nat_type: resp.nat_mapping.into(),
        mapped_endpoint: resp.reflexive_ipv4,
        relay_connected: resp.control_tcp_reachable,
        relay_rtt_ms: resp.relay_rtt_ms.map(|v| v.max(0.0).round() as u64),
        nat64_prefix: nat64_prefix
            .map(|p| format!("{}/{}", p.prefix_addr(), p.prefix_len().as_u8())),
    }
}

impl MobileStatusSnapshot {
    /// Serializes this snapshot into compact JSON strictly capped at `<= 4096` bytes for iOS App
    /// Group / `sendProviderMessage` IPC (`MAX_RO_IPC_BODY_BYTES`).
    pub fn to_bounded_ipc_json(&self) -> Result<Vec<u8>, MobileError> {
        let bounded = self.clone().into_bounded_ipc();
        serde_json::to_vec(&bounded).map_err(|err| {
            MobileError::internal(format!("failed serializing bounded status snapshot: {err}"))
        })
    }

    /// Returns a copy whose JSON encoding is guaranteed `<= 4096` bytes (`MAX_RO_IPC_BODY_BYTES`).
    #[must_use]
    pub fn into_bounded_ipc(mut self) -> Self {
        self.scrub_all_text_fields();
        if serialized_len(&self) <= MOBILE_IPC_HARD_LIMIT_BYTES {
            return self;
        }
        while !self.peers.is_empty() && serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES {
            drop(self.peers.pop());
        }
        while !self.self_network.candidates.is_empty()
            && serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES
        {
            drop(self.self_network.candidates.pop());
        }
        while self.warnings.len() > 1 && serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES {
            drop(self.warnings.pop());
        }
        while self
            .server_connection
            .as_ref()
            .is_some_and(|srv| !srv.stun_endpoints.is_empty())
            && serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES
        {
            if let Some(ref mut srv) = self.server_connection {
                drop(srv.stun_endpoints.pop());
            }
        }
        if serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES
            && let Some(ref mut srv) = self.server_connection
            && let Some(ref mut err) = srv.last_error
        {
            truncate_utf8_in_place(err, 96);
        }
        if serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES
            && let Some(ref mut warn) = self.self_network.overlay_conflict_warning
        {
            truncate_utf8_in_place(warn, 96);
        }
        if serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES {
            for w in &mut self.warnings {
                truncate_utf8_in_place(&mut w.message, 64);
            }
        }
        if serialized_len(&self) > MOBILE_IPC_HARD_LIMIT_BYTES {
            self.warnings.clear();
        }
        self
    }

    fn scrub_all_text_fields(&mut self) {
        if let Some(ref mut srv) = self.server_connection
            && let Some(ref mut err) = srv.last_error
        {
            let (clean, _) = scrub_diagnostic_secrets(err);
            *err = clean;
        }
        if let Some(ref mut warn) = self.self_network.overlay_conflict_warning {
            let (clean, _) = scrub_diagnostic_secrets(warn);
            *warn = clean;
        }
        for w in &mut self.warnings {
            let (clean, _) = scrub_diagnostic_secrets(&w.message);
            w.message = clean;
        }
    }
}

fn serialized_len(snap: &MobileStatusSnapshot) -> usize {
    serde_json::to_vec(snap).map_or(usize::MAX, |v| v.len())
}

fn truncate_utf8_in_place(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes.saturating_sub(3);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push_str("...");
}

#[cfg(test)]
mod tests {
    use super::{
        MOBILE_IPC_HARD_LIMIT_BYTES, MobileActivePathKind, MobileDaemonState, MobileError,
        MobileNatKind, MobilePeerStatus, MobilePendingJoinSession, MobilePlatformKind,
        MobilePlatformWarning, MobileSelfNetworkStatus, MobileStatusSnapshot, MobileTlsAuthMode,
        MobileWarningKind, parse_mobile_join_uri,
    };
    use mesh_core::{AppError, ErrorKind};

    fn dummy_snapshot(peer_count: usize) -> MobileStatusSnapshot {
        let peers = (0..peer_count)
            .map(|i| MobilePeerStatus {
                node_id: format!("01950000-0000-7000-8000-{i:012}"),
                name: format!("mobile-peer-{i}"),
                fqdn: format!("mobile-peer-{i}.mesh.internal"),
                overlay_ip: format!("100.64.{}.{}", (i / 250) + 1, (i % 250) + 1),
                online: i % 2 == 0,
                active_path: MobileActivePathKind::Relay,
                direct_endpoint: Some("198.51.100.5:51820".to_owned()),
                rtt_ms: Some(15),
                last_handshake_at_ms: Some(1_762_000_000_000),
                rx_bytes: 1024,
                tx_bytes: 2048,
            })
            .collect();
        MobileStatusSnapshot {
            daemon_state: MobileDaemonState::Connected,
            node_id: Some("01950000-0000-7000-8000-000000000001".to_owned()),
            node_name: Some("pixel-phone".to_owned()),
            fqdn: Some("pixel-phone.mesh.internal".to_owned()),
            overlay_ip: Some("100.64.0.10".to_owned()),
            overlay_cidr: Some("100.64.0.0/16".to_owned()),
            overlay_dns_ip: Some("100.64.255.254".to_owned()),
            tun_interface_name: Some("tun0".to_owned()),
            tun_mtu: 1280,
            netmap_version: 42,
            key_expires_at_ms: Some(1_800_000_000_000),
            server_connection: None,
            self_network: MobileSelfNetworkStatus {
                local_udp_port: 51820,
                bound_physical_interface: Some("wlan0".to_owned()),
                nat_type: MobileNatKind::EndpointIndependent,
                overlay_conflict_warning: None,
                nat64_active_prefix: None,
                candidates: vec!["192.0.2.10:51820".to_owned()],
            },
            peers,
            warnings: vec![MobilePlatformWarning {
                kind: MobileWarningKind::AndroidPrivateDnsStrict,
                message: "strict private DNS detected".to_owned(),
            }],
        }
    }

    #[test]
    fn test_mobile_error_preserves_sec05_and_classifies_special_errors() -> Result<(), String> {
        // Arrange
        let unauth = AppError::unauthenticated("wrong mpk_canary_12345 signature detail");
        let compat = AppError::invalid_argument("unknown variant `android`");
        let locked = AppError::unavailable("Keychain failed errSecInteractionNotAllowed (-25308)");
        let invalidated = AppError::internal("KeyPermanentlyInvalidatedException");

        // Act
        let m_unauth = MobileError::from(unauth);
        let m_compat = MobileError::from(compat);
        let m_locked = MobileError::from(locked);
        let m_inv = MobileError::from(invalidated);

        // Assert
        match m_unauth {
            MobileError::Unauthenticated {
                error_code,
                message,
            } => {
                assert_eq!(error_code, "E_UNAUTHENTICATED");
                assert_eq!(message, "authentication failed");
            }
            other => return Err(format!("expected Unauthenticated, got {other:?}")),
        }
        assert!(matches!(
            m_compat,
            MobileError::ServerUpgradeRequired { .. }
        ));
        assert!(matches!(m_locked, MobileError::DeviceLocked { .. }));
        assert!(matches!(m_inv, MobileError::KeystoreInvalidated { .. }));

        let roundtrip = MobileError::Unauthenticated {
            error_code: "E_UNAUTHENTICATED".to_owned(),
            message: "ignored".to_owned(),
        }
        .to_app_error();
        assert_eq!(roundtrip.kind(), ErrorKind::Unauthenticated);
        assert_eq!(roundtrip.public_message(), "authentication failed");
        Ok(())
    }

    #[test]
    fn test_parse_mobile_join_uri_masks_and_zeroizes_secret_session() -> Result<(), String> {
        // Arrange
        let tok = mesh_crypto::PreAuthToken::generate();
        let pin = format!("sha256:{}", "a".repeat(64));
        let encoded_pin = pin.replace(':', "%3A");
        let canary = "mpk_Q2FuYXJ5VG9rZW4zMkJ5dGVzQ2FuYXJ5VG9rZW4zMkI".to_owned();
        let uri = format!(
            "mesh://join?v=1&ep=203.0.113.10%3A8443&pin={encoded_pin}&key={canary}&name=iphone-15"
        );
        let _keep = tok;

        // Act
        let parsed = parse_mobile_join_uri(uri).map_err(|e| e.to_string())?;
        let debug_summary = format!("{:?}", parsed.summary);
        let debug_session = format!("{:?}", parsed.session);

        // Assert
        assert_eq!(parsed.summary.version, 1);
        assert_eq!(parsed.summary.server_endpoint, "203.0.113.10:8443");
        assert_eq!(parsed.summary.tls_auth_mode, MobileTlsAuthMode::SpkiPin);
        assert_eq!(parsed.summary.node_name.as_deref(), Some("iphone-15"));
        assert!(!debug_summary.contains(&canary));
        assert!(!debug_session.contains(&canary));
        assert!(parsed.summary.preauth_key_masked.starts_with("mpk_"));

        let consumed = parsed
            .session
            .take_preauth_key()
            .map_err(|e| e.to_string())?;
        assert_eq!(consumed.as_str(), canary);
        assert!(parsed.session.take_preauth_key().is_err());

        // Cancel clears unconsumed session
        let s2 = MobilePendingJoinSession::from_raw(canary).map_err(|e| e.to_string())?;
        s2.cancel();
        assert!(s2.take_preauth_key().is_err());
        assert_eq!(MobilePlatformKind::Android as u8, 0);
        Ok(())
    }

    #[test]
    fn test_mobile_status_snapshot_bounded_within_4096_bytes_for_ios_ipc() -> Result<(), String> {
        // Arrange: 150 peers would exceed 4096 bytes uncompressed
        let large = dummy_snapshot(150);
        let raw_len = serde_json::to_vec(&large).map_err(|e| e.to_string())?.len();
        assert!(raw_len > MOBILE_IPC_HARD_LIMIT_BYTES);

        // Act
        let json_bytes = large.to_bounded_ipc_json().map_err(|e| e.to_string())?;

        // Assert
        assert!(json_bytes.len() <= MOBILE_IPC_HARD_LIMIT_BYTES);
        Ok(())
    }
}
