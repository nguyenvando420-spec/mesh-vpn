//! Shared domain primitives, defaults, errors, clocks, backoff, and structured JSON logging
//! for the Mesh VPN workspace.

pub mod backoff;
pub mod brand;
pub mod clock;
pub mod defaults;
pub mod error;
pub mod logging;
pub mod mobile_uri;
pub mod types;

pub use backoff::{BackoffConfig, ExponentialBackoff};
pub use clock::{Clock, ClockJumpDetector, ClockJumpEvent, FakeClock, SystemClock};
pub use error::{AppError, AppResult, ErrorEnvelope, ErrorKind, ErrorResponse};
pub use logging::{
    BoundedRotatingWriter, LogGuard, LoggingConfig, MeshJsonFormatter, SharedLogWriter,
    init_json_logging,
};
pub use mobile_uri::{
    MAX_MOBILE_JOIN_URI_LEN, MOBILE_JOIN_URI_HOST, MOBILE_JOIN_URI_SCHEME, MOBILE_JOIN_URI_VERSION,
    MOBILE_SYSTEM_CA_PIN, MobileJoinTlsAuth, MobileJoinUri, NormalizedControlEndpoint,
    format_join_uri, is_ip_literal_host, normalize_control_endpoint, parse_join_uri,
    validate_desktop_tls_policy, validate_preauth_key,
};
pub use types::{KeyId, NodeId, NodeName, OverlayCidr, OverlayIp, Port, PublicKey, SpkiPin};
