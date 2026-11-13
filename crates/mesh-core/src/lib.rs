//! Shared domain primitives, defaults, errors, clocks, backoff, and structured JSON logging
//! for the Mesh VPN workspace.

pub mod backoff;
pub mod brand;
pub mod clock;
pub mod defaults;
pub mod error;
pub mod logging;
pub mod types;

pub use backoff::{BackoffConfig, ExponentialBackoff};
pub use clock::{Clock, ClockJumpDetector, ClockJumpEvent, FakeClock, SystemClock};
pub use error::{AppError, AppResult, ErrorEnvelope, ErrorKind, ErrorResponse};
pub use logging::{
    BoundedRotatingWriter, LogGuard, LoggingConfig, MeshJsonFormatter, SharedLogWriter,
    init_json_logging,
};
pub use types::{KeyId, NodeId, NodeName, OverlayCidr, OverlayIp, Port, PublicKey, SpkiPin};
