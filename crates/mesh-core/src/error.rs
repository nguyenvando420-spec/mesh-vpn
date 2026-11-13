//! Unified application error taxonomy (`ErrorKind` / `AppError` / `ErrorEnvelope`).
//!
//! Security requirement (`SEC-05`): any `ErrorKind::Unauthenticated` error MUST expose
//! the fixed public message `"authentication failed"` across all HTTP/IPC/wire boundaries
//! regardless of internal failure details.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical 12-variant error taxonomy shared across CLI, daemon, server, and wire payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Unexpected internal error; never expose internal details on the wire.
    Internal,
    /// Client supplied syntactically or semantically invalid parameters.
    InvalidArgument,
    /// Failed cryptographic or token authentication (`SEC-05`: fixed wire message).
    Unauthenticated,
    /// Caller lacks local OS privilege or administrative role (`SEC-14`).
    PermissionDenied,
    /// Authenticated node was explicitly revoked by an administrator (`US-029`).
    NodeRevoked,
    /// Authenticated node's identity key expired and requires re-registration (`US-031`).
    NodeKeyExpired,
    /// Requested entity or route does not exist.
    NotFound,
    /// Resource collision such as duplicate node name or exhausted IP pool.
    Conflict,
    /// Endpoint rate limiter rejected the request (`US-042`).
    RateLimited,
    /// Downstream service or peer is temporarily unreachable.
    Unavailable,
    /// Local TLS certificate validity check failed due to system clock skew (`US-003`).
    ClockSkew,
    /// Server SPKI fingerprint did not match the pinned expectation (`SEC-04`).
    PinMismatch,
}

impl ErrorKind {
    /// Returns the fixed machine-readable wire error code (`E_*`).
    #[must_use]
    pub const fn wire_code(self) -> &'static str {
        match self {
            Self::Internal => "E_INTERNAL",
            Self::InvalidArgument => "E_INVALID_ARG",
            Self::Unauthenticated => "E_UNAUTHENTICATED",
            Self::PermissionDenied => "E_PERM_DENIED",
            Self::NodeRevoked => "E_NODE_REVOKED",
            Self::NodeKeyExpired => "E_KEY_EXPIRED",
            Self::NotFound => "E_NOT_FOUND",
            Self::Conflict => "E_CONFLICT",
            Self::RateLimited => "E_RATE_LIMITED",
            Self::Unavailable => "E_UNAVAILABLE",
            Self::ClockSkew => "E_CLOCK_SKEW",
            Self::PinMismatch => "E_PIN_MISMATCH",
        }
    }

    /// Returns the HTTP status code mapped to this error kind.
    ///
    /// Local TLS validation kinds (`ClockSkew`, `PinMismatch`) map to `502` if surfaced
    /// through an HTTP boundary.
    #[must_use]
    pub const fn http_status_code(self) -> u16 {
        match self {
            Self::Internal => 500,
            Self::InvalidArgument => 400,
            Self::Unauthenticated => 401,
            Self::PermissionDenied | Self::NodeRevoked | Self::NodeKeyExpired => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::RateLimited => 429,
            Self::Unavailable => 503,
            Self::ClockSkew | Self::PinMismatch => 502,
        }
    }

    /// Returns `true` only when receiving this error over an already verified TLS channel
    /// must halt daemon automatic reconnect loops (`US-034 AC5`).
    #[must_use]
    pub const fn should_stop_auto_retry(self) -> bool {
        matches!(self, Self::NodeRevoked | Self::NodeKeyExpired)
    }

    /// Returns the default public message associated with this error kind.
    #[must_use]
    pub const fn default_public_message(self) -> &'static str {
        match self {
            Self::Internal => "internal server error",
            Self::InvalidArgument => "invalid argument",
            Self::Unauthenticated => "authentication failed",
            Self::PermissionDenied => "operation requires administrator/root privileges",
            Self::NodeRevoked => "node has been revoked by administrator",
            Self::NodeKeyExpired => "node key expired; re-authenticate with a new pre-auth key",
            Self::NotFound => "requested resource not found",
            Self::Conflict => "node name already exists or overlay address pool exhausted",
            Self::RateLimited => "rate limit exceeded; please retry later",
            Self::Unavailable => "service temporarily unavailable",
            Self::ClockSkew => "TLS certificate validity check failed; possible system clock skew",
            Self::PinMismatch => "server SPKI pin mismatch",
        }
    }
}

/// Wire JSON error payload nested under `{"error": ...}` (`api-design.md` §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    /// Normalized `snake_case` error kind.
    pub kind: ErrorKind,
    /// Stable uppercase error code (`E_*`).
    pub code: String,
    /// Safe public error message sanitized for external callers.
    pub message: String,
    /// Request correlation identifier for log tracing.
    pub request_id: String,
}

/// Outer HTTP/IPC JSON error wrapper matching `{"error": { ... }}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Inner error envelope.
    pub error: ErrorEnvelope,
}

/// Domain error carrying a safe external classification and optional internal diagnostic context.
#[derive(Debug, Error)]
#[error("{public_message}")]
pub struct AppError {
    kind: ErrorKind,
    public_message: String,
    internal_detail: Option<String>,
}

impl AppError {
    /// Creates an [`AppError`] while enforcing public message sanitization rules (`SEC-05`).
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        let raw = message.into();
        let (public_message, internal_detail) = sanitize_messages(kind, raw);
        Self {
            kind,
            public_message,
            internal_detail,
        }
    }

    /// Attaches an internal-only diagnostic detail that is never serialized over HTTP or IPC.
    #[must_use]
    pub fn with_internal_detail(mut self, detail: impl Into<String>) -> Self {
        self.internal_detail = Some(detail.into());
        self
    }

    /// Creates an [`ErrorKind::Unauthenticated`] error whose public message is always fixed.
    #[must_use]
    pub fn unauthenticated(internal_reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unauthenticated, internal_reason)
    }

    /// Creates an [`ErrorKind::Internal`] error hiding the internal cause from callers.
    #[must_use]
    pub fn internal(internal_reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, internal_reason)
    }

    /// Creates an [`ErrorKind::InvalidArgument`] error.
    #[must_use]
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArgument, message)
    }

    /// Creates an [`ErrorKind::PermissionDenied`] error.
    #[must_use]
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PermissionDenied, message)
    }

    /// Creates an [`ErrorKind::NotFound`] error.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    /// Creates an [`ErrorKind::Conflict`] error.
    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, message)
    }

    /// Creates an [`ErrorKind::RateLimited`] error.
    #[must_use]
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::RateLimited, message)
    }

    /// Creates an [`ErrorKind::Unavailable`] error.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unavailable, message)
    }

    /// Creates an [`ErrorKind::NodeRevoked`] error.
    #[must_use]
    pub fn node_revoked(internal_reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::NodeRevoked, "").with_internal_detail(internal_reason)
    }

    /// Creates an [`ErrorKind::NodeKeyExpired`] error.
    #[must_use]
    pub fn node_key_expired(internal_reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::NodeKeyExpired, "").with_internal_detail(internal_reason)
    }

    /// Creates an [`ErrorKind::ClockSkew`] error.
    #[must_use]
    pub fn clock_skew(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ClockSkew, message)
    }

    /// Creates an [`ErrorKind::PinMismatch`] error.
    #[must_use]
    pub fn pin_mismatch(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PinMismatch, message)
    }

    /// Returns the error classification.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the safe public error message (guaranteed constant for `Unauthenticated` / `Internal`).
    #[must_use]
    pub fn public_message(&self) -> &str {
        &self.public_message
    }

    /// Returns optional internal diagnostic details for operator logs only.
    #[must_use]
    pub fn internal_detail(&self) -> Option<&str> {
        self.internal_detail.as_deref()
    }

    /// Builds a wire-safe [`ErrorEnvelope`] containing zero internal details.
    #[must_use]
    pub fn to_envelope(&self, request_id: impl Into<String>) -> ErrorEnvelope {
        let message = match self.kind {
            ErrorKind::Unauthenticated => ErrorKind::Unauthenticated
                .default_public_message()
                .to_owned(),
            ErrorKind::Internal => ErrorKind::Internal.default_public_message().to_owned(),
            _ => self.public_message.clone(),
        };
        ErrorEnvelope {
            kind: self.kind,
            code: self.kind.wire_code().to_owned(),
            message,
            request_id: request_id.into(),
        }
    }

    /// Wraps the wire-safe [`ErrorEnvelope`] into [`ErrorResponse`].
    #[must_use]
    pub fn to_response(&self, request_id: impl Into<String>) -> ErrorResponse {
        ErrorResponse {
            error: self.to_envelope(request_id),
        }
    }
}

fn sanitize_messages(kind: ErrorKind, raw: String) -> (String, Option<String>) {
    match kind {
        ErrorKind::Unauthenticated => (
            ErrorKind::Unauthenticated
                .default_public_message()
                .to_owned(),
            non_empty_opt(raw),
        ),
        ErrorKind::Internal => (
            ErrorKind::Internal.default_public_message().to_owned(),
            non_empty_opt(raw),
        ),
        _ => {
            if raw.trim().is_empty() {
                (kind.default_public_message().to_owned(), None)
            } else {
                (raw, None)
            }
        }
    }
}

fn non_empty_opt(s: String) -> Option<String> {
    if s.trim().is_empty() { None } else { Some(s) }
}

/// Convenience `Result` alias using [`AppError`].
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::{AppError, ErrorKind};

    #[test]
    fn test_error_unauthenticated_redacts_internal_reason_consistently() {
        // Arrange
        let expired = AppError::unauthenticated("pre-auth key mpk_secret_expired expired at 12345");
        let unknown = AppError::unauthenticated("node key not found in redb");
        let bad_sig = AppError::unauthenticated("crypto_box decryption failed");

        // Act
        let e1 = expired.to_envelope("req_1");
        let e2 = unknown.to_envelope("req_2");
        let e3 = bad_sig.to_envelope("req_3");

        // Assert
        assert_eq!(e1.kind, ErrorKind::Unauthenticated);
        assert_eq!(e1.code, "E_UNAUTHENTICATED");
        assert_eq!(e1.kind.http_status_code(), 401);
        assert_eq!(e1.message, "authentication failed");
        assert_eq!(e2.message, "authentication failed");
        assert_eq!(e3.message, "authentication failed");
        assert!(!e1.message.contains("expired"));
        assert!(!e2.message.contains("redb"));
        assert!(!e3.message.contains("crypto_box"));
    }

    #[test]
    fn test_error_kind_stop_retry_and_status_mapping_matches_contract() {
        // Arrange
        let all = [
            ErrorKind::Internal,
            ErrorKind::InvalidArgument,
            ErrorKind::Unauthenticated,
            ErrorKind::PermissionDenied,
            ErrorKind::NodeRevoked,
            ErrorKind::NodeKeyExpired,
            ErrorKind::NotFound,
            ErrorKind::Conflict,
            ErrorKind::RateLimited,
            ErrorKind::Unavailable,
            ErrorKind::ClockSkew,
            ErrorKind::PinMismatch,
        ];

        // Act & Assert
        assert_eq!(ErrorKind::NodeKeyExpired.http_status_code(), 403);
        assert_eq!(ErrorKind::NodeKeyExpired.wire_code(), "E_KEY_EXPIRED");
        for kind in all {
            let expected_stop = matches!(kind, ErrorKind::NodeRevoked | ErrorKind::NodeKeyExpired);
            assert_eq!(kind.should_stop_auto_retry(), expected_stop);
            assert!(!kind.wire_code().is_empty());
        }
    }

    #[test]
    fn test_error_internal_hides_detail_from_wire_envelope() {
        // Arrange
        let err = AppError::internal("sqlite / redb corruption at offset 42");

        // Act
        let resp = err.to_response("req_99");

        // Assert
        assert_eq!(resp.error.code, "E_INTERNAL");
        assert_eq!(resp.error.message, "internal server error");
        assert_eq!(
            err.internal_detail(),
            Some("sqlite / redb corruption at offset 42")
        );
    }
}
