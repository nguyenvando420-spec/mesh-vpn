//! Structured low-level OS FFI errors mapped cleanly to `mesh_core::AppError`.

use std::io;

use thiserror::Error;

use mesh_core::AppError;

/// Error returned by OS system-call wrappers in `mesh-sys`.
#[derive(Debug, Error)]
pub enum SysError {
    /// Underlying OS I/O error with operation context.
    #[error("{operation} failed: {source}")]
    Io {
        /// Human-readable OS operation name.
        operation: &'static str,
        /// Captured `std::io::Error` or raw errno/Win32 code.
        source: io::Error,
    },
    /// Operation attempted without sufficient root/Administrator privilege.
    #[error("permission denied during {operation}")]
    PermissionDenied {
        /// Human-readable OS operation name.
        operation: &'static str,
    },
    /// OS peer credential or symlink/ownership security check failed.
    #[error("security invariant violation during {operation}: {detail}")]
    SecurityViolation {
        /// Security-sensitive operation name.
        operation: &'static str,
        /// Sanitized non-secret failure description.
        detail: String,
    },
    /// Feature or OS implementation not yet wired on this target build.
    #[error("OS adapter operation `{0}` is not supported yet")]
    NotImplemented(&'static str),
}

/// Convenience `Result` alias for `mesh-sys` functions.
pub type SysResult<T> = Result<T, SysError>;

impl SysError {
    /// Constructs [`SysError::Io`] for the named OS operation.
    #[must_use]
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::PermissionDenied {
            Self::PermissionDenied { operation }
        } else {
            Self::Io { operation, source }
        }
    }
}

impl From<SysError> for AppError {
    fn from(value: SysError) -> Self {
        match value {
            SysError::PermissionDenied { operation } => Self::permission_denied(format!(
                "administrator/root privileges required for `{operation}`"
            )),
            SysError::SecurityViolation { operation, detail } => {
                Self::permission_denied(format!("{operation}: {detail}"))
            }
            SysError::Io { operation, source } => {
                Self::internal(format!("OS error during `{operation}`: {source}"))
            }
            SysError::NotImplemented(op) => {
                Self::unavailable(format!("OS operation `{op}` not implemented"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use mesh_core::{AppError, ErrorKind};

    use super::SysError;

    #[test]
    fn test_sys_error_maps_permission_and_security_to_permission_denied() {
        // Arrange
        let perm = SysError::io("tun_open", io::Error::from(io::ErrorKind::PermissionDenied));
        let sec = SysError::SecurityViolation {
            operation: "parent_dir_check",
            detail: "symlink component rejected".to_owned(),
        };

        // Act
        let app_perm = AppError::from(perm);
        let app_sec = AppError::from(sec);

        // Assert
        assert_eq!(app_perm.kind(), ErrorKind::PermissionDenied);
        assert_eq!(app_sec.kind(), ErrorKind::PermissionDenied);
    }
}
