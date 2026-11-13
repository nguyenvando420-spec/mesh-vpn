//! Human-readable table formatting and stable `--json` serialization for `mesh` CLI output.

use std::io::{self, Write};

use mesh_core::{AppError, ErrorEnvelope, ErrorResponse};
use serde::Serialize;

/// Generic structured command output rendered either as aligned text or `--json`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CommandResultView {
    /// Status summary string.
    pub(crate) status: String,
    /// Structured message detail.
    pub(crate) detail: String,
}

/// Writes success output to `stdout` without using prohibited `println!` macros.
pub(crate) fn write_success(view: &CommandResultView, json: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    if json {
        let encoded = serde_json::to_string(view).unwrap_or_else(|_| {
            "{\"status\":\"error\",\"detail\":\"serialization failed\"}".to_owned()
        });
        writeln!(out, "{encoded}")
    } else {
        writeln!(out, "{}: {}", view.status, view.detail)
    }
}

/// Writes error output to `stderr` (or structured `ErrorResponse` JSON when `--json` is set).
pub(crate) fn write_error(err: &AppError, json: bool) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    if json {
        let envelope = ErrorEnvelope {
            kind: err.kind(),
            code: err.kind().wire_code().to_owned(),
            message: err.public_message().to_owned(),
            request_id: "cli-local".to_owned(),
        };
        let payload = ErrorResponse { error: envelope };
        let encoded = serde_json::to_string(&payload)
            .unwrap_or_else(|_| "{\"error\":{\"kind\":\"internal\"}}".to_owned());
        writeln!(stderr, "{encoded}")
    } else {
        writeln!(stderr, "error [{}]: {}", err.kind().wire_code(), err)
    }
}
