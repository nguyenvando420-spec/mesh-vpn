//! Server administration commands over `/run/mesh-server/admin.sock` (`preauthkey`, `node`,
//! `server`, `backup`, `restore`, `hardening-check`).

use mesh_core::{AppError, AppResult};

use crate::cli::{NodeVerb, PreauthkeyVerb, ServerVerb};
use crate::output::CommandResultView;

/// Executes a `mesh preauthkey <verb>` command against server admin IPC.
pub(crate) fn run_preauthkey(action: &PreauthkeyVerb) -> AppResult<CommandResultView> {
    let op = match action {
        PreauthkeyVerb::Create => "preauthkey create".to_owned(),
        PreauthkeyVerb::List => "preauthkey list".to_owned(),
        PreauthkeyVerb::Revoke { key_id } => format!("preauthkey revoke {key_id}"),
    };
    Err(AppError::unavailable(format!(
        "server command '{op}' will be implemented in WP-S1-05"
    )))
}

/// Executes a `mesh node <verb>` command against server admin IPC.
pub(crate) fn run_node(action: &NodeVerb) -> AppResult<CommandResultView> {
    let op = match action {
        NodeVerb::List => "node list".to_owned(),
        NodeVerb::Revoke { target } => format!("node revoke {target}"),
    };
    Err(AppError::unavailable(format!(
        "server command '{op}' will be implemented in WP-S1-05"
    )))
}

/// Executes a `mesh server <verb>` command against server admin IPC.
pub(crate) fn run_server(action: &ServerVerb) -> AppResult<CommandResultView> {
    let op = match action {
        ServerVerb::Status => "server status",
    };
    Err(AppError::unavailable(format!(
        "server command '{op}' will be implemented in WP-S1-05"
    )))
}

/// Executes backup, restore, or hardening check administration operations.
pub(crate) fn run_maintenance(operation: &str, arg: Option<&str>) -> AppResult<CommandResultView> {
    let label = match arg {
        Some(a) => format!("{operation}:{a}"),
        None => operation.to_owned(),
    };
    Err(AppError::unavailable(format!(
        "maintenance command '{label}' will be implemented in WP-S1-05"
    )))
}
