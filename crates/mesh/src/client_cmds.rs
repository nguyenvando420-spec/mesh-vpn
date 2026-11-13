//! Client daemon commands over `meshd-ro` (`status`/`peers`/`ping`/`netcheck`) and
//! `meshd-admin` (`up`/`down`/`set`/`rotate-key`/`cleanup`/`bugreport`).

use mesh_core::{AppError, AppResult};

use crate::output::CommandResultView;

/// Executes read-only client status/peers/ping/netcheck queries (`meshd-ro`).
pub(crate) fn run_ro_query(operation: &str, target: Option<&str>) -> AppResult<CommandResultView> {
    let label = match target {
        Some(t) => format!("{operation}:{t}"),
        None => operation.to_owned(),
    };
    Err(AppError::unavailable(format!(
        "client query '{label}' over meshd-ro IPC will be implemented in WP-S1-05"
    )))
}

/// Executes privileged client control mutations (`meshd-admin`).
pub(crate) fn run_admin_mutation(
    operation: &str,
    detail: Option<&str>,
) -> AppResult<CommandResultView> {
    let label = match detail {
        Some(d) => format!("{operation}:{d}"),
        None => operation.to_owned(),
    };
    Err(AppError::unavailable(format!(
        "client command '{label}' over meshd-admin IPC will be implemented in WP-S1-05"
    )))
}
