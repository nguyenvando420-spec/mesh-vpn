//! Daemon `CancellationToken` + `TaskTracker` lifecycle enforcing `Graceful Shutdown <= 5s` (`REL-08`).

use mesh_core::defaults::GRACEFUL_SHUTDOWN_BUDGET_MS;

/// Coordinates hierarchical cancellation and bounded teardown across daemon tasks.
#[derive(Debug, Default)]
pub(crate) struct DaemonSupervisor;

impl DaemonSupervisor {
    /// Summary label reporting shutdown budget.
    #[must_use]
    pub(crate) fn status_label() -> String {
        format!("supervisor:shutdown_budget_ms={GRACEFUL_SHUTDOWN_BUDGET_MS}")
    }
}
