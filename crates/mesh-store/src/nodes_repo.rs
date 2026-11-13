//! Node registration, lookup, IP quarantine reuse, and revocation repository (`WP-S1-01`).

use mesh_core::{AppError, AppResult, NodeId};

/// Repository managing registered overlay nodes (`WP-S1-01`).
#[derive(Debug, Default)]
pub struct NodesRepository;

impl NodesRepository {
    /// Looks up a node record by identifier (`WP-S1-01`).
    pub fn find_by_id(_node_id: NodeId) -> AppResult<()> {
        Err(AppError::unavailable(
            "nodes repository queries will be implemented in WP-S1-01",
        ))
    }
}
