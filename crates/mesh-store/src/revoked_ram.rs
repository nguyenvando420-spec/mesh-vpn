//! In-memory `RevokedSet` and fail-closed `64 KiB` emergency revocation binary log (`WP-S1-01`).

use std::collections::HashSet;

use mesh_core::NodeId;

/// Fixed `64 KiB` size of `emergency-revocations.bin` (Slot A `32 KiB` + Slot B `32 KiB`).
pub const EMERGENCY_REVOCATION_FILE_BYTES: usize = 65_536;

/// Lock-friendly memory cache of revoked node identifiers checked on hot paths (`WP-S1-01`).
#[derive(Debug, Default, Clone)]
pub struct RevokedSet {
    nodes: HashSet<NodeId>,
}

impl RevokedSet {
    /// Creates an empty [`RevokedSet`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `node_id` has been revoked.
    #[must_use]
    pub fn contains(&self, node_id: NodeId) -> bool {
        self.nodes.contains(&node_id)
    }

    /// Records `node_id` into the in-memory revocation set.
    pub fn insert(&mut self, node_id: NodeId) {
        self.nodes.insert(node_id);
    }
}
