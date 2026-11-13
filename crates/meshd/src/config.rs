//! Client bootstrap configuration (`bootstrap.toml`, `0600`) storing `server_endpoint` + `PinSet`
//! without secrets (implemented in `WP-S1-05`).

use mesh_core::SpkiPin;
use serde::{Deserialize, Serialize};

/// Non-secret daemon bootstrap settings (`database-design.md` §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct BootstrapConfig {
    /// Control server endpoint (`IP:port` or `https://...`).
    pub(crate) server_endpoint: Option<String>,
    /// Pinned server SPKI hashes (`sha256:<64_hex>`).
    pub(crate) pins: Vec<SpkiPin>,
}
