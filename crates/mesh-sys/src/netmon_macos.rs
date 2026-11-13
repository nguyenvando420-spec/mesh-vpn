//! macOS `PF_ROUTE` physical uplink interface and default route monitoring (`WP-S1-02`).

use crate::error::{SysError, SysResult};

/// Queries the current primary physical egress interface index on macOS.
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    Err(SysError::NotImplemented(
        "netmon_macos::query_primary_physical_if_index",
    ))
}
