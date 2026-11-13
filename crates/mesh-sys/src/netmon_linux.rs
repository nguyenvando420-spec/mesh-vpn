//! Linux Netlink physical uplink interface and default route monitoring (`WP-S1-03`).

use crate::error::{SysError, SysResult};

/// Queries the current primary physical egress interface index on Linux.
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    Err(SysError::NotImplemented(
        "netmon_linux::query_primary_physical_if_index",
    ))
}
