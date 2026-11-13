//! Windows `NotifyIpInterfaceChange` / IP Helper physical uplink interface monitor (`WP-S1-04`).

use crate::error::{SysError, SysResult};

/// Queries the current primary physical egress interface index on Windows.
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    Err(SysError::NotImplemented(
        "netmon_windows::query_primary_physical_if_index",
    ))
}
