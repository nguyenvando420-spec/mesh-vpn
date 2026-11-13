//! macOS `utunN` (`PF_SYSTEM` / `UTUN_CONTROL_NAME`) kernel socket management (`WP-S1-02`).

use crate::error::{SysError, SysResult};

/// Opens a macOS `utunN` device returning `(assigned_name, raw_fd)`.
pub fn open_utun_device(_unit_hint: Option<u32>) -> SysResult<(String, i32)> {
    Err(SysError::NotImplemented("tun_macos::open_utun_device"))
}
