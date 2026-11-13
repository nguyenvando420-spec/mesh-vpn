//! Windows Wintun verified DLL loader and ring-buffer adapter wrapper (`SEC`, `WP-S1-04`).

use std::path::Path;

use crate::error::{SysError, SysResult};

/// Loads `wintun.dll` from the verified application directory after constant-time SHA-256 verification.
pub fn verify_and_open_wintun(_dll_path: &Path, _expected_sha256_hex: &str) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "tun_windows::verify_and_open_wintun",
    ))
}
