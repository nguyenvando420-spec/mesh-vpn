//! Build script for `mesh-gui` (`MeshVPN.exe`), guarding MSVC-specific rules (`ADR-020`).

use std::ffi::OsStr;
use std::io::Write as _;

fn main() {
    if std::io::stdout()
        .write_all(b"cargo:rerun-if-env-changed=MESH_WINTUN_SHA256\n")
        .is_err()
    {
        std::process::exit(1);
    }

    if std::env::var_os("CARGO_CFG_TARGET_ENV").as_deref() == Some(OsStr::new("msvc")) {
        // MSVC-only linker configuration point (MinGW `gnu` and non-Windows skip cleanly).
    }
}
