//! Isolated OS FFI crate (`unsafe` is permitted ONLY inside `crates/mesh-sys` with
//! `unsafe_op_in_unsafe_fn = "deny"` and mandatory `// SAFETY:` comments).

pub mod error;

#[cfg(unix)]
pub mod fs_unix;

#[cfg(target_os = "linux")]
pub mod socket_linux;
#[cfg(target_os = "macos")]
pub mod socket_macos;
#[cfg(target_os = "windows")]
pub mod socket_windows;

#[cfg(target_os = "linux")]
pub mod tun_linux;
#[cfg(target_os = "macos")]
pub mod tun_macos;
#[cfg(target_os = "windows")]
pub mod tun_windows;

#[cfg(target_os = "linux")]
pub mod ipc_linux;
#[cfg(target_os = "macos")]
pub mod ipc_macos;
#[cfg(target_os = "windows")]
pub mod ipc_windows;

#[cfg(target_os = "linux")]
pub mod netmon_linux;
#[cfg(target_os = "macos")]
pub mod netmon_macos;
#[cfg(target_os = "windows")]
pub mod netmon_windows;

pub use error::{SysError, SysResult};
#[cfg(unix)]
pub use fs_unix::filesystem_usage_percent;
#[cfg(target_os = "windows")]
pub use netmon_windows::filesystem_usage_percent;
