//! Safe adoption of detached Android `VpnService` TUN file descriptors (`ADR-014`).

use std::io::Error;
use std::os::fd::{FromRawFd, OwnedFd};

use crate::error::SysResult;

/// Adopts a detached non-negative TUN descriptor from `ParcelFileDescriptor.detachFd()` into an RAII [`OwnedFd`].
pub fn adopt_raw_tun_fd(raw_fd: i32) -> SysResult<OwnedFd> {
    if raw_fd < 0 {
        return Err(crate::error::SysError::io(
            "adopt_raw_tun_fd",
            Error::from_raw_os_error(libc::EBADF),
        ));
    }
    // SAFETY: `fcntl(raw_fd, F_GETFD)` is a read-only descriptor validity check requiring no pointers.
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(crate::error::SysError::io(
            "adopt_raw_tun_fd",
            Error::last_os_error(),
        ));
    }
    // SAFETY: Caller detached exclusive descriptor ownership via `ParcelFileDescriptor.detachFd()`
    // and `fcntl(F_GETFD)` just confirmed `raw_fd` is an open file descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    Ok(owned)
}
