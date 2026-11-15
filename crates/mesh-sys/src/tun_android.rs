//! Safe adoption of detached Android `VpnService` TUN file descriptors (`ADR-014`).

use std::io::Error;
use std::os::fd::{FromRawFd, OwnedFd};

use crate::error::SysResult;

/// Adopts a detached non-negative TUN descriptor from `ParcelFileDescriptor.detachFd()` into an RAII [`OwnedFd`].
///
/// Validates descriptor liveness and enforces `FD_CLOEXEC` + `O_NONBLOCK` prior to transferring
/// ownership so failed validations never close an unowned or invalid descriptor.
pub fn adopt_raw_tun_fd(raw_fd: i32) -> SysResult<OwnedFd> {
    if raw_fd < 0 {
        return Err(crate::error::SysError::io(
            "adopt_raw_tun_fd",
            Error::from_raw_os_error(libc::EBADF),
        ));
    }
    // SAFETY: `fcntl(raw_fd, F_GETFD)` is a read-only descriptor validity check requiring no pointers.
    let fd_flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(crate::error::SysError::io(
            "adopt_raw_tun_fd",
            Error::last_os_error(),
        ));
    }
    if (fd_flags & libc::FD_CLOEXEC) == 0 {
        // SAFETY: `raw_fd` was verified open by `F_GETFD` and `F_SETFD` takes an integer bitmask.
        let set_fd_rc = unsafe { libc::fcntl(raw_fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) };
        if set_fd_rc < 0 {
            return Err(crate::error::SysError::io(
                "adopt_raw_tun_fd",
                Error::last_os_error(),
            ));
        }
    }
    // SAFETY: `raw_fd` was verified open by `F_GETFD` and `F_GETFL` takes no pointers.
    let status_flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
    if status_flags < 0 {
        return Err(crate::error::SysError::io(
            "adopt_raw_tun_fd",
            Error::last_os_error(),
        ));
    }
    if (status_flags & libc::O_NONBLOCK) == 0 {
        // SAFETY: `raw_fd` was verified open and `F_SETFL` takes an integer bitmask with no pointers.
        let set_fl_rc =
            unsafe { libc::fcntl(raw_fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK) };
        if set_fl_rc < 0 {
            return Err(crate::error::SysError::io(
                "adopt_raw_tun_fd",
                Error::last_os_error(),
            ));
        }
    }
    // SAFETY: Caller detached exclusive descriptor ownership via `ParcelFileDescriptor.detachFd()`,
    // `fcntl(F_GETFD)` confirmed `raw_fd` is an open file descriptor, and all `FD_CLOEXEC`/`O_NONBLOCK`
    // checks completed before creating `OwnedFd` (so earlier failures never close `raw_fd`).
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

    use super::adopt_raw_tun_fd;

    #[test]
    fn test_tun_android_adopt_rejects_negative_and_bad_fd() {
        // Arrange & Act
        let neg_res = adopt_raw_tun_fd(-1);
        let bad_res = adopt_raw_tun_fd(i32::MAX);

        // Assert
        assert!(neg_res.is_err());
        assert!(bad_res.is_err());
    }

    #[test]
    fn test_tun_android_adopt_enforces_cloexec_and_nonblock() {
        // Arrange
        let mut fds: [RawFd; 2] = [-1, -1];
        // SAFETY: `fds` is a valid 2-element stack array passed to `pipe`.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let [read_fd, write_fd] = fds;
        // SAFETY: `pipe` succeeded and yielded two fresh owned descriptors.
        let _write_guard = unsafe { OwnedFd::from_raw_fd(write_fd) };

        // Act
        let adopted = adopt_raw_tun_fd(read_fd);

        // Assert
        assert!(adopted.is_ok());
        if let Ok(owned) = adopted {
            let raw = owned.as_raw_fd();
            // SAFETY: `owned` holds an open file descriptor for read-only flag queries.
            let fd_flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
            // SAFETY: `owned` holds an open file descriptor for read-only flag queries.
            let fl_flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
            assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
            assert_ne!(fl_flags & libc::O_NONBLOCK, 0);
        }
    }
}
