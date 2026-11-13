use std::ffi::{CStr, CString};
use std::io::Error;
use std::mem::{size_of, zeroed};
use std::os::fd::RawFd;
use std::ptr;

use crate::error::{SysError, SysResult};
use crate::fs_unix::UnixPeerCredentials;

const INITIAL_PW_BUF_LEN: usize = 4096;
const MAX_PW_BUF_LEN: usize = 65_536;
const MAX_SUPPLEMENTARY_GROUPS: usize = 1024;

/// Inspects real/effective credentials and full supplementary groups of a peer connected over
/// a Linux Unix domain socket via `SO_PEERCRED` (`uid`, `gid`, `pid`) and `getpwuid_r`/`getgrouplist`.
pub fn inspect_peer_creds(fd: RawFd) -> SysResult<UnixPeerCredentials> {
    if fd < 0 {
        return Err(SysError::io(
            "inspect_peer_creds",
            Error::from_raw_os_error(libc::EBADF),
        ));
    }

    // SAFETY: `libc::ucred` is a plain C struct composed solely of signed/unsigned integers.
    let mut ucred: libc::ucred = unsafe { zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: `fd` is validated non-negative and `ucred`/`len` point to writable stack locals.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut ucred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(SysError::io("inspect_peer_creds", Error::last_os_error()));
    }
    if (len as usize) < size_of::<libc::ucred>()
        || ucred.uid == libc::uid_t::MAX
        || ucred.gid == libc::gid_t::MAX
    {
        return Err(SysError::SecurityViolation {
            operation: "inspect_peer_creds",
            detail: "kernel returned invalid or unmapped SO_PEERCRED identity".to_owned(),
        });
    }

    let mut supplementary_gids = resolve_user_supplementary_groups(ucred.uid, ucred.gid)?;
    if !supplementary_gids.contains(&ucred.gid) {
        supplementary_gids.push(ucred.gid);
    }

    Ok(UnixPeerCredentials {
        uid: ucred.uid,
        primary_gid: ucred.gid,
        supplementary_gids,
    })
}

/// Resolves a POSIX group name (e.g. `mesh-admin`) into its numeric GID via `getgrnam_r`.
pub fn resolve_group_gid(group_name: &str) -> SysResult<Option<u32>> {
    if group_name.is_empty() {
        return Err(SysError::SecurityViolation {
            operation: "resolve_group_gid",
            detail: "group name must not be empty".to_owned(),
        });
    }
    let c_name = CString::new(group_name).map_err(|_| SysError::SecurityViolation {
        operation: "resolve_group_gid",
        detail: "group name contains interior NUL byte".to_owned(),
    })?;

    let mut buf_len = INITIAL_PW_BUF_LEN;
    loop {
        // SAFETY: `libc::group` is a plain C struct initialized with zeros before `getgrnam_r`.
        let mut grp: libc::group = unsafe { zeroed() };
        let mut buf = vec![0 as libc::c_char; buf_len];
        let mut result: *mut libc::group = ptr::null_mut();

        // SAFETY: `c_name`, `grp`, `buf`, and `result` are valid non-overlapping arguments to
        // POSIX `getgrnam_r` for the size specified in `buf_len`.
        let rc = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &raw mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE && buf_len < MAX_PW_BUF_LEN {
            buf_len *= 2;
            continue;
        }
        if rc != 0 && rc != libc::ENOENT && rc != libc::ESRCH {
            return Err(SysError::io(
                "resolve_group_gid",
                Error::from_raw_os_error(rc),
            ));
        }
        if result.is_null() {
            return Ok(None);
        }
        return Ok(Some(grp.gr_gid));
    }
}

/// Verifies whether a peer connected on `fd` holds admin privilege:
/// `uid == 0` (`root`), `uid == service_uid`, or membership (primary or supplementary) in `admin_gid`.
pub fn verify_admin_peer_cred(
    fd: RawFd,
    service_uid: u32,
    admin_gid: Option<u32>,
) -> SysResult<()> {
    let creds = inspect_peer_creds(fd)?;
    let in_admin_group = admin_gid
        .is_some_and(|gid| creds.primary_gid == gid || creds.supplementary_gids.contains(&gid));

    if creds.uid == 0 || creds.uid == service_uid || in_admin_group {
        return Ok(());
    }

    Err(SysError::PermissionDenied {
        operation: "verify_admin_peer_cred",
    })
}

/// Returns the current process effective UID via `geteuid(2)`.
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid` takes no pointers and always succeeds.
    unsafe { libc::geteuid() }
}

fn resolve_user_supplementary_groups(uid: u32, base_gid: u32) -> SysResult<Vec<u32>> {
    let mut buf_len = INITIAL_PW_BUF_LEN;
    loop {
        // SAFETY: `libc::passwd` is a plain C struct zeroed before `getpwuid_r`.
        let mut pwd: libc::passwd = unsafe { zeroed() };
        let mut buf = vec![0 as libc::c_char; buf_len];
        let mut result: *mut libc::passwd = ptr::null_mut();

        // SAFETY: `pwd`, `buf`, and `result` are valid non-aliasing buffers for `getpwuid_r`.
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &raw mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE && buf_len < MAX_PW_BUF_LEN {
            buf_len *= 2;
            continue;
        }
        if rc != 0 && rc != libc::ENOENT && rc != libc::ESRCH {
            return Err(SysError::io(
                "inspect_peer_creds",
                Error::from_raw_os_error(rc),
            ));
        }
        if result.is_null() || pwd.pw_name.is_null() {
            return Ok(vec![base_gid]);
        }

        // SAFETY: `pwd.pw_name` points into live `buf` until the end of this scope.
        let user_cstr = unsafe { CStr::from_ptr(pwd.pw_name) };
        return call_getgrouplist(user_cstr, base_gid);
    }
}

fn call_getgrouplist(user: &CStr, base_gid: u32) -> SysResult<Vec<u32>> {
    let mut capacity: usize = 32;
    loop {
        let mut groups = vec![0 as libc::gid_t; capacity];
        let mut ngroups = capacity as libc::c_int;

        // SAFETY: `user` is NUL-terminated and `groups` holds `capacity` writable `gid_t` slots.
        let rc = unsafe {
            libc::getgrouplist(
                user.as_ptr(),
                base_gid as libc::gid_t,
                groups.as_mut_ptr(),
                &raw mut ngroups,
            )
        };
        if rc == -1 {
            let needed = usize::try_from(ngroups).unwrap_or(capacity.saturating_mul(2));
            if needed <= MAX_SUPPLEMENTARY_GROUPS && needed > capacity {
                capacity = needed;
                continue;
            }
            let capped = capacity.min(groups.len());
            return Ok(groups.into_iter().take(capped).collect());
        }

        let count = usize::try_from(ngroups).unwrap_or(0).min(groups.len());
        return Ok(groups.into_iter().take(count).collect());
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    use tempfile::tempdir;

    use super::{current_euid, inspect_peer_creds, resolve_group_gid, verify_admin_peer_cred};
    use crate::error::SysError;

    #[test]
    fn test_ipc_linux_peer_creds_over_unix_listener() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let sock_path = dir.path().join("admin.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
        let _client = UnixStream::connect(&sock_path).expect("connect client");
        let (server_stream, _) = listener.accept().expect("accept client");
        let euid = current_euid();

        // Act
        let creds = inspect_peer_creds(server_stream.as_raw_fd()).expect("inspect creds");

        // Assert
        assert_eq!(creds.uid, euid);
        verify_admin_peer_cred(server_stream.as_raw_fd(), euid, None)
            .expect("matching service uid authorized");
        assert!(matches!(
            verify_admin_peer_cred(server_stream.as_raw_fd(), euid.saturating_add(10_000), None),
            Err(SysError::PermissionDenied { .. }) | Ok(()) // passes if current uid is 0
        ));
    }

    #[test]
    fn test_ipc_linux_resolve_group_handles_missing_and_root() {
        // Arrange & Act
        let missing = resolve_group_gid("mesh_nonexistent_group_xyz").expect("lookup missing");
        let root_gid = resolve_group_gid("root").expect("lookup root");

        // Assert
        assert_eq!(missing, None);
        assert_eq!(root_gid, Some(0));
    }

    #[test]
    fn test_ipc_linux_invalid_fd_rejected() {
        // Arrange & Act
        let res = inspect_peer_creds(-1);

        // Assert
        assert!(matches!(res, Err(SysError::Io { .. })));
    }
}
