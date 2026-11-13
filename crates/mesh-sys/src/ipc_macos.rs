use std::ffi::CStr;
use std::io::Error;
use std::mem::{size_of, zeroed};
use std::os::fd::RawFd;
use std::ptr;

use crate::error::{SysError, SysResult};
use crate::fs_unix::UnixPeerCredentials;

const INITIAL_PW_BUF_LEN: usize = 4096;
const MAX_PW_BUF_LEN: usize = 65_536;
const MAX_SUPPLEMENTARY_GROUPS: usize = 1024;

/// Inspects credentials of a peer connected over a macOS Unix domain socket via both
/// `getpeereid(3)` and `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`.
///
/// When `xucred.cr_ngroups` hits the kernel `16`-group cap (`cr_groups.len()`), falls back to
/// `getpwuid_r` + `getgrouplist` so members of >16 groups (such as `admin` gid `80`) are detected.
pub fn inspect_peer_creds(fd: RawFd) -> SysResult<UnixPeerCredentials> {
    if fd < 0 {
        return Err(SysError::io(
            "inspect_peer_creds",
            Error::from_raw_os_error(libc::EBADF),
        ));
    }

    let (euid, egid) = query_peereid(fd)?;
    let ucred = query_local_peercred(fd)?;
    if ucred.cr_uid != euid {
        return Err(SysError::SecurityViolation {
            operation: "inspect_peer_creds",
            detail: format!(
                "mismatch between getpeereid uid ({euid}) and LOCAL_PEERCRED uid ({})",
                ucred.cr_uid
            ),
        });
    }

    let ngroups = usize::try_from(ucred.cr_ngroups)
        .unwrap_or(0)
        .min(ucred.cr_groups.len());
    let mut gids = Vec::with_capacity(ngroups.saturating_add(1));
    if let Some(slice) = ucred.cr_groups.get(..ngroups) {
        gids.extend_from_slice(slice);
    }
    if !gids.contains(&egid) {
        gids.push(egid);
    }

    if ngroups >= ucred.cr_groups.len() {
        let full_gids = resolve_user_supplementary_groups(euid, egid)?;
        for gid in full_gids {
            if !gids.contains(&gid) {
                gids.push(gid);
            }
        }
    }

    Ok(UnixPeerCredentials {
        uid: euid,
        primary_gid: egid,
        supplementary_gids: gids,
    })
}

/// Verifies whether a peer connected on a macOS Admin socket holds `root` (`uid == 0`) or
/// belongs to `admin_gid` (`gid == 80` on macOS, including via >16 supplementary groups).
pub fn verify_admin_peer_cred(fd: RawFd, admin_gid: u32) -> SysResult<()> {
    let creds = inspect_peer_creds(fd)?;
    if creds.uid == 0
        || creds.primary_gid == admin_gid
        || creds.supplementary_gids.contains(&admin_gid)
    {
        return Ok(());
    }

    Err(SysError::PermissionDenied {
        operation: "verify_admin_peer_cred",
    })
}

fn query_peereid(fd: RawFd) -> SysResult<(u32, u32)> {
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;

    // SAFETY: `fd` is validated non-negative and `euid`/`egid` are writable stack locals.
    let rc = unsafe { libc::getpeereid(fd, &raw mut euid, &raw mut egid) };
    if rc != 0 {
        return Err(SysError::io("inspect_peer_creds", Error::last_os_error()));
    }

    Ok((euid, egid))
}

fn query_local_peercred(fd: RawFd) -> SysResult<libc::xucred> {
    // SAFETY: `libc::xucred` is a plain C struct composed solely of integer fields.
    let mut ucred: libc::xucred = unsafe { zeroed() };
    let mut len = size_of::<libc::xucred>() as libc::socklen_t;

    // SAFETY: `fd` is validated non-negative and `ucred`/`len` point to writable stack locals.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            (&raw mut ucred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(SysError::io("inspect_peer_creds", Error::last_os_error()));
    }
    if (len as usize) < size_of::<libc::xucred>() || ucred.cr_version != libc::XUCRED_VERSION {
        return Err(SysError::SecurityViolation {
            operation: "inspect_peer_creds",
            detail: format!(
                "unexpected macOS xucred layout/version ({})",
                ucred.cr_version
            ),
        });
    }

    Ok(ucred)
}

fn resolve_user_supplementary_groups(uid: u32, base_gid: u32) -> SysResult<Vec<u32>> {
    let mut buf_len = INITIAL_PW_BUF_LEN;
    loop {
        // SAFETY: `libc::passwd` is a plain C struct zero-initialized before `getpwuid_r`.
        let mut pwd: libc::passwd = unsafe { zeroed() };
        let mut buf = vec![0 as libc::c_char; buf_len];
        let mut result: *mut libc::passwd = ptr::null_mut();

        // SAFETY: `pwd`, `buf`, and `result` are valid non-overlapping buffers for `getpwuid_r`.
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
        return call_macos_getgrouplist(user_cstr, base_gid);
    }
}

fn call_macos_getgrouplist(user: &CStr, base_gid: u32) -> SysResult<Vec<u32>> {
    let mut capacity: usize = 32;
    loop {
        let mut groups = vec![0 as libc::c_int; capacity];
        let mut ngroups = capacity as libc::c_int;

        // SAFETY: Darwin `getgrouplist` accepts `*const c_char`, `basegid: c_int`, `*mut c_int`,
        // and `*mut c_int`; `groups` provides `capacity` writable elements.
        let rc = unsafe {
            libc::getgrouplist(
                user.as_ptr(),
                base_gid as libc::c_int,
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
            return Ok(groups
                .into_iter()
                .take(capacity)
                .filter_map(|g| u32::try_from(g).ok())
                .collect());
        }

        let count = usize::try_from(ngroups).unwrap_or(0).min(groups.len());
        return Ok(groups
            .into_iter()
            .take(count)
            .filter_map(|g| u32::try_from(g).ok())
            .collect());
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    use tempfile::tempdir;

    use super::{inspect_peer_creds, verify_admin_peer_cred};
    use crate::error::SysError;

    #[test]
    fn test_ipc_macos_peer_creds_over_unix_listener() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let sock_path = dir.path().join("meshd-admin.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
        let _client = UnixStream::connect(&sock_path).expect("connect client");
        let (server_stream, _) = listener.accept().expect("accept client");
        // SAFETY: `geteuid` is always safe to call.
        let euid = unsafe { libc::geteuid() };

        // Act
        let creds = inspect_peer_creds(server_stream.as_raw_fd()).expect("inspect creds");

        // Assert
        assert_eq!(creds.uid, euid);
        assert!(!creds.supplementary_gids.is_empty());
        verify_admin_peer_cred(server_stream.as_raw_fd(), creds.primary_gid)
            .expect("matching primary gid authorized");
    }

    #[test]
    fn test_ipc_macos_invalid_fd_rejected() {
        // Arrange & Act
        let res = inspect_peer_creds(-1);

        // Assert
        assert!(matches!(res, Err(SysError::Io { .. })));
    }
}
