use std::ffi::CString;
use std::fs::{self, DirBuilder, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::{SysError, SysResult};

/// Security policy enforced on privileged runtime directories and files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureDirPolicy {
    /// Required owner user ID (`0` for root-owned paths).
    pub expected_uid: u32,
    /// Optional required owner group ID (`Some(80)` for macOS `admin`, etc.).
    pub expected_gid: Option<u32>,
    /// Maximum allowed POSIX permission bits (e.g. `0o755`, `0o700`, `0o644`).
    pub max_mode: u32,
}

/// Verified credentials of a peer connected over a local Unix domain socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixPeerCredentials {
    /// Effective/real peer user ID.
    pub uid: u32,
    /// Primary peer group ID.
    pub primary_gid: u32,
    /// Full set of supplementary group IDs resolved for the peer user.
    pub supplementary_gids: Vec<u32>,
}

const MAX_SYSTEM_SYMLINK_HOPS: u8 = 4;
const GROUP_OR_WORLD_WRITE_MASK: u32 = 0o022;
const PERMISSION_AND_SPECIAL_BITS_MASK: u32 = 0o7777;

/// Verifies that an existing runtime directory and all its ancestors satisfy `policy`.
///
/// Rejects relative paths, leaf symlinks, non-root untrusted symlinks in parent paths,
/// unexpected ownership, and group/world-writable permission bits (`0o022`).
pub fn verify_secure_runtime_dir(path: &Path, policy: SecureDirPolicy) -> SysResult<()> {
    verify_ancestor_chain(path, policy.expected_uid, 0)?;
    let meta = open_leaf_nofollow_metadata(path, "verify_secure_runtime_dir", true)?;
    verify_leaf_metadata(path, &meta, policy, true, "verify_secure_runtime_dir")
}

/// Prepares a runtime directory securely, creating it with `policy.max_mode` if absent.
///
/// Always validates existing ancestors before creation and re-verifies the opened leaf
/// using `O_NOFOLLOW` to prevent TOCTOU symlink replacement attacks.
pub fn prepare_secure_runtime_dir(path: &Path, policy: SecureDirPolicy) -> SysResult<()> {
    if !path.is_absolute() {
        return Err(SysError::SecurityViolation {
            operation: "prepare_secure_runtime_dir",
            detail: format!("path '{}' must be absolute", path.display()),
        });
    }

    verify_ancestor_chain(path, policy.expected_uid, 0)?;

    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(SysError::SecurityViolation {
                    operation: "prepare_secure_runtime_dir",
                    detail: format!("target path '{}' must not be a symlink", path.display()),
                });
            }
            if !meta.is_dir() {
                return Err(SysError::SecurityViolation {
                    operation: "prepare_secure_runtime_dir",
                    detail: format!("target path '{}' is not a directory", path.display()),
                });
            }
            if let Some(expected_gid) = policy.expected_gid
                && meta.gid() != expected_gid
            {
                apply_group_or_owner_if_allowed(path, policy.expected_uid, expected_gid)?;
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            create_dir_strict(path, policy)?;
        }
        Err(err) => return Err(SysError::io("prepare_secure_runtime_dir", err)),
    }

    verify_secure_runtime_dir(path, policy)
}

/// Verifies that an existing regular file (such as a daemon binary, plist, or state file)
/// and all of its ancestor directories satisfy `policy` without symlink substitution.
pub fn verify_secure_file(path: &Path, policy: SecureDirPolicy) -> SysResult<()> {
    verify_ancestor_chain(path, policy.expected_uid, 0)?;
    let meta = open_leaf_nofollow_metadata(path, "verify_secure_file", false)?;
    verify_leaf_metadata(path, &meta, policy, false, "verify_secure_file")
}

/// Returns the current process's effective user ID via `libc::geteuid`.
#[must_use]
pub fn current_euid() -> u32 {
    // SAFETY: `libc::geteuid()` has no preconditions and always returns the process EUID.
    unsafe { libc::geteuid() }
}

/// Updates group ownership of `path` (without following symlinks) via `lchown` when its
/// current group differs from `gid`.
///
/// Works both when running with effective UID `0` and when an unprivileged file/socket owner
/// assigns group ownership to one of its supplementary groups.
pub fn set_path_group_if_root(path: &Path, gid: u32) -> SysResult<()> {
    let meta =
        fs::symlink_metadata(path).map_err(|err| SysError::io("set_path_group_if_root", err))?;
    if meta.file_type().is_symlink() {
        return Err(SysError::SecurityViolation {
            operation: "set_path_group_if_root",
            detail: format!("path '{}' must not be a symlink", path.display()),
        });
    }
    // Unix domain sockets (`S_IFSOCK`) cannot be `open(2)`-ed (`ENXIO`/`EOPNOTSUPP`), while
    // regular files and directories are re-opened via `O_NOFOLLOW` to prevent TOCTOU races.
    let verified_meta = if meta.file_type().is_socket() {
        meta
    } else {
        open_leaf_nofollow_metadata(path, "set_path_group_if_root", meta.is_dir())?
    };
    if verified_meta.gid() == gid {
        return Ok(());
    }

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| SysError::SecurityViolation {
            operation: "set_path_group_if_root",
            detail: format!("path '{}' contains an interior NUL byte", path.display()),
        })?;
    let keep_uid = u32::MAX as libc::uid_t;

    // SAFETY: `c_path` is a NUL-terminated path string and `lchown` never follows symlinks.
    let rc = unsafe { libc::lchown(c_path.as_ptr(), keep_uid, gid as libc::gid_t) };
    if rc != 0 {
        return Err(SysError::io(
            "set_path_group_if_root",
            std::io::Error::last_os_error(),
        ));
    }

    Ok(())
}

fn create_dir_strict(path: &Path, policy: SecureDirPolicy) -> SysResult<()> {
    let mut builder = DirBuilder::new();
    builder.mode(policy.max_mode & 0o777);
    match builder.create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => return Err(SysError::io("prepare_secure_runtime_dir", err)),
    }

    if let Some(expected_gid) = policy.expected_gid {
        apply_group_or_owner_if_allowed(path, policy.expected_uid, expected_gid)?;
    }

    Ok(())
}

fn apply_group_or_owner_if_allowed(path: &Path, uid: u32, gid: u32) -> SysResult<()> {
    let meta = open_leaf_nofollow_metadata(path, "prepare_secure_runtime_dir", true)?;
    // SAFETY: `libc::geteuid()` has no preconditions and always returns the process EUID.
    let current_euid = unsafe { libc::geteuid() };
    if meta.gid() == gid && (current_euid != 0 || meta.uid() == uid) {
        return Ok(());
    }

    let target_uid = if current_euid == 0 {
        uid as libc::uid_t
    } else {
        u32::MAX as libc::uid_t
    };

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| SysError::SecurityViolation {
            operation: "prepare_secure_runtime_dir",
            detail: format!("path '{}' contains an interior NUL byte", path.display()),
        })?;

    // SAFETY: `c_path` is a valid NUL-terminated C string pointing to a directory verified via
    // `O_NOFOLLOW`, and `lchown` never follows symlinks.
    let rc = unsafe { libc::lchown(c_path.as_ptr(), target_uid, gid as libc::gid_t) };
    if rc != 0 {
        return Err(SysError::io(
            "prepare_secure_runtime_dir",
            std::io::Error::last_os_error(),
        ));
    }

    Ok(())
}

fn open_leaf_nofollow_metadata(
    path: &Path,
    operation: &'static str,
    expect_dir: bool,
) -> SysResult<Metadata> {
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if expect_dir {
        flags |= libc::O_DIRECTORY;
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                SysError::SecurityViolation {
                    operation,
                    detail: format!("path '{}' must not be a symlink", path.display()),
                }
            } else {
                SysError::io(operation, err)
            }
        })?;

    file.metadata().map_err(|err| SysError::io(operation, err))
}

fn verify_leaf_metadata(
    path: &Path,
    meta: &Metadata,
    policy: SecureDirPolicy,
    expect_dir: bool,
    operation: &'static str,
) -> SysResult<()> {
    if expect_dir && !meta.is_dir() {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!("path '{}' must be a directory", path.display()),
        });
    }
    if !expect_dir && !meta.is_file() {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!("path '{}' must be a regular file", path.display()),
        });
    }
    if meta.uid() != policy.expected_uid {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!(
                "path '{}' owned by uid {} instead of {}",
                path.display(),
                meta.uid(),
                policy.expected_uid
            ),
        });
    }
    if let Some(expected_gid) = policy.expected_gid
        && meta.gid() != expected_gid
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!(
                "path '{}' owned by gid {} instead of {}",
                path.display(),
                meta.gid(),
                expected_gid
            ),
        });
    }

    let mode = meta.mode() & PERMISSION_AND_SPECIAL_BITS_MASK;
    if (mode & !policy.max_mode) != 0 || (mode & GROUP_OR_WORLD_WRITE_MASK) != 0 {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!(
                "path '{}' has unsafe mode {:04o} (max {:04o})",
                path.display(),
                mode,
                policy.max_mode
            ),
        });
    }

    Ok(())
}

fn verify_ancestor_chain(path: &Path, expected_leaf_uid: u32, symlink_depth: u8) -> SysResult<()> {
    if !path.is_absolute() {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!("path '{}' must be absolute", path.display()),
        });
    }
    if symlink_depth > MAX_SYSTEM_SYMLINK_HOPS {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!(
                "too many symlinks resolving ancestors of '{}'",
                path.display()
            ),
        });
    }

    let Some(parent) = path.parent() else {
        return Ok(());
    };

    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        if matches!(component, Component::RootDir) {
            inspect_root_or_ancestor_dir(&current, expected_leaf_uid)?;
            continue;
        }
        verify_single_ancestor(&current, expected_leaf_uid, symlink_depth)?;
    }

    Ok(())
}

fn verify_single_ancestor(
    ancestor: &Path,
    expected_leaf_uid: u32,
    symlink_depth: u8,
) -> SysResult<()> {
    let meta = fs::symlink_metadata(ancestor).map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            SysError::SecurityViolation {
                operation: "verify_ancestor_chain",
                detail: format!("missing ancestor directory '{}'", ancestor.display()),
            }
        } else {
            SysError::io("verify_ancestor_chain", err)
        }
    })?;

    if meta.file_type().is_symlink() {
        return verify_trusted_os_symlink(ancestor, &meta, expected_leaf_uid, symlink_depth);
    }

    inspect_root_or_ancestor_dir(ancestor, expected_leaf_uid)
}

fn verify_trusted_os_symlink(
    link_path: &Path,
    link_meta: &Metadata,
    expected_leaf_uid: u32,
    symlink_depth: u8,
) -> SysResult<()> {
    // Only OS-managed root symlinks (such as `/var -> private/var` on macOS or
    // `/var/run -> /run` on Linux) may appear in an ancestor chain.
    if link_meta.uid() != 0 {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!(
                "non-root symlink '{}' (uid {}) in ancestor chain",
                link_path.display(),
                link_meta.uid()
            ),
        });
    }

    let target =
        fs::canonicalize(link_path).map_err(|err| SysError::io("verify_ancestor_chain", err))?;
    let next_depth = symlink_depth.saturating_add(1);
    if next_depth > MAX_SYSTEM_SYMLINK_HOPS {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!("symlink loop at '{}'", link_path.display()),
        });
    }

    verify_ancestor_chain(&target, expected_leaf_uid, next_depth)?;
    inspect_root_or_ancestor_dir(&target, expected_leaf_uid)
}

fn inspect_root_or_ancestor_dir(dir: &Path, expected_leaf_uid: u32) -> SysResult<()> {
    let meta = open_leaf_nofollow_metadata(dir, "verify_ancestor_chain", true)?;
    if !meta.is_dir() {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!("ancestor '{}' is not a directory", dir.display()),
        });
    }

    let owner_ok = meta.uid() == 0 || meta.uid() == expected_leaf_uid;
    if !owner_ok {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!(
                "ancestor '{}' owned by untrusted uid {}",
                dir.display(),
                meta.uid()
            ),
        });
    }

    let mode = meta.mode() & PERMISSION_AND_SPECIAL_BITS_MASK;
    if (mode & GROUP_OR_WORLD_WRITE_MASK) != 0
        && !is_macos_system_var_run(dir, meta.uid(), meta.gid(), mode)
    {
        return Err(SysError::SecurityViolation {
            operation: "verify_ancestor_chain",
            detail: format!(
                "ancestor '{}' has group/world write bits ({:04o})",
                dir.display(),
                mode
            ),
        });
    }

    Ok(())
}

fn is_macos_system_var_run(dir: &Path, uid: u32, gid: u32, mode: u32) -> bool {
    #[cfg(target_os = "macos")]
    {
        // Standard macOS ships `/private/var/run` (`/var/run`) as `0775 root:daemon` (`gid 1`) and
        // system parent directories (`/Library`, `/usr/local`, `/usr/local/libexec`) may be
        // `0775 root:admin` (`gid 80`) without world-write bits.
        if uid != 0 || (mode & 0o002) != 0 {
            return false;
        }
        let is_var_run = dir == Path::new("/var/run") || dir == Path::new("/private/var/run");
        if is_var_run && gid == 1 {
            return true;
        }
        let is_macos_admin_parent = dir == Path::new("/usr/local")
            || dir == Path::new("/usr/local/libexec")
            || dir == Path::new("/Library");
        is_macos_admin_parent && gid == 80
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (dir, uid, gid, mode);
        false
    }
}

/// Computes the used capacity percentage (`0..=100`) of the filesystem containing `path`
/// using `libc::statvfs` (`HR-S1-05`).
pub fn filesystem_usage_percent(path: &Path) -> SysResult<u8> {
    const OP: &str = "filesystem_usage_percent";
    let target = if path.is_file() {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    } else {
        path
    };
    let c_path = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        SysError::io(
            OP,
            std::io::Error::new(
                ErrorKind::InvalidInput,
                "filesystem path contains interior NUL byte",
            ),
        )
    })?;

    let mut stat = MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `c_path` is a valid NUL-terminated path buffer and `stat` is a properly
    // aligned writable `libc::statvfs` output struct for the duration of the syscall.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(SysError::io(OP, std::io::Error::last_os_error()));
    }
    // SAFETY: `libc::statvfs` succeeded (`rc == 0`), initializing all fields of `stat`.
    let stat = unsafe { stat.assume_init() };

    let total_blocks = u128::from(stat.f_blocks);
    if total_blocks == 0 {
        return Err(SysError::io(
            OP,
            std::io::Error::new(
                ErrorKind::InvalidData,
                "filesystem reported zero total blocks",
            ),
        ));
    }
    let avail_blocks = u128::from(stat.f_bavail).min(total_blocks);
    let used_blocks = total_blocks.saturating_sub(avail_blocks);
    let pct = used_blocks.saturating_mul(100) / total_blocks;
    u8::try_from(pct.min(100)).map_err(|_| {
        SysError::io(
            OP,
            std::io::Error::new(ErrorKind::InvalidData, "filesystem percentage out of range"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        SecureDirPolicy, filesystem_usage_percent, prepare_secure_runtime_dir,
        verify_leaf_metadata, verify_secure_file, verify_secure_runtime_dir,
    };
    use crate::error::SysError;

    fn current_uid_and_gid() -> (u32, u32) {
        // SAFETY: `geteuid` and `getegid` are always safe to call.
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    #[test]
    fn test_fs_unix_relative_path_rejected() {
        // Arrange
        let policy = SecureDirPolicy {
            expected_uid: 0,
            expected_gid: None,
            max_mode: 0o755,
        };

        // Act
        let res = verify_secure_runtime_dir(Path::new("relative/meshd"), policy);

        // Assert
        assert!(matches!(res, Err(SysError::SecurityViolation { .. })));
    }

    #[test]
    fn test_fs_unix_leaf_symlink_rejected() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).expect("create real dir");
        let link_dir = dir.path().join("meshd-link");
        symlink(&real_dir, &link_dir).expect("create symlink");
        let (uid, gid) = current_uid_and_gid();
        let policy = SecureDirPolicy {
            expected_uid: uid,
            expected_gid: Some(gid),
            max_mode: 0o755,
        };

        // Act
        let res = prepare_secure_runtime_dir(&link_dir, policy);

        // Assert
        assert!(matches!(res, Err(SysError::SecurityViolation { .. })));
    }

    #[test]
    fn test_fs_unix_world_writable_tmp_ancestor_rejected() {
        // Arrange: `/tmp` has sticky world-writable mode (`01777`), so root-mode verification rejects it.
        let dir = tempfile::tempdir_in("/tmp").expect("create tempdir in /tmp");
        let leaf = dir.path().join("meshd");
        std::fs::create_dir(&leaf).expect("create leaf");
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700))
            .expect("chmod leaf");
        let (uid, gid) = current_uid_and_gid();
        let policy = SecureDirPolicy {
            expected_uid: uid,
            expected_gid: Some(gid),
            max_mode: 0o700,
        };

        // Act
        let res = verify_secure_runtime_dir(&leaf, policy);

        // Assert
        assert!(matches!(res, Err(SysError::SecurityViolation { .. })));
    }

    #[test]
    fn test_fs_unix_leaf_mode_violation_rejected() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let leaf = dir.path().join("db");
        std::fs::create_dir(&leaf).expect("create leaf");
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o775))
            .expect("chmod leaf");
        let meta = std::fs::symlink_metadata(&leaf).expect("metadata");
        let (uid, gid) = current_uid_and_gid();
        let policy = SecureDirPolicy {
            expected_uid: uid,
            expected_gid: Some(gid),
            max_mode: 0o700,
        };

        // Act
        let res = verify_leaf_metadata(&leaf, &meta, policy, true, "test");

        // Assert
        assert!(matches!(res, Err(SysError::SecurityViolation { .. })));
    }

    #[test]
    fn test_fs_unix_leaf_secure_dir_and_file_checks() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let file = dir.path().join("meshd.bin");
        std::fs::write(&file, b"binary").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
            .expect("chmod file");
        let meta = std::fs::symlink_metadata(&file).expect("metadata");
        let (uid, gid) = current_uid_and_gid();
        let policy = SecureDirPolicy {
            expected_uid: uid,
            expected_gid: Some(gid),
            max_mode: 0o755,
        };

        // Act & Assert
        verify_leaf_metadata(&file, &meta, policy, false, "test")
            .expect("0755 regular file matches policy");
        assert!(verify_secure_file(Path::new("relative.bin"), policy).is_err());
    }

    #[test]
    fn test_fs_unix_set_path_group_noop_on_matching_gid_and_rejects_symlink() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let file = dir.path().join("socket-target");
        std::fs::write(&file, b"ok").expect("write target");
        let link = dir.path().join("socket-link");
        symlink(&file, &link).expect("create symlink");
        let (_uid, gid) = current_uid_and_gid();

        // Act
        super::set_path_group_if_root(&file, gid).expect("matching gid returns Ok without root");
        let link_res = super::set_path_group_if_root(&link, gid);

        // Assert
        assert!(matches!(link_res, Err(SysError::SecurityViolation { .. })));
    }

    #[test]
    fn test_fs_unix_filesystem_usage_percent_reads_dir_and_file() {
        // Arrange
        let dir = tempdir().expect("create tempdir");
        let file = dir.path().join("control.redb");
        std::fs::write(&file, b"db").expect("write test file");

        // Act
        let dir_pct = filesystem_usage_percent(dir.path()).expect("statvfs on dir");
        let file_pct = filesystem_usage_percent(&file).expect("statvfs on file");
        let missing = filesystem_usage_percent(&dir.path().join("missing-subdir"));

        // Assert
        assert!(dir_pct <= 100);
        assert!(file_pct <= 100);
        assert!(missing.is_err());
    }

    #[test]
    fn test_fs_unix_macos_system_dir_exemptions() {
        // Arrange
        let var_run = Path::new("/var/run");
        let private_var_run = Path::new("/private/var/run");
        let usr_local_libexec = Path::new("/usr/local/libexec");
        let untrusted = Path::new("/tmp/foo");

        // Act & Assert
        #[cfg(target_os = "macos")]
        {
            assert!(super::is_macos_system_var_run(var_run, 0, 1, 0o775));
            assert!(super::is_macos_system_var_run(private_var_run, 0, 1, 0o775));
            assert!(super::is_macos_system_var_run(
                usr_local_libexec,
                0,
                80,
                0o775
            ));
            assert!(!super::is_macos_system_var_run(var_run, 0, 1, 0o777));
            assert!(!super::is_macos_system_var_run(untrusted, 0, 1, 0o775));
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(!super::is_macos_system_var_run(var_run, 0, 1, 0o775));
            assert!(!super::is_macos_system_var_run(
                private_var_run,
                0,
                1,
                0o775
            ));
            assert!(!super::is_macos_system_var_run(
                usr_local_libexec,
                0,
                80,
                0o775
            ));
            assert!(!super::is_macos_system_var_run(untrusted, 0, 1, 0o775));
        }
    }
}
