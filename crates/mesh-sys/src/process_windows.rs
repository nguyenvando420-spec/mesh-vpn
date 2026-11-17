//! Windows Explorer double-click detection and detached GUI launcher (`ADR-022`, `US-100`).

use std::ffi::OsString;
use std::io;
use std::mem::{self, size_of};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME, GetLastError, HANDLE};
use windows_sys::Win32::System::Console::GetConsoleProcessList;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CreateProcessW, DETACHED_PROCESS, GetCurrentProcess,
    GetCurrentProcessId, GetProcessTimes, OpenProcess, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, STARTUPINFOW,
};

use crate::error::{SysError, SysResult};
use crate::gui_windows::OwnedWinHandle;

const MAX_WIDE_PATH_LEN: usize = 32_768;

/// Returns `true` only when the current Windows console process was launched directly by
/// interactive Windows Explorer double-click:
/// 1. `GetConsoleProcessList == 1` (not launched inside an existing shell/terminal),
/// 2. Parent PID creation time strictly precedes self creation time (anti-PID-reuse),
/// 3. Parent image path matches `<WindowsDir>\explorer.exe` case-insensitively.
pub fn is_interactive_explorer_double_click() -> SysResult<bool> {
    const OP: &str = "process_windows::is_interactive_explorer_double_click";

    // (a) Must be the sole process attached to this console (excludes cmd/pwsh/wt/IDE shells).
    let mut console_pids = [0_u32; 4];
    // SAFETY: `console_pids` is a valid writable stack buffer of 4 `u32` elements.
    let console_count = unsafe { GetConsoleProcessList(console_pids.as_mut_ptr(), 4) };
    if console_count != 1 {
        return Ok(false);
    }

    // (b) Capture process snapshot to resolve `th32ParentProcessID` of the current process.
    // SAFETY: `GetCurrentProcessId` takes no pointers and returns the caller's PID.
    let self_pid = unsafe { GetCurrentProcessId() };
    // SAFETY: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` snapshots all processes.
    let raw_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let Some(snap) = OwnedWinHandle::from_raw(raw_snap) else {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    };
    let Some(parent_pid) = find_parent_pid(&snap, self_pid)? else {
        return Ok(false);
    };
    if parent_pid == 0 || parent_pid == self_pid {
        return Ok(false);
    }

    // (c) Open parent process with least-privilege query access; fail closed if inaccessible.
    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` and `FALSE` (`0`) does not
    // inherit handles and requests read-only process metadata.
    let raw_parent = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid) };
    let Some(parent_handle) = OwnedWinHandle::from_raw(raw_parent) else {
        return Ok(false);
    };

    // (d) Verify `parent_creation_time < self_creation_time` to defeat PID reuse races.
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that must not be closed.
    let self_handle = unsafe { GetCurrentProcess() };
    let Some(self_created) = query_process_creation_time(self_handle) else {
        return Ok(false);
    };
    let Some(parent_created) = query_process_creation_time(parent_handle.as_raw()) else {
        return Ok(false);
    };
    if parent_created >= self_created {
        return Ok(false);
    }

    // (e) Verify normalized parent image path equals `<GetWindowsDirectoryW>\explorer.exe`.
    let Some(parent_image) = query_process_image_path(parent_handle.as_raw()) else {
        return Ok(false);
    };
    let Some(windows_dir) = query_windows_directory() else {
        return Ok(false);
    };
    Ok(is_normalized_explorer_path(&parent_image, &windows_dir))
}

/// Spawns the Windows GUI executable (`MeshVPN.exe`) detached from any console
/// (`CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`) without invoking any shell (`ADR-022`).
pub fn spawn_detached_gui(exe_path: &Path) -> SysResult<()> {
    const OP: &str = "process_windows::spawn_detached_gui";
    if exe_path.as_os_str().is_empty() {
        return Err(SysError::io(
            OP,
            io::Error::new(io::ErrorKind::InvalidInput, "empty GUI executable path"),
        ));
    }

    let meta = std::fs::symlink_metadata(exe_path).map_err(|err| SysError::io(OP, err))?;
    if meta.file_type().is_symlink() {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "refusing to launch GUI executable via symbolic link".to_owned(),
        });
    }
    if !meta.file_type().is_file() {
        return Err(SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "GUI executable path is not a regular file",
            ),
        ));
    }

    let wide_app = path_to_wide_nul(exe_path, OP, false)?;
    let mut wide_cmdline = path_to_wide_nul(exe_path, OP, true)?;

    let si_size = u32::try_from(size_of::<STARTUPINFOW>()).map_err(|_| {
        SysError::io(
            OP,
            io::Error::new(io::ErrorKind::InvalidInput, "STARTUPINFOW size overflow"),
        )
    })?;
    // SAFETY: `STARTUPINFOW` and `PROCESS_INFORMATION` are plain Win32 C structs.
    let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
    startup_info.cb = si_size;
    // SAFETY: `PROCESS_INFORMATION` is zero-initialized before `CreateProcessW` populates handles.
    let mut proc_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    // Strictly avoid `CREATE_BREAKAWAY_FROM_JOB` so Windows 10/11 Job Objects never return
    // `ERROR_ACCESS_DENIED (5)` (`HR-DGUI-G2-01`).
    let creation_flags = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;

    // SAFETY: `wide_app` and `wide_cmdline` are NUL-terminated UTF-16 buffers (`wide_cmdline` is
    // mutable as required by `CreateProcessW`), and `startup_info`/`proc_info` are valid stack
    // structs whose lifetime spans the call.
    let ok = unsafe {
        CreateProcessW(
            wide_app.as_ptr(),
            wide_cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            creation_flags,
            ptr::null(),
            ptr::null(),
            &raw const startup_info,
            &raw mut proc_info,
        )
    };
    if ok == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }

    let _process_handle = OwnedWinHandle::from_raw(proc_info.hProcess);
    let _thread_handle = OwnedWinHandle::from_raw(proc_info.hThread);
    Ok(())
}

fn find_parent_pid(snap: &OwnedWinHandle, self_pid: u32) -> SysResult<Option<u32>> {
    const OP: &str = "process_windows::find_parent_pid";
    let entry_size = u32::try_from(size_of::<PROCESSENTRY32W>()).map_err(|_| {
        SysError::io(
            OP,
            io::Error::new(io::ErrorKind::InvalidInput, "PROCESSENTRY32W size overflow"),
        )
    })?;
    // SAFETY: `PROCESSENTRY32W` is a plain C-compatible Win32 POD struct.
    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = entry_size;

    // SAFETY: `snap` is a valid `TH32CS_SNAPPROCESS` handle and `entry.dwSize` is set.
    let mut has_entry = unsafe { Process32FirstW(snap.as_raw(), &raw mut entry) };
    while has_entry != 0 {
        if entry.th32ProcessID == self_pid {
            return Ok(Some(entry.th32ParentProcessID));
        }
        // SAFETY: `snap` and `entry` remain valid for continued ToolHelp enumeration.
        has_entry = unsafe { Process32NextW(snap.as_raw(), &raw mut entry) };
    }
    Ok(None)
}

fn query_process_creation_time(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: `handle` is an open process handle/pseudo-handle and all 4 `FILETIME` structs are valid.
    let ok = unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if ok == 0 {
        return None;
    }
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn query_process_image_path(handle: HANDLE) -> Option<PathBuf> {
    let mut capacity = 1024_usize;
    loop {
        let mut buf = vec![0_u16; capacity];
        let mut len = u32::try_from(buf.len()).ok()?;
        // SAFETY: `handle` was opened with `PROCESS_QUERY_LIMITED_INFORMATION` and `buf` holds `len` UTF-16 units.
        let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &raw mut len) };
        if ok != 0 {
            let used = usize::try_from(len).ok()?;
            let slice = buf.get(..used)?;
            return Some(PathBuf::from(OsString::from_wide(slice)));
        }
        // SAFETY: Reads the last Win32 error set by `QueryFullProcessImageNameW`.
        let err = unsafe { GetLastError() };
        if err == ERROR_INSUFFICIENT_BUFFER && capacity < MAX_WIDE_PATH_LEN {
            capacity = capacity.saturating_mul(2).min(MAX_WIDE_PATH_LEN);
            continue;
        }
        return None;
    }
}

fn query_windows_directory() -> Option<PathBuf> {
    let mut buf = vec![0_u16; 512];
    let cap = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is a writable UTF-16 buffer of length `cap`.
    let needed = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), cap) };
    if needed == 0 {
        return None;
    }
    if needed > cap {
        let resized = usize::try_from(needed).ok()?;
        buf.resize(resized, 0);
        let retry_cap = u32::try_from(buf.len()).ok()?;
        // SAFETY: `buf` was resized to at least `needed` UTF-16 code units.
        let written = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), retry_cap) };
        if written == 0 || written > retry_cap {
            return None;
        }
        let used = usize::try_from(written).ok()?;
        let slice = buf.get(..used)?;
        return Some(PathBuf::from(OsString::from_wide(slice)));
    }
    let used = usize::try_from(needed).ok()?;
    let slice = buf.get(..used)?;
    Some(PathBuf::from(OsString::from_wide(slice)))
}

fn normalize_windows_path(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = resolved.to_string_lossy();
    let stripped = text.strip_prefix(r"\\?\").unwrap_or(text.as_ref());
    stripped.trim_end_matches(['\\', '/']).to_lowercase()
}

fn is_normalized_explorer_path(parent_image: &Path, windows_dir: &Path) -> bool {
    let expected = windows_dir.join("explorer.exe");
    normalize_windows_path(parent_image) == normalize_windows_path(&expected)
}

fn path_to_wide_nul(path: &Path, operation: &'static str, quoted: bool) -> SysResult<Vec<u16>> {
    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    if units.contains(&0) {
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "interior NUL in path"),
        ));
    }
    if units.contains(&u16::from(b'"')) {
        return Err(SysError::io(
            operation,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "double quote in executable path",
            ),
        ));
    }
    let mut wide = Vec::with_capacity(units.len() + if quoted { 3 } else { 1 });
    if quoted {
        wide.push(u16::from(b'"'));
    }
    wide.extend_from_slice(&units);
    if quoted {
        wide.push(u16::from(b'"'));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::error::SysError;

    use super::{
        is_interactive_explorer_double_click, is_normalized_explorer_path, spawn_detached_gui,
    };

    #[test]
    fn test_process_windows_rejects_empty_and_missing_gui_path() {
        // Arrange & Act
        let explorer = is_interactive_explorer_double_click();
        let empty_spawn = spawn_detached_gui(Path::new(""));
        let missing_spawn = spawn_detached_gui(Path::new(r"C:\nonexistent-mesh-dir\MeshVPN.exe"));

        // Assert: running under cargo test must never be classified as Explorer double-click.
        assert!(matches!(explorer, Ok(false)));
        assert!(matches!(empty_spawn, Err(SysError::Io { .. })));
        assert!(missing_spawn.is_err());
    }

    #[test]
    fn test_process_windows_explorer_path_normalization_is_case_insensitive_and_strict() {
        // Arrange
        let win_dir = Path::new(r"C:\Windows");

        // Act & Assert
        assert!(is_normalized_explorer_path(
            Path::new(r"C:\WINDOWS\Explorer.EXE"),
            win_dir
        ));
        assert!(is_normalized_explorer_path(
            Path::new(r"\\?\C:\Windows\explorer.exe"),
            win_dir
        ));
        assert!(!is_normalized_explorer_path(
            Path::new(r"C:\Users\alice\explorer.exe"),
            win_dir
        ));
        assert!(!is_normalized_explorer_path(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            win_dir
        ));
    }
}
