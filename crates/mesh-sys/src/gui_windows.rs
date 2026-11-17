//! Isolated Windows GUI, UAC elevation, Named Pipe handoff, atomic unprivileged sink write,
//! anti-TOCTOU DLL locking, single-instance coordination, and registry/shortcut helpers
//! (`ADR-020`, `ADR-021`, `ADR-023`, `ADR-026`, `BLK-DGUI-G2-02/04/05`).

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Graphics::Gdi::{DeleteObject, HGDIOBJ};
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::System::DataExchange::CloseClipboard;
use windows_sys::Win32::System::Registry::{HKEY, RegCloseKey};
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, DestroyMenu, HICON, HMENU, SetProcessDPIAware,
};

use crate::error::{SysError, SysResult};
use crate::ipc_windows::WindowsPeerCredentials;

/// Single-instance mutex name scoped to the active Windows user session (`ADR-026`).
pub const GUI_SINGLE_INSTANCE_MUTEX: &str = r"Local\MeshVpnGuiSingleInstance";

/// Graceful shutdown event signaled when upgrading `MeshVPN.exe` (`ADR-026`).
pub const GUI_SHUTDOWN_EVENT: &str = r"Local\MeshVpnGuiShutdownEvent";

/// Canonical prefix for ephemeral authenticated UAC handoff pipes (`ADR-021`).
pub const HANDOFF_PIPE_PREFIX: &str = r"\\.\pipe\mesh-gui-handoff-";

/// Win32 error code `ERROR_FILE_NOT_FOUND` (`2`).
pub const WIN_ERROR_FILE_NOT_FOUND: i32 = 2;

/// Win32 error code `ERROR_ACCESS_DENIED` (`5`).
pub const WIN_ERROR_ACCESS_DENIED: i32 = 5;

/// Win32 error code `ERROR_PIPE_BUSY` (`231`).
pub const WIN_ERROR_PIPE_BUSY: i32 = 231;

/// Win32 error code `ERROR_SERVICE_DOES_NOT_EXIST` (`1060`).
pub const WIN_ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Win32 error code `ERROR_CANCELLED` (`1223`, user canceled UAC prompt).
pub const WIN_ERROR_CANCELLED: i32 = 1223;

/// RAII guard closing a Win32 `HANDLE` (`CloseHandle`) on drop.
pub struct OwnedWinHandle(HANDLE);

// SAFETY: Kernel handles wrapped by `OwnedWinHandle` are exclusively owned and closed once in `Drop`.
unsafe impl Send for OwnedWinHandle {}

impl OwnedWinHandle {
    /// Wraps a non-null, non-`INVALID_HANDLE_VALUE` Win32 `HANDLE`.
    #[must_use]
    pub fn from_raw(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// Borrows the underlying raw `HANDLE`.
    #[must_use]
    pub const fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl fmt::Debug for OwnedWinHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedWinHandle").finish_non_exhaustive()
    }
}

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` was validated non-null and != `INVALID_HANDLE_VALUE` and is owned solely by `self`.
            let _closed = unsafe { CloseHandle(self.0) };
        }
    }
}

/// RAII guard destroying a Win32 `HICON` (`DestroyIcon`) on drop.
pub struct OwnedIcon(HICON);

impl OwnedIcon {
    /// Wraps a non-null `HICON`.
    #[must_use]
    pub fn from_raw(icon: HICON) -> Option<Self> {
        if icon.is_null() {
            None
        } else {
            Some(Self(icon))
        }
    }

    /// Borrows the underlying raw `HICON`.
    #[must_use]
    pub const fn as_raw(&self) -> HICON {
        self.0
    }
}

impl fmt::Debug for OwnedIcon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedIcon").finish_non_exhaustive()
    }
}

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a live `HICON` owned exclusively by `self`.
            let _destroyed = unsafe { DestroyIcon(self.0) };
        }
    }
}

/// RAII guard destroying a Win32 `HMENU` (`DestroyMenu`) on drop.
pub struct OwnedMenu(HMENU);

impl OwnedMenu {
    /// Wraps a non-null `HMENU`.
    #[must_use]
    pub fn from_raw(menu: HMENU) -> Option<Self> {
        if menu.is_null() {
            None
        } else {
            Some(Self(menu))
        }
    }

    /// Borrows the underlying raw `HMENU`.
    #[must_use]
    pub const fn as_raw(&self) -> HMENU {
        self.0
    }
}

impl fmt::Debug for OwnedMenu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedMenu").finish_non_exhaustive()
    }
}

impl Drop for OwnedMenu {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a live `HMENU` owned exclusively by `self`.
            let _destroyed = unsafe { DestroyMenu(self.0) };
        }
    }
}

/// RAII guard deleting a Win32 GDI object (`DeleteObject`) on drop.
pub struct OwnedGdiObj(HGDIOBJ);

impl OwnedGdiObj {
    /// Wraps a non-null `HGDIOBJ`.
    #[must_use]
    pub fn from_raw(obj: HGDIOBJ) -> Option<Self> {
        if obj.is_null() { None } else { Some(Self(obj)) }
    }

    /// Borrows the underlying raw `HGDIOBJ`.
    #[must_use]
    pub const fn as_raw(&self) -> HGDIOBJ {
        self.0
    }
}

impl fmt::Debug for OwnedGdiObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedGdiObj").finish_non_exhaustive()
    }
}

impl Drop for OwnedGdiObj {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a live GDI object owned exclusively by `self`.
            let _deleted = unsafe { DeleteObject(self.0) };
        }
    }
}

/// RAII guard closing a Win32 Registry key (`RegCloseKey`) on drop.
pub struct OwnedRegKey(HKEY);

impl OwnedRegKey {
    /// Wraps an opened `HKEY`.
    #[must_use]
    pub fn from_raw(key: HKEY) -> Option<Self> {
        if key.is_null() { None } else { Some(Self(key)) }
    }

    /// Borrows the underlying raw `HKEY`.
    #[must_use]
    pub const fn as_raw(&self) -> HKEY {
        self.0
    }
}

impl fmt::Debug for OwnedRegKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRegKey").finish_non_exhaustive()
    }
}

impl Drop for OwnedRegKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an open registry key handle owned exclusively by `self`.
            let _closed = unsafe { RegCloseKey(self.0) };
        }
    }
}

/// RAII guard closing the Win32 clipboard (`CloseClipboard`) on drop.
#[derive(Debug)]
pub struct ClipboardGuard;

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        // SAFETY: Matches an earlier successful `OpenClipboard` on this thread.
        let _closed = unsafe { CloseClipboard() };
    }
}

/// RAII guard reverting Named Pipe client impersonation (`RevertToSelf`) on drop.
#[derive(Debug)]
pub struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: Restores the thread's original security token after `ImpersonateNamedPipeClient`.
        let ok = unsafe { RevertToSelf() };
        if ok == 0 {
            tracing::error!(
                target: "mesh::sys::gui_windows",
                error = %io::Error::last_os_error(),
                "RevertToSelf failed"
            );
        }
    }
}

/// Single-instance mutex guard held for the lifetime of `MeshVPN.exe`.
#[derive(Debug)]
pub struct SingleInstanceGuard {
    _mutex: OwnedWinHandle,
}

/// Read-only Windows Service Control Manager state of `MeshVpnAgent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsServiceProbeState {
    /// Service is not registered in SCM (`ERROR_SERVICE_DOES_NOT_EXIST`).
    NotInstalled,
    /// Service is registered and currently stopped.
    Stopped,
    /// Service is running.
    Running,
    /// Service is transitioning (`START_PENDING` / `STOP_PENDING` / etc.).
    Pending,
}

/// Visual state categories rendered into System Tray 16x16 / 32x32 bitmap icons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayStatusIconKind {
    /// Tunnel connected cleanly (`DaemonState::Connected`).
    Connected,
    /// Connecting or control temporarily unreachable (`Connecting` / `Degraded`).
    ConnectingOrDegraded,
    /// Enrolled or unconfigured but stopped.
    Stopped,
    /// `MeshVpnAgent` service missing or stopped.
    DaemonUnavailable,
    /// Requires user action (`ReauthRequired` / `Revoked` / `Error`).
    WarningOrError,
}

/// Validates that `pipe_name` matches `\\.\pipe\mesh-gui-handoff-<32_lowercase_hex>` (`ADR-021`).
#[must_use]
pub fn is_valid_handoff_pipe_name(pipe_name: &str) -> bool {
    let Some(hex_id) = pipe_name.strip_prefix(HANDOFF_PIPE_PREFIX) else {
        return false;
    };
    hex_id.len() == 32
        && hex_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Returns `true` when `err` represents Win32 `ERROR_CANCELLED (1223)` from UAC dismissal.
#[must_use]
pub fn is_uac_cancelled_error(err: &SysError) -> bool {
    matches!(
        err,
        SysError::Io { source, .. } if source.raw_os_error() == Some(WIN_ERROR_CANCELLED)
    )
}

/// Enables Per-Monitor V2 DPI awareness on Windows 10/11 (falling back safely on older builds).
pub fn enable_per_monitor_v2_dpi() -> SysResult<()> {
    // SAFETY: `SetProcessDpiAwarenessContext` takes a constant Win32 pseudo-handle with no pointer dereference.
    let ok = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    if ok != 0 {
        return Ok(());
    }
    // SAFETY: Fallback to system DPI awareness if Per-Monitor V2 is unavailable; takes no arguments.
    let _fallback = unsafe { SetProcessDPIAware() };
    Ok(())
}

/// Initializes Win32 Common Controls v6 (`ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES`).
pub fn init_common_controls() -> SysResult<()> {
    Err(SysError::NotImplemented(
        "gui_windows::init_common_controls",
    ))
}

/// Launches `exe_path` elevated via `ShellExecuteExW("runas")` with `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`
/// passing ONLY `--elevated-worker --handoff-pipe <pipe_name>` (never secrets or save paths, `ADR-021`).
pub fn launch_elevated_worker(
    exe_path: &Path,
    handoff_pipe_name: &str,
) -> SysResult<OwnedWinHandle> {
    if exe_path.as_os_str().is_empty() || !is_valid_handoff_pipe_name(handoff_pipe_name) {
        return Err(SysError::SecurityViolation {
            operation: "gui_windows::launch_elevated_worker",
            detail: "invalid executable or handoff pipe name".to_owned(),
        });
    }
    Err(SysError::NotImplemented(
        "gui_windows::launch_elevated_worker",
    ))
}

/// Ephemeral Named Pipe server bound by the Medium-Integrity GUI (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<UserSid>)`,
/// `FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS | FILE_FLAG_OVERLAPPED`, `ADR-021`).
#[derive(Debug)]
pub struct HandoffPipeServer {
    pipe_name: String,
    handle: OwnedWinHandle,
}

impl HandoffPipeServer {
    /// Binds a new single-instance Named Pipe server waiting for the elevated worker.
    pub fn bind(pipe_name: &str) -> SysResult<Self> {
        if !is_valid_handoff_pipe_name(pipe_name) {
            return Err(SysError::SecurityViolation {
                operation: "gui_windows::HandoffPipeServer::bind",
                detail: "invalid handoff pipe name".to_owned(),
            });
        }
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeServer::bind",
        ))
    }

    /// Returns the bound pipe name.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Returns a handle reference to the bound pipe.
    #[must_use]
    pub const fn handle(&self) -> &OwnedWinHandle {
        &self.handle
    }

    /// Waits for client connection, enforces `GetNamedPipeClientProcessId == child_pid`, reads the
    /// 13-byte `0x00 WorkerHello` frame within `timeout_ms`, and verifies `BA`/`SY` membership via
    /// `ImpersonateNamedPipeClient(SecurityIdentification)` -> `OpenThreadToken` -> `CheckTokenMembership`
    /// (without calling `OpenProcess`/`OpenProcessToken`, `BLK-DGUI-G2-04`).
    pub fn accept_and_verify_worker(
        &self,
        _child_pid: u32,
        _timeout_ms: u32,
    ) -> SysResult<WindowsPeerCredentials> {
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeServer::accept_and_verify_worker",
        ))
    }

    /// Reads up to `buf.len()` bytes with overlapped timeout `timeout_ms`.
    pub fn read_blocking(&self, _buf: &mut [u8], _timeout_ms: u32) -> SysResult<usize> {
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeServer::read_blocking",
        ))
    }

    /// Writes `data` to the connected handoff pipe.
    pub fn write_blocking(&self, _data: &[u8]) -> SysResult<usize> {
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeServer::write_blocking",
        ))
    }

    /// Cancels pending overlapped I/O on the pipe handle during cancellation/shutdown.
    pub fn cancel_io(&self) {}
}

/// Elevated worker client connection to the GUI's ephemeral handoff pipe (`SECURITY_SQOS_PRESENT |
/// SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED`, sends `0x00 WorkerHello` immediately, `BLK-DGUI-G2-04`).
#[derive(Debug)]
pub struct HandoffPipeClient {
    handle: OwnedWinHandle,
}

impl HandoffPipeClient {
    /// Connects to `pipe_name` with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and transmits
    /// the 13-byte `MGH1` `0x00 WorkerHello` frame.
    pub fn connect_and_send_hello(pipe_name: &str, _timeout_ms: u32) -> SysResult<Self> {
        if !is_valid_handoff_pipe_name(pipe_name) {
            return Err(SysError::SecurityViolation {
                operation: "gui_windows::HandoffPipeClient::connect_and_send_hello",
                detail: "invalid handoff pipe name".to_owned(),
            });
        }
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeClient::connect_and_send_hello",
        ))
    }

    /// Borrows the underlying pipe handle.
    #[must_use]
    pub const fn handle(&self) -> &OwnedWinHandle {
        &self.handle
    }

    /// Reads up to `buf.len()` bytes with overlapped timeout `timeout_ms`.
    pub fn read_blocking(&self, _buf: &mut [u8], _timeout_ms: u32) -> SysResult<usize> {
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeClient::read_blocking",
        ))
    }

    /// Writes `data` to the handoff pipe.
    pub fn write_blocking(&self, _data: &[u8]) -> SysResult<usize> {
        Err(SysError::NotImplemented(
            "gui_windows::HandoffPipeClient::write_blocking",
        ))
    }

    /// Cancels pending overlapped I/O on the pipe handle.
    pub fn cancel_io(&self) {}
}

/// Atomic Temp-Sibling Sink Writer for Medium-Integrity bugreport streaming (`ADR-023`, `BLK-DGUI-G2-05`).
///
/// Supports both new creation and Replace of an existing regular `.tar` file while rejecting
/// system directories, parent reparse points, and destination symlinks/reparse points.
#[derive(Debug)]
pub struct UnprivilegedSinkWriter {
    dest_path: PathBuf,
    temp_path: PathBuf,
    expected_total_bytes: u64,
    cumulative_bytes: u64,
    file: Option<File>,
    finalized: bool,
}

impl UnprivilegedSinkWriter {
    /// Validates `dest_path` and `expected_total_bytes` (`1..=MAX_BUGREPORT_ARCHIVE_BYTES`), verifies
    /// non-reparse parent and destination, and creates `parent/.mesh-bugreport-<hex>.tar.part`.
    pub fn create(dest_path: &Path, expected_total_bytes: u64) -> SysResult<Self> {
        let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
        if dest_path.as_os_str().is_empty()
            || expected_total_bytes == 0
            || expected_total_bytes > max_bytes
        {
            return Err(SysError::io(
                "gui_windows::UnprivilegedSinkWriter::create",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid destination path or bugreport archive size",
                ),
            ));
        }
        Err(SysError::NotImplemented(
            "gui_windows::UnprivilegedSinkWriter::create",
        ))
    }

    /// Returns the final destination path.
    #[must_use]
    pub fn dest_path(&self) -> &Path {
        &self.dest_path
    }

    /// Returns the temporary `.part` sibling path.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    /// Returns cumulative bytes written so far.
    #[must_use]
    pub const fn cumulative_bytes(&self) -> u64 {
        self.cumulative_bytes
    }

    /// Returns expected archive byte length.
    #[must_use]
    pub const fn expected_total_bytes(&self) -> u64 {
        self.expected_total_bytes
    }

    /// Appends one validated chunk (`<= 64 KiB`) without exceeding `expected_total_bytes`.
    pub fn write_chunk(&mut self, _chunk: &[u8]) -> SysResult<()> {
        Err(SysError::NotImplemented(
            "gui_windows::UnprivilegedSinkWriter::write_chunk",
        ))
    }

    /// Enforces `expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes <= 20 MiB`,
    /// calls `sync_all()`, closes handle, re-checks `dest`, and atomically replaces `dest`.
    pub fn finalize(mut self) -> SysResult<u64> {
        self.finalized = false;
        drop(self.file.take());
        Err(SysError::NotImplemented(
            "gui_windows::UnprivilegedSinkWriter::finalize",
        ))
    }
}

impl Drop for UnprivilegedSinkWriter {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.finalized && !self.temp_path.as_os_str().is_empty() {
            let _removed = std::fs::remove_file(&self.temp_path);
        }
    }
}

/// Opens `path` read-only with `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT`, rejecting
/// symlinks/reparse points so SHA-256 verification and copy operate on the locked handle (`ADR-026`).
pub fn open_anti_toctou_read_locked(path: &Path) -> SysResult<File> {
    if path.as_os_str().is_empty() {
        return Err(SysError::io(
            "gui_windows::open_anti_toctou_read_locked",
            io::Error::new(io::ErrorKind::InvalidInput, "empty file path"),
        ));
    }
    Err(SysError::NotImplemented(
        "gui_windows::open_anti_toctou_read_locked",
    ))
}

/// Acquires `Local\MeshVpnGuiSingleInstance`, returning `Ok(None)` if another instance already owns it.
pub fn acquire_single_instance_mutex() -> SysResult<Option<SingleInstanceGuard>> {
    Err(SysError::NotImplemented(
        "gui_windows::acquire_single_instance_mutex",
    ))
}

/// Signals `Local\MeshVpnGuiShutdownEvent` so an older running Tray instance exits cleanly (`ADR-026`).
pub fn signal_shutdown_event() -> SysResult<()> {
    Err(SysError::NotImplemented(
        "gui_windows::signal_shutdown_event",
    ))
}

/// Waits up to `timeout_ms` on `Local\MeshVpnGuiShutdownEvent` (`true` when signaled).
pub fn wait_shutdown_event(_timeout_ms: u32) -> SysResult<bool> {
    Ok(false)
}

/// Removes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<app_name>` and user `.lnk` shortcuts
/// via `SHGetKnownFolderPath` + `CoTaskMemFree` + `std::fs::remove_file` (`BLK-DGUI-G2-02`, `US-115`).
pub fn remove_user_shortcuts_and_autostart(_app_name: &str) -> SysResult<()> {
    Err(SysError::NotImplemented(
        "gui_windows::remove_user_shortcuts_and_autostart",
    ))
}

/// Enables or removes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<app_name>` (`US-108`).
pub fn set_user_autostart(_app_name: &str, _command_line: &str, _enabled: bool) -> SysResult<()> {
    Err(SysError::NotImplemented("gui_windows::set_user_autostart"))
}

/// Queries whether `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<app_name>` is present.
pub fn is_user_autostart_enabled(_app_name: &str) -> SysResult<bool> {
    Ok(false)
}

/// Reads current Unicode text and `GetClipboardSequenceNumber()` from the Windows clipboard.
pub fn read_clipboard_utf16_with_seq() -> SysResult<(u32, Option<String>)> {
    Err(SysError::NotImplemented(
        "gui_windows::read_clipboard_utf16_with_seq",
    ))
}

/// Writes Unicode text to the Windows clipboard and returns the new sequence number.
pub fn write_clipboard_utf16_with_seq(_text: &str) -> SysResult<u32> {
    Err(SysError::NotImplemented(
        "gui_windows::write_clipboard_utf16_with_seq",
    ))
}

/// Clears the clipboard only when `GetClipboardSequenceNumber() == expected_seq` (`US-104`).
pub fn clear_clipboard_if_seq_matches(_expected_seq: u32) -> SysResult<bool> {
    Ok(false)
}

/// Shows the native Win32 Save File dialog (`GetSaveFileNameW` + `OFN_OVERWRITEPROMPT`) for `.tar`
/// bugreports, returning `Ok(None)` when canceled.
pub fn save_tar_file_dialog(
    _owner_hwnd: isize,
    _default_filename: &str,
) -> SysResult<Option<PathBuf>> {
    Err(SysError::NotImplemented(
        "gui_windows::save_tar_file_dialog",
    ))
}

/// Probes `service_name` read-only via Win32 SCM without requiring Administrator elevation.
pub fn query_service_status_readonly(_service_name: &str) -> SysResult<WindowsServiceProbeState> {
    Err(SysError::NotImplemented(
        "gui_windows::query_service_status_readonly",
    ))
}

/// Creates a 16x16 / 32x32 bitmap `HICON` in RAM representing `kind` without external `.rc`/`.res`.
pub fn create_tray_status_icon(_kind: TrayStatusIconKind, _size_px: i32) -> SysResult<OwnedIcon> {
    Err(SysError::NotImplemented(
        "gui_windows::create_tray_status_icon",
    ))
}

/// Registers the `"TaskbarCreated"` broadcast message ID for Explorer-restart tray recovery.
pub fn register_taskbar_created_message() -> SysResult<u32> {
    Err(SysError::NotImplemented(
        "gui_windows::register_taskbar_created_message",
    ))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use crate::error::SysError;

    use super::{
        HANDOFF_PIPE_PREFIX, UnprivilegedSinkWriter, WIN_ERROR_CANCELLED, is_uac_cancelled_error,
        is_valid_handoff_pipe_name,
    };

    #[test]
    fn test_gui_windows_validates_handoff_pipe_name_and_error_helpers() {
        // Arrange
        let valid = format!("{HANDOFF_PIPE_PREFIX}{}", "0123456789abcdef".repeat(2));
        let upper = format!("{HANDOFF_PIPE_PREFIX}{}", "0123456789ABCDEF".repeat(2));
        let short = format!("{HANDOFF_PIPE_PREFIX}0123");
        let cancelled = SysError::io(
            "ShellExecuteExW",
            io::Error::from_raw_os_error(WIN_ERROR_CANCELLED),
        );
        let other = SysError::io("ShellExecuteExW", io::Error::from_raw_os_error(5));

        // Act & Assert
        assert!(is_valid_handoff_pipe_name(&valid));
        assert!(!is_valid_handoff_pipe_name(&upper));
        assert!(!is_valid_handoff_pipe_name(&short));
        assert!(!is_valid_handoff_pipe_name(r"\\.\pipe\mesh-agent-admin"));
        assert!(is_uac_cancelled_error(&cancelled));
        assert!(!is_uac_cancelled_error(&other));
        assert!(UnprivilegedSinkWriter::create(Path::new("out.tar"), 0).is_err());
    }
}
