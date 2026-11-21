//! Isolated Windows GUI, UAC elevation, Named Pipe handoff, atomic unprivileged sink write,
//! anti-TOCTOU DLL locking, single-instance coordination, and registry/shortcut helpers
//! (`ADR-020`, `ADR-021`, `ADR-023`, `ADR-026`, `BLK-DGUI-G2-02/04/05`).

use std::cell::Cell;
use std::ffi::{OsStr, OsString, c_void};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::mem::{self, size_of};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use mesh_core::defaults::MAX_BUGREPORT_ARCHIVE_BYTES;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER,
    ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SUCCESS, FILETIME, GENERIC_READ,
    GENERIC_WRITE, GetLastError, GlobalFree, HANDLE, HLOCAL, HWND, INVALID_HANDLE_VALUE, LPARAM,
    LRESULT, LocalFree, RECT, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WPARAM,
};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, BitBlt, CLEARTYPE_QUALITY, COLOR_BTNFACE, CreateBitmap, CreateCompatibleBitmap,
    CreateCompatibleDC, CreateFontIndirectW, CreateFontW, CreatePen, CreateSolidBrush,
    DEFAULT_CHARSET, DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DeleteDC,
    DeleteObject, DrawFocusRect, DrawTextW, EndPaint, FillRect, GetStockObject, HBRUSH, HDC,
    HGDIOBJ, InvalidateRect, LOGFONTW, NULL_PEN, OPAQUE, PAINTSTRUCT, PS_SOLID, RoundRect, SRCCOPY,
    SelectObject, SetBkColor, SetBkMode, SetTextColor, TRANSPARENT, UpdateWindow,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, CheckTokenMembership, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
    GetSecurityDescriptorDacl, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    RevertToSelf, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    WriteFile,
};
use windows_sys::Win32::System::Com::{CoCreateGuid, CoTaskMemFree};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
    REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_ACTION,
    SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONS_FLAG,
    SERVICE_FAILURE_ACTIONSW, SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, GR_GDIOBJECTS, GetCurrentProcess,
    GetCurrentThread, GetExitCodeProcess, GetGuiResources, GetProcessId, OpenEventW,
    OpenProcessToken, OpenThreadToken, SetEvent, Sleep, WaitForMultipleObjects,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW, NotifyWinEvent};
use windows_sys::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetSaveFileNameW, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT,
    OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Controls::{
    DRAWITEMSTRUCT, ICC_LISTVIEW_CLASSES, ICC_STANDARD_CLASSES, ICC_TAB_CLASSES,
    INITCOMMONCONTROLSEX, InitCommonControlsEx,
};
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow, GetSystemMetricsForDpi,
    SetProcessDpiAwarenessContext, SystemParametersInfoForDpi,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, GetKeyState, SetFocus, VK_CONTROL,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_Desktop, FOLDERID_Programs, FOLDERID_StartMenu, NIF_ICON, NIF_INFO, NIF_MESSAGE,
    NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, SEE_MASK_NOASYNC,
    SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SHGetKnownFolderPath, Shell_NotifyIconW,
    ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_AUTORADIOBUTTON, BS_DEFPUSHBUTTON,
    BS_OWNERDRAW, BS_PUSHBUTTON, CHILDID_SELF, CREATESTRUCTW, CW_USEDEFAULT, CreateIconIndirect,
    CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow,
    DispatchMessageW, ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_PASSWORD, ES_READONLY,
    EVENT_OBJECT_NAMECHANGE, FindWindowW, GWLP_USERDATA, GetClientRect, GetCursorPos, GetDlgCtrlID,
    GetMessageW, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, HICON, HMENU, ICON_BIG,
    ICON_SMALL, ICONINFO, IDC_ARROW, IDYES, IsDialogMessageW, KillTimer, LB_ADDSTRING,
    LB_GETCURSEL, LB_RESETCONTENT, LB_SETCURSEL, LBS_NOTIFY, LoadCursorW, MB_ICONERROR,
    MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_YESNO, MF_CHECKED, MF_GRAYED, MF_POPUP,
    MF_SEPARATOR, MF_STRING, MSG, MessageBoxW, MoveWindow, NONCLIENTMETRICSW, OBJID_CLIENT,
    PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW, SM_CXSMICON,
    SMTO_ABORTIFHUNG, SPI_GETHIGHCONTRAST, SPI_GETNONCLIENTMETRICS, SW_HIDE, SW_RESTORE, SW_SHOW,
    SW_SHOWNORMAL, SendMessageTimeoutW, SendMessageW, SetForegroundWindow, SetProcessDPIAware,
    SetTimer, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, SystemParametersInfoW,
    TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenuEx, TranslateMessage, WM_APP,
    WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX,
    WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_DRAWITEM, WM_ENDSESSION, WM_ERASEBKGND,
    WM_KEYDOWN, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NCCREATE, WM_NCDESTROY, WM_PAINT,
    WM_QUERYENDSESSION, WM_RBUTTONUP, WM_SETFONT, WM_SETICON, WM_SETTINGCHANGE, WM_SIZE,
    WM_THEMECHANGED, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_CLIPCHILDREN,
    WS_EX_CONTROLPARENT, WS_GROUP, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use windows_sys::core::GUID;

use crate::error::{SysError, SysResult};
use crate::ipc_windows::WindowsPeerCredentials;

/// Single-instance mutex name scoped to the active Windows user session (`ADR-026`).
pub const GUI_SINGLE_INSTANCE_MUTEX: &str = r"Local\MeshVpnGuiSingleInstance";

/// Graceful shutdown event signaled when upgrading `MeshVPN.exe` (`ADR-026`).
pub const GUI_SHUTDOWN_EVENT: &str = r"Local\MeshVpnGuiShutdownEvent";

/// Broadcast/window activation message name for single-instance focus handoff.
pub const GUI_ACTIVATE_MESSAGE_NAME: &str = "MeshVpnGui_Activate_v1";

/// Canonical prefix for ephemeral authenticated UAC handoff pipes (`ADR-021`).
pub const HANDOFF_PIPE_PREFIX: &str = r"\\.\pipe\mesh-gui-handoff-";

/// Win32 SCM service name for `meshd.exe --service`.
pub const WINDOWS_SERVICE_NAME: &str = "MeshVpnAgent";

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

const SS_LEFT: u32 = 0x0000;
const SS_NOPREFIX: u32 = 0x0080;

/// Custom Win32 message ID for System Tray callbacks.
pub const WM_APP_TRAY_CALLBACK: u32 = WM_APP + 1;

/// Custom Win32 message ID waking the UI after background IPC poll completion.
pub const WM_APP_STATE_REFRESH: u32 = WM_APP + 2;

/// Custom Win32 message ID notifying UI of elevated worker / async action completion.
pub const WM_APP_WORKER_DONE: u32 = WM_APP + 3;

/// Custom Win32 message ID requesting graceful Tray shutdown during an upgrade.
pub const WM_APP_GRACEFUL_SHUTDOWN: u32 = WM_APP + 4;

/// Custom Win32 message ID querying running GUI SemVer `(major << 16) | (minor << 8) | patch`.
pub const WM_APP_QUERY_VERSION: u32 = WM_APP + 5;

/// Custom Win32 message ID delivering Netcheck probe results.
pub const WM_APP_NETCHECK_DONE: u32 = WM_APP + 6;

/// Custom Win32 message ID delivering Ping probe results.
pub const WM_APP_PING_DONE: u32 = WM_APP + 7;

/// Custom Win32 message ID delivering bugreport export results.
pub const WM_APP_BUGREPORT_DONE: u32 = WM_APP + 8;

/// Win32 mouse left button release (`WM_LBUTTONUP`) forwarded in `on_tray_callback`.
pub const WIN_WM_LBUTTONUP: u32 = WM_LBUTTONUP;

/// Win32 mouse left double-click (`WM_LBUTTONDBLCLK`) forwarded in `on_tray_callback`.
pub const WIN_WM_LBUTTONDBLCLK: u32 = WM_LBUTTONDBLCLK;

/// Win32 mouse right button release (`WM_RBUTTONUP`) forwarded in `on_tray_callback`.
pub const WIN_WM_RBUTTONUP: u32 = WM_RBUTTONUP;

/// Win32 button click notification code (`BN_CLICKED`) forwarded in `on_command`.
pub const WIN_BN_CLICKED: u16 = 0;

/// Win32 edit text-change notification code (`EN_CHANGE`) forwarded in `on_command`.
pub const WIN_EN_CHANGE: u16 = 0x0300;

/// Win32 list box selection-change notification code (`LBN_SELCHANGE`) forwarded in `on_command`.
pub const WIN_LBN_SELCHANGE: u16 = 1;

/// Win32 `WS_OVERLAPPEDWINDOW` window style bitmask (`ADR-027`).
pub const WIN_WS_OVERLAPPEDWINDOW: u32 = WS_OVERLAPPEDWINDOW;

/// Win32 `WS_CLIPCHILDREN` window style bitmask preventing child repaint flicker (`ADR-027`).
pub const WIN_WS_CLIPCHILDREN: u32 = WS_CLIPCHILDREN;

/// Canonical `dwStyle` for the main Dashboard window (`WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN`).
///
/// Placed strictly in `dwStyle` (NOT `dwExStyle`, where `WS_EX_CLIPCHILDREN` does not exist).
pub const MAIN_WINDOW_STYLE: u32 = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;

/// Win32 `WM_CTLCOLORSTATIC` message identifier forwarded to [`WindowEventHandler::on_ctlcolor`].
pub const WIN_WM_CTLCOLORSTATIC: u32 = WM_CTLCOLORSTATIC;

/// Win32 `WM_CTLCOLOREDIT` message identifier forwarded to [`WindowEventHandler::on_ctlcolor`].
pub const WIN_WM_CTLCOLOREDIT: u32 = WM_CTLCOLOREDIT;

/// Win32 `WM_CTLCOLORLISTBOX` message identifier forwarded to [`WindowEventHandler::on_ctlcolor`].
pub const WIN_WM_CTLCOLORLISTBOX: u32 = WM_CTLCOLORLISTBOX;

/// Win32 `WM_CTLCOLORBTN` message identifier forwarded to [`WindowEventHandler::on_ctlcolor`].
pub const WIN_WM_CTLCOLORBTN: u32 = WM_CTLCOLORBTN;

/// Win32 `ODS_SELECTED` item state flag for `BS_OWNERDRAW` controls (`WM_DRAWITEM`).
pub const WIN_ODS_SELECTED: u32 = 0x0001;

/// Win32 `ODS_DISABLED` item state flag for `BS_OWNERDRAW` controls (`WM_DRAWITEM`).
pub const WIN_ODS_DISABLED: u32 = 0x0004;

/// Win32 `ODS_FOCUS` item state flag for `BS_OWNERDRAW` controls (`WM_DRAWITEM`).
pub const WIN_ODS_FOCUS: u32 = 0x0010;

/// Safe OS-neutral projection of Win32 `DRAWITEMSTRUCT` for `BS_OWNERDRAW` controls (`ADR-027`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerDrawItem {
    /// Child control identifier (`CtlID`).
    pub control_id: u16,
    /// Target device context handle (`HDC`) as `isize`.
    pub hdc: isize,
    /// Bounding rectangle in control client coordinates.
    pub rect: ControlRect,
    /// Bitmask of `WIN_ODS_*` flags (`selected`, `disabled`, `focus`).
    pub item_state: u32,
    /// Child control window handle (`HWND`) as `isize`.
    pub hwnd_item: isize,
}

const MGH1_MAGIC: [u8; 4] = *b"MGH1";
const MGH1_HELLO_FRAME_LEN: usize = 13;
const MGH1_PROTOCOL_VERSION: u32 = 1;
const HANDOFF_PIPE_BUF_BYTES: u32 = 65_536;
const HANDOFF_WRITE_TIMEOUT_MS: u32 = 15_000;
const MAX_BUGREPORT_CHUNK_BYTES: usize = 65_536;
const MAX_WIDE_PATH_CHARS: usize = 32_768;
const STILL_ACTIVE_EXIT_CODE: u32 = 259;
const REG_RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const BST_CHECKED_VAL: usize = 1;
const BST_UNCHECKED_VAL: usize = 0;

/// RAII guard closing a Win32 `HANDLE` (`CloseHandle`) on drop.
pub struct OwnedWinHandle(HANDLE);

// SAFETY: Kernel handles wrapped by `OwnedWinHandle` are exclusively owned and closed once in
// `Drop`.
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
            // SAFETY: `self.0` was validated non-null and != `INVALID_HANDLE_VALUE` and is owned
            // solely by `self`.
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

    /// Borrows the underlying raw `HGDIOBJ` handle encoded as `isize` for safe FFI return values
    /// (such as `HBRUSH` returned from `WM_CTLCOLOR*`).
    #[must_use]
    pub fn as_raw_isize(&self) -> isize {
        self.0 as isize
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

/// RAII guard deleting a Win32 memory DC (`DeleteDC`) on drop.
///
/// Do NOT use for DCs returned by `BeginPaint` (use [`PaintGuard`]) or `GetDC`.
pub struct OwnedMemDc(isize);

impl OwnedMemDc {
    /// Creates a memory DC compatible with `hdc_ref` (`CreateCompatibleDC`).
    ///
    /// Passing `0` creates a memory DC compatible with the application's current screen.
    #[must_use]
    pub fn from_compatible(hdc_ref: isize) -> Option<Self> {
        // SAFETY: `CreateCompatibleDC` accepts null (`0`) or a live `HDC` and returns a new
        // memory DC (or null on failure).
        let mem_dc = unsafe { CreateCompatibleDC(hdc_ref as HDC) };
        if mem_dc.is_null() {
            None
        } else {
            Some(Self(mem_dc as isize))
        }
    }

    /// Borrows the underlying raw `HDC` handle as `isize`.
    #[must_use]
    pub const fn as_raw(&self) -> isize {
        self.0
    }
}

impl fmt::Debug for OwnedMemDc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnedMemDc(0x{:x})", self.0)
    }
}

impl Drop for OwnedMemDc {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: `self.0` is a live memory DC owned exclusively by `self`.
            unsafe {
                DeleteDC(self.0 as _);
            }
        }
    }
}

/// RAII guard calling `EndPaint` on drop for a `BeginPaint` session.
pub struct PaintGuard {
    hwnd: isize,
    ps: PAINTSTRUCT,
    hdc: isize,
}

impl PaintGuard {
    /// Begins painting for `hwnd` (`BeginPaint`), returning `None` if invalid or failed.
    #[must_use]
    pub fn begin(hwnd: isize) -> Option<Self> {
        if hwnd == 0 {
            return None;
        }
        // SAFETY: `PAINTSTRUCT` does not derive `Default` in `windows-sys 0.59`, and
        // zero-initialization is valid prior to `BeginPaint`.
        let mut ps: PAINTSTRUCT = unsafe { std::mem::zeroed() };
        // SAFETY: `hwnd` is a non-zero live window handle validated by the caller.
        let hdc = unsafe { BeginPaint(hwnd as HWND, &raw mut ps) };
        if hdc.is_null() {
            None
        } else {
            Some(Self {
                hwnd,
                ps,
                hdc: hdc as isize,
            })
        }
    }

    /// Returns the paint `HDC` handle as `isize`.
    #[must_use]
    pub const fn hdc(&self) -> isize {
        self.hdc
    }

    /// Returns the invalid paint rectangle as [`ControlRect`].
    #[must_use]
    pub const fn rect(&self) -> ControlRect {
        ControlRect {
            x: self.ps.rcPaint.left,
            y: self.ps.rcPaint.top,
            w: self.ps.rcPaint.right.saturating_sub(self.ps.rcPaint.left),
            h: self.ps.rcPaint.bottom.saturating_sub(self.ps.rcPaint.top),
        }
    }
}

impl fmt::Debug for PaintGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PaintGuard(hwnd=0x{:x}, hdc=0x{:x})",
            self.hwnd, self.hdc
        )
    }
}

impl Drop for PaintGuard {
    fn drop(&mut self) {
        if self.hwnd != 0 {
            // SAFETY: `self.hwnd` and `self.ps` match the earlier `BeginPaint` call.
            unsafe {
                EndPaint(self.hwnd as HWND, &raw const self.ps);
            }
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
        // SAFETY: Restores the thread's original security token after
        // `ImpersonateNamedPipeClient`.
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

struct LocalAllocGuard(*mut c_void);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by a Win32 API using `LocalAlloc`.
            let _rem = unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

struct CoTaskMemGuard(*mut c_void);

impl Drop for CoTaskMemGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `SHGetKnownFolderPath` via COM task allocator.
            unsafe { CoTaskMemFree(self.0) };
        }
    }
}

struct GlobalLockGuard(HANDLE);

impl Drop for GlobalLockGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Matches an earlier successful `GlobalLock` on `self.0`.
            let _unlocked = unsafe { GlobalUnlock(self.0) };
        }
    }
}

struct OwnedScHandle(SC_HANDLE);

impl OwnedScHandle {
    fn from_raw(handle: SC_HANDLE) -> Option<Self> {
        if handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    const fn as_raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for OwnedScHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is an open SCM or service handle owned solely by `self`.
            let _closed = unsafe { CloseServiceHandle(self.0) };
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

/// Standard modal `MessageBoxW` category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageBoxKind {
    /// Informational message (`OK`).
    Info,
    /// Warning alert (`OK`).
    Warning,
    /// Error alert (`OK`).
    Error,
    /// Yes/No confirmation prompt (`Yes` returns `true`).
    ConfirmYesNo,
}

/// Tray context menu item specification rendered cleanly without `unsafe` in `mesh-gui`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayMenuEntry {
    /// Disabled status summary header row.
    Header(String),
    /// Horizontal menu separator.
    Separator,
    /// Clickable action item returning `id` when activated.
    Action {
        /// Command identifier returned from `show_tray_context_menu`.
        id: u16,
        /// Display label (`&` escaped cleanly as needed by caller).
        label: String,
        /// Whether item is clickable.
        enabled: bool,
        /// Whether checkmark is shown.
        checked: bool,
        /// Whether item is bold default action.
        default: bool,
    },
    /// Nested submenu (e.g. `Peers`).
    Submenu {
        /// Submenu label.
        label: String,
        /// Whether submenu is enabled.
        enabled: bool,
        /// Nested child items.
        items: Vec<TrayMenuEntry>,
    },
}

/// Parameters for creating and running the main Win32 Dashboard window.
#[derive(Debug)]
pub struct GuiWindowSpec<'a> {
    /// Win32 window class name.
    pub class_name: &'a str,
    /// Initial window title.
    pub title: &'a str,
    /// Initial logical width at 96 DPI.
    pub width_96dpi: i32,
    /// Initial logical height at 96 DPI.
    pub height_96dpi: i32,
    /// When `true`, starts hidden in System Tray (`--minimized`).
    pub start_hidden: bool,
    /// Registered `MeshVpnGui_Activate_v1` broadcast message ID.
    pub activate_msg: u32,
    /// Registered `TaskbarCreated` broadcast message ID.
    pub taskbar_created_msg: u32,
    /// Initial window icon.
    pub initial_icon: Option<&'a OwnedIcon>,
}

/// Safe event callback trait implemented by `mesh-gui::window` without writing `unsafe`.
pub trait WindowEventHandler {
    /// Invoked once inside `WM_CREATE` after HWND creation.
    fn on_create(&self, hwnd: isize);
    /// Invoked on `WM_COMMAND` from buttons, checkboxes, radios, edits, or listboxes.
    fn on_command(&self, hwnd: isize, control_id: u16, notify_code: u16);
    /// Invoked on `WM_TIMER`.
    fn on_timer(&self, hwnd: isize, timer_id: usize);
    /// Invoked on `WM_APP_TRAY_CALLBACK` (`lparam` low word mouse message).
    fn on_tray_callback(&self, hwnd: isize, event_msg: u32);
    /// Invoked when `explorer.exe` restarts and broadcasts `TaskbarCreated`.
    fn on_taskbar_created(&self, hwnd: isize);
    /// Invoked when a second instance sends `MeshVpnGui_Activate_v1`.
    fn on_activate_requested(&self, hwnd: isize);
    /// Invoked on `WM_APP_GRACEFUL_SHUTDOWN`, `WM_QUERYENDSESSION`, or `WM_ENDSESSION`.
    fn on_graceful_shutdown(&self, hwnd: isize);
    /// Invoked for custom `WM_APP_*` background notifications.
    fn on_app_message(&self, hwnd: isize, msg: u32, wparam: usize, lparam: isize);
    /// Invoked before `TranslateMessage` when `Ctrl+V` is pressed inside `hwnd`.
    fn on_ctrl_v(&self, hwnd: isize, focused_control_id: u16);
    /// Invoked on `WM_DPICHANGED`.
    fn on_dpi_changed(&self, hwnd: isize, dpi: u32);
    /// Invoked on `WM_SIZE`.
    fn on_resize(&self, hwnd: isize, width: i32, height: i32);
    /// Invoked on `WM_APP_QUERY_VERSION` returning packed `(major << 16) | (minor << 8) | patch`.
    fn on_query_version(&self) -> isize;
    /// Invoked on `WM_CLOSE`; return `true` to hide/suppress default `DestroyWindow`.
    fn on_close(&self, hwnd: isize) -> bool;
    /// Invoked on `WM_DESTROY` prior to `PostQuitMessage(0)`.
    fn on_destroy(&self, hwnd: isize);
    /// Invoked on `WM_SETTINGCHANGE` or `WM_THEMECHANGED` (`ADR-027`).
    fn on_theme_changed(&self, _hwnd: isize) {}
    /// Invoked on `WM_CTLCOLORSTATIC`, `WM_CTLCOLOREDIT`, `WM_CTLCOLORLISTBOX`, `WM_CTLCOLORBTN`.
    ///
    /// Return a non-zero `HBRUSH` encoded as `isize` to override background painting, or `0` to
    /// delegate to `DefWindowProcW`.
    fn on_ctlcolor(&self, _hwnd: isize, _hdc: isize, _control_hwnd: isize, _msg: u32) -> isize {
        0
    }
    /// Invoked on `WM_PAINT`; return `true` when painted via [`PaintGuard`], or `false` for default.
    fn on_paint(&self, _hwnd: isize) -> bool {
        false
    }
    /// Invoked on `WM_ERASEBKGND`; return `true` to suppress default background erase flicker.
    fn on_erase_bkgnd(&self, _hwnd: isize, _hdc: isize) -> bool {
        false
    }
    /// Invoked on `WM_DRAWITEM` for `BS_OWNERDRAW` buttons/tabs/pills (`ADR-027`).
    fn on_draw_item(&self, _hwnd: isize, _item: &OwnerDrawItem) -> bool {
        false
    }
}

/// Safe Win32 System Tray notification icon handle (`Shell_NotifyIconW`).
pub struct TrayIconController {
    hwnd: HWND,
    icon_id: u32,
    added: bool,
}

impl fmt::Debug for TrayIconController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrayIconController")
            .field("icon_id", &self.icon_id)
            .field("added", &self.added)
            .finish_non_exhaustive()
    }
}

impl TrayIconController {
    /// Creates an unregistered tray controller bound to `hwnd`.
    #[must_use]
    pub const fn new(hwnd: isize, icon_id: u32) -> Self {
        Self {
            hwnd: hwnd as HWND,
            icon_id,
            added: false,
        }
    }

    /// Adds (or re-adds after `TaskbarCreated`) the tray icon with bounded retry (`US-103 AC5`).
    pub fn add_or_restore(&mut self, icon: &OwnedIcon, tooltip: &str) -> SysResult<()> {
        const OP: &str = "gui_windows::TrayIconController::add_or_restore";
        let nid = build_notify_icon_data(self.hwnd, self.icon_id, icon, tooltip);
        for attempt in 0..4_u32 {
            // SAFETY: `nid` is a fully initialized `NOTIFYICONDATAW` pointing to a live `HICON`
            // and `HWND` for the duration of `Shell_NotifyIconW`.
            let ok = unsafe { Shell_NotifyIconW(NIM_ADD, &raw const nid) };
            if ok != 0 {
                self.added = true;
                return Ok(());
            }
            // Retry `NIM_MODIFY` in case the icon already exists in shell cache.
            // SAFETY: `nid` remains initialized for `NIM_MODIFY`.
            let mod_ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &raw const nid) };
            if mod_ok != 0 {
                self.added = true;
                return Ok(());
            }
            if attempt < 3 {
                win_sleep_ms(120 * (attempt + 1));
            }
        }
        Err(SysError::io(OP, io::Error::last_os_error()))
    }

    /// Updates the existing tray icon image and tooltip (falls back to `NIM_ADD` if absent).
    pub fn update(&mut self, icon: &OwnedIcon, tooltip: &str) -> SysResult<()> {
        if !self.added {
            return self.add_or_restore(icon, tooltip);
        }
        let nid = build_notify_icon_data(self.hwnd, self.icon_id, icon, tooltip);
        // SAFETY: `nid` holds valid icon handle and NUL-terminated UTF-16 tooltip.
        let ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &raw const nid) };
        if ok != 0 {
            return Ok(());
        }
        self.add_or_restore(icon, tooltip)
    }

    /// Displays an informational tray balloon tip (called at most once per session on minimize).
    pub fn show_info_balloon(&self, icon: &OwnedIcon, title: &str, body: &str) -> SysResult<()> {
        const OP: &str = "gui_windows::TrayIconController::show_info_balloon";
        let mut nid = build_notify_icon_data(self.hwnd, self.icon_id, icon, title);
        nid.uFlags |= NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO;
        write_wide_fixed(&mut nid.szInfoTitle, title);
        write_wide_fixed(&mut nid.szInfo, body);
        // SAFETY: `nid` is fully initialized with NUL-terminated UTF-16 `szInfoTitle`/`szInfo`.
        let ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &raw const nid) };
        if ok == 0 {
            return Err(SysError::io(OP, io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Removes the tray icon immediately (`NIM_DELETE`).
    pub fn remove(&mut self) {
        if !self.added {
            return;
        }
        // SAFETY: `NOTIFYICONDATAW` is POD zero-initialized before setting `cbSize`, `hWnd`, `uID`.
        let mut nid: NOTIFYICONDATAW = unsafe { mem::zeroed() };
        nid.cbSize = u32::try_from(size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
        nid.hWnd = self.hwnd;
        nid.uID = self.icon_id;
        // SAFETY: Removes the tray icon belonging to `(self.hwnd, self.icon_id)`.
        let _removed = unsafe { Shell_NotifyIconW(NIM_DELETE, &raw const nid) };
        self.added = false;
    }
}

impl Drop for TrayIconController {
    fn drop(&mut self) {
        self.remove();
    }
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
    // SAFETY: `SetProcessDpiAwarenessContext` takes a constant Win32 pseudo-handle with no
    // pointer dereference.
    let ok = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    if ok != 0 {
        return Ok(());
    }
    // SAFETY: Fallback to system DPI awareness if Per-Monitor V2 is unavailable; takes no args.
    let _fallback = unsafe { SetProcessDPIAware() };
    Ok(())
}

/// Initializes Win32 Common Controls
/// (`ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES`), falling back to
/// `ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES` when ComCtl32 v5.82 is loaded without an SxS v6
/// manifest.
pub fn init_common_controls() -> SysResult<()> {
    const OP: &str = "gui_windows::init_common_controls";
    let dw_size = u32::try_from(size_of::<INITCOMMONCONTROLSEX>()).unwrap_or(8);
    let full = INITCOMMONCONTROLSEX {
        dwSize: dw_size,
        dwICC: ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES,
    };
    // SAFETY: `full` is a valid stack `INITCOMMONCONTROLSEX` whose `dwSize` matches its size.
    if unsafe { InitCommonControlsEx(&raw const full) } != 0 {
        return Ok(());
    }
    // Standard USER32 controls (`BUTTON`, `EDIT`, `STATIC`, `LISTBOX`) are built in and do not
    // require `ICC_STANDARD_CLASSES`, which ComCtl32 v5.82 rejects without an SxS v6 manifest.
    let fallback = INITCOMMONCONTROLSEX {
        dwSize: dw_size,
        dwICC: ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES,
    };
    // SAFETY: `fallback` is a valid stack `INITCOMMONCONTROLSEX` whose `dwSize` matches its size.
    if unsafe { InitCommonControlsEx(&raw const fallback) } != 0 {
        return Ok(());
    }
    Err(SysError::io(OP, io::Error::last_os_error()))
}

/// Returns `true` when the current process token holds elevated privileges (`TokenIsElevated`).
pub fn is_current_process_elevated() -> SysResult<bool> {
    const OP: &str = "gui_windows::is_current_process_elevated";
    let mut tok_raw: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle; `tok_raw` receives the token handle.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut tok_raw) };
    if ok == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    let Some(token) = OwnedWinHandle::from_raw(tok_raw) else {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    };
    query_token_is_elevated(token.as_raw(), OP)
}

/// Launches `exe_path` elevated via `ShellExecuteExW("runas")` with
/// `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC` passing ONLY
/// `--elevated-worker --handoff-pipe <pipe_name>` (never secrets or save paths, `ADR-021`).
pub fn launch_elevated_worker(
    exe_path: &Path,
    handoff_pipe_name: &str,
) -> SysResult<OwnedWinHandle> {
    const OP: &str = "gui_windows::launch_elevated_worker";
    if exe_path.as_os_str().is_empty() || !is_valid_handoff_pipe_name(handoff_pipe_name) {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "invalid executable or handoff pipe name".to_owned(),
        });
    }
    let meta = fs::symlink_metadata(exe_path).map_err(|err| SysError::io(OP, err))?;
    if meta.file_type().is_symlink()
        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !meta.file_type().is_file()
    {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "refusing to elevate symlink, reparse point, or non-regular file".to_owned(),
        });
    }

    let clean_path = strip_verbatim_prefix(exe_path);
    let params = format!("--elevated-worker --handoff-pipe {handoff_pipe_name}");
    if contains_shell_metacharacters(&params) {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "rejected unsafe characters in elevated worker parameters".to_owned(),
        });
    }

    let verb_wide = encode_wide_nul_str("runas", OP)?;
    let file_wide = encode_wide_nul_os(clean_path.as_os_str(), OP)?;
    let params_wide = encode_wide_nul_str(&params, OP)?;

    // SAFETY: `SHELLEXECUTEINFOW` is a POD C struct zero-initialized before setting pointers.
    let mut sei: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
    sei.cbSize = u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    sei.lpVerb = verb_wide.as_ptr();
    sei.lpFile = file_wide.as_ptr();
    sei.lpParameters = params_wide.as_ptr();
    sei.nShow = SW_HIDE;

    // SAFETY: `sei` and all UTF-16 NUL-terminated buffers (`verb_wide`, `file_wide`, `params_wide`)
    // remain valid and pinned for the entire synchronous `ShellExecuteExW` call.
    let ok = unsafe { ShellExecuteExW(&raw mut sei) };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(WIN_ERROR_CANCELLED) {
            return Err(SysError::Io {
                operation: OP,
                source: err,
            });
        }
        return Err(map_win_io_error(OP, err));
    }

    OwnedWinHandle::from_raw(sei.hProcess).ok_or_else(|| {
        SysError::io(
            OP,
            io::Error::other("ShellExecuteExW succeeded without returning process handle"),
        )
    })
}

/// Returns the Win32 PID for a process handle (`GetProcessId`).
pub fn get_process_id(proc_handle: &OwnedWinHandle) -> SysResult<u32> {
    const OP: &str = "gui_windows::get_process_id";
    // SAFETY: `proc_handle` holds a live process handle owned by the caller.
    let pid = unsafe { GetProcessId(proc_handle.as_raw()) };
    if pid == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    Ok(pid)
}

/// Waits up to `timeout_ms` for `proc_handle` to exit (`true` if exited).
pub fn wait_process_exit(proc_handle: &OwnedWinHandle, timeout_ms: u32) -> SysResult<bool> {
    const OP: &str = "gui_windows::wait_process_exit";
    // SAFETY: `proc_handle` is a valid process handle owned by caller.
    let status = unsafe { WaitForSingleObject(proc_handle.as_raw(), timeout_ms) };
    if status == WAIT_OBJECT_0 {
        Ok(true)
    } else if status == WAIT_TIMEOUT {
        Ok(false)
    } else {
        Err(SysError::io(OP, io::Error::last_os_error()))
    }
}

/// Queries the Win32 process exit code (`None` if still active).
pub fn get_process_exit_code(proc_handle: &OwnedWinHandle) -> SysResult<Option<u32>> {
    const OP: &str = "gui_windows::get_process_exit_code";
    let mut code: u32 = 0;
    // SAFETY: `proc_handle` is a valid process handle and `code` is writable stack storage.
    let ok = unsafe { GetExitCodeProcess(proc_handle.as_raw(), &raw mut code) };
    if ok == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    if code == STILL_ACTIVE_EXIT_CODE {
        Ok(None)
    } else {
        Ok(Some(code))
    }
}

/// Ephemeral Named Pipe server bound by the Medium-Integrity GUI
/// (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<UserSid>)`,
/// `FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS | FILE_FLAG_OVERLAPPED`, `ADR-021`).
#[derive(Debug)]
pub struct HandoffPipeServer {
    pipe_name: String,
    handle: OwnedWinHandle,
}

impl HandoffPipeServer {
    /// Binds a new single-instance Named Pipe server waiting for the elevated worker.
    pub fn bind(pipe_name: &str) -> SysResult<Self> {
        const OP: &str = "gui_windows::HandoffPipeServer::bind";
        if !is_valid_handoff_pipe_name(pipe_name) {
            return Err(SysError::SecurityViolation {
                operation: OP,
                detail: "invalid handoff pipe name".to_owned(),
            });
        }

        let user_sid = current_process_user_sid_string(OP)?;
        let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{user_sid})");
        let sddl_wide = encode_wide_nul_str(&sddl, OP)?;

        let mut sd_ptr: *mut c_void = ptr::null_mut();
        // SAFETY: `sddl_wide` is NUL-terminated UTF-16 and `sd_ptr` receives a `LocalAlloc` SD.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd_ptr,
                ptr::null_mut(),
            )
        };
        if ok == 0 || sd_ptr.is_null() {
            return Err(map_win_io_error(OP, io::Error::last_os_error()));
        }
        let _sd_guard = LocalAllocGuard(sd_ptr);

        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: sd_ptr,
            bInheritHandle: 0,
        };
        let pipe_wide = encode_wide_nul_str(pipe_name, OP)?;
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

        // SAFETY: `pipe_wide` is NUL-terminated UTF-16 and `sa` points to a valid security
        // descriptor kept alive across `CreateNamedPipeW`.
        let raw = unsafe {
            CreateNamedPipeW(
                pipe_wide.as_ptr(),
                open_mode,
                pipe_mode,
                1,
                HANDOFF_PIPE_BUF_BYTES,
                HANDOFF_PIPE_BUF_BYTES,
                0,
                &raw const sa,
            )
        };
        let Some(handle) = OwnedWinHandle::from_raw(raw) else {
            return Err(map_win_io_error(OP, io::Error::last_os_error()));
        };

        Ok(Self {
            pipe_name: pipe_name.to_owned(),
            handle,
        })
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
    /// `ImpersonateNamedPipeClient(SecurityIdentification)` -> `OpenThreadToken` ->
    /// `CheckTokenMembership` + `TokenElevation` (without calling `OpenProcess`/`OpenProcessToken`,
    /// `BLK-DGUI-G2-04`).
    pub fn accept_and_verify_worker(
        &self,
        child_pid: u32,
        timeout_ms: u32,
    ) -> SysResult<WindowsPeerCredentials> {
        self.accept_and_verify_inner(None, child_pid, timeout_ms)
    }

    /// Same as [`Self::accept_and_verify_worker`], while also failing immediately if `child_proc`
    /// exits before connecting to the handoff pipe.
    pub fn accept_and_verify_worker_watching_process(
        &self,
        child_proc: &OwnedWinHandle,
        child_pid: u32,
        timeout_ms: u32,
    ) -> SysResult<WindowsPeerCredentials> {
        self.accept_and_verify_inner(Some(child_proc), child_pid, timeout_ms)
    }

    /// Connects, verifies `GetNamedPipeClientProcessId == child_pid` and `0x00 WorkerHello`, and
    /// returns `(credentials, token_is_elevated)` without rejecting non-elevated local test peers.
    pub fn accept_hello_and_read_credentials(
        &self,
        child_pid: u32,
        timeout_ms: u32,
    ) -> SysResult<(WindowsPeerCredentials, bool)> {
        const OP: &str = "gui_windows::HandoffPipeServer::accept_hello_and_read_credentials";
        if child_pid == 0 {
            return Err(SysError::SecurityViolation {
                operation: OP,
                detail: "invalid expected worker PID 0".to_owned(),
            });
        }
        let started = Instant::now();
        accept_pipe_overlapped(self.handle.as_raw(), None, timeout_ms, OP)?;
        verify_pipe_client_pid(self.handle.as_raw(), child_pid, OP)?;

        let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        let rem_ms = timeout_ms.saturating_sub(elapsed_ms).clamp(100, 5_000);
        read_and_validate_worker_hello(self.handle.as_raw(), rem_ms, OP)?;

        impersonate_and_inspect_pipe_thread_token(self.handle.as_raw(), OP)
    }

    fn accept_and_verify_inner(
        &self,
        child_proc: Option<&OwnedWinHandle>,
        child_pid: u32,
        timeout_ms: u32,
    ) -> SysResult<WindowsPeerCredentials> {
        const OP: &str = "gui_windows::HandoffPipeServer::accept_and_verify_worker";
        if child_pid == 0 {
            return Err(SysError::SecurityViolation {
                operation: OP,
                detail: "invalid expected worker PID 0".to_owned(),
            });
        }

        let started = Instant::now();
        accept_pipe_overlapped(self.handle.as_raw(), child_proc, timeout_ms, OP)?;
        verify_pipe_client_pid(self.handle.as_raw(), child_pid, OP)?;

        let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        let rem_ms = timeout_ms.saturating_sub(elapsed_ms).clamp(100, 5_000);
        read_and_validate_worker_hello(self.handle.as_raw(), rem_ms, OP)?;

        let (creds, is_elevated) =
            impersonate_and_inspect_pipe_thread_token(self.handle.as_raw(), OP)?;
        if !is_elevated || !(creds.is_builtin_admin || creds.is_local_system) {
            return Err(SysError::PermissionDenied { operation: OP });
        }
        Ok(creds)
    }

    /// Reads up to `buf.len()` bytes with overlapped timeout `timeout_ms`.
    pub fn read_blocking(&self, buf: &mut [u8], timeout_ms: u32) -> SysResult<usize> {
        pipe_read_overlapped(
            self.handle.as_raw(),
            buf,
            timeout_ms,
            "gui_windows::HandoffPipeServer::read_blocking",
        )
    }

    /// Reads an exact buffer slice with overlapped deadline `timeout_ms`.
    pub fn read_exact_blocking(&self, buf: &mut [u8], timeout_ms: u32) -> SysResult<()> {
        pipe_read_exact_overlapped(
            self.handle.as_raw(),
            buf,
            timeout_ms,
            "gui_windows::HandoffPipeServer::read_exact_blocking",
        )
    }

    /// Writes `data` to the connected handoff pipe.
    pub fn write_blocking(&self, data: &[u8]) -> SysResult<usize> {
        pipe_write_overlapped(
            self.handle.as_raw(),
            data,
            HANDOFF_WRITE_TIMEOUT_MS,
            "gui_windows::HandoffPipeServer::write_blocking",
        )
    }

    /// Writes the entire `data` slice to the connected handoff pipe.
    pub fn write_all_blocking(&self, data: &[u8]) -> SysResult<()> {
        pipe_write_all_overlapped(
            self.handle.as_raw(),
            data,
            HANDOFF_WRITE_TIMEOUT_MS,
            "gui_windows::HandoffPipeServer::write_all_blocking",
        )
    }

    /// Cancels pending overlapped I/O on the pipe handle during cancellation/shutdown.
    pub fn cancel_io(&self) {
        // SAFETY: `self.handle` is an open Win32 pipe handle owned by `self`.
        let _cancelled = unsafe { CancelIoEx(self.handle.as_raw(), ptr::null()) };
    }
}

/// Elevated worker client connection to the GUI's ephemeral handoff pipe
/// (`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED`, sends
/// `0x00 WorkerHello` immediately, `BLK-DGUI-G2-04`).
#[derive(Debug)]
pub struct HandoffPipeClient {
    handle: OwnedWinHandle,
}

impl HandoffPipeClient {
    /// Connects to `pipe_name` with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and
    /// transmits the 13-byte `MGH1` `0x00 WorkerHello` frame.
    pub fn connect_and_send_hello(pipe_name: &str, timeout_ms: u32) -> SysResult<Self> {
        const OP: &str = "gui_windows::HandoffPipeClient::connect_and_send_hello";
        if !is_valid_handoff_pipe_name(pipe_name) {
            return Err(SysError::SecurityViolation {
                operation: OP,
                detail: "invalid handoff pipe name".to_owned(),
            });
        }

        let wide = encode_wide_nul_str(pipe_name, OP)?;
        let flags = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms.max(100)));

        let handle = loop {
            // SAFETY: `wide` is NUL-terminated UTF-16 and all flags are Win32 constants.
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    flags,
                    ptr::null_mut(),
                )
            };
            if let Some(h) = OwnedWinHandle::from_raw(raw) {
                break h;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(WIN_ERROR_PIPE_BUSY) {
                let now = Instant::now();
                let Some(rem) = deadline.checked_duration_since(now) else {
                    return Err(SysError::io(
                        OP,
                        io::Error::new(io::ErrorKind::TimedOut, "handoff pipe busy timeout"),
                    ));
                };
                let wait_ms = u32::try_from(rem.as_millis()).unwrap_or(500).min(250);
                // SAFETY: `wide` is NUL-terminated UTF-16.
                let _waited = unsafe { WaitNamedPipeW(wide.as_ptr(), wait_ms) };
                continue;
            }
            return Err(map_win_io_error(OP, err));
        };

        let mut hello = [0_u8; MGH1_HELLO_FRAME_LEN];
        hello[0..4].copy_from_slice(&MGH1_MAGIC);
        if let Some(ft) = hello.get_mut(4) {
            *ft = 0x00;
        }
        if let Some(len_dst) = hello.get_mut(5..9) {
            len_dst.copy_from_slice(&4_u32.to_le_bytes());
        }
        if let Some(ver_dst) = hello.get_mut(9..13) {
            ver_dst.copy_from_slice(&MGH1_PROTOCOL_VERSION.to_le_bytes());
        }

        pipe_write_all_overlapped(handle.as_raw(), &hello, timeout_ms.max(1_000), OP)?;
        Ok(Self { handle })
    }

    /// Borrows the underlying pipe handle.
    #[must_use]
    pub const fn handle(&self) -> &OwnedWinHandle {
        &self.handle
    }

    /// Reads up to `buf.len()` bytes with overlapped timeout `timeout_ms`.
    pub fn read_blocking(&self, buf: &mut [u8], timeout_ms: u32) -> SysResult<usize> {
        pipe_read_overlapped(
            self.handle.as_raw(),
            buf,
            timeout_ms,
            "gui_windows::HandoffPipeClient::read_blocking",
        )
    }

    /// Reads an exact buffer slice with overlapped deadline `timeout_ms`.
    pub fn read_exact_blocking(&self, buf: &mut [u8], timeout_ms: u32) -> SysResult<()> {
        pipe_read_exact_overlapped(
            self.handle.as_raw(),
            buf,
            timeout_ms,
            "gui_windows::HandoffPipeClient::read_exact_blocking",
        )
    }

    /// Writes `data` to the handoff pipe.
    pub fn write_blocking(&self, data: &[u8]) -> SysResult<usize> {
        pipe_write_overlapped(
            self.handle.as_raw(),
            data,
            HANDOFF_WRITE_TIMEOUT_MS,
            "gui_windows::HandoffPipeClient::write_blocking",
        )
    }

    /// Writes the entire `data` slice to the handoff pipe.
    pub fn write_all_blocking(&self, data: &[u8]) -> SysResult<()> {
        pipe_write_all_overlapped(
            self.handle.as_raw(),
            data,
            HANDOFF_WRITE_TIMEOUT_MS,
            "gui_windows::HandoffPipeClient::write_all_blocking",
        )
    }

    /// Cancels pending overlapped I/O on the pipe handle.
    pub fn cancel_io(&self) {
        // SAFETY: `self.handle` is an open Win32 pipe handle owned by `self`.
        let _cancelled = unsafe { CancelIoEx(self.handle.as_raw(), ptr::null()) };
    }
}

/// Atomic Temp-Sibling Sink Writer for Medium-Integrity bugreport streaming
/// (`ADR-023`, `BLK-DGUI-G2-05`).
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
    /// Validates `dest_path` and `expected_total_bytes` (`1..=MAX_BUGREPORT_ARCHIVE_BYTES`),
    /// verifies non-reparse parent and destination, and creates
    /// `parent/.mesh-bugreport-<hex>.tar.part`.
    pub fn create(dest_path: &Path, expected_total_bytes: u64) -> SysResult<Self> {
        const OP: &str = "gui_windows::UnprivilegedSinkWriter::create";
        let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
        if dest_path.as_os_str().is_empty()
            || expected_total_bytes == 0
            || expected_total_bytes > max_bytes
        {
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid destination path or bugreport archive size",
                ),
            ));
        }

        validate_sink_dest_path(dest_path, OP)?;
        let parent = dest_path.parent().ok_or_else(|| {
            SysError::io(
                OP,
                io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"),
            )
        })?;
        verify_non_reparse_directory(parent, OP)?;
        verify_dest_regular_or_absent(dest_path, OP)?;

        let random_hex = new_guid_hex_32();
        let temp_path = parent.join(format!(".mesh-bugreport-{random_hex}.tar.part"));

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&temp_path)
            .map_err(|err| map_win_io_error(OP, err))?;

        verify_regular_disk_handle(&file, OP)?;

        Ok(Self {
            dest_path: dest_path.to_path_buf(),
            temp_path,
            expected_total_bytes,
            cumulative_bytes: 0,
            file: Some(file),
            finalized: false,
        })
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
    pub fn write_chunk(&mut self, chunk: &[u8]) -> SysResult<()> {
        const OP: &str = "gui_windows::UnprivilegedSinkWriter::write_chunk";
        if self.finalized {
            return Err(SysError::io(
                OP,
                io::Error::new(io::ErrorKind::InvalidInput, "sink writer already finalized"),
            ));
        }
        if chunk.len() > MAX_BUGREPORT_CHUNK_BYTES {
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bugreport chunk exceeds 64 KiB",
                ),
            ));
        }
        let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
        let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        let next_total = self
            .cumulative_bytes
            .checked_add(chunk_len)
            .ok_or_else(|| {
                SysError::io(
                    OP,
                    io::Error::new(io::ErrorKind::InvalidInput, "bugreport size overflow"),
                )
            })?;
        if next_total > self.expected_total_bytes || next_total > max_bytes {
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bugreport stream exceeded declared or maximum archive size",
                ),
            ));
        }
        let Some(file) = self.file.as_mut() else {
            return Err(SysError::io(
                OP,
                io::Error::new(io::ErrorKind::BrokenPipe, "sink file handle already closed"),
            ));
        };
        if !chunk.is_empty() {
            file.write_all(chunk).map_err(|err| SysError::io(OP, err))?;
        }
        self.cumulative_bytes = next_total;
        Ok(())
    }

    /// Enforces `expected_total_bytes > 0 && cumulative_bytes == expected_total_bytes <= 20 MiB`,
    /// calls `sync_all()`, closes handle, re-checks `dest`, and atomically replaces `dest`.
    pub fn finalize(mut self) -> SysResult<u64> {
        const OP: &str = "gui_windows::UnprivilegedSinkWriter::finalize";
        let max_bytes = u64::try_from(MAX_BUGREPORT_ARCHIVE_BYTES).unwrap_or(u64::MAX);
        if self.expected_total_bytes == 0
            || self.cumulative_bytes != self.expected_total_bytes
            || self.cumulative_bytes > max_bytes
        {
            drop(self.file.take());
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "bugreport archive incomplete: wrote {} of {} bytes",
                        self.cumulative_bytes, self.expected_total_bytes
                    ),
                ),
            ));
        }

        let Some(file) = self.file.take() else {
            return Err(SysError::io(
                OP,
                io::Error::new(io::ErrorKind::BrokenPipe, "sink file handle missing"),
            ));
        };
        file.sync_all().map_err(|err| SysError::io(OP, err))?;
        drop(file);

        verify_dest_regular_or_absent(&self.dest_path, OP)?;
        let temp_wide = encode_wide_nul_os(self.temp_path.as_os_str(), OP)?;
        let dest_wide = encode_wide_nul_os(self.dest_path.as_os_str(), OP)?;

        // SAFETY: `temp_wide` and `dest_wide` are NUL-terminated UTF-16 paths in the same
        // non-reparse directory; `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` replaces
        // `dest` atomically only after `sync_all()` and closing `.part`.
        let moved = unsafe {
            MoveFileExW(
                temp_wide.as_ptr(),
                dest_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            return Err(map_win_io_error(OP, io::Error::last_os_error()));
        }

        self.finalized = true;
        Ok(self.cumulative_bytes)
    }
}

impl Drop for UnprivilegedSinkWriter {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.finalized && !self.temp_path.as_os_str().is_empty() {
            let _removed = fs::remove_file(&self.temp_path);
        }
    }
}

/// Opens `path` read-only with `FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT`, rejecting
/// symlinks/reparse points so SHA-256 verification and copy operate on the locked handle
/// (`ADR-026`).
pub fn open_anti_toctou_read_locked(path: &Path) -> SysResult<File> {
    const OP: &str = "gui_windows::open_anti_toctou_read_locked";
    if path.as_os_str().is_empty()
        || !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "path must be absolute without parent traversal".to_owned(),
        });
    }
    if let Some(parent) = path.parent() {
        let parent_meta = fs::symlink_metadata(parent).map_err(|err| map_win_io_error(OP, err))?;
        if parent_meta.file_type().is_symlink()
            || (parent_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        {
            return Err(SysError::SecurityViolation {
                operation: OP,
                detail: "parent directory cannot be a symlink or reparse point".to_owned(),
            });
        }
    }
    let link_meta = fs::symlink_metadata(path).map_err(|err| map_win_io_error(OP, err))?;
    if link_meta.file_type().is_symlink()
        || (link_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !link_meta.file_type().is_file()
    {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "target path cannot be a symlink, reparse point, or directory".to_owned(),
        });
    }

    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|err| map_win_io_error(OP, err))?;

    verify_regular_disk_handle(&file, OP)?;
    Ok(file)
}

/// Acquires `Local\MeshVpnGuiSingleInstance`, returning `Ok(None)` if another instance owns it.
pub fn acquire_single_instance_mutex() -> SysResult<Option<SingleInstanceGuard>> {
    const OP: &str = "gui_windows::acquire_single_instance_mutex";
    let wide = encode_wide_nul_str(GUI_SINGLE_INSTANCE_MUTEX, OP)?;
    // SAFETY: `wide` is NUL-terminated UTF-16 naming a session-local Win32 mutex.
    let raw = unsafe { CreateMutexW(ptr::null(), 0, wide.as_ptr()) };
    let last_err = io::Error::last_os_error();
    let Some(handle) = OwnedWinHandle::from_raw(raw) else {
        return Err(map_win_io_error(OP, last_err));
    };
    if last_err.raw_os_error() == Some(i32::try_from(ERROR_ALREADY_EXISTS).unwrap_or(183)) {
        return Ok(None);
    }
    Ok(Some(SingleInstanceGuard { _mutex: handle }))
}

/// Signals `Local\MeshVpnGuiShutdownEvent` so an older running Tray instance exits cleanly
/// (`ADR-026`).
pub fn signal_shutdown_event() -> SysResult<()> {
    const OP: &str = "gui_windows::signal_shutdown_event";
    let wide = encode_wide_nul_str(GUI_SHUTDOWN_EVENT, OP)?;
    // SAFETY: `wide` is NUL-terminated UTF-16 naming a session-local Win32 event.
    let opened = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
    let handle = if let Some(h) = OwnedWinHandle::from_raw(opened) {
        h
    } else {
        // SAFETY: Create event in case listener has not registered yet or race occurred.
        let created = unsafe { CreateEventW(ptr::null(), 1, 0, wide.as_ptr()) };
        OwnedWinHandle::from_raw(created)
            .ok_or_else(|| SysError::io(OP, io::Error::last_os_error()))?
    };
    // SAFETY: `handle` is an open Win32 event handle with `EVENT_MODIFY_STATE`.
    let ok = unsafe { SetEvent(handle.as_raw()) };
    if ok == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    Ok(())
}

/// Waits up to `timeout_ms` on `Local\MeshVpnGuiShutdownEvent` (`true` when signaled).
pub fn wait_shutdown_event(timeout_ms: u32) -> SysResult<bool> {
    const OP: &str = "gui_windows::wait_shutdown_event";
    let handle = create_named_shutdown_event()?;
    wait_event_signaled(&handle, timeout_ms, OP)
}

/// Creates or opens the persistent manual-reset `Local\MeshVpnGuiShutdownEvent` handle.
pub fn create_named_shutdown_event() -> SysResult<OwnedWinHandle> {
    const OP: &str = "gui_windows::create_named_shutdown_event";
    let wide = encode_wide_nul_str(GUI_SHUTDOWN_EVENT, OP)?;
    // SAFETY: `wide` is NUL-terminated UTF-16 naming a session-local manual-reset event.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, wide.as_ptr()) };
    OwnedWinHandle::from_raw(raw).ok_or_else(|| SysError::io(OP, io::Error::last_os_error()))
}

/// Polls/waits on an `OwnedWinHandle` event (`true` if signaled).
pub fn wait_event_signaled(
    handle: &OwnedWinHandle,
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<bool> {
    // SAFETY: `handle` is a valid Win32 event handle owned by caller.
    let status = unsafe { WaitForSingleObject(handle.as_raw(), timeout_ms) };
    if status == WAIT_OBJECT_0 {
        Ok(true)
    } else if status == WAIT_TIMEOUT {
        Ok(false)
    } else {
        Err(SysError::io(operation, io::Error::last_os_error()))
    }
}

/// Registers the `"MeshVpnGui_Activate_v1"` window message ID for single-instance activation.
pub fn register_activate_window_message() -> SysResult<u32> {
    const OP: &str = "gui_windows::register_activate_window_message";
    let wide = encode_wide_nul_str(GUI_ACTIVATE_MESSAGE_NAME, OP)?;
    // SAFETY: `wide` is a NUL-terminated UTF-16 message name.
    let id = unsafe { RegisterWindowMessageW(wide.as_ptr()) };
    if id == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    Ok(id)
}

/// Finds an existing top-level window matching `class_name` in the current desktop session.
#[must_use]
pub fn find_window_by_class(class_name: &str) -> Option<isize> {
    let wide = encode_wide_nul_str(class_name, "gui_windows::find_window_by_class").ok()?;
    // SAFETY: `wide` is a NUL-terminated UTF-16 window class name.
    let hwnd = unsafe { FindWindowW(wide.as_ptr(), ptr::null()) };
    if hwnd.is_null() {
        None
    } else {
        Some(hwnd as isize)
    }
}

/// Queries an existing GUI instance's packed version via `SendMessageTimeoutW`.
#[must_use]
pub fn query_window_version(hwnd: isize, timeout_ms: u32) -> Option<u32> {
    let mut result: usize = 0;
    // SAFETY: `hwnd` is an active top-level window handle in the current session.
    let ok = unsafe {
        SendMessageTimeoutW(
            hwnd as HWND,
            WM_APP_QUERY_VERSION,
            0,
            0,
            SMTO_ABORTIFHUNG,
            timeout_ms,
            &raw mut result,
        )
    };
    if ok == 0 {
        None
    } else {
        u32::try_from(result).ok()
    }
}

/// Requests an existing GUI window to show & focus itself (`activate_msg` + `SetForegroundWindow`).
pub fn activate_existing_gui_window(hwnd: isize, activate_msg: u32) {
    let target = hwnd as HWND;
    // SAFETY: Standard Win32 window restore & foreground activation calls on valid `HWND`.
    unsafe {
        let _shown = ShowWindow(target, SW_RESTORE);
        let _fg = SetForegroundWindow(target);
        let _posted = PostMessageW(target, activate_msg, 0, 0);
    }
}

/// Posts `WM_APP_GRACEFUL_SHUTDOWN` to an existing GUI window.
pub fn post_graceful_shutdown_to_window(hwnd: isize) {
    // SAFETY: `PostMessageW` safely queues `WM_APP_GRACEFUL_SHUTDOWN` to `hwnd`.
    let _posted = unsafe { PostMessageW(hwnd as HWND, WM_APP_GRACEFUL_SHUTDOWN, 0, 0) };
}

/// Removes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<app_name>` and user `.lnk`
/// shortcuts via `SHGetKnownFolderPath` + `CoTaskMemFree` + `std::fs::remove_file`
/// (`BLK-DGUI-G2-02`, `US-115`).
pub fn remove_user_shortcuts_and_autostart(app_name: &str) -> SysResult<()> {
    const OP: &str = "gui_windows::remove_user_shortcuts_and_autostart";
    set_user_autostart(app_name, "", false)?;

    let known_folders = [FOLDERID_Desktop, FOLDERID_Programs, FOLDERID_StartMenu];
    for folder_id in known_folders {
        if let Some(dir) = resolve_known_folder_path(&folder_id) {
            remove_shortcut_if_exists(&dir.join(format!("{app_name}.lnk")), OP)?;
            remove_shortcut_if_exists(&dir.join("Mesh VPN.lnk"), OP)?;
            let subdir = dir.join("Mesh VPN");
            if subdir.is_dir() {
                remove_shortcut_if_exists(&subdir.join("Mesh VPN.lnk"), OP)?;
                remove_shortcut_if_exists(&subdir.join(format!("{app_name}.lnk")), OP)?;
                if fs::read_dir(&subdir).is_ok_and(|mut it| it.next().is_none()) {
                    let _removed = fs::remove_dir(&subdir);
                }
            }
        }
    }
    Ok(())
}

/// Enables or removes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<app_name>` (`US-108`).
pub fn set_user_autostart(app_name: &str, command_line: &str, enabled: bool) -> SysResult<()> {
    const OP: &str = "gui_windows::set_user_autostart";
    validate_registry_value_name(app_name, OP)?;
    if enabled && (command_line.is_empty() || command_line.contains(['\0', '\r', '\n'])) {
        return Err(SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid autostart command line",
            ),
        ));
    }

    let subkey_wide = encode_wide_nul_str(REG_RUN_SUBKEY, OP)?;
    let value_wide = encode_wide_nul_str(app_name, OP)?;
    let mut raw_key: HKEY = ptr::null_mut();

    // SAFETY: `subkey_wide` is NUL-terminated UTF-16 under predefined `HKEY_CURRENT_USER`.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            ptr::null(),
            &raw mut raw_key,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(map_win_status(OP, status));
    }
    let Some(key) = OwnedRegKey::from_raw(raw_key) else {
        return Err(SysError::io(
            OP,
            io::Error::other("null HKCU registry handle"),
        ));
    };

    if !enabled {
        // SAFETY: `key` is an open `KEY_SET_VALUE` handle and `value_wide` is NUL-terminated.
        let del_rc = unsafe { RegDeleteValueW(key.as_raw(), value_wide.as_ptr()) };
        if del_rc != ERROR_SUCCESS && del_rc != u32::try_from(WIN_ERROR_FILE_NOT_FOUND).unwrap_or(2)
        {
            return Err(map_win_status(OP, del_rc));
        }
        return Ok(());
    }

    let cmd_wide = encode_wide_nul_str(command_line, OP)?;
    let byte_len = u32::try_from(cmd_wide.len().saturating_mul(2)).map_err(|_| {
        SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry value length overflow",
            ),
        )
    })?;
    // SAFETY: `cmd_wide` is NUL-terminated UTF-16 spanning `byte_len` bytes.
    let set_rc = unsafe {
        RegSetValueExW(
            key.as_raw(),
            value_wide.as_ptr(),
            0,
            REG_SZ,
            cmd_wide.as_ptr().cast::<u8>(),
            byte_len,
        )
    };
    if set_rc != ERROR_SUCCESS {
        return Err(map_win_status(OP, set_rc));
    }
    Ok(())
}

/// Queries whether `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<app_name>` is present.
pub fn is_user_autostart_enabled(app_name: &str) -> SysResult<bool> {
    const OP: &str = "gui_windows::is_user_autostart_enabled";
    validate_registry_value_name(app_name, OP)?;
    let subkey_wide = encode_wide_nul_str(REG_RUN_SUBKEY, OP)?;
    let value_wide = encode_wide_nul_str(app_name, OP)?;
    let mut raw_key: HKEY = ptr::null_mut();

    // SAFETY: `subkey_wide` is NUL-terminated UTF-16 under `HKEY_CURRENT_USER`.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &raw mut raw_key,
        )
    };
    if status == u32::try_from(WIN_ERROR_FILE_NOT_FOUND).unwrap_or(2) {
        return Ok(false);
    }
    if status != ERROR_SUCCESS {
        return Err(map_win_status(OP, status));
    }
    let Some(key) = OwnedRegKey::from_raw(raw_key) else {
        return Ok(false);
    };

    let mut value_type: u32 = 0;
    let mut data_len: u32 = 0;
    // SAFETY: Probes existence and type of `value_wide` under `key`.
    let q_rc = unsafe {
        RegQueryValueExW(
            key.as_raw(),
            value_wide.as_ptr(),
            ptr::null_mut(),
            &raw mut value_type,
            ptr::null_mut(),
            &raw mut data_len,
        )
    };
    if q_rc == u32::try_from(WIN_ERROR_FILE_NOT_FOUND).unwrap_or(2) {
        return Ok(false);
    }
    if q_rc != ERROR_SUCCESS && q_rc != ERROR_MORE_DATA {
        return Err(map_win_status(OP, q_rc));
    }
    Ok(value_type == REG_SZ && data_len > 2)
}

/// Reads current Unicode text and `GetClipboardSequenceNumber()` from the Windows clipboard.
pub fn read_clipboard_utf16_with_seq() -> SysResult<(u32, Option<String>)> {
    const OP: &str = "gui_windows::read_clipboard_utf16_with_seq";
    let _guard = open_clipboard_with_retry(OP)?;
    // SAFETY: `GetClipboardSequenceNumber` takes no arguments and returns a `u32`.
    let seq = unsafe { GetClipboardSequenceNumber() };
    let text = read_clipboard_unicode_locked()?;
    Ok((seq, text))
}

/// Writes Unicode text to the Windows clipboard and returns the new sequence number.
pub fn write_clipboard_utf16_with_seq(text: &str) -> SysResult<u32> {
    const OP: &str = "gui_windows::write_clipboard_utf16_with_seq";
    let wide = encode_wide_nul_str(text, OP)?;
    let byte_len = wide.len().saturating_mul(2);
    // SAFETY: Allocates movable global memory for Win32 clipboard ownership transfer.
    let hmem = unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_len) };
    if hmem.is_null() {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    // SAFETY: `hmem` is a newly allocated movable global block of `byte_len` bytes.
    let ptr_mem = unsafe { GlobalLock(hmem) };
    if ptr_mem.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: `hmem` has not been transferred to `SetClipboardData`.
        let _freed = unsafe { GlobalFree(hmem) };
        return Err(SysError::io(OP, err));
    }
    // SAFETY: `wide` contains `wide.len()` `u16` values (`byte_len` bytes) and does not overlap
    // `ptr_mem`.
    unsafe {
        ptr::copy_nonoverlapping(wide.as_ptr().cast::<u8>(), ptr_mem.cast::<u8>(), byte_len);
        let _unlocked = GlobalUnlock(hmem);
    }

    let _guard = match open_clipboard_with_retry(OP) {
        Ok(g) => g,
        Err(err) => {
            // SAFETY: Failed opening clipboard before ownership transfer.
            let _freed = unsafe { GlobalFree(hmem) };
            return Err(err);
        }
    };
    // SAFETY: Clipboard is open on current thread.
    let emptied = unsafe { EmptyClipboard() };
    if emptied == 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `EmptyClipboard` failed so `hmem` is still owned locally.
        let _freed = unsafe { GlobalFree(hmem) };
        return Err(SysError::io(OP, err));
    }
    // SAFETY: On success, Windows assumes ownership of `hmem`; on failure, we free it below.
    let set_res = unsafe { SetClipboardData(u32::from(CF_UNICODETEXT), hmem) };
    if set_res.is_null() {
        let err = io::Error::last_os_error();
        // SAFETY: `SetClipboardData` failed so `hmem` remains owned locally.
        let _freed = unsafe { GlobalFree(hmem) };
        return Err(SysError::io(OP, err));
    }
    // SAFETY: Returns updated clipboard sequence number.
    let seq = unsafe { GetClipboardSequenceNumber() };
    Ok(seq)
}

/// Clears the clipboard only when `GetClipboardSequenceNumber() == expected_seq` (`US-104`).
pub fn clear_clipboard_if_seq_matches(expected_seq: u32) -> SysResult<bool> {
    clear_clipboard_if_seq_and_predicate(expected_seq, |_| true)
}

/// Atomically holds `OpenClipboard` (`ClipboardGuard`) across BOTH `GetClipboardSequenceNumber()`
/// and `predicate(current_text)` before invoking `EmptyClipboard()`, eliminating the check-to-clear
/// race window (`IG-DGUI-WA-01`, `US-104`, `US-105`).
pub fn clear_clipboard_if_seq_and_predicate<F>(expected_seq: u32, predicate: F) -> SysResult<bool>
where
    F: FnOnce(&str) -> bool,
{
    const OP: &str = "gui_windows::clear_clipboard_if_seq_and_predicate";
    let _guard = open_clipboard_with_retry(OP)?;
    // SAFETY: `GetClipboardSequenceNumber` takes no pointers.
    let current_seq = unsafe { GetClipboardSequenceNumber() };
    if current_seq != expected_seq {
        return Ok(false);
    }
    let Some(current_text) = read_clipboard_unicode_locked()? else {
        return Ok(false);
    };
    if !predicate(&current_text) {
        return Ok(false);
    }
    // SAFETY: `ClipboardGuard` is held continuously; seq and content predicate both matched.
    let emptied = unsafe { EmptyClipboard() };
    if emptied == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    Ok(true)
}

/// Shows the native Win32 Save File dialog (`GetSaveFileNameW` + `OFN_OVERWRITEPROMPT`) for
/// `.tar` bugreports, returning `Ok(None)` when canceled.
pub fn save_tar_file_dialog(
    owner_hwnd: isize,
    default_filename: &str,
) -> SysResult<Option<PathBuf>> {
    const OP: &str = "gui_windows::save_tar_file_dialog";
    let mut file_buf = vec![0_u16; MAX_WIDE_PATH_CHARS];
    let safe_default = default_filename.replace(['\0', '/', '\\', ':'], "_");
    let def_units: Vec<u16> = OsStr::new(&safe_default).encode_wide().collect();
    let copy_len = def_units.len().min(file_buf.len().saturating_sub(1));
    if let (Some(dst), Some(src)) = (file_buf.get_mut(..copy_len), def_units.get(..copy_len)) {
        dst.copy_from_slice(src);
    }

    let filter: Vec<u16> = "Tar Archive (*.tar)\0*.tar\0All Files (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    let title = encode_wide_nul_str("Export Redacted Bugreport", OP)?;
    let def_ext = encode_wide_nul_str("tar", OP)?;

    // SAFETY: `OPENFILENAMEW` is a plain Win32 C struct zero-initialized before setting fields.
    let mut ofn: OPENFILENAMEW = unsafe { mem::zeroed() };
    ofn.lStructSize = u32::try_from(size_of::<OPENFILENAMEW>()).unwrap_or(0);
    ofn.hwndOwner = owner_hwnd as HWND;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = file_buf.as_mut_ptr();
    ofn.nMaxFile = u32::try_from(file_buf.len()).unwrap_or(MAX_WIDE_PATH_CHARS as u32);
    ofn.lpstrTitle = title.as_ptr();
    ofn.lpstrDefExt = def_ext.as_ptr();
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

    // SAFETY: `ofn` and all referenced UTF-16 buffers live across the synchronous modal call.
    let ok = unsafe { GetSaveFileNameW(&raw mut ofn) };
    if ok != 0 {
        let nul_pos = file_buf
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(file_buf.len());
        let slice = file_buf.get(..nul_pos).unwrap_or(&[]);
        return Ok(Some(PathBuf::from(OsString::from_wide(slice))));
    }

    // SAFETY: `CommDlgExtendedError` returns `0` when user canceled the dialog.
    let dlg_err = unsafe { CommDlgExtendedError() };
    if dlg_err == 0 {
        Ok(None)
    } else {
        Err(SysError::io(
            OP,
            io::Error::other(format!("GetSaveFileNameW failed (code {dlg_err})")),
        ))
    }
}

/// Probes `service_name` read-only via Win32 SCM without requiring Administrator elevation.
pub fn query_service_status_readonly(service_name: &str) -> SysResult<WindowsServiceProbeState> {
    const OP: &str = "gui_windows::query_service_status_readonly";
    let svc_wide = encode_wide_nul_str(service_name, OP)?;
    // SAFETY: Opens local SCM database strictly with `SC_MANAGER_CONNECT`.
    let raw_scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    let Some(scm) = OwnedScHandle::from_raw(raw_scm) else {
        return Err(map_win_io_error(OP, io::Error::last_os_error()));
    };

    // SAFETY: `scm` is live and `svc_wide` is NUL-terminated UTF-16.
    let raw_svc = unsafe { OpenServiceW(scm.as_raw(), svc_wide.as_ptr(), SERVICE_QUERY_STATUS) };
    let Some(svc) = OwnedScHandle::from_raw(raw_svc) else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(WIN_ERROR_SERVICE_DOES_NOT_EXIST) {
            return Ok(WindowsServiceProbeState::NotInstalled);
        }
        return Err(map_win_io_error(OP, err));
    };

    let status = query_service_process_status(svc.as_raw(), OP)?;
    Ok(map_service_state(status.dwCurrentState))
}

/// Registers/configures `service_name` (`LocalSystem`, `SERVICE_AUTO_START`, 5s restart recovery)
/// and starts it, waiting up to `10_000 ms` for `SERVICE_RUNNING`.
pub fn ensure_and_start_windows_service(
    service_name: &str,
    display_name: &str,
    description: &str,
    bin_path_cmd: &str,
) -> SysResult<()> {
    const OP: &str = "gui_windows::ensure_and_start_windows_service";
    let svc_wide = encode_wide_nul_str(service_name, OP)?;
    let disp_wide = encode_wide_nul_str(display_name, OP)?;
    let desc_wide = encode_wide_nul_str(description, OP)?;
    let bin_wide = encode_wide_nul_str(bin_path_cmd, OP)?;

    // SAFETY: Connects to local SCM with `SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE`.
    let raw_scm = unsafe {
        OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    };
    let Some(scm) = OwnedScHandle::from_raw(raw_scm) else {
        return Err(map_win_io_error(OP, io::Error::last_os_error()));
    };

    // SAFETY: Checks whether `service_name` already exists.
    let existing = unsafe { OpenServiceW(scm.as_raw(), svc_wide.as_ptr(), SERVICE_ALL_ACCESS) };
    let svc = if let Some(h) = OwnedScHandle::from_raw(existing) {
        // SAFETY: Updates existing service configuration to canonical binary path & auto-start.
        let cfg_ok = unsafe {
            ChangeServiceConfigW(
                h.as_raw(),
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin_wide.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                disp_wide.as_ptr(),
            )
        };
        if cfg_ok == 0 {
            return Err(map_win_io_error(OP, io::Error::last_os_error()));
        }
        h
    } else {
        let open_err = io::Error::last_os_error();
        if open_err.raw_os_error() != Some(WIN_ERROR_SERVICE_DOES_NOT_EXIST) {
            return Err(map_win_io_error(OP, open_err));
        }
        // SAFETY: Registers new LocalSystem auto-start Win32 service.
        let created = unsafe {
            CreateServiceW(
                scm.as_raw(),
                svc_wide.as_ptr(),
                disp_wide.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin_wide.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };
        OwnedScHandle::from_raw(created)
            .ok_or_else(|| map_win_io_error(OP, io::Error::last_os_error()))?
    };

    let mut desc = SERVICE_DESCRIPTIONW {
        lpDescription: desc_wide.as_ptr().cast_mut(),
    };
    // SAFETY: `desc` points to NUL-terminated UTF-16 `desc_wide` across synchronous call.
    let _desc_ok = unsafe {
        ChangeServiceConfig2W(
            svc.as_raw(),
            SERVICE_CONFIG_DESCRIPTION,
            (&raw mut desc).cast::<c_void>(),
        )
    };

    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 10_000,
        },
    ];
    let mut failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: 3,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: `failure_actions` and `actions` stack array remain valid for synchronous call.
    let _fa_ok = unsafe {
        ChangeServiceConfig2W(
            svc.as_raw(),
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&raw mut failure_actions).cast::<c_void>(),
        )
    };

    let mut fa_flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: 1,
    };
    // SAFETY: `fa_flag` is valid stack storage.
    let _flag_ok = unsafe {
        ChangeServiceConfig2W(
            svc.as_raw(),
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&raw mut fa_flag).cast::<c_void>(),
        )
    };

    // SAFETY: Starts `svc` with zero service arguments.
    let start_ok = unsafe { StartServiceW(svc.as_raw(), 0, ptr::null()) };
    if start_ok == 0 {
        let start_err = io::Error::last_os_error();
        if start_err.raw_os_error()
            != Some(i32::try_from(ERROR_SERVICE_ALREADY_RUNNING).unwrap_or(1056))
        {
            return Err(map_win_io_error(OP, start_err));
        }
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let st = query_service_process_status(svc.as_raw(), OP)?;
        if st.dwCurrentState == SERVICE_RUNNING {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for Windows service to reach RUNNING state",
                ),
            ));
        }
        win_sleep_ms(200);
    }
}

/// Stops `service_name` gracefully (up to 10s) and optionally deletes its SCM registration.
pub fn stop_and_optionally_delete_windows_service(
    service_name: &str,
    delete: bool,
) -> SysResult<()> {
    const OP: &str = "gui_windows::stop_and_optionally_delete_windows_service";
    const DELETE_RIGHT: u32 = 0x0001_0000;
    let svc_wide = encode_wide_nul_str(service_name, OP)?;
    // SAFETY: Opens local SCM for service stop/delete control.
    let raw_scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    let Some(scm) = OwnedScHandle::from_raw(raw_scm) else {
        return Err(map_win_io_error(OP, io::Error::last_os_error()));
    };

    let access = SERVICE_STOP | SERVICE_QUERY_STATUS | if delete { DELETE_RIGHT } else { 0 };
    // SAFETY: `svc_wide` is NUL-terminated UTF-16.
    let raw_svc = unsafe { OpenServiceW(scm.as_raw(), svc_wide.as_ptr(), access) };
    let Some(svc) = OwnedScHandle::from_raw(raw_svc) else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(WIN_ERROR_SERVICE_DOES_NOT_EXIST) {
            return Ok(());
        }
        return Err(map_win_io_error(OP, err));
    };

    let initial = query_service_process_status(svc.as_raw(), OP)?;
    if initial.dwCurrentState != SERVICE_STOPPED {
        // SAFETY: `SERVICE_STATUS` is POD zeroed before `ControlService`.
        let mut ctrl_status: SERVICE_STATUS = unsafe { mem::zeroed() };
        // SAFETY: Requests graceful service stop via SCM.
        let _stopped =
            unsafe { ControlService(svc.as_raw(), SERVICE_CONTROL_STOP, &raw mut ctrl_status) };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let st = query_service_process_status(svc.as_raw(), OP)?;
            if st.dwCurrentState == SERVICE_STOPPED {
                break;
            }
            if Instant::now() >= deadline {
                return Err(SysError::io(
                    OP,
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for Windows service to stop",
                    ),
                ));
            }
            win_sleep_ms(200);
        }
    }

    if delete {
        // SAFETY: Service handle was opened with `DELETE` permission.
        let del_ok = unsafe { DeleteService(svc.as_raw()) };
        if del_ok == 0 {
            let err = io::Error::last_os_error();
            // ERROR_SERVICE_MARKED_FOR_DELETE (1072) is idempotent success.
            if err.raw_os_error() != Some(1072) {
                return Err(map_win_io_error(OP, err));
            }
        }
    }
    Ok(())
}

/// Applies an explicit protected SDDL DACL onto an existing directory (`ADR-026`, `US-106`).
pub fn set_directory_sddl_acl(dir_path: &Path, sddl: &str) -> SysResult<()> {
    const OP: &str = "gui_windows::set_directory_sddl_acl";
    fs::create_dir_all(dir_path).map_err(|err| map_win_io_error(OP, err))?;
    let sddl_wide = encode_wide_nul_str(sddl, OP)?;
    let mut path_wide = encode_wide_nul_os(dir_path.as_os_str(), OP)?;

    let mut sd_ptr: *mut c_void = ptr::null_mut();
    // SAFETY: `sddl_wide` is NUL-terminated UTF-16 and `sd_ptr` receives a `LocalAlloc` SD.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd_ptr,
            ptr::null_mut(),
        )
    };
    if ok == 0 || sd_ptr.is_null() {
        return Err(map_win_io_error(OP, io::Error::last_os_error()));
    }
    let _sd_guard = LocalAllocGuard(sd_ptr);

    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut p_dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `sd_ptr` is a valid security descriptor owned by `_sd_guard`.
    let got_dacl = unsafe {
        GetSecurityDescriptorDacl(
            sd_ptr,
            &raw mut dacl_present,
            &raw mut p_dacl,
            &raw mut dacl_defaulted,
        )
    };
    if got_dacl == 0 || dacl_present == 0 || p_dacl.is_null() {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }

    // SAFETY: `path_wide` is NUL-terminated UTF-16 and `p_dacl` points inside live `_sd_guard`.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            p_dacl,
            ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(map_win_status(OP, rc));
    }
    Ok(())
}

/// Schedules a locked executable binary for deletion on next reboot
/// (`MOVEFILE_DELAY_UNTIL_REBOOT`).
pub fn schedule_delete_on_reboot(path: &Path) -> SysResult<()> {
    const OP: &str = "gui_windows::schedule_delete_on_reboot";
    let wide = encode_wide_nul_os(path.as_os_str(), OP)?;
    // SAFETY: `wide` is NUL-terminated UTF-16; `lpNewFileName = null` with
    // `MOVEFILE_DELAY_UNTIL_REBOOT` queues file removal on next reboot.
    let ok = unsafe { MoveFileExW(wide.as_ptr(), ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
    if ok == 0 {
        return Err(map_win_io_error(OP, io::Error::last_os_error()));
    }
    Ok(())
}

/// Creates a 16x16 / 32x32..=256x256 bitmap `HICON` in RAM representing `kind` without external
/// `.rc`/`.res`.
pub fn create_tray_status_icon(kind: TrayStatusIconKind, size_px: i32) -> SysResult<OwnedIcon> {
    let clamped = size_px.clamp(16, 256);
    let bgra = render_badge_bgra(kind, clamped);
    create_tray_status_icon_from_bgra(clamped, clamped, &bgra)
}

/// Creates an `OwnedIcon` directly from a caller-supplied 32-bit BGRA pixel buffer.
pub fn create_tray_status_icon_from_bgra(
    width: i32,
    height: i32,
    bgra_pixels: &[u8],
) -> SysResult<OwnedIcon> {
    const OP: &str = "gui_windows::create_tray_status_icon_from_bgra";
    let expected_len = usize::try_from(width.max(1))
        .unwrap_or(16)
        .saturating_mul(usize::try_from(height.max(1)).unwrap_or(16))
        .saturating_mul(4);
    if width <= 0 || height <= 0 || bgra_pixels.len() != expected_len {
        return Err(SysError::io(
            OP,
            io::Error::new(io::ErrorKind::InvalidInput, "invalid icon BGRA dimensions"),
        ));
    }

    // SAFETY: `CreateBitmap` copies `bgra_pixels` synchronously into a 32-bpp GDI color bitmap.
    let color_bmp_raw =
        unsafe { CreateBitmap(width, height, 1, 32, bgra_pixels.as_ptr().cast::<c_void>()) };
    let Some(color_bmp) = OwnedGdiObj::from_raw(color_bmp_raw) else {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    };

    let mask_stride = ((width + 15) / 16) * 2;
    let mask_len = usize::try_from(mask_stride)
        .unwrap_or(2)
        .saturating_mul(usize::try_from(height).unwrap_or(16));
    let mask_bytes = vec![0_u8; mask_len];
    // SAFETY: `CreateBitmap` allocates a 1-bpp mask bitmap of zeros (alpha comes from 32-bpp DIB).
    let mask_bmp_raw = unsafe { CreateBitmap(width, height, 1, 1, mask_bytes.as_ptr().cast()) };
    let Some(mask_bmp) = OwnedGdiObj::from_raw(mask_bmp_raw) else {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    };

    let info = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask_bmp.as_raw(),
        hbmColor: color_bmp.as_raw(),
    };
    // SAFETY: `info` references two valid GDI bitmaps owned by `mask_bmp` and `color_bmp`.
    let raw_icon = unsafe { CreateIconIndirect(&raw const info) };
    OwnedIcon::from_raw(raw_icon).ok_or_else(|| SysError::io(OP, io::Error::last_os_error()))
}

/// Registers the `"TaskbarCreated"` broadcast message ID for Explorer-restart tray recovery.
pub fn register_taskbar_created_message() -> SysResult<u32> {
    const OP: &str = "gui_windows::register_taskbar_created_message";
    let wide = encode_wide_nul_str("TaskbarCreated", OP)?;
    // SAFETY: `wide` is a NUL-terminated UTF-16 message identifier.
    let msg = unsafe { RegisterWindowMessageW(wide.as_ptr()) };
    if msg == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    Ok(msg)
}

/// Shows the Win32 Tray popup menu at the cursor position and returns the chosen command ID.
pub fn show_tray_context_menu(hwnd: isize, entries: &[TrayMenuEntry]) -> SysResult<Option<u16>> {
    const OP: &str = "gui_windows::show_tray_context_menu";
    let mut owned_submenus = Vec::new();
    let root = build_popup_menu(entries, &mut owned_submenus, OP)?;

    let mut pt = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
    // SAFETY: `pt` is writable stack storage.
    let got_pos = unsafe { GetCursorPos(&raw mut pt) };
    if got_pos == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }

    let target = hwnd as HWND;
    // SAFETY: `SetForegroundWindow` ensures the menu dismisses cleanly when clicking elsewhere.
    let _fg = unsafe { SetForegroundWindow(target) };
    // SAFETY: `root` is a valid `HMENU`, `target` owns the menu loop, and `TPM_RETURNCMD` returns
    // the chosen item ID synchronously.
    let cmd = unsafe {
        TrackPopupMenuEx(
            root.as_raw(),
            TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
            pt.x,
            pt.y,
            target,
            ptr::null(),
        )
    };
    // SAFETY: Microsoft KB135788 workaround posting `WM_NULL` so menu closes cleanly.
    let _null_post = unsafe { PostMessageW(target, 0, 0, 0) };
    drop(owned_submenus);
    drop(root);

    if cmd <= 0 {
        Ok(None)
    } else {
        Ok(u16::try_from(cmd).ok())
    }
}

/// Displays a modal Win32 message box (`Info`, `Warning`, `Error`, or `ConfirmYesNo`).
pub fn show_message_box(hwnd: isize, title: &str, text: &str, kind: MessageBoxKind) -> bool {
    let Ok(title_w) = encode_wide_nul_str(title, "show_message_box") else {
        return false;
    };
    let Ok(text_w) = encode_wide_nul_str(text, "show_message_box") else {
        return false;
    };
    let flags = match kind {
        MessageBoxKind::Info => MB_OK | MB_ICONINFORMATION,
        MessageBoxKind::Warning => MB_OK | MB_ICONWARNING,
        MessageBoxKind::Error => MB_OK | MB_ICONERROR,
        MessageBoxKind::ConfirmYesNo => MB_YESNO | MB_ICONWARNING,
    };
    // SAFETY: `title_w` and `text_w` are NUL-terminated UTF-16 buffers kept alive during the call.
    let res = unsafe { MessageBoxW(hwnd as HWND, text_w.as_ptr(), title_w.as_ptr(), flags) };
    match kind {
        MessageBoxKind::ConfirmYesNo => res == IDYES,
        _ => true,
    }
}

struct WindowBridge<'a> {
    handler: *const (dyn WindowEventHandler + 'a),
    activate_msg: u32,
    taskbar_created_msg: u32,
    claimed_by_hwnd: *const Cell<bool>,
}

/// Registers the Win32 window class, creates the main Dashboard window, and runs the message loop.
pub fn run_gui_window(spec: GuiWindowSpec<'_>, handler: &dyn WindowEventHandler) -> SysResult<()> {
    const OP: &str = "gui_windows::run_gui_window";
    let class_wide = encode_wide_nul_str(spec.class_name, OP)?;
    let title_wide = encode_wide_nul_str(spec.title, OP)?;

    // SAFETY: `GetModuleHandleW(null)` returns the current executable's `HINSTANCE`.
    let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
    // SAFETY: `LoadCursorW(null, IDC_ARROW)` loads a standard shared arrow cursor.
    let cursor = unsafe { LoadCursorW(ptr::null_mut(), IDC_ARROW) };
    let wnd_cls = WNDCLASSEXW {
        cbSize: u32::try_from(size_of::<WNDCLASSEXW>()).unwrap_or(0),
        style: 0,
        lpfnWndProc: Some(gui_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: spec.initial_icon.map_or(ptr::null_mut(), OwnedIcon::as_raw),
        hCursor: cursor,
        hbrBackground: ((COLOR_BTNFACE + 1) as usize) as HBRUSH,
        lpszMenuName: ptr::null(),
        lpszClassName: class_wide.as_ptr(),
        hIconSm: spec.initial_icon.map_or(ptr::null_mut(), OwnedIcon::as_raw),
    };

    // SAFETY: `wnd_cls` references live `class_wide` and valid static `gui_wnd_proc`.
    let atom = unsafe { RegisterClassExW(&raw const wnd_cls) };
    if atom == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }

    let bridge_claimed = Cell::new(false);
    let bridge = Box::new(WindowBridge {
        handler: std::ptr::from_ref(handler),
        activate_msg: spec.activate_msg,
        taskbar_created_msg: spec.taskbar_created_msg,
        claimed_by_hwnd: &raw const bridge_claimed,
    });
    let bridge_ptr = Box::into_raw(bridge);

    // SAFETY: `class_wide` and `title_wide` are NUL-terminated UTF-16 strings; `bridge_ptr` is
    // transferred to `WM_NCCREATE` and reclaimed on `WM_NCDESTROY` (or below if `CreateWindowExW`
    // fails before `WM_NCCREATE` sets `bridge_claimed`).
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class_wide.as_ptr(),
            title_wide.as_ptr(),
            MAIN_WINDOW_STYLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            spec.width_96dpi,
            spec.height_96dpi,
            ptr::null_mut(),
            ptr::null_mut(),
            hinstance,
            bridge_ptr.cast::<c_void>(),
        )
    };
    if hwnd.is_null() {
        let err = io::Error::last_os_error();
        if !bridge_claimed.get() {
            // SAFETY: `CreateWindowExW` failed before `WM_NCCREATE` attached `bridge_ptr` to
            // `GWLP_USERDATA`, so `WM_NCDESTROY` did not run and `bridge_ptr` remains owned here.
            let _reclaimed = unsafe { Box::from_raw(bridge_ptr) };
        }
        return Err(SysError::io(OP, err));
    }

    let show_cmd = if spec.start_hidden {
        SW_HIDE
    } else {
        SW_SHOWNORMAL
    };
    // SAFETY: `hwnd` is a valid newly created window on this thread.
    let _shown = unsafe { ShowWindow(hwnd, show_cmd) };
    // SAFETY: `hwnd` is a valid newly created window on this thread.
    let _updated = unsafe { UpdateWindow(hwnd) };
    if !spec.start_hidden {
        // SAFETY: Brings the newly opened Dashboard window to foreground focus.
        let _fg = unsafe { SetForegroundWindow(hwnd) };
    }

    // SAFETY: `MSG` is a plain Win32 C struct zero-initialized before `GetMessageW`.
    let mut msg: MSG = unsafe { mem::zeroed() };
    loop {
        // SAFETY: `GetMessageW` writes the next queued thread message into stack `msg`.
        let status = unsafe { GetMessageW(&raw mut msg, ptr::null_mut(), 0, 0) };
        if status <= 0 {
            break;
        }
        if msg.message == WM_KEYDOWN && msg.wParam == usize::from(b'V') && is_ctrl_down() {
            let focused_id = get_focused_control_id();
            handler.on_ctrl_v(hwnd as isize, focused_id);
        }
        // SAFETY: `IsDialogMessageW` implements Tab/Shift+Tab keyboard navigation across controls.
        let handled = unsafe { IsDialogMessageW(hwnd, &raw const msg) };
        if handled == 0 {
            // SAFETY: Dispatches normal window messages through `gui_wnd_proc`.
            unsafe {
                let _translated = TranslateMessage(&raw const msg);
                let _dispatched = DispatchMessageW(&raw const msg);
            }
        }
    }
    Ok(())
}

// SAFETY: Win32 window procedure invoked synchronously by Windows message dispatch on the GUI
// thread with a valid `HWND`; `GWLP_USERDATA` holds either null or a live `WindowBridge` pointer.
unsafe extern "system" fn gui_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_NCCREATE {
        let cs_ptr = lparam as *const CREATESTRUCTW;
        if !cs_ptr.is_null() {
            // SAFETY: `lparam` on `WM_NCCREATE` points to a valid `CREATESTRUCTW`.
            let lp = unsafe { (*cs_ptr).lpCreateParams };
            let bridge_ptr = lp.cast::<WindowBridge<'_>>();
            if !bridge_ptr.is_null() {
                // SAFETY: `bridge_ptr` points to the live `WindowBridge` allocated in
                // `run_gui_window` on this UI thread, and `claimed_by_hwnd` stays on its stack.
                unsafe {
                    (*(*bridge_ptr).claimed_by_hwnd).set(true);
                }
            }
            // SAFETY: Associates `WindowBridge` raw pointer with `hwnd` user data.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, lp as isize) };
        }
        // SAFETY: Standard default `WM_NCCREATE` processing.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    }

    // SAFETY: Reads `WindowBridge` pointer stored in `GWLP_USERDATA`.
    let raw_bridge = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut WindowBridge<'_>;
    if msg == WM_NCDESTROY {
        if !raw_bridge.is_null() {
            // SAFETY: Clear pointer before freeing the boxed `WindowBridge`.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
            // SAFETY: `raw_bridge` was allocated via `Box::into_raw` in `run_gui_window`.
            let _dropped = unsafe { Box::from_raw(raw_bridge) };
        }
        // SAFETY: Standard default `WM_NCDESTROY` processing.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    }

    if raw_bridge.is_null() {
        // SAFETY: `WindowBridge` is not yet attached or already torn down.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    }

    // SAFETY: `raw_bridge` lives from `WM_NCCREATE` until `WM_NCDESTROY`, and `handler`
    // outlives `run_gui_window`.
    let bridge = unsafe { &*raw_bridge };
    // SAFETY: `bridge.handler` is a shared `&dyn WindowEventHandler` pointing to the live handler.
    let handler = unsafe { &*bridge.handler };

    if msg == bridge.taskbar_created_msg && bridge.taskbar_created_msg != 0 {
        handler.on_taskbar_created(hwnd as isize);
        return 0;
    }
    if msg == bridge.activate_msg && bridge.activate_msg != 0 {
        handler.on_activate_requested(hwnd as isize);
        return 0;
    }

    match msg {
        WM_CREATE => {
            handler.on_create(hwnd as isize);
            0
        }
        WM_COMMAND => {
            let ctrl_id = u16::try_from(wparam & 0xffff).unwrap_or(0);
            let notify_code = u16::try_from((wparam >> 16) & 0xffff).unwrap_or(0);
            handler.on_command(hwnd as isize, ctrl_id, notify_code);
            0
        }
        WM_TIMER => {
            handler.on_timer(hwnd as isize, wparam);
            0
        }
        WM_APP_TRAY_CALLBACK => {
            let event_msg = u32::try_from(lparam & 0xffff).unwrap_or(0);
            if matches!(event_msg, WM_LBUTTONUP | WM_LBUTTONDBLCLK | WM_RBUTTONUP) {
                handler.on_tray_callback(hwnd as isize, event_msg);
            }
            0
        }
        WM_APP_GRACEFUL_SHUTDOWN => {
            handler.on_graceful_shutdown(hwnd as isize);
            0
        }
        WM_APP_QUERY_VERSION => handler.on_query_version(),
        WM_APP_STATE_REFRESH
        | WM_APP_WORKER_DONE
        | WM_APP_NETCHECK_DONE
        | WM_APP_PING_DONE
        | WM_APP_BUGREPORT_DONE => {
            handler.on_app_message(hwnd as isize, msg, wparam, lparam);
            0
        }
        WM_DPICHANGED => {
            let new_dpi = u32::try_from(wparam & 0xffff).unwrap_or(96);
            let suggested_ptr = lparam as *const RECT;
            if !suggested_ptr.is_null() {
                // SAFETY: `lparam` on `WM_DPICHANGED` points to a valid `RECT`.
                let rc = unsafe { &*suggested_ptr };
                // SAFETY: Moves window cleanly to Windows-recommended DPI-scaled rect.
                let _moved = unsafe {
                    SetWindowPos(
                        hwnd,
                        ptr::null_mut(),
                        rc.left,
                        rc.top,
                        rc.right - rc.left,
                        rc.bottom - rc.top,
                        0x0014, // SWP_NOZORDER | SWP_NOACTIVATE
                    )
                };
            }
            handler.on_dpi_changed(hwnd as isize, new_dpi);
            0
        }
        WM_SIZE => {
            let width = i32::from(i16::try_from(lparam & 0xffff).unwrap_or(0));
            let height = i32::from(i16::try_from((lparam >> 16) & 0xffff).unwrap_or(0));
            handler.on_resize(hwnd as isize, width, height);
            0
        }
        WM_SETTINGCHANGE | WM_THEMECHANGED => {
            handler.on_theme_changed(hwnd as isize);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX | WM_CTLCOLORBTN => {
            let brush = handler.on_ctlcolor(hwnd as isize, wparam as isize, lparam, msg);
            if brush != 0 {
                brush
            } else {
                // SAFETY: Standard Win32 default control color fallback.
                unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
            }
        }
        WM_ERASEBKGND => {
            if handler.on_erase_bkgnd(hwnd as isize, wparam as isize) {
                1
            } else {
                // SAFETY: Standard Win32 default background erase fallback.
                unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
            }
        }
        WM_PAINT => {
            if handler.on_paint(hwnd as isize) {
                0
            } else {
                // SAFETY: Standard Win32 default paint fallback.
                unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
            }
        }
        WM_DRAWITEM => {
            let dis_ptr = lparam as *const DRAWITEMSTRUCT;
            if !dis_ptr.is_null() {
                // SAFETY: `lparam` on `WM_DRAWITEM` points to a valid `DRAWITEMSTRUCT`.
                let dis = unsafe { &*dis_ptr };
                let item = OwnerDrawItem {
                    control_id: u16::try_from(dis.CtlID).unwrap_or(0),
                    hdc: dis.hDC as isize,
                    rect: ControlRect::new(
                        dis.rcItem.left,
                        dis.rcItem.top,
                        dis.rcItem.right.saturating_sub(dis.rcItem.left),
                        dis.rcItem.bottom.saturating_sub(dis.rcItem.top),
                    ),
                    item_state: dis.itemState,
                    hwnd_item: dis.hwndItem as isize,
                };
                if handler.on_draw_item(hwnd as isize, &item) {
                    return 1;
                }
            }
            // SAFETY: Standard Win32 default owner-draw fallback.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_QUERYENDSESSION => {
            handler.on_graceful_shutdown(hwnd as isize);
            1
        }
        WM_ENDSESSION => {
            if wparam != 0 {
                handler.on_graceful_shutdown(hwnd as isize);
            }
            0
        }
        WM_CLOSE => {
            if handler.on_close(hwnd as isize) {
                return 0;
            }
            // SAFETY: Default close processing destroys the window when `on_close` returns `false`.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        WM_DESTROY => {
            handler.on_destroy(hwnd as isize);
            // SAFETY: Exits the thread's `GetMessageW` loop cleanly.
            unsafe { PostQuitMessage(0) };
            0
        }
        // SAFETY: Standard Win32 default window procedure fallback.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Creates a Win32 static text label (`SS_LEFT | SS_NOPREFIX`).
/// Position and size of a Win32 child control in physical window pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRect {
    /// Horizontal position in client coordinates.
    pub x: i32,
    /// Vertical position in client coordinates.
    pub y: i32,
    /// Width in pixels.
    pub w: i32,
    /// Height in pixels.
    pub h: i32,
}

impl ControlRect {
    /// Constructs a child control bounding rectangle.
    #[must_use]
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }
}

/// Creates a Win32 static label control (`SS_LEFT | SS_NOPREFIX`).
pub fn create_static_text(
    parent: isize,
    id: u16,
    text: &str,
    rect: ControlRect,
) -> SysResult<isize> {
    create_child_control(ChildControlSpec {
        parent,
        class_name: "STATIC",
        text,
        style: WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Creates a Win32 push button (`WS_TABSTOP | BS_PUSHBUTTON` or `BS_DEFPUSHBUTTON`).
pub fn create_button(
    parent: isize,
    id: u16,
    text: &str,
    rect: ControlRect,
    is_default: bool,
) -> SysResult<isize> {
    let style = WS_CHILD
        | WS_VISIBLE
        | WS_TABSTOP
        | u32::try_from(if is_default {
            BS_DEFPUSHBUTTON
        } else {
            BS_PUSHBUTTON
        })
        .unwrap_or(0);
    create_child_control(ChildControlSpec {
        parent,
        class_name: "BUTTON",
        text,
        style,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Creates a Win32 owner-drawn push button (`WS_TABSTOP | BS_OWNERDRAW`) for Dark Mode CTAs,
/// navigation tabs, and peer filter chips (`ADR-027`).
pub fn create_owner_draw_button(
    parent: isize,
    id: u16,
    text: &str,
    rect: ControlRect,
) -> SysResult<isize> {
    let style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | u32::try_from(BS_OWNERDRAW).unwrap_or(0);
    create_child_control(ChildControlSpec {
        parent,
        class_name: "BUTTON",
        text,
        style,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Creates a Win32 auto-checkbox (`WS_TABSTOP | BS_AUTOCHECKBOX`).
pub fn create_checkbox(parent: isize, id: u16, text: &str, rect: ControlRect) -> SysResult<isize> {
    let style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | u32::try_from(BS_AUTOCHECKBOX).unwrap_or(0);
    create_child_control(ChildControlSpec {
        parent,
        class_name: "BUTTON",
        text,
        style,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Creates a Win32 auto-radio button (`WS_TABSTOP | BS_AUTORADIOBUTTON`).
pub fn create_radio_button(
    parent: isize,
    id: u16,
    text: &str,
    rect: ControlRect,
    group_start: bool,
) -> SysResult<isize> {
    let mut style =
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | u32::try_from(BS_AUTORADIOBUTTON).unwrap_or(0);
    if group_start {
        style |= WS_GROUP;
    }
    create_child_control(ChildControlSpec {
        parent,
        class_name: "BUTTON",
        text,
        style,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Creates a Win32 edit control (supporting `ES_PASSWORD` and multiline read-only log/detail box).
pub fn create_edit(
    parent: isize,
    id: u16,
    text: &str,
    rect: ControlRect,
    password: bool,
    multiline_readonly: bool,
) -> SysResult<isize> {
    let mut style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP;
    if multiline_readonly {
        style |=
            u32::try_from(ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY).unwrap_or(0) | WS_VSCROLL;
    } else {
        style |= u32::try_from(ES_AUTOHSCROLL).unwrap_or(0);
        if password {
            style |= u32::try_from(ES_PASSWORD).unwrap_or(0);
        }
    }
    create_child_control(ChildControlSpec {
        parent,
        class_name: "EDIT",
        text,
        style,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Creates a Win32 list box (`LBS_NOTIFY | WS_VSCROLL | WS_BORDER | WS_TABSTOP`).
pub fn create_listbox(parent: isize, id: u16, rect: ControlRect) -> SysResult<isize> {
    let style = WS_CHILD
        | WS_VISIBLE
        | WS_BORDER
        | WS_TABSTOP
        | WS_VSCROLL
        | u32::try_from(LBS_NOTIFY).unwrap_or(0);
    create_child_control(ChildControlSpec {
        parent,
        class_name: "LISTBOX",
        text: "",
        style,
        ex_style: 0,
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
        id,
    })
}

/// Moves and resizes a Win32 child control.
pub fn set_control_bounds(ctrl: isize, x: i32, y: i32, w: i32, h: i32) {
    // SAFETY: `MoveWindow` safely repositions an existing child `HWND`.
    let _moved = unsafe { MoveWindow(ctrl as HWND, x, y, w.max(1), h.max(1), 1) };
}

/// Sets the text of a Win32 control (`SetWindowTextW`).
pub fn set_control_text(ctrl: isize, text: &str) {
    if let Ok(wide) = encode_wide_nul_str(text, "set_control_text") {
        // SAFETY: `wide` is NUL-terminated UTF-16 kept alive across `SetWindowTextW`.
        let _set = unsafe { SetWindowTextW(ctrl as HWND, wide.as_ptr()) };
    }
}

/// Reads the current text from a Win32 edit/control (`GetWindowTextW`).
#[must_use]
pub fn get_control_text(ctrl: isize) -> String {
    let hwnd = ctrl as HWND;
    // SAFETY: Queries UTF-16 length of control text.
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len <= 0 {
        return String::new();
    }
    let cap = usize::try_from(len).unwrap_or(0).saturating_add(1);
    let mut buf = vec![0_u16; cap];
    let max_count = i32::try_from(buf.len()).unwrap_or(i32::MAX);
    // SAFETY: `buf` holds `max_count` writable UTF-16 units.
    let copied = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), max_count) };
    let used = usize::try_from(copied.max(0)).unwrap_or(0).min(buf.len());
    String::from_utf16_lossy(buf.get(..used).unwrap_or(&[]))
}

/// Shows or hides a Win32 child control (`ShowWindow`).
pub fn set_control_visible(ctrl: isize, visible: bool) {
    // SAFETY: `ShowWindow` updates visibility of child `HWND`.
    let _shown = unsafe { ShowWindow(ctrl as HWND, if visible { SW_SHOW } else { SW_HIDE }) };
}

/// Enables or disables a Win32 child control (`EnableWindow`).
pub fn set_control_enabled(ctrl: isize, enabled: bool) {
    // SAFETY: `EnableWindow` safely updates interactive state of child `HWND`.
    let _prev = unsafe { EnableWindow(ctrl as HWND, i32::from(enabled)) };
}

/// Reads checkbox / radio button check state (`BM_GETCHECK`).
#[must_use]
pub fn get_checkbox_checked(ctrl: isize) -> bool {
    // SAFETY: Sends standard `BM_GETCHECK` to a `BUTTON` child control.
    let res = unsafe { SendMessageW(ctrl as HWND, BM_GETCHECK, 0, 0) };
    res == isize::try_from(BST_CHECKED_VAL).unwrap_or(1)
}

/// Sets checkbox / radio button check state (`BM_SETCHECK`).
pub fn set_checkbox_checked(ctrl: isize, checked: bool) {
    let val = if checked {
        BST_CHECKED_VAL
    } else {
        BST_UNCHECKED_VAL
    };
    // SAFETY: Sends standard `BM_SETCHECK` to a `BUTTON` child control.
    let _res = unsafe { SendMessageW(ctrl as HWND, BM_SETCHECK, val, 0) };
}

/// Replaces all entries in a Win32 `LISTBOX` control and preserves/applies selection.
pub fn listbox_reset_and_fill(ctrl: isize, items: &[String], selected_idx: Option<usize>) {
    let hwnd = ctrl as HWND;
    // SAFETY: Clears existing items from a `LISTBOX` child control.
    let _reset = unsafe { SendMessageW(hwnd, LB_RESETCONTENT, 0, 0) };
    for item in items {
        if let Ok(wide) = encode_wide_nul_str(item, "listbox_add") {
            // SAFETY: `wide` is NUL-terminated UTF-16 copied synchronously by `LB_ADDSTRING`.
            let _idx = unsafe { SendMessageW(hwnd, LB_ADDSTRING, 0, wide.as_ptr() as isize) };
        }
    }
    if let Some(idx) = selected_idx
        && idx < items.len()
    {
        // SAFETY: `idx` was checked `< items.len()`.
        let _sel = unsafe { SendMessageW(hwnd, LB_SETCURSEL, idx, 0) };
    }
}

/// Returns the selected zero-based index in a Win32 `LISTBOX`, if any.
#[must_use]
pub fn listbox_selected_index(ctrl: isize) -> Option<usize> {
    // SAFETY: Queries current selection from a `LISTBOX` control.
    let res = unsafe { SendMessageW(ctrl as HWND, LB_GETCURSEL, 0, 0) };
    if res < 0 {
        None
    } else {
        usize::try_from(res).ok()
    }
}

/// Applies an `OwnedGdiObj` (`HFONT`) to a Win32 child control (`WM_SETFONT`).
pub fn set_control_font(ctrl: isize, font: &OwnedGdiObj) {
    // SAFETY: `font.as_raw()` is a live `HFONT` owned by caller.
    let _res = unsafe { SendMessageW(ctrl as HWND, WM_SETFONT, font.as_raw() as usize, 1) };
}

/// Moves keyboard focus to `ctrl` (`SetFocus`).
pub fn set_focus_control(ctrl: isize) {
    // SAFETY: Transfers keyboard focus to a valid control `HWND`.
    let _prev = unsafe { SetFocus(ctrl as HWND) };
}

/// Creates a crisp DPI-scaled Segoe UI / message font for the given window DPI.
pub fn create_dpi_ui_font(dpi: u32) -> SysResult<OwnedGdiObj> {
    const OP: &str = "gui_windows::create_dpi_ui_font";
    let safe_dpi = dpi.max(72);
    // SAFETY: `NONCLIENTMETRICSW` is POD zeroed before setting `cbSize`.
    let mut ncm: NONCLIENTMETRICSW = unsafe { mem::zeroed() };
    ncm.cbSize = u32::try_from(size_of::<NONCLIENTMETRICSW>()).unwrap_or(0);
    // SAFETY: `ncm` is writable stack storage matching `ncm.cbSize`.
    let spi_ok = unsafe {
        SystemParametersInfoForDpi(
            SPI_GETNONCLIENTMETRICS,
            ncm.cbSize,
            (&raw mut ncm).cast::<c_void>(),
            0,
            safe_dpi,
        )
    };
    if spi_ok != 0 {
        // SAFETY: `ncm.lfMessageFont` was populated by `SystemParametersInfoForDpi`.
        let raw_font = unsafe { CreateFontIndirectW(&raw const ncm.lfMessageFont) };
        if let Some(owned) = OwnedGdiObj::from_raw(raw_font.cast::<c_void>()) {
            return Ok(owned);
        }
    }

    let height = -(i32::try_from((14 * safe_dpi) / 96).unwrap_or(14).max(12));
    let face = encode_wide_nul_str("Segoe UI", OP)?;
    // SAFETY: `face` is NUL-terminated UTF-16 `"Segoe UI"`.
    let fallback =
        unsafe { CreateFontW(height, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, face.as_ptr()) };
    OwnedGdiObj::from_raw(fallback.cast::<c_void>())
        .ok_or_else(|| SysError::io(OP, io::Error::last_os_error()))
}

/// Queries current DPI for `hwnd` (`GetDpiForWindow`, falling back to `96`).
#[must_use]
pub fn get_dpi_for_window(hwnd: isize) -> u32 {
    // SAFETY: `GetDpiForWindow` returns `0` if `hwnd` is invalid or pre-Win10-1607.
    let dpi = unsafe { GetDpiForWindow(hwnd as HWND) };
    if dpi == 0 { 96 } else { dpi }
}

/// Queries recommended small icon size in pixels for `dpi` (`GetSystemMetricsForDpi(SM_CXSMICON)`).
#[must_use]
pub fn get_sm_icon_px_for_dpi(dpi: u32) -> i32 {
    // SAFETY: Pure system metric query for `SM_CXSMICON` at `dpi`.
    let px = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi.max(72)) };
    if px <= 0 {
        (16 * i32::try_from(dpi.max(72)).unwrap_or(96)) / 96
    } else {
        px.clamp(16, 256)
    }
}

/// Returns the client area `(width, height)` of `hwnd`.
#[must_use]
pub fn get_client_size(hwnd: isize) -> (i32, i32) {
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: `rc` is valid writable stack storage.
    let ok = unsafe { GetClientRect(hwnd as HWND, &raw mut rc) };
    if ok == 0 {
        (0, 0)
    } else {
        ((rc.right - rc.left).max(0), (rc.bottom - rc.top).max(0))
    }
}

/// Restores, shows, and brings `hwnd` to foreground focus.
pub fn show_window_and_focus(hwnd: isize) {
    let target = hwnd as HWND;
    // SAFETY: `target` is the live top-level Dashboard `HWND`.
    unsafe {
        let _shown = ShowWindow(target, SW_RESTORE);
        let _fg = SetForegroundWindow(target);
    }
}

/// Hides `hwnd` cleanly to the System Tray (`ShowWindow(SW_HIDE)`).
pub fn hide_window(hwnd: isize) {
    // SAFETY: `hwnd` is the live top-level Dashboard `HWND`.
    let _hidden = unsafe { ShowWindow(hwnd as HWND, SW_HIDE) };
}

/// Destroys `hwnd`, triggering `WM_DESTROY` and `PostQuitMessage(0)`.
pub fn destroy_window(hwnd: isize) {
    // SAFETY: Destroys the main window on the thread that created it.
    let _destroyed = unsafe { DestroyWindow(hwnd as HWND) };
}

/// Assigns `icon` as both small and large window icon for `hwnd`.
pub fn set_window_icon(hwnd: isize, icon: &OwnedIcon) {
    let target = hwnd as HWND;
    let raw = icon.as_raw() as isize;
    // SAFETY: `raw` is a live `HICON` owned by caller.
    unsafe {
        let _sm = SendMessageW(
            target,
            WM_SETICON,
            usize::try_from(ICON_SMALL).unwrap_or(0),
            raw,
        );
        let _bg = SendMessageW(
            target,
            WM_SETICON,
            usize::try_from(ICON_BIG).unwrap_or(1),
            raw,
        );
    }
}

/// Installs or replaces a Win32 timer on `hwnd`.
pub fn set_window_timer(hwnd: isize, timer_id: usize, interval_ms: u32) {
    // SAFETY: Schedules a `WM_TIMER` notification on `hwnd`.
    let _res = unsafe { SetTimer(hwnd as HWND, timer_id, interval_ms, None) };
}

/// Cancels a previously installed Win32 timer on `hwnd`.
pub fn kill_window_timer(hwnd: isize, timer_id: usize) {
    // SAFETY: Cancels `timer_id` associated with `hwnd`.
    let _res = unsafe { KillTimer(hwnd as HWND, timer_id) };
}

/// Posts a custom `WM_APP_*` notification safely from any background thread to `hwnd`.
pub fn post_app_message(hwnd: isize, msg: u32, wparam: usize, lparam: isize) {
    if hwnd == 0 {
        return;
    }
    // SAFETY: `PostMessageW` is explicitly thread-safe across threads for a valid `HWND`.
    let _posted = unsafe { PostMessageW(hwnd as HWND, msg, wparam, lparam) };
}

/// Creates a memory DC compatible with `hdc` and a sized off-screen bitmap `(width, height)`.
#[must_use]
pub fn create_double_buffer(
    hdc: isize,
    width: i32,
    height: i32,
) -> Option<(OwnedMemDc, OwnedGdiObj)> {
    if hdc == 0 || width <= 0 || height <= 0 {
        return None;
    }
    let mem_dc = OwnedMemDc::from_compatible(hdc)?;
    // SAFETY: `hdc` is a valid non-zero DC and `width`/`height` are strictly positive.
    let raw_bmp = unsafe { CreateCompatibleBitmap(hdc as HDC, width, height) };
    let bmp = OwnedGdiObj::from_raw(raw_bmp.cast::<c_void>())?;
    Some((mem_dc, bmp))
}

/// Applies or clears the DWM immersive dark titlebar attribute on `hwnd`.
///
/// Uses `DWMWA_USE_IMMERSIVE_DARK_MODE` (`20`) and falls back to `19` on older Windows 10 builds.
pub fn apply_window_dark_titlebar(hwnd: isize, is_dark: bool) {
    if hwnd == 0 {
        return;
    }
    const DWM_DARK_ATTR_PRE_20H1: u32 = 19;
    let value: i32 = i32::from(is_dark);
    let attr = u32::try_from(DWMWA_USE_IMMERSIVE_DARK_MODE).unwrap_or(20);
    let val_size = u32::try_from(size_of::<i32>()).unwrap_or(4);
    // SAFETY: `hwnd` is non-zero and `value` is a live stack `i32` matching `val_size`.
    let hr = unsafe {
        DwmSetWindowAttribute(
            hwnd as HWND,
            attr,
            (&raw const value).cast::<c_void>(),
            val_size,
        )
    };
    if hr < 0 {
        // SAFETY: Pre-20H1 Windows 10 fallback attribute `19` with the same `value` buffer.
        let _fallback_hr = unsafe {
            DwmSetWindowAttribute(
                hwnd as HWND,
                DWM_DARK_ATTR_PRE_20H1,
                (&raw const value).cast::<c_void>(),
                val_size,
            )
        };
    }
}

fn open_hkcu_subkey_readonly(subkey: &str, operation: &'static str) -> Option<OwnedRegKey> {
    let subkey_wide = encode_wide_nul_str(subkey, operation).ok()?;
    let mut raw_key: HKEY = ptr::null_mut();
    // SAFETY: `subkey_wide` is NUL-terminated UTF-16 under `HKEY_CURRENT_USER`.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_wide.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &raw mut raw_key,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    OwnedRegKey::from_raw(raw_key)
}

/// Reads `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme`.
///
/// Returns `true` (light theme) when the key or value is absent or unreadable (`ADR-027`).
#[must_use]
pub fn read_windows_apps_use_light_theme() -> bool {
    const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    const OP: &str = "gui_windows::read_windows_apps_use_light_theme";
    let Some(key) = open_hkcu_subkey_readonly(SUBKEY, OP) else {
        return true;
    };
    let Ok(val_wide) = encode_wide_nul_str("AppsUseLightTheme", OP) else {
        return true;
    };
    let mut value_type: u32 = 0;
    let mut data: u32 = 1;
    let mut data_len = u32::try_from(size_of::<u32>()).unwrap_or(4);
    // SAFETY: `key` is an open registry handle, `val_wide` is NUL-terminated UTF-16, and
    // `data` is 4-byte stack storage matching `data_len`.
    let rc = unsafe {
        RegQueryValueExW(
            key.as_raw(),
            val_wide.as_ptr(),
            ptr::null_mut(),
            &raw mut value_type,
            (&raw mut data).cast::<u8>(),
            &raw mut data_len,
        )
    };
    if rc == ERROR_SUCCESS && value_type == REG_DWORD && data_len == 4 {
        data != 0
    } else {
        true
    }
}

/// Queries whether Windows High Contrast mode is currently active (`SPI_GETHIGHCONTRAST`).
#[must_use]
pub fn detect_high_contrast() -> bool {
    // SAFETY: `HIGHCONTRASTW` is a plain Win32 C struct zero-initialized before setting `cbSize`.
    let mut hc: HIGHCONTRASTW = unsafe { mem::zeroed() };
    let cb_size = u32::try_from(size_of::<HIGHCONTRASTW>()).unwrap_or(0);
    hc.cbSize = cb_size;
    // SAFETY: `uiParam` and `hc.cbSize` both equal `size_of::<HIGHCONTRASTW>()`.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            cb_size,
            (&raw mut hc).cast::<c_void>(),
            0,
        )
    };
    ok != 0 && (hc.dwFlags & HCF_HIGHCONTRASTON) != 0
}

/// Reads `HKCU\Control Panel\International\LocaleName` and returns `true` for Vietnamese (`vi*`).
#[must_use]
pub fn detect_windows_system_locale_is_vi() -> bool {
    const SUBKEY: &str = r"Control Panel\International";
    const OP: &str = "gui_windows::detect_windows_system_locale_is_vi";
    let Some(key) = open_hkcu_subkey_readonly(SUBKEY, OP) else {
        return false;
    };
    let Ok(val_wide) = encode_wide_nul_str("LocaleName", OP) else {
        return false;
    };
    let mut value_type: u32 = 0;
    let mut buf = [0_u16; 64];
    let mut byte_len = u32::try_from(size_of_val(&buf)).unwrap_or(128);
    // SAFETY: `buf` provides `byte_len` writable bytes for `RegQueryValueExW`.
    let rc = unsafe {
        RegQueryValueExW(
            key.as_raw(),
            val_wide.as_ptr(),
            ptr::null_mut(),
            &raw mut value_type,
            buf.as_mut_ptr().cast::<u8>(),
            &raw mut byte_len,
        )
    };
    if rc != ERROR_SUCCESS || value_type != REG_SZ {
        return false;
    }
    let units = usize::try_from(byte_len / 2).unwrap_or(0).min(buf.len());
    let nul_pos = buf
        .get(..units)
        .and_then(|s| s.iter().position(|&c| c == 0))
        .unwrap_or(units);
    let locale = String::from_utf16_lossy(buf.get(..nul_pos).unwrap_or(&[]));
    locale.trim().to_ascii_lowercase().starts_with("vi")
}

/// Invalidates the entire client area of `hwnd` and requests immediate repaint (`UpdateWindow`).
pub fn invalidate_window(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    // SAFETY: `hwnd` is a non-zero live window handle and null rect invalidates the full client area.
    unsafe {
        let _inv = InvalidateRect(hwnd as HWND, ptr::null(), 1);
        let _upd = UpdateWindow(hwnd as HWND);
    }
}

/// Creates a solid Win32 GDI brush (`CreateSolidBrush`) owned by [`OwnedGdiObj`].
#[must_use]
pub fn create_solid_brush(color: u32) -> Option<OwnedGdiObj> {
    // SAFETY: `CreateSolidBrush` allocates a standalone `HBRUSH` owned exclusively by the caller.
    let raw = unsafe { CreateSolidBrush(color) };
    OwnedGdiObj::from_raw(raw.cast::<c_void>())
}

/// Creates a solid Win32 GDI pen (`CreatePen(PS_SOLID, width, color)`) owned by [`OwnedGdiObj`].
#[must_use]
pub fn create_solid_pen(width: i32, color: u32) -> Option<OwnedGdiObj> {
    // SAFETY: `CreatePen` allocates a standalone `HPEN` owned exclusively by the caller.
    let raw = unsafe { CreatePen(PS_SOLID, width.max(1), color) };
    OwnedGdiObj::from_raw(raw.cast::<c_void>())
}

/// Computes `LOGFONTW.lfHeight` from point size and DPI using pure integer math (no `MulDiv`,
/// `ADR-027`): `lfHeight = -(((base_pt * dpi) + 36) / 72)`.
#[must_use]
pub const fn calc_font_height_for_dpi(base_pt: i32, dpi: u32) -> i32 {
    let safe_pt = if base_pt <= 0 { 10 } else { base_pt };
    let safe_dpi = if dpi < 72 { 72 } else { dpi };
    let dpi_i32 = if safe_dpi > i32::MAX as u32 {
        96
    } else {
        safe_dpi as i32
    };
    -(((safe_pt * dpi_i32) + 36) / 72)
}

/// Creates a DPI-scaled Win32 `HFONT` (`CreateFontIndirectW`) using pure integer height
/// calculation (`lfHeight = -(((point_size * dpi) + 36) / 72)`, `ADR-027`).
#[must_use]
pub fn create_font_for_dpi(
    face: &str,
    point_size: i32,
    weight: i32,
    dpi: i32,
) -> Option<OwnedGdiObj> {
    let safe_dpi = u32::try_from(dpi.max(72)).unwrap_or(96);
    let height = calc_font_height_for_dpi(point_size, safe_dpi);
    // SAFETY: `LOGFONTW` is a plain POD C struct safely zero-initialized before populating fields.
    let mut lf: LOGFONTW = unsafe { mem::zeroed() };
    lf.lfHeight = height;
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    write_wide_fixed(&mut lf.lfFaceName, face);
    // SAFETY: `lf` is fully initialized with NUL-terminated UTF-16 `lfFaceName`.
    let raw = unsafe { CreateFontIndirectW(&raw const lf) };
    OwnedGdiObj::from_raw(raw.cast::<c_void>())
}

/// Configures text color, background color, and background mode (`TRANSPARENT`/`OPAQUE`) on `hdc`.
pub fn set_dc_text_and_bk_color(hdc: isize, text_color: u32, bk_color: u32, transparent: bool) {
    if hdc == 0 {
        return;
    }
    let dc = hdc as HDC;
    // SAFETY: `dc` is a valid non-zero `HDC` supplied by `WM_CTLCOLOR*` or `WM_PAINT`.
    unsafe {
        let _tc = SetTextColor(dc, text_color);
        let _bc = SetBkColor(dc, bk_color);
        let _bm = SetBkMode(
            dc,
            if transparent {
                i32::try_from(TRANSPARENT).unwrap_or(1)
            } else {
                i32::try_from(OPAQUE).unwrap_or(2)
            },
        );
    }
}

/// Executes `paint(mem_dc)` on an off-screen double buffer `(width, height)`, `BitBlt`s onto
/// `target_hdc`, and restores the original stock bitmap BEFORE dropping `OwnedGdiObj` and
/// `OwnedMemDc` so zero GDI handles leak (`ADR-027`).
pub fn with_double_buffer<F>(target_hdc: isize, width: i32, height: i32, paint: F) -> bool
where
    F: FnOnce(isize),
{
    let Some((mem_dc, bmp)) = create_double_buffer(target_hdc, width, height) else {
        return false;
    };
    let mem_raw = mem_dc.as_raw() as HDC;
    // SAFETY: `mem_raw` is a live memory DC and `bmp` is a compatible bitmap owned by this scope.
    let old_bmp = unsafe { SelectObject(mem_raw, bmp.as_raw()) };
    paint(mem_dc.as_raw());
    // SAFETY: `target_hdc` and `mem_raw` are valid DCs with dimensions `(width, height)`.
    let blt_ok = unsafe {
        BitBlt(
            target_hdc as HDC,
            0,
            0,
            width,
            height,
            mem_raw,
            0,
            0,
            SRCCOPY,
        )
    };
    // SAFETY: Must restore original stock bitmap BEFORE `bmp` drops (`DeleteObject`).
    let _restored = unsafe { SelectObject(mem_raw, old_bmp) };
    drop(bmp);
    drop(mem_dc);
    blt_ok != 0
}

/// Fills `rect` on `hdc` using `brush` (`FillRect`).
pub fn fill_rect_with_brush(hdc: isize, rect: &ControlRect, brush: &OwnedGdiObj) {
    if hdc == 0 || rect.w <= 0 || rect.h <= 0 {
        return;
    }
    let rc = RECT {
        left: rect.x,
        top: rect.y,
        right: rect.x.saturating_add(rect.w),
        bottom: rect.y.saturating_add(rect.h),
    };
    // SAFETY: `hdc` is a live DC, `rc` is valid stack storage, and `brush` is a live `HBRUSH`.
    let _filled = unsafe { FillRect(hdc as HDC, &raw const rc, brush.as_raw() as HBRUSH) };
}

/// Draws a rounded card (`RoundRect`) filled with `fill_brush` and outlined with `border_pen`,
/// restoring stock GDI objects before returning (`ADR-027`).
pub fn draw_rounded_card(
    hdc: isize,
    rect: &ControlRect,
    radius: i32,
    fill_brush: &OwnedGdiObj,
    border_pen: &OwnedGdiObj,
) {
    if hdc == 0 || rect.w <= 0 || rect.h <= 0 {
        return;
    }
    let dc = hdc as HDC;
    let dia = radius.max(0).saturating_mul(2);
    // SAFETY: Selects live `fill_brush` and `border_pen`, draws `RoundRect`, and restores both
    // previous stock objects before returning.
    unsafe {
        let old_brush = SelectObject(dc, fill_brush.as_raw());
        let old_pen = SelectObject(dc, border_pen.as_raw());
        let _ok = RoundRect(
            dc,
            rect.x,
            rect.y,
            rect.x.saturating_add(rect.w),
            rect.y.saturating_add(rect.h),
            dia,
            dia,
        );
        let _r1 = SelectObject(dc, old_pen);
        let _r2 = SelectObject(dc, old_brush);
    }
}

/// Draws a rounded semantic status pill with centered text, restoring stock GDI objects (`ADR-027`).
pub fn draw_status_pill(
    hdc: isize,
    rect: &ControlRect,
    text: &str,
    bg_brush: &OwnedGdiObj,
    text_color: u32,
    font: &OwnedGdiObj,
) {
    if hdc == 0 || rect.w <= 0 || rect.h <= 0 {
        return;
    }
    let dc = hdc as HDC;
    let dia = rect.h.max(8);
    // SAFETY: Selects `bg_brush` and stock `NULL_PEN`, draws rounded pill, then restores both.
    unsafe {
        let null_pen = GetStockObject(NULL_PEN);
        let old_brush = SelectObject(dc, bg_brush.as_raw());
        let old_pen = SelectObject(dc, null_pen);
        let _ok = RoundRect(
            dc,
            rect.x,
            rect.y,
            rect.x.saturating_add(rect.w),
            rect.y.saturating_add(rect.h),
            dia,
            dia,
        );
        let _r1 = SelectObject(dc, old_pen);
        let _r2 = SelectObject(dc, old_brush);
    }
    draw_text_in_rect(hdc, rect, text, text_color, font, true);
}

/// Draws single-line text clipped cleanly inside `rect` with transparent background (`DrawTextW`).
pub fn draw_text_in_rect(
    hdc: isize,
    rect: &ControlRect,
    text: &str,
    text_color: u32,
    font: &OwnedGdiObj,
    center: bool,
) {
    if hdc == 0 || rect.w <= 0 || rect.h <= 0 || text.is_empty() {
        return;
    }
    let wide: Vec<u16> = text.encode_utf16().collect();
    if wide.is_empty() {
        return;
    }
    let dc = hdc as HDC;
    let mut rc = RECT {
        left: rect.x,
        top: rect.y,
        right: rect.x.saturating_add(rect.w),
        bottom: rect.y.saturating_add(rect.h),
    };
    let flags = DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | if center { DT_CENTER } else { DT_LEFT };
    let count = i32::try_from(wide.len()).unwrap_or(i32::MAX);
    // SAFETY: `wide` holds `count` UTF-16 units, `font` is a live `HFONT`, and `old_font` is
    // restored before returning.
    unsafe {
        let old_font = SelectObject(dc, font.as_raw());
        let _bm = SetBkMode(dc, i32::try_from(TRANSPARENT).unwrap_or(1));
        let _tc = SetTextColor(dc, text_color);
        let _drawn = DrawTextW(dc, wide.as_ptr(), count, &raw mut rc, flags);
        let _r = SelectObject(dc, old_font);
    }
}

/// Visual styling parameters for painting a `BS_OWNERDRAW` button/tab/filter chip (`ADR-027`).
#[derive(Debug)]
pub struct OwnerDrawButtonStyle<'a> {
    /// Display text rendered centered inside the control.
    pub text: &'a str,
    /// Background fill brush (`HBRUSH`).
    pub bg_brush: &'a OwnedGdiObj,
    /// Outline border pen (`HPEN`).
    pub border_pen: &'a OwnedGdiObj,
    /// Foreground text `COLORREF` (`0x00BBGGRR`).
    pub text_color: u32,
    /// Font handle (`HFONT`).
    pub font: &'a OwnedGdiObj,
    /// Whether to draw a keyboard focus cue (`WIN_ODS_FOCUS`).
    pub focused: bool,
}

/// Paints a `BS_OWNERDRAW` button/tab/filter chip inside `WM_DRAWITEM` (`ADR-027`).
pub fn draw_owner_draw_button(hdc: isize, rect: &ControlRect, style: &OwnerDrawButtonStyle<'_>) {
    if hdc == 0 || rect.w <= 0 || rect.h <= 0 {
        return;
    }
    draw_rounded_card(hdc, rect, 6, style.bg_brush, style.border_pen);
    draw_text_in_rect(hdc, rect, style.text, style.text_color, style.font, true);
    if style.focused && rect.w > 6 && rect.h > 6 {
        let focus_rc = RECT {
            left: rect.x + 3,
            top: rect.y + 3,
            right: rect.x + rect.w - 3,
            bottom: rect.y + rect.h - 3,
        };
        // SAFETY: `hdc` is a live `WM_DRAWITEM` DC and `focus_rc` is valid stack storage.
        let _f = unsafe { DrawFocusRect(hdc as HDC, &raw const focus_rc) };
    }
}

/// Returns the current process GDI object handle count (`GetGuiResources(GR_GDIOBJECTS)`).
///
/// Used by automated leak-gate tests (`contracts §5.3`, `US-123`).
#[must_use]
pub fn get_gui_resources_gdi_count() -> u32 {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle valid for `GetGuiResources`.
    unsafe { GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) }
}

/// Returns `size_of::<HIGHCONTRASTW>() as u32` used for `SPI_GETHIGHCONTRAST` (`ADR-027`).
#[must_use]
pub const fn high_contrast_struct_cb_size() -> u32 {
    let sz = size_of::<HIGHCONTRASTW>();
    if sz > u32::MAX as usize { 0 } else { sz as u32 }
}

/// Updates an accessible text label proxy via `SetWindowTextW` and notifies screen readers via
/// `NotifyWinEvent(EVENT_OBJECT_NAMECHANGE)` (`US-139`, zero `IAccessible`).
pub fn announce_accessible_label(hwnd: isize, label: &str) {
    if hwnd == 0 {
        return;
    }
    set_control_text(hwnd, label);
    // SAFETY: `hwnd` is a non-zero live window handle and constants match Win32 accessibility API.
    unsafe {
        NotifyWinEvent(
            EVENT_OBJECT_NAMECHANGE,
            hwnd as HWND,
            OBJID_CLIENT,
            i32::try_from(CHILDID_SELF).unwrap_or(0),
        );
    }
}

fn get_focused_control_id() -> u16 {
    // SAFETY: Returns focused `HWND` on current thread (or null).
    let focused = unsafe { GetFocus() };
    if focused.is_null() {
        return 0;
    }
    // SAFETY: Queries child dialog ID for `focused` window handle.
    let id = unsafe { GetDlgCtrlID(focused) };
    u16::try_from(id.max(0)).unwrap_or(0)
}

fn is_ctrl_down() -> bool {
    // SAFETY: Queries current key state of `VK_CONTROL`.
    let state = unsafe { GetKeyState(i32::from(VK_CONTROL)) };
    state < 0
}

struct ChildControlSpec<'a> {
    parent: isize,
    class_name: &'a str,
    text: &'a str,
    style: u32,
    ex_style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
}

fn create_child_control(spec: ChildControlSpec<'_>) -> SysResult<isize> {
    const OP: &str = "gui_windows::create_child_control";
    let class_w = encode_wide_nul_str(spec.class_name, OP)?;
    let text_w = encode_wide_nul_str(spec.text, OP)?;
    // SAFETY: `GetModuleHandleW(null)` returns the current executable's `HINSTANCE`.
    let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
    // SAFETY: `class_w` and `text_w` are NUL-terminated UTF-16 buffers kept alive across
    // `CreateWindowExW`, and `spec.parent` is an active top-level window handle.
    let hwnd = unsafe {
        CreateWindowExW(
            spec.ex_style,
            class_w.as_ptr(),
            text_w.as_ptr(),
            spec.style,
            spec.x,
            spec.y,
            spec.w.max(1),
            spec.h.max(1),
            spec.parent as HWND,
            usize::from(spec.id) as HMENU,
            hinstance,
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    Ok(hwnd as isize)
}

fn build_popup_menu(
    entries: &[TrayMenuEntry],
    owned_submenus: &mut Vec<OwnedMenu>,
    operation: &'static str,
) -> SysResult<OwnedMenu> {
    // SAFETY: `CreatePopupMenu` allocates an empty Win32 popup `HMENU`.
    let raw_menu = unsafe { CreatePopupMenu() };
    let menu = OwnedMenu::from_raw(raw_menu)
        .ok_or_else(|| SysError::io(operation, io::Error::last_os_error()))?;

    for entry in entries {
        match entry {
            TrayMenuEntry::Header(label) => {
                let wide = encode_wide_nul_str(label, operation)?;
                // SAFETY: `menu` is a live `HMENU` and `wide` is NUL-terminated UTF-16.
                let _ok =
                    unsafe { AppendMenuW(menu.as_raw(), MF_STRING | MF_GRAYED, 0, wide.as_ptr()) };
            }
            TrayMenuEntry::Separator => {
                // SAFETY: Appends horizontal separator to `menu`.
                let _ok = unsafe { AppendMenuW(menu.as_raw(), MF_SEPARATOR, 0, ptr::null()) };
            }
            TrayMenuEntry::Action {
                id,
                label,
                enabled,
                checked,
                ..
            } => {
                let wide = encode_wide_nul_str(label, operation)?;
                let mut flags = MF_STRING;
                if !*enabled {
                    flags |= MF_GRAYED;
                }
                if *checked {
                    flags |= MF_CHECKED;
                }
                // SAFETY: `menu` is a live `HMENU` and `wide` is NUL-terminated UTF-16.
                let _ok =
                    unsafe { AppendMenuW(menu.as_raw(), flags, usize::from(*id), wide.as_ptr()) };
            }
            TrayMenuEntry::Submenu {
                label,
                enabled,
                items,
            } => {
                let sub = build_popup_menu(items, owned_submenus, operation)?;
                let sub_raw = sub.as_raw();
                owned_submenus.push(sub);
                let wide = encode_wide_nul_str(label, operation)?;
                let mut flags = MF_POPUP | MF_STRING;
                if !*enabled {
                    flags |= MF_GRAYED;
                }
                // SAFETY: `sub_raw` remains alive via `owned_submenus` while `menu` is open.
                let _ok =
                    unsafe { AppendMenuW(menu.as_raw(), flags, sub_raw as usize, wide.as_ptr()) };
            }
        }
    }
    Ok(menu)
}

fn build_notify_icon_data(
    hwnd: HWND,
    icon_id: u32,
    icon: &OwnedIcon,
    tooltip: &str,
) -> NOTIFYICONDATAW {
    // SAFETY: `NOTIFYICONDATAW` is POD zero-initialized before setting explicit fields.
    let mut nid: NOTIFYICONDATAW = unsafe { mem::zeroed() };
    nid.cbSize = u32::try_from(size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
    nid.hWnd = hwnd;
    nid.uID = icon_id;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_APP_TRAY_CALLBACK;
    nid.hIcon = icon.as_raw();
    write_wide_fixed(&mut nid.szTip, tooltip);
    nid
}

fn write_wide_fixed(dst: &mut [u16], text: &str) {
    if dst.is_empty() {
        return;
    }
    dst.fill(0);
    let max_units = dst.len().saturating_sub(1);
    for (idx, unit) in text.encode_utf16().take(max_units).enumerate() {
        if let Some(slot) = dst.get_mut(idx) {
            *slot = unit;
        }
    }
}

fn accept_pipe_overlapped(
    pipe: HANDLE,
    child_proc: Option<&OwnedWinHandle>,
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<()> {
    let (event, mut ov) = create_overlapped_event(operation)?;
    // SAFETY: `pipe` was opened with `FILE_FLAG_OVERLAPPED` and `ov` stays pinned until wait ends.
    let ok = unsafe { ConnectNamedPipe(pipe, &raw mut ov) };
    if ok != 0 {
        return Ok(());
    }
    // SAFETY: Reads thread-local error set by `ConnectNamedPipe`.
    let code = unsafe { GetLastError() };
    if code == ERROR_PIPE_CONNECTED {
        return Ok(());
    }
    if code != ERROR_IO_PENDING {
        return Err(map_win_io_error(
            operation,
            io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
        ));
    }

    let wait_res = if let Some(proc_h) = child_proc {
        let handles = [event.as_raw(), proc_h.as_raw()];
        // SAFETY: Both `event` and `proc_h` remain valid throughout `WaitForMultipleObjects`.
        let status = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout_ms) };
        if status == WAIT_OBJECT_0 {
            Ok(())
        } else if status == WAIT_OBJECT_0 + 1 {
            cancel_and_drain_overlapped(pipe, &raw const ov);
            let exit_code = get_process_exit_code(proc_h).ok().flatten().unwrap_or(1);
            Err(SysError::io(
                operation,
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("elevated worker exited early (code {exit_code}) before connecting"),
                ),
            ))
        } else if status == WAIT_TIMEOUT {
            cancel_and_drain_overlapped(pipe, &raw const ov);
            Err(SysError::io(
                operation,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for worker connect",
                ),
            ))
        } else {
            cancel_and_drain_overlapped(pipe, &raw const ov);
            Err(SysError::io(operation, io::Error::last_os_error()))
        }
    } else {
        // SAFETY: `event` stays valid across wait.
        let status = unsafe { WaitForSingleObject(event.as_raw(), timeout_ms) };
        if status == WAIT_OBJECT_0 {
            Ok(())
        } else if status == WAIT_TIMEOUT {
            cancel_and_drain_overlapped(pipe, &raw const ov);
            Err(SysError::io(
                operation,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for worker connect",
                ),
            ))
        } else {
            cancel_and_drain_overlapped(pipe, &raw const ov);
            Err(SysError::io(operation, io::Error::last_os_error()))
        }
    };
    wait_res?;

    let mut transferred: u32 = 0;
    // SAFETY: `pipe` and `ov` are still live; finishes overlapped connect status check.
    let done = unsafe { GetOverlappedResult(pipe, &raw const ov, &raw mut transferred, 1) };
    drop(event);
    if done == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    Ok(())
}

fn verify_pipe_client_pid(
    pipe: HANDLE,
    expected_pid: u32,
    operation: &'static str,
) -> SysResult<()> {
    let mut actual_pid: u32 = 0;
    // SAFETY: `pipe` is a connected Named Pipe handle and `actual_pid` is writable stack storage.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &raw mut actual_pid) };
    if ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    if actual_pid == 0 || actual_pid != expected_pid {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!(
                "handoff pipe client PID {actual_pid} does not match expected {expected_pid}"
            ),
        });
    }
    Ok(())
}

fn read_and_validate_worker_hello(
    pipe: HANDLE,
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<()> {
    let mut hello = [0_u8; MGH1_HELLO_FRAME_LEN];
    pipe_read_exact_overlapped(pipe, &mut hello, timeout_ms, operation)?;
    let (magic, rest) = hello
        .split_at_checked(4)
        .ok_or_else(|| SysError::SecurityViolation {
            operation,
            detail: "short MGH1 WorkerHello frame".to_owned(),
        })?;
    if magic != MGH1_MAGIC {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "invalid MGH1 WorkerHello magic".to_owned(),
        });
    }
    let frame_type = rest.first().copied().unwrap_or(0xff);
    let len_bytes: [u8; 4] = rest
        .get(1..5)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 4]);
    let ver_bytes: [u8; 4] = rest
        .get(5..9)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0; 4]);
    let payload_len = u32::from_le_bytes(len_bytes);
    let proto_ver = u32::from_le_bytes(ver_bytes);
    if frame_type != 0x00 || payload_len != 4 || proto_ver != MGH1_PROTOCOL_VERSION {
        return Err(SysError::SecurityViolation {
            operation,
            detail: format!(
                "invalid WorkerHello (type=0x{frame_type:02x}, len={payload_len}, ver={proto_ver})"
            ),
        });
    }
    Ok(())
}

fn impersonate_and_inspect_pipe_thread_token(
    pipe: HANDLE,
    operation: &'static str,
) -> SysResult<(WindowsPeerCredentials, bool)> {
    // SAFETY: `pipe` is a connected Named Pipe that has already delivered `0x00 WorkerHello` bytes,
    // so `ImpersonateNamedPipeClient` grants a `SecurityIdentification` thread token without
    // requiring `SeImpersonatePrivilege` or `OpenProcessToken` (`BLK-DGUI-G2-04`).
    let imp_ok = unsafe { ImpersonateNamedPipeClient(pipe) };
    if imp_ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    let _imp_guard = ImpersonationGuard;

    let mut token_raw: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentThread` is a pseudo-handle; `OpenThreadToken(..., OpenAsSelf = TRUE)`
    // opens the impersonated client token strictly with `TOKEN_QUERY`.
    let tok_ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token_raw) };
    let Some(token) = OwnedWinHandle::from_raw(tok_ok_handle(tok_ok, token_raw)) else {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    };

    let is_builtin_admin =
        check_well_known_sid_member(token.as_raw(), WinBuiltinAdministratorsSid, operation)?;
    let is_local_system =
        check_well_known_sid_member(token.as_raw(), WinLocalSystemSid, operation)?;
    let is_elevated = query_token_is_elevated(token.as_raw(), operation)?;
    let principal = query_token_user_sid_string(token.as_raw(), operation)?;

    Ok((
        WindowsPeerCredentials {
            is_builtin_admin,
            is_local_system,
            principal,
        },
        is_elevated,
    ))
}

const fn tok_ok_handle(ok: i32, raw: HANDLE) -> HANDLE {
    if ok == 0 { ptr::null_mut() } else { raw }
}

fn check_well_known_sid_member(
    token: HANDLE,
    sid_type: i32,
    operation: &'static str,
) -> SysResult<bool> {
    let mut sid_buf = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = u32::try_from(sid_buf.len()).unwrap_or(SECURITY_MAX_SID_SIZE);
    // SAFETY: `sid_buf` holds `SECURITY_MAX_SID_SIZE` writable bytes.
    let sid_ok = unsafe {
        CreateWellKnownSid(
            sid_type,
            ptr::null_mut(),
            sid_buf.as_mut_ptr().cast::<c_void>(),
            &raw mut sid_size,
        )
    };
    if sid_ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }

    let mut is_member: i32 = 0;
    // SAFETY: `token` is an impersonation token opened with `TOKEN_QUERY`; `sid_buf` is valid SID.
    let check_ok = unsafe {
        CheckTokenMembership(
            token,
            sid_buf.as_ptr().cast::<c_void>() as PSID,
            &raw mut is_member,
        )
    };
    if check_ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    Ok(is_member != 0)
}

fn query_token_is_elevated(token: HANDLE, operation: &'static str) -> SysResult<bool> {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned: u32 = 0;
    let len = u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(4);
    // SAFETY: `token` was opened with `TOKEN_QUERY` and `elevation` is valid stack storage.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            len,
            &raw mut returned,
        )
    };
    if ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn current_process_user_sid_string(operation: &'static str) -> SysResult<String> {
    let mut tok_raw: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle; opens process token for `TOKEN_QUERY`.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut tok_raw) };
    let Some(token) = OwnedWinHandle::from_raw(tok_ok_handle(ok, tok_raw)) else {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    };
    query_token_user_sid_string(token.as_raw(), operation)
}

fn query_token_user_sid_string(token: HANDLE, operation: &'static str) -> SysResult<String> {
    let mut required: u32 = 0;
    // SAFETY: Probe call retrieves exact `TOKEN_USER` byte size.
    let _probe =
        unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut required) };
    let first_err = io::Error::last_os_error();
    let needed = usize::try_from(required).unwrap_or(0);
    if needed < size_of::<TOKEN_USER>() {
        if first_err.raw_os_error() != Some(i32::try_from(ERROR_INSUFFICIENT_BUFFER).unwrap_or(122))
        {
            return Err(map_win_io_error(operation, first_err));
        }
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidData, "short TokenUser payload"),
        ));
    }

    let mut buf = vec![0_u64; needed.div_ceil(size_of::<u64>())];
    let buf_len = u32::try_from(buf.len().saturating_mul(size_of::<u64>())).unwrap_or(required);
    // SAFETY: `buf` is zeroed, `u64`-aligned, and at least `needed` bytes long.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            buf_len,
            &raw mut required,
        )
    };
    if ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }

    // SAFETY: `GetTokenInformation(TokenUser)` initializes `TOKEN_USER` at start of `buf`.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut wide_sid: *mut u16 = ptr::null_mut();
    // SAFETY: `user.User.Sid` points inside `buf`; `wide_sid` receives a `LocalAlloc` string.
    let conv_ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut wide_sid) };
    if conv_ok == 0 || wide_sid.is_null() {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    let _str_guard = LocalAllocGuard(wide_sid.cast::<c_void>());
    Ok(read_wide_ptr_nul_lossy(wide_sid, 512))
}

fn pipe_read_exact_overlapped(
    pipe: HANDLE,
    mut buf: &mut [u8],
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<()> {
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms.max(1)));
    while !buf.is_empty() {
        let now = Instant::now();
        let Some(rem) = deadline.checked_duration_since(now) else {
            return Err(SysError::io(
                operation,
                io::Error::new(io::ErrorKind::TimedOut, "handoff pipe read timed out"),
            ));
        };
        let step_ms = u32::try_from(rem.as_millis()).unwrap_or(u32::MAX).max(1);
        let n = pipe_read_overlapped(pipe, buf, step_ms, operation)?;
        if n == 0 {
            return Err(SysError::io(
                operation,
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "handoff pipe closed mid-frame",
                ),
            ));
        }
        let Some((_head, tail)) = buf.split_at_mut_checked(n) else {
            return Err(SysError::io(
                operation,
                io::Error::new(io::ErrorKind::InvalidData, "overlapped read exceeded slice"),
            ));
        };
        buf = tail;
    }
    Ok(())
}

fn pipe_read_overlapped(
    pipe: HANDLE,
    buf: &mut [u8],
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let max_read = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    let (event, mut ov) = create_overlapped_event(operation)?;
    let mut bytes_read: u32 = 0;

    // SAFETY: `pipe` is open with `FILE_FLAG_OVERLAPPED`, `buf` stays valid until
    // `GetOverlappedResult` / cancellation drain completes, and `ov` owns `event`.
    let ok = unsafe {
        ReadFile(
            pipe,
            buf.as_mut_ptr(),
            max_read,
            &raw mut bytes_read,
            &raw mut ov,
        )
    };
    if ok != 0 {
        return Ok(usize::try_from(bytes_read).unwrap_or(usize::MAX));
    }
    // SAFETY: Reads thread-local error set by `ReadFile`.
    let code = unsafe { GetLastError() };
    if code == ERROR_BROKEN_PIPE || code == ERROR_NO_DATA {
        return Ok(0);
    }
    if code != ERROR_IO_PENDING {
        return Err(map_overlapped_error(
            operation,
            io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
        ));
    }

    // SAFETY: `event` stays valid across `WaitForSingleObject`.
    let wait = unsafe { WaitForSingleObject(event.as_raw(), timeout_ms) };
    if wait == WAIT_TIMEOUT {
        cancel_and_drain_overlapped(pipe, &raw const ov);
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::TimedOut, "handoff pipe read timed out"),
        ));
    }
    if wait == WAIT_FAILED {
        cancel_and_drain_overlapped(pipe, &raw const ov);
        return Err(SysError::io(operation, io::Error::last_os_error()));
    }

    let mut transferred: u32 = 0;
    // SAFETY: `buf` and `ov` remain valid until `GetOverlappedResult` completes.
    let done = unsafe { GetOverlappedResult(pipe, &raw const ov, &raw mut transferred, 1) };
    drop(event);
    if done == 0 {
        let err = io::Error::last_os_error();
        if is_pipe_eof(&err) {
            return Ok(0);
        }
        return Err(map_overlapped_error(operation, err));
    }
    Ok(usize::try_from(transferred).unwrap_or(usize::MAX))
}

fn pipe_write_all_overlapped(
    pipe: HANDLE,
    mut data: &[u8],
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<()> {
    while !data.is_empty() {
        let n = pipe_write_overlapped(pipe, data, timeout_ms, operation)?;
        if n == 0 {
            return Err(SysError::io(
                operation,
                io::Error::new(io::ErrorKind::WriteZero, "handoff pipe wrote 0 bytes"),
            ));
        }
        data = data.get(n..).unwrap_or(&[]);
    }
    Ok(())
}

fn pipe_write_overlapped(
    pipe: HANDLE,
    data: &[u8],
    timeout_ms: u32,
    operation: &'static str,
) -> SysResult<usize> {
    if data.is_empty() {
        return Ok(0);
    }
    let max_write = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let (event, mut ov) = create_overlapped_event(operation)?;
    let mut written: u32 = 0;

    // SAFETY: `data` stays valid until `GetOverlappedResult` / cancellation drain completes.
    let ok = unsafe {
        WriteFile(
            pipe,
            data.as_ptr(),
            max_write,
            &raw mut written,
            &raw mut ov,
        )
    };
    if ok != 0 {
        return Ok(usize::try_from(written).unwrap_or(usize::MAX));
    }
    // SAFETY: Reads thread-local error set by `WriteFile`.
    let code = unsafe { GetLastError() };
    if code != ERROR_IO_PENDING {
        return Err(map_overlapped_error(
            operation,
            io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
        ));
    }

    // SAFETY: `event` stays valid across wait.
    let wait = unsafe { WaitForSingleObject(event.as_raw(), timeout_ms) };
    if wait == WAIT_TIMEOUT {
        cancel_and_drain_overlapped(pipe, &raw const ov);
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::TimedOut, "handoff pipe write timed out"),
        ));
    }
    if wait == WAIT_FAILED {
        cancel_and_drain_overlapped(pipe, &raw const ov);
        return Err(SysError::io(operation, io::Error::last_os_error()));
    }

    let mut transferred: u32 = 0;
    // SAFETY: `data` and `ov` remain pinned until `GetOverlappedResult` completes.
    let done = unsafe { GetOverlappedResult(pipe, &raw const ov, &raw mut transferred, 1) };
    drop(event);
    if done == 0 {
        return Err(map_overlapped_error(operation, io::Error::last_os_error()));
    }
    Ok(usize::try_from(transferred).unwrap_or(usize::MAX))
}

fn create_overlapped_event(operation: &'static str) -> SysResult<(OwnedWinHandle, OVERLAPPED)> {
    // SAFETY: Creates an unnamed manual-reset Win32 event for overlapped pipe I/O.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    let Some(event) = OwnedWinHandle::from_raw(raw) else {
        return Err(SysError::io(operation, io::Error::last_os_error()));
    };
    // SAFETY: `OVERLAPPED` is a POD C struct safely zero-initialized before setting `hEvent`.
    let mut ov: OVERLAPPED = unsafe { mem::zeroed() };
    ov.hEvent = event.as_raw();
    Ok((event, ov))
}

fn cancel_and_drain_overlapped(pipe: HANDLE, ov: *const OVERLAPPED) {
    // SAFETY: Cancels the specific in-flight `ov` I/O and waits for kernel to release buffer ptrs.
    unsafe {
        let _cancelled = CancelIoEx(pipe, ov);
        let mut transferred: u32 = 0;
        let _drained = GetOverlappedResult(pipe, ov, &raw mut transferred, 1);
    }
}

fn is_pipe_eof(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == i32::try_from(ERROR_BROKEN_PIPE).unwrap_or(109)
                || code == i32::try_from(ERROR_NO_DATA).unwrap_or(232)
    )
}

fn map_overlapped_error(operation: &'static str, err: io::Error) -> SysError {
    if err.raw_os_error() == Some(i32::try_from(ERROR_OPERATION_ABORTED).unwrap_or(995)) {
        return SysError::io(
            operation,
            io::Error::new(io::ErrorKind::Interrupted, "handoff pipe I/O cancelled"),
        );
    }
    map_win_io_error(operation, err)
}

fn validate_sink_dest_path(dest: &Path, operation: &'static str) -> SysResult<()> {
    if !dest.is_absolute() || dest.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "bugreport save destination must be absolute without `..`".to_owned(),
        });
    }
    if dest.file_name().is_none() {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "bugreport destination must include a file name".to_owned(),
        });
    }
    let norm = normalize_windows_cmp_path(dest);
    if is_forbidden_system_dir_path(&norm) {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "refusing to write bugreport into protected system directory".to_owned(),
        });
    }
    if let Some(parent) = dest.parent()
        && let Ok(canon_parent) = fs::canonicalize(parent)
        && let Some(fname) = dest.file_name()
    {
        let canon_full = normalize_windows_cmp_path(&canon_parent.join(fname));
        if is_forbidden_system_dir_path(&canon_full) {
            return Err(SysError::SecurityViolation {
                operation,
                detail: "refusing to write bugreport into canonical protected system directory"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn is_forbidden_system_dir_path(norm_lower: &str) -> bool {
    let mut blocked: Vec<String> = Vec::new();
    if let Some(win_dir) = query_windows_dir_path() {
        blocked.push(normalize_windows_cmp_path(&win_dir));
    } else {
        blocked.push(r"c:\windows".to_owned());
    }
    for var in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
    ] {
        if let Some(val) = std::env::var_os(var)
            && !val.is_empty()
        {
            blocked.push(normalize_windows_cmp_path(&PathBuf::from(val)));
        }
    }
    let prog_data = std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    blocked.push(normalize_windows_cmp_path(&prog_data.join("Mesh")));

    blocked.into_iter().any(|dir| {
        !dir.is_empty() && (norm_lower == dir || norm_lower.starts_with(&format!(r"{dir}\")))
    })
}

fn verify_non_reparse_directory(dir: &Path, operation: &'static str) -> SysResult<()> {
    let meta = fs::symlink_metadata(dir).map_err(|err| map_win_io_error(operation, err))?;
    if meta.file_type().is_symlink()
        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !meta.file_type().is_dir()
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "destination parent directory cannot be a symlink or reparse point".to_owned(),
        });
    }

    let wide = encode_wide_nul_os(dir.as_os_str(), operation)?;
    // SAFETY: Opens directory with backup semantics and open-reparse-point for attribute checks.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let Some(handle) = OwnedWinHandle::from_raw(raw) else {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    };
    let info = query_handle_file_info(handle.as_raw(), operation)?;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "destination parent handle is a reparse point or non-directory".to_owned(),
        });
    }
    Ok(())
}

fn verify_dest_regular_or_absent(dest: &Path, operation: &'static str) -> SysResult<()> {
    let meta = match fs::symlink_metadata(dest) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(map_win_io_error(operation, err)),
    };
    if meta.file_type().is_symlink()
        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || !meta.file_type().is_file()
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "existing destination cannot be a symlink, reparse point, or directory"
                .to_owned(),
        });
    }

    let wide = encode_wide_nul_os(dest.as_os_str(), operation)?;
    // SAFETY: Opens existing target with `FILE_FLAG_OPEN_REPARSE_POINT` for attribute check.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let Some(handle) = OwnedWinHandle::from_raw(raw) else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(WIN_ERROR_FILE_NOT_FOUND) {
            return Ok(());
        }
        return Err(map_win_io_error(operation, err));
    };
    verify_raw_regular_disk_handle(handle.as_raw(), operation)
}

fn verify_regular_disk_handle(file: &File, operation: &'static str) -> SysResult<()> {
    let meta = file
        .metadata()
        .map_err(|err| SysError::io(operation, err))?;
    if !meta.is_file() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "file handle must refer to a regular non-reparse file".to_owned(),
        });
    }
    verify_raw_regular_disk_handle(file.as_raw_handle() as HANDLE, operation)
}

fn verify_raw_regular_disk_handle(raw_handle: HANDLE, operation: &'static str) -> SysResult<()> {
    // SAFETY: `raw_handle` is a live kernel file handle owned by caller.
    let file_type = unsafe { GetFileType(raw_handle) };
    if file_type != FILE_TYPE_DISK {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "target handle is not a regular disk file".to_owned(),
        });
    }
    let info = query_handle_file_info(raw_handle, operation)?;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "target handle refers to a reparse point or directory".to_owned(),
        });
    }
    Ok(())
}

fn query_handle_file_info(
    raw_handle: HANDLE,
    operation: &'static str,
) -> SysResult<BY_HANDLE_FILE_INFORMATION> {
    let zero_ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: 0,
        ftCreationTime: zero_ft,
        ftLastAccessTime: zero_ft,
        ftLastWriteTime: zero_ft,
        dwVolumeSerialNumber: 0,
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        nNumberOfLinks: 0,
        nFileIndexHigh: 0,
        nFileIndexLow: 0,
    };
    // SAFETY: `raw_handle` is open and `info` is valid writable stack storage.
    let ok = unsafe { GetFileInformationByHandle(raw_handle, &raw mut info) };
    if ok == 0 {
        return Err(SysError::io(operation, io::Error::last_os_error()));
    }
    Ok(info)
}

fn new_guid_hex_32() -> String {
    let mut guid = GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0_u8; 8],
    };
    // SAFETY: `CoCreateGuid` initializes a stack `GUID` via Windows RPC CSPRNG.
    let _hr = unsafe { CoCreateGuid(&raw mut guid) };
    format!(
        "{:08x}{:04x}{:04x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7],
    )
}

fn query_service_process_status(
    svc: SC_HANDLE,
    operation: &'static str,
) -> SysResult<SERVICE_STATUS_PROCESS> {
    // SAFETY: `SERVICE_STATUS_PROCESS` is POD zeroed before `QueryServiceStatusEx`.
    let mut status: SERVICE_STATUS_PROCESS = unsafe { mem::zeroed() };
    let mut needed: u32 = 0;
    let buf_len = u32::try_from(size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(0);
    // SAFETY: `svc` is an open `SERVICE_QUERY_STATUS` handle and `status` is writable stack memory.
    let ok = unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast::<u8>(),
            buf_len,
            &raw mut needed,
        )
    };
    if ok == 0 {
        return Err(map_win_io_error(operation, io::Error::last_os_error()));
    }
    Ok(status)
}

const fn map_service_state(state: u32) -> WindowsServiceProbeState {
    match state {
        SERVICE_RUNNING => WindowsServiceProbeState::Running,
        SERVICE_STOPPED => WindowsServiceProbeState::Stopped,
        SERVICE_START_PENDING | SERVICE_STOP_PENDING | SERVICE_PAUSE_PENDING | SERVICE_PAUSED => {
            WindowsServiceProbeState::Pending
        }
        _ => WindowsServiceProbeState::Pending,
    }
}

fn resolve_known_folder_path(folder_id: &GUID) -> Option<PathBuf> {
    let mut raw_ptr: *mut u16 = ptr::null_mut();
    // SAFETY: `folder_id` is a valid Win32 `KNOWNFOLDERID`; `raw_ptr` is freed via `CoTaskMemFree`.
    let hr = unsafe { SHGetKnownFolderPath(folder_id, 0, ptr::null_mut(), &raw mut raw_ptr) };
    if hr != 0 || raw_ptr.is_null() {
        return None;
    }
    let _guard = CoTaskMemGuard(raw_ptr.cast::<c_void>());
    let text = read_wide_ptr_nul_lossy(raw_ptr, MAX_WIDE_PATH_CHARS);
    if text.is_empty() {
        None
    } else {
        Some(PathBuf::from(text))
    }
}

fn remove_shortcut_if_exists(path: &Path, operation: &'static str) -> SysResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => fs::remove_file(path).map_err(|err| map_win_io_error(operation, err)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(map_win_io_error(operation, err)),
    }
}

fn open_clipboard_with_retry(operation: &'static str) -> SysResult<ClipboardGuard> {
    for attempt in 0..8_u32 {
        // SAFETY: Opens the system clipboard for the current thread without associating a window.
        let ok = unsafe { OpenClipboard(ptr::null_mut()) };
        if ok != 0 {
            return Ok(ClipboardGuard);
        }
        if attempt < 7 {
            win_sleep_ms(12);
        }
    }
    Err(SysError::io(operation, io::Error::last_os_error()))
}

fn win_sleep_ms(ms: u32) {
    // SAFETY: Synchronous non-async backoff wait inside dedicated Win32/SCM/pipe helper.
    unsafe { Sleep(ms) };
}

fn read_clipboard_unicode_locked() -> SysResult<Option<String>> {
    // SAFETY: Caller holds active `ClipboardGuard`.
    let avail = unsafe { IsClipboardFormatAvailable(u32::from(CF_UNICODETEXT)) };
    if avail == 0 {
        return Ok(None);
    }
    // SAFETY: `CF_UNICODETEXT` is available while `ClipboardGuard` is held.
    let hmem = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT)) };
    if hmem.is_null() {
        return Ok(None);
    }
    // SAFETY: Queries byte size of clipboard global handle.
    let total_bytes = unsafe { GlobalSize(hmem) };
    if total_bytes < 2 {
        return Ok(None);
    }
    // SAFETY: Locks `hmem` and releases via `_unlock` guard before returning.
    let locked = unsafe { GlobalLock(hmem) };
    if locked.is_null() {
        return Ok(None);
    }
    let _unlock = GlobalLockGuard(hmem);
    let max_u16 = (total_bytes / 2).min(1_048_576);
    let wide_ptr = locked.cast::<u16>();
    let mut len: usize = 0;
    while len < max_u16 {
        // SAFETY: `len < max_u16` stays strictly inside `GlobalSize(hmem)` bytes.
        let ch = unsafe { *wide_ptr.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `wide_ptr` holds `len` valid UTF-16 units before NUL inside locked global memory.
    let slice = unsafe { std::slice::from_raw_parts(wide_ptr, len) };
    Ok(Some(String::from_utf16_lossy(slice)))
}

fn validate_registry_value_name(name: &str, operation: &'static str) -> SysResult<()> {
    if name.is_empty() || name.contains(['\0', '\\', '\r', '\n']) {
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "invalid registry value name"),
        ));
    }
    Ok(())
}

fn query_windows_dir_path() -> Option<PathBuf> {
    let mut buf = vec![0_u16; 512];
    let cap = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` is writable UTF-16 buffer of length `cap`.
    let needed = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), cap) };
    if needed == 0 || needed > cap {
        return None;
    }
    let used = usize::try_from(needed).ok()?;
    Some(PathBuf::from(OsString::from_wide(buf.get(..used)?)))
}

fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(stripped) = raw.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

fn normalize_windows_cmp_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('/', r"\");
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.trim_end_matches('\\').to_ascii_lowercase()
}

fn contains_shell_metacharacters(text: &str) -> bool {
    text.bytes().any(|b| {
        b.is_ascii_control()
            || matches!(
                b,
                b';' | b'|' | b'&' | b'$' | b'(' | b')' | b'\'' | b'"' | b'`' | b'>' | b'<'
            )
    })
}

fn read_wide_ptr_nul_lossy(ptr_wide: *const u16, max_units: usize) -> String {
    let mut len: usize = 0;
    while len < max_units {
        // SAFETY: Scans for NUL terminator within Win32-allocated UTF-16 string buffer.
        let ch = unsafe { *ptr_wide.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `ptr_wide` holds `len` UTF-16 code units before NUL.
    let slice = unsafe { std::slice::from_raw_parts(ptr_wide, len) };
    String::from_utf16_lossy(slice)
}

fn encode_wide_nul_str(text: &str, operation: &'static str) -> SysResult<Vec<u16>> {
    encode_wide_nul_os(OsStr::new(text), operation)
}

fn encode_wide_nul_os(value: &OsStr, operation: &'static str) -> SysResult<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "interior NUL byte in string"),
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn map_win_io_error(operation: &'static str, err: io::Error) -> SysError {
    if err.kind() == io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(WIN_ERROR_ACCESS_DENIED)
    {
        return SysError::PermissionDenied { operation };
    }
    SysError::io(operation, err)
}

fn map_win_status(operation: &'static str, code: u32) -> SysError {
    map_win_io_error(
        operation,
        io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
    )
}

fn render_badge_bgra(kind: TrayStatusIconKind, size_px: i32) -> Vec<u8> {
    let (r, g, b) = match kind {
        TrayStatusIconKind::Connected => (0x10_u8, 0xb9_u8, 0x81_u8),
        TrayStatusIconKind::ConnectingOrDegraded => (0xf5_u8, 0x9e_u8, 0x0b_u8),
        TrayStatusIconKind::Stopped => (0x64_u8, 0x74_u8, 0x8b_u8),
        TrayStatusIconKind::DaemonUnavailable => (0x47_u8, 0x55_u8, 0x69_u8),
        TrayStatusIconKind::WarningOrError => (0xef_u8, 0x44_u8, 0x44_u8),
    };
    let s = usize::try_from(size_px.max(16)).unwrap_or(16);
    let mut buf = vec![0_u8; s * s * 4];
    let center = (s as f32) * 0.5;
    let outer_r = (s as f32) * 0.44;
    let inner_r = (s as f32) * 0.19;
    for y in 0..s {
        for x in 0..s {
            let dx = (x as f32 + 0.5) - center;
            let dy = (y as f32 + 0.5) - center;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = (y * s + x) * 4;
            let (pr, pg, pb, pa) = if dist <= inner_r {
                (255_u8, 255_u8, 255_u8, 255_u8)
            } else if dist <= outer_r {
                (r, g, b, 255_u8)
            } else if dist <= outer_r + 1.0 {
                let cov = ((outer_r + 1.0 - dist).clamp(0.0, 1.0) * 255.0) as u8;
                (r, g, b, cov)
            } else {
                (0, 0, 0, 0)
            };
            if let Some(dst) = buf.get_mut(idx..idx + 4) {
                dst.copy_from_slice(&[pb, pg, pr, pa]);
            }
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;

    use tempfile::tempdir;

    static GDI_TEST_LOCK: Mutex<()> = Mutex::new(());

    use super::{
        HANDOFF_PIPE_PREFIX, OwnedMemDc, PaintGuard, TrayStatusIconKind, UnprivilegedSinkWriter,
        WIN_ERROR_CANCELLED, apply_window_dark_titlebar, create_double_buffer,
        create_tray_status_icon, detect_high_contrast, detect_windows_system_locale_is_vi,
        init_common_controls, invalidate_window, is_uac_cancelled_error,
        is_valid_handoff_pipe_name, open_anti_toctou_read_locked,
        read_windows_apps_use_light_theme,
    };
    use crate::error::SysError;

    #[test]
    fn test_gui_windows_validates_handoff_pipe_name_and_error_helpers() {
        // Arrange
        let valid = format!("{HANDOFF_PIPE_PREFIX}{}", "0123456789abcdef".repeat(2));
        let upper = format!("{HANDOFF_PIPE_PREFIX}{}", "0123456789ABCDEF".repeat(2));
        let short = format!("{HANDOFF_PIPE_PREFIX}0123");
        let cancelled = SysError::io(
            "ShellExecuteExW",
            std::io::Error::from_raw_os_error(WIN_ERROR_CANCELLED),
        );
        let other = SysError::io("ShellExecuteExW", std::io::Error::from_raw_os_error(5));

        // Act & Assert
        assert!(is_valid_handoff_pipe_name(&valid));
        assert!(!is_valid_handoff_pipe_name(&upper));
        assert!(!is_valid_handoff_pipe_name(&short));
        assert!(!is_valid_handoff_pipe_name(r"\\.\pipe\mesh-agent-admin"));
        assert!(is_uac_cancelled_error(&cancelled));
        assert!(!is_uac_cancelled_error(&other));
        assert!(UnprivilegedSinkWriter::create(Path::new("out.tar"), 0).is_err());
    }

    #[test]
    fn test_gui_windows_sink_writer_atomic_replace_and_anti_toctou_lock() {
        // Arrange
        let Ok(dir) = tempdir() else {
            return;
        };
        let dest = dir.path().join("report.tar");
        assert!(fs::write(&dest, b"prior-report-bytes").is_ok());

        // Act 1: mid-stream drop leaves prior dest intact and cleans .part
        let writer = UnprivilegedSinkWriter::create(&dest, 10);
        assert!(
            writer.is_ok(),
            "UnprivilegedSinkWriter::create failed: {writer:?}"
        );
        let Ok(mut writer) = writer else {
            return;
        };
        let part_path = writer.temp_path().to_path_buf();
        assert!(part_path.exists());
        assert!(writer.write_chunk(b"12345").is_ok());
        drop(writer);

        assert!(!part_path.exists());
        assert_eq!(
            fs::read(&dest).ok().as_deref(),
            Some(&b"prior-report-bytes"[..])
        );

        // Act 2: complete stream atomically replaces dest
        let Ok(mut writer2) = UnprivilegedSinkWriter::create(&dest, 10) else {
            return;
        };
        assert!(writer2.write_chunk(b"0123456789").is_ok());
        let finalized = writer2.finalize();
        assert!(matches!(finalized, Ok(10)));
        assert_eq!(fs::read(&dest).ok().as_deref(), Some(&b"0123456789"[..]));

        // Act 3: anti-TOCTOU lock blocks concurrent write until dropped
        let locked = open_anti_toctou_read_locked(&dest);
        assert!(locked.is_ok());
        let write_while_locked = fs::OpenOptions::new().write(true).open(&dest);
        assert!(write_while_locked.is_err());
        drop(locked);
        assert!(fs::OpenOptions::new().write(true).open(&dest).is_ok());
    }

    #[test]
    fn test_gui_windows_creates_dpi_tray_icons_16_to_256px() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange & Act
        for px in [16, 24, 32, 64, 128, 256] {
            let icon = create_tray_status_icon(TrayStatusIconKind::Connected, px);
            assert!(
                icon.is_ok(),
                "create_tray_status_icon({px}) failed: {icon:?}"
            );
        }
    }

    #[test]
    fn test_init_common_controls_succeeds_on_windows() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange & Act
        let res = init_common_controls();

        // Assert
        assert!(res.is_ok(), "init_common_controls failed: {res:?}");
    }

    #[test]
    fn test_gdi_dwm_raii_and_safe_wrapper_stubs_on_windows() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange & Act
        let mem_dc = OwnedMemDc::from_compatible(0);
        let null_paint = PaintGuard::begin(0);
        let null_buf = create_double_buffer(0, 64, 32);
        apply_window_dark_titlebar(0, true);
        invalidate_window(0);
        let _light = read_windows_apps_use_light_theme();
        let _hc = detect_high_contrast();
        let _is_vi = detect_windows_system_locale_is_vi();

        // Assert
        assert!(null_paint.is_none());
        assert!(null_buf.is_none());
        if let Some(dc) = mem_dc {
            assert_ne!(dc.as_raw(), 0);
            assert!(format!("{dc:?}").starts_with("OwnedMemDc(0x"));
        }
    }

    #[test]
    fn test_gdi_obj_no_leak() {
        let _lock = GDI_TEST_LOCK.lock();
        let run_cycle = || {
            let brush = super::create_solid_brush(0x00FC_FAF8);
            let pen = super::create_solid_pen(1, 0x00E1_D5CB);
            let font = super::create_font_for_dpi("Segoe UI", 10, 400, 96);
            assert!(brush.is_some());
            assert!(pen.is_some());
            assert!(font.is_some());
            if let Some(dc) = OwnedMemDc::from_compatible(0) {
                let painted = super::with_double_buffer(dc.as_raw(), 160, 80, |mem_dc| {
                    if let (Some(b), Some(p), Some(f)) = (&brush, &pen, &font) {
                        let rect = super::ControlRect::new(4, 4, 152, 72);
                        super::draw_rounded_card(mem_dc, &rect, 8, b, p);
                        super::draw_status_pill(mem_dc, &rect, "Connected", b, 0x00FF_FFFF, f);
                    }
                });
                assert!(painted);
            }
        };

        // Arrange: warm up one-time process GDI32/ClearType/Uniscribe cache before baseline
        run_cycle();
        run_cycle();

        // Act: allocate brushes, pens, fonts, and double buffers across 16 cycles, then drop all.
        let mut zero_delta = false;
        let mut last_pair = (0_u32, 0_u32);
        for _attempt in 0..5 {
            let before = super::get_gui_resources_gdi_count();
            for _ in 0..16 {
                run_cycle();
            }
            let after = super::get_gui_resources_gdi_count();
            last_pair = (before, after);
            if after == before {
                zero_delta = true;
                break;
            }
        }

        // Assert: zero GDI handle delta after full RAII drop
        assert!(
            zero_delta,
            "GDI handle leak detected: before={}, after={}",
            last_pair.0, last_pair.1
        );
    }

    #[test]
    fn test_owned_mem_dc_lifecycle() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange: warm up one-time process GDI initialization
        drop(OwnedMemDc::from_compatible(0));
        let before = super::get_gui_resources_gdi_count();

        // Act
        {
            let mem_dc = OwnedMemDc::from_compatible(0);
            assert!(mem_dc.is_some());
            if let Some(dc) = mem_dc {
                assert_ne!(dc.as_raw(), 0);
                let buf = create_double_buffer(dc.as_raw(), 64, 32);
                assert!(buf.is_some());
                assert!(format!("{dc:?}").contains("OwnedMemDc("));
            }
        }

        // Assert
        let after = super::get_gui_resources_gdi_count();
        assert_eq!(after, before);
    }

    #[test]
    fn test_paint_guard_drop() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange & Act
        let guard_null = PaintGuard::begin(0);
        super::announce_accessible_label(0, "Accessible label no-op");

        // Assert
        assert!(guard_null.is_none());
    }

    #[test]
    fn test_detect_high_contrast_cbsize() {
        let _lock = GDI_TEST_LOCK.lock();
        // Arrange & Act
        let cb_size = super::high_contrast_struct_cb_size();
        let _hc = detect_high_contrast();

        // Assert: HIGHCONTRASTW is { cbSize: u32, dwFlags: u32, lpszDefaultScheme: *mut u16 }
        assert_eq!(
            usize::try_from(cb_size).unwrap_or(0),
            std::mem::size_of::<windows_sys::Win32::UI::Accessibility::HIGHCONTRASTW>()
        );
        assert!(cb_size >= 12);
    }

    #[test]
    fn test_ws_clipchildren_in_dwstyle() {
        // Arrange & Act
        let style = super::MAIN_WINDOW_STYLE;

        // Assert: WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN must live in dwStyle (ADR-027)
        assert_ne!(style & super::WIN_WS_CLIPCHILDREN, 0);
        assert_eq!(
            style & super::WIN_WS_OVERLAPPEDWINDOW,
            super::WIN_WS_OVERLAPPEDWINDOW
        );
        assert_eq!(super::calc_font_height_for_dpi(12, 96), -16);
        assert_eq!(super::calc_font_height_for_dpi(12, 144), -24);
        assert_eq!(super::calc_font_height_for_dpi(10, 192), -27);
    }
}
