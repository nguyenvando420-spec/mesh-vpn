//! Windows Wintun verified DLL loader and ring-buffer adapter wrapper (`US-015`, `ADR-011`).

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, RawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS,
    FILETIME, FreeLibrary, GetLastError, HANDLE, HMODULE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, GetFileInformationByHandle,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LoadLibraryExW,
};
use windows_sys::Win32::System::Threading::{SetEvent, WaitForSingleObject};
use windows_sys::core::{GUID, PCSTR, PCWSTR};

use crate::error::{SysError, SysResult};

/// Fixed Windows Wintun adapter name (`US-015 AC1/AC2`).
pub const DEFAULT_WINTUN_ADAPTER_NAME: &str = "MeshVPN";
/// Fixed Wintun tunnel type registered in Windows network configuration.
pub const DEFAULT_WINTUN_TUNNEL_TYPE: &str = "Mesh";
/// Fixed deterministic adapter GUID preventing ghost `#2` duplicate adapters (`US-015 AC2`).
pub const DEFAULT_WINTUN_GUID: u128 = 0x4d45_5348_5650_4e31_8000_0000_0000_0001;
/// Default Wintun ring buffer capacity (1 MiB, inside Wintun's `[128 KiB, 64 MiB]` range).
pub const DEFAULT_WINTUN_RING_CAPACITY: u32 = 0x0010_0000;
const MIN_RING_CAPACITY: u32 = 0x0002_0000;
const MAX_RING_CAPACITY: u32 = 0x0400_0000;

type WintunCreateAdapterFn = unsafe extern "system" fn(PCWSTR, PCWSTR, *const GUID) -> HANDLE;
type WintunOpenAdapterFn = unsafe extern "system" fn(PCWSTR) -> HANDLE;
type WintunCloseAdapterFn = unsafe extern "system" fn(HANDLE);
type WintunGetAdapterLuidFn = unsafe extern "system" fn(HANDLE, *mut NET_LUID_LH);
type WintunStartSessionFn = unsafe extern "system" fn(HANDLE, u32) -> HANDLE;
type WintunEndSessionFn = unsafe extern "system" fn(HANDLE);
type WintunGetReadWaitEventFn = unsafe extern "system" fn(HANDLE) -> HANDLE;
type WintunReceivePacketFn = unsafe extern "system" fn(HANDLE, *mut u32) -> *const u8;
type WintunReleaseReceivePacketFn = unsafe extern "system" fn(HANDLE, *const u8);
type WintunAllocateSendPacketFn = unsafe extern "system" fn(HANDLE, u32) -> *mut u8;
type WintunSendPacketFn = unsafe extern "system" fn(HANDLE, *const u8);

macro_rules! load_wintun_sym {
    ($module:expr, $sym:expr, $fn_ty:ty, $op:expr) => {{
        // SAFETY: `$module` is a live module handle loaded by `WintunDll` and `$sym` is NUL-terminated.
        let proc = unsafe { GetProcAddress($module, $sym.as_ptr().cast::<u8>() as PCSTR) };
        match proc {
            Some(func) => {
                // SAFETY: `Wintun` 0.14 exports these symbols with the exact `extern "system"` ABI.
                Ok(unsafe {
                    core::mem::transmute::<unsafe extern "system" fn() -> isize, $fn_ty>(func)
                })
            }
            None => Err(SysError::io($op, io::Error::last_os_error())),
        }
    }};
}

/// Verified `wintun.dll` handle loaded strictly from an explicit path via
/// `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`.
pub struct WintunDll {
    module: HMODULE,
    create_adapter: WintunCreateAdapterFn,
    open_adapter: WintunOpenAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    get_adapter_luid: WintunGetAdapterLuidFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    get_read_wait_event: WintunGetReadWaitEventFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
}

// SAFETY: Resolved Win32 `wintun.dll` entry points remain immutable until `FreeLibrary` runs in
// `Drop` after all dependent adapters and sessions have been dropped.
unsafe impl Send for WintunDll {}
// SAFETY: Function pointers inside `WintunDll` are read-only and Wintun's C API is thread-safe.
unsafe impl Sync for WintunDll {}

impl fmt::Debug for WintunDll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunDll").finish_non_exhaustive()
    }
}

impl Drop for WintunDll {
    fn drop(&mut self) {
        if !self.module.is_null() {
            // SAFETY: `self.module` was returned by `LoadLibraryExW` and is owned solely by `self`.
            let _freed = unsafe { FreeLibrary(self.module) };
        }
    }
}

/// Live Wintun network adapter handle keeping `WintunDll` pinned for its lifetime.
pub struct WintunAdapter {
    dll: Arc<WintunDll>,
    handle: HANDLE,
    name: String,
    guid: u128,
}

// SAFETY: Wintun adapter handles are kernel/driver object handles owned cleanly until `Drop`.
unsafe impl Send for WintunAdapter {}
// SAFETY: Operations synchronize via `&self` or immutable handle queries; handle closes only in `Drop`.
unsafe impl Sync for WintunAdapter {}

impl fmt::Debug for WintunAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunAdapter")
            .field("name", &self.name)
            .field("guid", &format_args!("{:032x}", self.guid))
            .finish_non_exhaustive()
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: `self.handle` was created/opened via `self.dll` and not yet closed.
            unsafe { (self.dll.close_adapter)(self.handle) };
        }
    }
}

/// Active Wintun ring-buffer session holding `Arc<WintunAdapter>` so drop order is strictly
/// `Session` -> `Adapter` -> `WintunDll`.
pub struct WintunSession {
    adapter: Arc<WintunAdapter>,
    handle: HANDLE,
    read_wait_event: HANDLE,
}

// SAFETY: Session handles serialize RX/TX safely across worker tasks; `WintunEndSession` runs once in `Drop`.
unsafe impl Send for WintunSession {}
// SAFETY: Shared callers access Wintun thread-safe session calls and wait handles.
unsafe impl Sync for WintunSession {}

impl fmt::Debug for WintunSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WintunSession")
            .field("adapter", &self.adapter)
            .finish_non_exhaustive()
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: `self.handle` was started via `WintunStartSession` on live `self.adapter`.
            unsafe { (self.adapter.dll.end_session)(self.handle) };
        }
    }
}

/// Kernel NTFS read-locked handle on a verified `wintun.dll` regular file (`BLK-S1-09`).
///
/// Holding this guard keeps `FILE_SHARE_READ` open across `mesh-crypto` SHA-256 verification and
/// `LoadLibraryExW`, preventing concurrent overwrite, rename, or deletion (anti-TOCTOU).
#[derive(Debug)]
pub struct LockedWintunFile {
    file: File,
    path: PathBuf,
}

impl LockedWintunFile {
    /// Opens `dll_path` with `FILE_SHARE_READ` + `FILE_FLAG_OPEN_REPARSE_POINT` and verifies
    /// absolute path hygiene, filename `wintun.dll`, regular-file type, and non-reparse attributes.
    ///
    /// When `require_app_dir` is `true`, also enforces that `dll_path` resides directly inside
    /// the current executable directory.
    pub fn open(dll_path: &Path, require_app_dir: bool) -> SysResult<Self> {
        const OP: &str = "tun_windows::LockedWintunFile::open";
        validate_wintun_path_hygiene(dll_path, require_app_dir, OP)?;

        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dll_path)
            .map_err(|err| map_win_open_error(OP, err))?;

        verify_locked_handle_attributes(&file, dll_path, OP)?;

        Ok(Self {
            file,
            path: dll_path.to_path_buf(),
        })
    }

    /// Returns the validated absolute path of the locked `wintun.dll` file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrows the locked read-only `File` handle for streaming verification.
    #[must_use]
    pub const fn file(&self) -> &File {
        &self.file
    }

    /// Mutably borrows the locked `File` handle (e.g. for seeking and hashing before `LoadLibraryExW`).
    #[must_use]
    pub const fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

/// Returns the expected application-local `wintun.dll` path next to the running executable.
pub fn resolve_app_wintun_path() -> SysResult<PathBuf> {
    const OP: &str = "tun_windows::resolve_app_wintun_path";
    let exe = std::env::current_exe().map_err(|err| SysError::io(OP, err))?;
    let parent = exe.parent().ok_or_else(|| {
        SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::NotFound,
                "executable path has no parent directory",
            ),
        )
    })?;
    Ok(parent.join("wintun.dll"))
}

impl WintunDll {
    /// Loads `wintun.dll` using `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` while keeping the caller's
    /// `FILE_SHARE_READ` lock (`locked`) held open across the `LoadLibraryExW` call (`BLK-S1-09`).
    ///
    /// Callers in `mesh-net` MUST have already verified the SHA-256 digest of `locked` via
    /// `mesh-crypto` before invoking this method.
    pub fn load_with_read_lock(locked: &LockedWintunFile) -> SysResult<Arc<Self>> {
        const OP: &str = "tun_windows::WintunDll::load_with_read_lock";
        validate_wintun_path_hygiene(locked.path(), false, OP)?;
        verify_locked_handle_attributes(locked.file(), locked.path(), OP)?;

        let wide = encode_utf16_nul(locked.path().as_os_str(), OP)?;
        // SAFETY: `wide` is NUL-terminated UTF-16 pointing to the locked non-reparse `wintun.dll`;
        // `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` forbids `PATH` and current-directory probing.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
            )
        };
        if module.is_null() {
            let err = io::Error::last_os_error();
            return Err(map_win_open_error(OP, err));
        }

        // Guard ensures `FreeLibrary` runs if any symbol lookup below fails.
        let mut dll = Self {
            module,
            create_adapter: noop_create_adapter,
            open_adapter: noop_open_adapter,
            close_adapter: noop_close_adapter,
            get_adapter_luid: noop_get_luid,
            start_session: noop_start_session,
            end_session: noop_end_session,
            get_read_wait_event: noop_get_event,
            receive_packet: noop_receive_packet,
            release_receive_packet: noop_release_packet,
            allocate_send_packet: noop_alloc_send,
            send_packet: noop_send_packet,
        };

        dll.create_adapter =
            load_wintun_sym!(module, c"WintunCreateAdapter", WintunCreateAdapterFn, OP)?;
        dll.open_adapter = load_wintun_sym!(module, c"WintunOpenAdapter", WintunOpenAdapterFn, OP)?;
        dll.close_adapter =
            load_wintun_sym!(module, c"WintunCloseAdapter", WintunCloseAdapterFn, OP)?;
        dll.get_adapter_luid =
            load_wintun_sym!(module, c"WintunGetAdapterLUID", WintunGetAdapterLuidFn, OP)?;
        dll.start_session =
            load_wintun_sym!(module, c"WintunStartSession", WintunStartSessionFn, OP)?;
        dll.end_session = load_wintun_sym!(module, c"WintunEndSession", WintunEndSessionFn, OP)?;
        dll.get_read_wait_event = load_wintun_sym!(
            module,
            c"WintunGetReadWaitEvent",
            WintunGetReadWaitEventFn,
            OP
        )?;
        dll.receive_packet =
            load_wintun_sym!(module, c"WintunReceivePacket", WintunReceivePacketFn, OP)?;
        dll.release_receive_packet = load_wintun_sym!(
            module,
            c"WintunReleaseReceivePacket",
            WintunReleaseReceivePacketFn,
            OP
        )?;
        dll.allocate_send_packet = load_wintun_sym!(
            module,
            c"WintunAllocateSendPacket",
            WintunAllocateSendPacketFn,
            OP
        )?;
        dll.send_packet = load_wintun_sym!(module, c"WintunSendPacket", WintunSendPacketFn, OP)?;
        Ok(Arc::new(dll))
    }
}

impl WintunAdapter {
    /// Reuses an existing fixed-name adapter or creates a new one using fixed `guid`, avoiding `#2`
    /// ghost adapters (`US-015 AC2`). Returns `PermissionDenied` if Administrator rights are missing.
    pub fn open_or_create(dll: &Arc<WintunDll>, name: &str, guid: u128) -> SysResult<Arc<Self>> {
        const OP: &str = "tun_windows::WintunAdapter::open_or_create";
        if name.is_empty() || name.contains('\0') {
            return Err(SysError::io(
                OP,
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Wintun adapter name"),
            ));
        }

        let wide_name = encode_utf16_nul(&OsString::from(name), OP)?;
        let wide_type = encode_utf16_nul(&OsString::from(DEFAULT_WINTUN_TUNNEL_TYPE), OP)?;
        let win_guid = guid_from_u128(guid);

        // SAFETY: `wide_name` is a valid NUL-terminated UTF-16 string and `dll` holds a valid proc.
        let existing = unsafe { (dll.open_adapter)(wide_name.as_ptr()) };
        let handle = if !existing.is_null() {
            existing
        } else {
            // SAFETY: `GetLastError` queries the thread-local Win32 error code from `WintunOpenAdapter`.
            let open_err = unsafe { GetLastError() };
            if open_err == ERROR_ACCESS_DENIED {
                return Err(SysError::PermissionDenied { operation: OP });
            }
            if open_err != ERROR_FILE_NOT_FOUND && open_err != 0 {
                tracing::debug!(
                    target: "mesh::sys::tun_windows",
                    error_code = open_err,
                    adapter = %name,
                    "WintunOpenAdapter did not find reusable adapter; attempting creation"
                );
            }
            // SAFETY: `wide_name` and `wide_type` are NUL-terminated UTF-16 strings; `win_guid`
            // lives across the synchronous `WintunCreateAdapter` FFI call.
            let created = unsafe {
                (dll.create_adapter)(wide_name.as_ptr(), wide_type.as_ptr(), &raw const win_guid)
            };
            if created.is_null() {
                let err = io::Error::last_os_error();
                return Err(map_win_open_error(OP, err));
            }
            created
        };

        Ok(Arc::new(Self {
            dll: Arc::clone(dll),
            handle,
            name: name.to_owned(),
            guid,
        }))
    }

    /// Returns the fixed adapter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the adapter's Windows `NET_LUID.Value`.
    #[must_use]
    pub fn luid_value(&self) -> u64 {
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: `self.handle` is an open adapter handle and `luid` points to writable stack storage.
        unsafe { (self.dll.get_adapter_luid)(self.handle, &raw mut luid) };
        // SAFETY: `NET_LUID_LH.Value` is a plain `u64` union view initialized by `WintunGetAdapterLUID`.
        unsafe { luid.Value }
    }

    /// Resolves the Windows IPv4/IPv6 interface index (`ifIndex`) for this Wintun adapter.
    pub fn interface_index(&self) -> SysResult<u32> {
        const OP: &str = "tun_windows::WintunAdapter::interface_index";
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: `self.handle` is valid and `luid` is writable.
        unsafe { (self.dll.get_adapter_luid)(self.handle, &raw mut luid) };
        let mut if_index: u32 = 0;
        // SAFETY: `luid` is initialized and `if_index` points to a stack `u32`.
        let status = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut if_index) };
        if status != 0 {
            let err = io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX));
            return Err(SysError::io(OP, err));
        }
        Ok(if_index)
    }

    /// Starts a Wintun ring-buffer session (`capacity` must be a power of two within Wintun bounds).
    pub fn start_session(self: &Arc<Self>, capacity: u32) -> SysResult<WintunSession> {
        const OP: &str = "tun_windows::WintunAdapter::start_session";
        if !capacity.is_power_of_two()
            || !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&capacity)
        {
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Wintun ring capacity must be a power of two in [128 KiB, 64 MiB]",
                ),
            ));
        }

        // SAFETY: `self.handle` is a valid Wintun adapter handle owned by `Arc<Self>`.
        let session = unsafe { (self.dll.start_session)(self.handle, capacity) };
        if session.is_null() {
            return Err(map_win_open_error(OP, io::Error::last_os_error()));
        }

        // SAFETY: `session` was just returned by `WintunStartSession` and remains owned by `WintunSession`.
        let wait_event = unsafe { (self.dll.get_read_wait_event)(session) };
        if wait_event.is_null() {
            // SAFETY: Close partial session handle before bubbling up error.
            unsafe { (self.dll.end_session)(session) };
            return Err(SysError::io(OP, io::Error::last_os_error()));
        }

        Ok(WintunSession {
            adapter: Arc::clone(self),
            handle: session,
            read_wait_event: wait_event,
        })
    }
}

impl WintunSession {
    /// Returns the raw Windows manual/auto-reset event handle signaled when packets arrive.
    #[must_use]
    pub fn read_wait_event(&self) -> RawHandle {
        self.read_wait_event as RawHandle
    }

    /// Waits up to `timeout_ms` for packets on the receive ring (`false` on timeout).
    pub fn wait_readable(&self, timeout_ms: u32) -> SysResult<bool> {
        const OP: &str = "tun_windows::WintunSession::wait_readable";
        // SAFETY: `self.read_wait_event` is owned by the live `WintunSession` handle.
        let status = unsafe { WaitForSingleObject(self.read_wait_event, timeout_ms) };
        if status == WAIT_OBJECT_0 {
            Ok(true)
        } else if status == WAIT_TIMEOUT {
            Ok(false)
        } else {
            Err(SysError::io(OP, io::Error::last_os_error()))
        }
    }

    /// Signals the read-wait event so a blocked background RX thread wakes immediately on close.
    pub fn wake_reader(&self) -> SysResult<()> {
        const OP: &str = "tun_windows::WintunSession::wake_reader";
        if self.read_wait_event.is_null() {
            return Ok(());
        }
        // SAFETY: `self.read_wait_event` remains owned by `self` until `WintunEndSession` in `Drop`.
        let ok = unsafe { SetEvent(self.read_wait_event) };
        if ok == 0 {
            return Err(SysError::io(OP, io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Attempts a non-blocking receive from the Wintun ring buffer into `out_buf`.
    pub fn try_receive_packet(&self, out_buf: &mut [u8]) -> SysResult<Option<usize>> {
        const OP: &str = "tun_windows::WintunSession::try_receive_packet";
        let mut size: u32 = 0;
        // SAFETY: `self.handle` is a live Wintun session and `size` points to a stack `u32`.
        let pkt_ptr = unsafe { (self.adapter.dll.receive_packet)(self.handle, &raw mut size) };
        if pkt_ptr.is_null() {
            // SAFETY: `GetLastError` reads the thread-local error set by `WintunReceivePacket`.
            let code = unsafe { GetLastError() };
            if code == ERROR_NO_MORE_ITEMS {
                return Ok(None);
            }
            return Err(SysError::io(
                OP,
                io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
            ));
        }

        let len = usize::try_from(size).unwrap_or(usize::MAX);
        let result = if let Some(dst) = out_buf.get_mut(..len) {
            // SAFETY: `WintunReceivePacket` grants shared read access to `len` valid bytes at `pkt_ptr`
            // until `WintunReleaseReceivePacket` is called below; `dst` is non-overlapping.
            unsafe { ptr::copy_nonoverlapping(pkt_ptr, dst.as_mut_ptr(), len) };
            Ok(Some(len))
        } else {
            Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "incoming packet exceeds receive buffer capacity",
                ),
            ))
        };

        // SAFETY: `pkt_ptr` was returned by `WintunReceivePacket` and must always be released.
        unsafe { (self.adapter.dll.release_receive_packet)(self.handle, pkt_ptr) };
        result
    }

    /// Sends one complete IP packet through the Wintun transmit ring buffer.
    pub fn send_packet(&self, packet: &[u8]) -> SysResult<()> {
        const OP: &str = "tun_windows::WintunSession::send_packet";
        if packet.is_empty() || packet.len() > usize::from(u16::MAX) {
            return Err(SysError::io(
                OP,
                io::Error::new(io::ErrorKind::InvalidInput, "invalid IP packet length"),
            ));
        }
        let len_u32 = u32::try_from(packet.len()).map_err(|_| {
            SysError::io(
                OP,
                io::Error::new(io::ErrorKind::InvalidInput, "packet length overflow"),
            )
        })?;

        // SAFETY: `self.handle` is a valid active Wintun session.
        let ring_ptr = unsafe { (self.adapter.dll.allocate_send_packet)(self.handle, len_u32) };
        if ring_ptr.is_null() {
            // SAFETY: `GetLastError` reports ring overflow or shutdown after failed allocation.
            let code = unsafe { GetLastError() };
            if code == ERROR_BUFFER_OVERFLOW {
                return Err(SysError::io(
                    OP,
                    io::Error::new(io::ErrorKind::WouldBlock, "Wintun TX ring buffer is full"),
                ));
            }
            return Err(SysError::io(
                OP,
                io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
            ));
        }

        // SAFETY: `ring_ptr` owns `len_u32` writable bytes inside the Wintun ring until
        // `WintunSendPacket` publishes it; `packet` does not overlap ring memory.
        unsafe {
            ptr::copy_nonoverlapping(packet.as_ptr(), ring_ptr, packet.len());
            (self.adapter.dll.send_packet)(self.handle, ring_ptr);
        }
        Ok(())
    }
}

fn validate_wintun_path_hygiene(
    dll_path: &Path,
    require_app_dir: bool,
    operation: &'static str,
) -> SysResult<()> {
    if !dll_path.is_absolute()
        || dll_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "wintun.dll path must be canonical and absolute".to_owned(),
        });
    }
    let valid_name = dll_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("wintun.dll"));
    if !valid_name {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "DLL file name must be wintun.dll".to_owned(),
        });
    }
    let parent = dll_path
        .parent()
        .ok_or_else(|| SysError::SecurityViolation {
            operation,
            detail: "wintun.dll path must include a parent directory".to_owned(),
        })?;
    let parent_meta =
        fs::symlink_metadata(parent).map_err(|err| map_win_open_error(operation, err))?;
    if parent_meta.file_type().is_symlink()
        || (parent_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "wintun.dll parent directory cannot be a symlink or reparse point".to_owned(),
        });
    }
    if require_app_dir {
        let app_dll = resolve_app_wintun_path()?;
        let app_parent = app_dll
            .parent()
            .ok_or_else(|| SysError::SecurityViolation {
                operation,
                detail: "application executable directory could not be resolved".to_owned(),
            })?;
        let canon_parent =
            fs::canonicalize(parent).map_err(|err| map_win_open_error(operation, err))?;
        let canon_app_parent =
            fs::canonicalize(app_parent).map_err(|err| map_win_open_error(operation, err))?;
        if canon_parent != canon_app_parent {
            return Err(SysError::SecurityViolation {
                operation,
                detail: "wintun.dll must reside inside the application executable directory"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_locked_handle_attributes(
    file: &File,
    dll_path: &Path,
    operation: &'static str,
) -> SysResult<()> {
    let link_meta =
        fs::symlink_metadata(dll_path).map_err(|err| map_win_open_error(operation, err))?;
    if link_meta.file_type().is_symlink()
        || (link_meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "wintun.dll path cannot be a symlink or reparse point".to_owned(),
        });
    }
    let meta = file
        .metadata()
        .map_err(|err| SysError::io(operation, err))?;
    if !meta.is_file() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "wintun.dll handle must refer to a regular non-reparse file".to_owned(),
        });
    }

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
    // SAFETY: `file` owns an open kernel file handle and `info` is valid writable stack storage.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &raw mut info) };
    if ok == 0 {
        return Err(SysError::io(operation, io::Error::last_os_error()));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(SysError::SecurityViolation {
            operation,
            detail: "wintun.dll handle points to a filesystem reparse point".to_owned(),
        });
    }
    Ok(())
}

fn map_win_open_error(operation: &'static str, err: io::Error) -> SysError {
    if err.kind() == io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(i32::try_from(ERROR_ACCESS_DENIED).unwrap_or(5))
    {
        return SysError::PermissionDenied { operation };
    }
    SysError::io(operation, err)
}

fn encode_utf16_nul(value: &std::ffi::OsStr, operation: &'static str) -> SysResult<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(SysError::io(
            operation,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "string contains interior NUL byte",
            ),
        ));
    }
    wide.push(0);
    Ok(wide)
}

const fn guid_from_u128(value: u128) -> GUID {
    let data1 = (value >> 96) as u32;
    let data2 = ((value >> 80) & 0xffff) as u16;
    let data3 = ((value >> 64) & 0xffff) as u16;
    let data4 = (value as u64).to_be_bytes();
    GUID {
        data1,
        data2,
        data3,
        data4,
    }
}

// Placeholder stubs used only transiently during `WintunDll` struct initialization before symbol lookup.
unsafe extern "system" fn noop_create_adapter(_: PCWSTR, _: PCWSTR, _: *const GUID) -> HANDLE {
    ptr::null_mut()
}
unsafe extern "system" fn noop_open_adapter(_: PCWSTR) -> HANDLE {
    ptr::null_mut()
}
unsafe extern "system" fn noop_close_adapter(_: HANDLE) {}
unsafe extern "system" fn noop_get_luid(_: HANDLE, _: *mut NET_LUID_LH) {}
unsafe extern "system" fn noop_start_session(_: HANDLE, _: u32) -> HANDLE {
    ptr::null_mut()
}
unsafe extern "system" fn noop_end_session(_: HANDLE) {}
unsafe extern "system" fn noop_get_event(_: HANDLE) -> HANDLE {
    ptr::null_mut()
}
unsafe extern "system" fn noop_receive_packet(_: HANDLE, _: *mut u32) -> *const u8 {
    ptr::null()
}
unsafe extern "system" fn noop_release_packet(_: HANDLE, _: *const u8) {}
unsafe extern "system" fn noop_alloc_send(_: HANDLE, _: u32) -> *mut u8 {
    ptr::null_mut()
}
unsafe extern "system" fn noop_send_packet(_: HANDLE, _: *const u8) {}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::path::Path;

    use tempfile::tempdir;

    use super::{LockedWintunFile, SysError, WintunDll, guid_from_u128};

    #[test]
    fn test_tun_windows_read_lock_blocks_concurrent_overwrite_until_dropped() {
        // Arrange
        let dir = tempdir();
        assert!(dir.is_ok());
        let Ok(dir) = dir else {
            return;
        };
        let dll = dir.path().join("wintun.dll");
        assert!(fs::write(&dll, b"tamper-protected-wintun-stub").is_ok());

        // Act: hold FILE_SHARE_READ kernel lock cleanly, verify concurrent write/load semantics.
        let locked = LockedWintunFile::open(&dll, false);
        assert!(locked.is_ok(), "LockedWintunFile::open failed: {locked:?}");
        let Ok(locked) = locked else {
            return;
        };

        let concurrent_write = OpenOptions::new().write(true).open(&dll);
        let concurrent_rename = fs::rename(&dll, dir.path().join("renamed.dll"));
        // Even with non-PE bytes, LoadLibraryExW runs ONLY after caller finishes hashing; here we
        // expect an OS IO error (BadExeFormat / InvalidImage), NOT a file sharing failure.
        let load_non_pe = WintunDll::load_with_read_lock(&locked);

        // Assert
        assert!(
            concurrent_write.is_err(),
            "FILE_SHARE_READ lock must forbid concurrent writes"
        );
        assert!(
            concurrent_rename.is_err(),
            "FILE_SHARE_READ lock must forbid concurrent renames"
        );
        assert!(matches!(load_non_pe, Err(SysError::Io { .. })));

        drop(locked);
        assert!(OpenOptions::new().write(true).open(&dll).is_ok());
    }

    #[test]
    fn test_tun_windows_rejects_relative_parent_traversal_and_non_wintun_paths() {
        // Arrange
        let dir = tempdir();
        assert!(dir.is_ok());
        let Ok(dir) = dir else {
            return;
        };
        let wrong_name = dir.path().join("evil.dll");
        let real_dll = dir.path().join("wintun.dll");
        assert!(fs::write(&wrong_name, b"abc").is_ok());
        assert!(fs::write(&real_dll, b"abc").is_ok());

        // Act
        let rel_res = LockedWintunFile::open(Path::new("wintun.dll"), false);
        let name_res = LockedWintunFile::open(&wrong_name, false);
        let outside_app_res = LockedWintunFile::open(&real_dll, true);

        // Assert
        assert!(matches!(rel_res, Err(SysError::SecurityViolation { .. })));
        assert!(matches!(name_res, Err(SysError::SecurityViolation { .. })));
        assert!(matches!(
            outside_app_res,
            Err(SysError::SecurityViolation { .. })
        ));
    }

    #[test]
    fn test_tun_windows_fixed_guid_encoding_is_deterministic() {
        // Arrange
        let raw = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10_u128;

        // Act
        let guid = guid_from_u128(raw);

        // Assert
        assert_eq!(guid.data1, 0x0102_0304);
        assert_eq!(guid.data2, 0x0506);
        assert_eq!(guid.data3, 0x0708);
        assert_eq!(guid.data4, [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]);
    }
}
