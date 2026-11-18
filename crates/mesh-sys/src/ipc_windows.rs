//! Windows Named Pipe creation with `FILE_FLAG_FIRST_PIPE_INSTANCE` and explicit SDDL (`WP-S1-04`).

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{
    AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle,
};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_CANNOT_IMPERSONATE, ERROR_INSUFFICIENT_BUFFER,
    ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GetLastError,
    HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateTokenEx, GetTokenInformation, PSID,
    RevertToSelf, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SecurityIdentification,
    TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenImpersonation, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::error::{SysError, SysResult};

/// Protected SDDL ACL restricting Admin Named Pipe strictly to LocalSystem (`SY`) and Builtin Admins (`BA`).
pub const ADMIN_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// Protected SDDL ACL allowing read-only IPC queries from Authenticated Users (`AU`) alongside `SY` and `BA`.
pub const RO_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

const PIPE_BUFFER_BYTES: u32 = 16 * 1024;

/// Named Pipe security ACL tier matching `api-design.md` §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeAclMode {
    /// Read-only pipe (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`).
    ReadOnly,
    /// Privileged Admin pipe (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`).
    Admin,
    /// Server Admin pipe (`SY` + `BA` + current server process owner SID when resolved).
    ServerAdmin,
}

/// Verified Windows Named Pipe client token flags (`S-1-5-32-544` BA and `S-1-5-18` SY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPeerCredentials {
    /// Caller holds Builtin Administrators (`BA`).
    pub is_builtin_admin: bool,
    /// Caller holds LocalSystem (`SY`).
    pub is_local_system: bool,
    /// Non-secret caller SID string for audit logs.
    pub principal: String,
}

/// Safe overlapped Named Pipe server instance bound with an explicit SDDL DACL.
#[derive(Debug)]
pub struct SecuredPipeServer {
    handle: OwnedHandle,
}

impl SecuredPipeServer {
    /// Binds a new SDDL-secured Named Pipe server instance (`first_instance = true` rejects squatters).
    pub fn bind(pipe_name: &str, mode: PipeAclMode, first_instance: bool) -> SysResult<Self> {
        let handle = create_secured_named_pipe_instance(pipe_name, mode, first_instance)?;
        Ok(Self { handle })
    }

    /// Waits synchronously via overlapped I/O until a client connects to this pipe instance.
    pub fn accept_blocking(&self) -> SysResult<()> {
        const OP: &str = "ipc_windows::SecuredPipeServer::accept_blocking";
        let (event, mut ov) = create_overlapped_event(OP)?;
        // SAFETY: `self.handle` is opened with `FILE_FLAG_OVERLAPPED` and `ov` stays pinned in
        // this stack frame until `GetOverlappedResult(..., TRUE)` finishes or immediate completion returns.
        let ok = unsafe { ConnectNamedPipe(self.handle.as_raw_handle(), &raw mut ov) };
        if ok != 0 {
            return Ok(());
        }
        // SAFETY: Reads last Win32 error set by `ConnectNamedPipe`.
        let code = unsafe { GetLastError() };
        if code == ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        if code == ERROR_IO_PENDING {
            let mut transferred: u32 = 0;
            // SAFETY: `self.handle` and `ov` (backed by live `event`) remain valid during wait.
            let done = unsafe {
                GetOverlappedResult(
                    self.handle.as_raw_handle(),
                    &raw const ov,
                    &raw mut transferred,
                    1,
                )
            };
            drop(event);
            if done == 0 {
                return Err(map_overlapped_wait_error(OP, io::Error::last_os_error()));
            }
            return Ok(());
        }
        drop(event);
        Err(map_win_error(
            OP,
            io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
        ))
    }

    /// Inspects the connected peer's security token SIDs without relying on pipe names alone.
    pub fn inspect_peer(&self) -> SysResult<WindowsPeerCredentials> {
        inspect_named_pipe_peer(self.handle.as_handle())
    }

    /// Reads bytes from the connected pipe using per-call overlapped I/O (`0` indicates clean EOF).
    pub fn read_blocking(&self, buf: &mut [u8]) -> SysResult<usize> {
        const OP: &str = "ipc_windows::SecuredPipeServer::read_blocking";
        if buf.is_empty() {
            return Ok(0);
        }
        let max_read = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let (event, mut ov) = create_overlapped_event(OP)?;
        let mut bytes_read: u32 = 0;
        // SAFETY: `self.handle` is valid, `buf` holds `max_read` writable bytes across the wait,
        // and `ov` owns `event` for the duration of the overlapped read.
        let ok = unsafe {
            ReadFile(
                self.handle.as_raw_handle(),
                buf.as_mut_ptr(),
                max_read,
                &raw mut bytes_read,
                &raw mut ov,
            )
        };
        if ok != 0 {
            return Ok(usize::try_from(bytes_read).unwrap_or(usize::MAX));
        }
        // SAFETY: Reads thread-local error code from `ReadFile`.
        let code = unsafe { GetLastError() };
        if code == ERROR_BROKEN_PIPE || code == ERROR_NO_DATA {
            return Ok(0);
        }
        if code != ERROR_IO_PENDING {
            return Err(map_overlapped_wait_error(
                OP,
                io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
            ));
        }
        let mut transferred: u32 = 0;
        // SAFETY: `buf` and `ov` remain pinned until `GetOverlappedResult(..., TRUE)` completes.
        let done = unsafe {
            GetOverlappedResult(
                self.handle.as_raw_handle(),
                &raw const ov,
                &raw mut transferred,
                1,
            )
        };
        drop(event);
        if done == 0 {
            let err = io::Error::last_os_error();
            if is_eof_pipe_error(&err) {
                return Ok(0);
            }
            return Err(map_overlapped_wait_error(OP, err));
        }
        Ok(usize::try_from(transferred).unwrap_or(usize::MAX))
    }

    /// Writes bytes to the connected pipe using per-call overlapped I/O.
    pub fn write_blocking(&self, data: &[u8]) -> SysResult<usize> {
        const OP: &str = "ipc_windows::SecuredPipeServer::write_blocking";
        if data.is_empty() {
            return Ok(0);
        }
        let max_write = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let (event, mut ov) = create_overlapped_event(OP)?;
        let mut written: u32 = 0;
        // SAFETY: `data` holds `max_write` readable bytes until overlapped write finishes below.
        let ok = unsafe {
            WriteFile(
                self.handle.as_raw_handle(),
                data.as_ptr(),
                max_write,
                &raw mut written,
                &raw mut ov,
            )
        };
        if ok != 0 {
            return Ok(usize::try_from(written).unwrap_or(usize::MAX));
        }
        // SAFETY: Reads thread-local error code from `WriteFile`.
        let code = unsafe { GetLastError() };
        if code != ERROR_IO_PENDING {
            return Err(map_overlapped_wait_error(
                OP,
                io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX)),
            ));
        }
        let mut transferred: u32 = 0;
        // SAFETY: `data` and `ov` stay valid until `GetOverlappedResult(..., TRUE)` completes.
        let done = unsafe {
            GetOverlappedResult(
                self.handle.as_raw_handle(),
                &raw const ov,
                &raw mut transferred,
                1,
            )
        };
        drop(event);
        if done == 0 {
            return Err(map_overlapped_wait_error(OP, io::Error::last_os_error()));
        }
        Ok(usize::try_from(transferred).unwrap_or(usize::MAX))
    }

    /// Cancels all pending overlapped operations on this pipe handle (for graceful shutdown).
    pub fn cancel_io(&self) {
        // SAFETY: `self.handle` is an open handle owned by `self`; `CancelIoEx(..., null)` wakes
        // blocked threads cleanly during shutdown.
        let _cancelled = unsafe { CancelIoEx(self.handle.as_raw_handle(), ptr::null()) };
    }

    /// Borrows the underlying pipe handle safely.
    #[must_use]
    pub fn as_handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }
}

struct LocalAllocGuard(*mut c_void);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by a Win32 API using `LocalAlloc`.
            let rem = unsafe { LocalFree(self.0 as HLOCAL) };
            if !rem.is_null() {
                tracing::error!(
                    target: "mesh::sys::ipc_windows",
                    "LocalFree failed to release security buffer"
                );
            }
        }
    }
}

struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        // SAFETY: `RevertToSelf` restores the thread's primary security context after impersonation.
        let ok = unsafe { RevertToSelf() };
        if ok == 0 {
            tracing::error!(
                target: "mesh::sys::ipc_windows",
                error = %io::Error::last_os_error(),
                "RevertToSelf failed after Named Pipe client inspection"
            );
        }
    }
}

/// Returns the SDDL DACL string enforcing `mode`.
#[must_use]
pub const fn sddl_for_pipe_mode(mode: PipeAclMode) -> &'static str {
    match mode {
        PipeAclMode::ReadOnly => RO_PIPE_SDDL,
        PipeAclMode::Admin | PipeAclMode::ServerAdmin => ADMIN_PIPE_SDDL,
    }
}

/// Returns the SID string (e.g. `S-1-5-21-...`) of the current process's user account.
pub fn current_process_user_sid() -> SysResult<String> {
    const OP: &str = "ipc_windows::current_process_user_sid";
    let mut token_raw: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle; `token_raw` receives an owned token.
    let tok_ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token_raw) };
    if tok_ok == 0 || token_raw.is_null() || token_raw == INVALID_HANDLE_VALUE {
        return Err(map_win_error(OP, io::Error::last_os_error()));
    }
    // SAFETY: `token_raw` is a fresh owned kernel token returned by `OpenProcessToken`.
    let token = unsafe { OwnedHandle::from_raw_handle(token_raw) };
    query_token_user_sid_string(token.as_raw_handle(), OP)
}

/// Creates the first instance of a Windows Named Pipe enforcing `FILE_FLAG_FIRST_PIPE_INSTANCE`
/// and the explicit SDDL DACL (`api-design.md` §5.1).
pub fn create_secured_named_pipe(pipe_name: &str, mode: PipeAclMode) -> SysResult<OwnedHandle> {
    create_secured_named_pipe_instance(pipe_name, mode, true)
}

/// Creates a Named Pipe server instance with explicit SDDL DACL (`PIPE_REJECT_REMOTE_CLIENTS`).
///
/// Set `first_instance = true` on the initial bind so Windows rejects pre-squatted pipes.
pub fn create_secured_named_pipe_instance(
    pipe_name: &str,
    mode: PipeAclMode,
    first_instance: bool,
) -> SysResult<OwnedHandle> {
    const OP: &str = "ipc_windows::create_secured_named_pipe";
    validate_pipe_name(pipe_name, OP)?;

    let sddl_string = if mode == PipeAclMode::ServerAdmin
        && let Ok(sid) = current_process_user_sid()
        && sid.starts_with("S-1-")
        && sid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})")
    } else {
        sddl_for_pipe_mode(mode).to_owned()
    };
    let sddl_wide = to_wide_nul(&sddl_string, OP)?;
    let mut sd_ptr: *mut c_void = ptr::null_mut();
    // SAFETY: `sddl_wide` is NUL-terminated UTF-16 and `sd_ptr` receives a `LocalAlloc` descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd_ptr,
            ptr::null_mut(),
        )
    };
    if ok == 0 || sd_ptr.is_null() {
        return Err(map_win_error(OP, io::Error::last_os_error()));
    }
    let _sd_guard = LocalAllocGuard(sd_ptr);

    let sa_len = u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0);
    let sa = SECURITY_ATTRIBUTES {
        nLength: sa_len,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };

    let pipe_wide = to_wide_nul(pipe_name, OP)?;
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first_instance {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    // SAFETY: `pipe_wide` is NUL-terminated and `sa` points to a valid `SECURITY_DESCRIPTOR`
    // kept alive across `CreateNamedPipeW`.
    let raw = unsafe {
        CreateNamedPipeW(
            pipe_wide.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &raw const sa,
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(map_win_error(OP, io::Error::last_os_error()));
    }

    // SAFETY: `raw` is a fresh pipe server handle validated non-null and != `INVALID_HANDLE_VALUE`.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// Impersonates and inspects connected Named Pipe client token SIDs (`S-1-5-32-544` BA and `S-1-5-18` SY).
///
/// Uses `ImpersonateNamedPipeClient` when data has already been read; if Windows returns
/// `ERROR_CANNOT_IMPERSONATE` (`1368`) on a newly connected zero-byte stream, inspects the client
/// process's duplicated `SecurityIdentification` token instead.
pub fn inspect_named_pipe_peer(handle: BorrowedHandle<'_>) -> SysResult<WindowsPeerCredentials> {
    const OP: &str = "ipc_windows::inspect_named_pipe_peer";
    let raw_pipe = handle.as_raw_handle();

    // SAFETY: `handle` borrows an open Named Pipe server handle for the duration of this call.
    let imp_ok = unsafe { ImpersonateNamedPipeClient(raw_pipe) };
    if imp_ok != 0 {
        let _impersonation = ImpersonationGuard;
        let mut token_raw: HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentThread` is a pseudo-handle; `token_raw` receives an impersonation token.
        let open_ok =
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token_raw) };
        if open_ok == 0 || token_raw.is_null() || token_raw == INVALID_HANDLE_VALUE {
            return Err(map_win_error(OP, io::Error::last_os_error()));
        }
        // SAFETY: `token_raw` is a newly opened kernel token owned by this function.
        let token = unsafe { OwnedHandle::from_raw_handle(token_raw) };
        return extract_credentials_from_impersonation_token(token.as_raw_handle(), OP);
    }

    let imp_err = io::Error::last_os_error();
    if imp_err.raw_os_error() == Some(i32::try_from(ERROR_CANNOT_IMPERSONATE).unwrap_or(1368)) {
        return inspect_peer_via_process_token(raw_pipe, OP);
    }
    Err(map_win_error(OP, imp_err))
}

fn inspect_peer_via_process_token(
    raw_pipe: HANDLE,
    operation: &'static str,
) -> SysResult<WindowsPeerCredentials> {
    let mut client_pid: u32 = 0;
    // SAFETY: `raw_pipe` is borrowed from a live `BorrowedHandle` and `client_pid` is writable.
    let pid_ok = unsafe { GetNamedPipeClientProcessId(raw_pipe, &raw mut client_pid) };
    if pid_ok == 0 || client_pid == 0 {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }

    // SAFETY: Opens connected client process strictly for limited token querying.
    let proc_raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, client_pid) };
    if proc_raw.is_null() || proc_raw == INVALID_HANDLE_VALUE {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }
    // SAFETY: `proc_raw` is an owned process handle returned by `OpenProcess`.
    let proc_handle = unsafe { OwnedHandle::from_raw_handle(proc_raw) };

    let mut primary_raw: HANDLE = ptr::null_mut();
    // SAFETY: `proc_handle` is open and `primary_raw` receives its primary token handle.
    let tok_ok = unsafe {
        OpenProcessToken(
            proc_handle.as_raw_handle(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut primary_raw,
        )
    };
    if tok_ok == 0 || primary_raw.is_null() || primary_raw == INVALID_HANDLE_VALUE {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }
    // SAFETY: `primary_raw` is an owned primary token handle.
    let primary_tok = unsafe { OwnedHandle::from_raw_handle(primary_raw) };

    let mut imp_raw: HANDLE = ptr::null_mut();
    // SAFETY: Duplicates primary token at non-impersonating `SecurityIdentification` level
    // required by `CheckTokenMembership`.
    let dup_ok = unsafe {
        DuplicateTokenEx(
            primary_tok.as_raw_handle(),
            TOKEN_QUERY,
            ptr::null(),
            SecurityIdentification,
            TokenImpersonation,
            &raw mut imp_raw,
        )
    };
    if dup_ok == 0 || imp_raw.is_null() || imp_raw == INVALID_HANDLE_VALUE {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }
    // SAFETY: `imp_raw` is an owned `SecurityIdentification` token handle.
    let imp_tok = unsafe { OwnedHandle::from_raw_handle(imp_raw) };
    extract_credentials_from_impersonation_token(imp_tok.as_raw_handle(), operation)
}

fn extract_credentials_from_impersonation_token(
    token_raw: HANDLE,
    operation: &'static str,
) -> SysResult<WindowsPeerCredentials> {
    let is_builtin_admin =
        check_well_known_membership(token_raw, WinBuiltinAdministratorsSid, operation)?;
    let is_local_system = check_well_known_membership(token_raw, WinLocalSystemSid, operation)?;
    let principal = query_token_user_sid_string(token_raw, operation)?;
    Ok(WindowsPeerCredentials {
        is_builtin_admin,
        is_local_system,
        principal,
    })
}

fn check_well_known_membership(
    token: HANDLE,
    sid_type: i32,
    operation: &'static str,
) -> SysResult<bool> {
    let mut sid_buf = [0_u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = u32::try_from(sid_buf.len()).unwrap_or(SECURITY_MAX_SID_SIZE);
    // SAFETY: `sid_buf` has size `SECURITY_MAX_SID_SIZE` and receives one well-known binary SID.
    let sid_ok = unsafe {
        CreateWellKnownSid(
            sid_type,
            ptr::null_mut(),
            sid_buf.as_mut_ptr().cast::<c_void>(),
            &raw mut sid_size,
        )
    };
    if sid_ok == 0 {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }

    let mut is_member: i32 = 0;
    // SAFETY: `token` is an impersonation token opened with `TOKEN_QUERY`; `sid_buf` holds an initialized SID.
    let check_ok = unsafe {
        CheckTokenMembership(
            token,
            sid_buf.as_ptr().cast::<c_void>() as PSID,
            &raw mut is_member,
        )
    };
    if check_ok == 0 {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }
    Ok(is_member != 0)
}

fn query_token_user_sid_string(token: HANDLE, operation: &'static str) -> SysResult<String> {
    let mut required: u32 = 0;
    // SAFETY: Probe call with null buffer retrieves exact byte size for `TokenUser`.
    let _probe =
        unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut required) };
    let first_err = io::Error::last_os_error();
    let needed = usize::try_from(required).unwrap_or(0);
    if needed < size_of::<TOKEN_USER>() {
        if first_err.raw_os_error() != Some(i32::try_from(ERROR_INSUFFICIENT_BUFFER).unwrap_or(122))
        {
            return Err(map_win_error(operation, first_err));
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
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }

    // SAFETY: `GetTokenInformation(TokenUser)` initializes `TOKEN_USER` at start of `buf`.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut wide_sid: *mut u16 = ptr::null_mut();
    // SAFETY: `user.User.Sid` points inside `buf`; `wide_sid` receives a `LocalAlloc` string.
    let conv_ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut wide_sid) };
    if conv_ok == 0 || wide_sid.is_null() {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }
    let _str_guard = LocalAllocGuard(wide_sid.cast::<c_void>());

    let mut len: usize = 0;
    while len < 512 {
        // SAFETY: Scanning for NUL terminator within Win32 `ConvertSidToStringSidW` output buffer.
        let ch = unsafe { *wide_sid.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `wide_sid` holds `len` valid UTF-16 code units before the NUL terminator.
    let slice = unsafe { std::slice::from_raw_parts(wide_sid, len) };
    Ok(String::from_utf16_lossy(slice))
}

fn create_overlapped_event(operation: &'static str) -> SysResult<(OwnedHandle, OVERLAPPED)> {
    // SAFETY: Null security descriptor + unnamed manual-reset event allocates a private event handle.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(map_win_error(operation, io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh event handle validated non-null and != `INVALID_HANDLE_VALUE`.
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: Win32 `OVERLAPPED` is a plain C struct safely zero-initialized before setting `hEvent`.
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.hEvent = event.as_raw_handle();
    Ok((event, ov))
}

fn is_eof_pipe_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == i32::try_from(ERROR_BROKEN_PIPE).unwrap_or(109)
                || code == i32::try_from(ERROR_NO_DATA).unwrap_or(232)
    )
}

fn map_overlapped_wait_error(operation: &'static str, err: io::Error) -> SysError {
    if err.raw_os_error() == Some(i32::try_from(ERROR_OPERATION_ABORTED).unwrap_or(995)) {
        return SysError::io(
            operation,
            io::Error::new(io::ErrorKind::Interrupted, "named pipe I/O cancelled"),
        );
    }
    map_win_error(operation, err)
}

fn validate_pipe_name(pipe_name: &str, operation: &'static str) -> SysResult<()> {
    const PREFIX: &str = r"\\.\pipe\";
    let Some(suffix) = pipe_name.strip_prefix(PREFIX) else {
        return Err(SysError::io(
            operation,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "named pipe path must begin with \\\\.\\pipe\\",
            ),
        ));
    };
    if suffix.is_empty() || suffix.contains('\\') || suffix.contains('\0') {
        return Err(SysError::io(
            operation,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Windows pipe name suffix",
            ),
        ));
    }
    Ok(())
}

fn to_wide_nul(text: &str, operation: &'static str) -> SysResult<Vec<u16>> {
    if text.contains('\0') {
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "interior NUL byte in string"),
        ));
    }
    let mut wide: Vec<u16> = std::ffi::OsStr::new(text).encode_wide().collect();
    wide.push(0);
    Ok(wide)
}

fn map_win_error(operation: &'static str, err: io::Error) -> SysError {
    if err.kind() == io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(i32::try_from(ERROR_ACCESS_DENIED).unwrap_or(5))
    {
        return SysError::PermissionDenied { operation };
    }
    SysError::io(operation, err)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read as _, Write as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use super::{
        ADMIN_PIPE_SDDL, PipeAclMode, RO_PIPE_SDDL, SecuredPipeServer, SysError,
        create_secured_named_pipe, inspect_named_pipe_peer, sddl_for_pipe_mode,
    };

    static TEST_PIPE_SEQ: AtomicU64 = AtomicU64::new(1);

    fn unique_test_pipe_name(label: &str) -> String {
        let seq = TEST_PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\mesh-test-{label}-{}-{seq}", std::process::id())
    }

    #[test]
    fn test_ipc_windows_sddl_matches_api_design_contract() {
        // Arrange / Act
        let admin = sddl_for_pipe_mode(PipeAclMode::Admin);
        let ro = sddl_for_pipe_mode(PipeAclMode::ReadOnly);

        // Assert
        assert_eq!(admin, ADMIN_PIPE_SDDL);
        assert_eq!(ro, RO_PIPE_SDDL);
        assert_eq!(admin, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(ro, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)");
    }

    #[test]
    fn test_ipc_windows_sddl_pipe_creation_and_first_instance_blocks_duplicate() {
        // Arrange
        let pipe_name = unique_test_pipe_name("first-inst");

        // Act
        let first = create_secured_named_pipe(&pipe_name, PipeAclMode::ReadOnly);
        assert!(
            first.is_ok(),
            "initial secured pipe creation failed: {first:?}"
        );
        let duplicate = create_secured_named_pipe(&pipe_name, PipeAclMode::ReadOnly);

        // Assert: FILE_FLAG_FIRST_PIPE_INSTANCE must block duplicate creation while first lives.
        assert!(matches!(duplicate, Err(SysError::PermissionDenied { .. })));

        // Releasing first instance cleanly allows creating the pipe again.
        drop(first);
        let recreated = create_secured_named_pipe(&pipe_name, PipeAclMode::Admin);
        assert!(
            recreated.is_ok(),
            "recreating after drop failed: {recreated:?}"
        );
    }

    #[test]
    fn test_ipc_windows_rejects_malformed_pipe_names() {
        // Arrange / Act
        let no_prefix = create_secured_named_pipe("mesh-test-pipe", PipeAclMode::ReadOnly);
        let nested = create_secured_named_pipe(r"\\.\pipe\sub\name", PipeAclMode::ReadOnly);
        let empty = create_secured_named_pipe(r"\\.\pipe\", PipeAclMode::ReadOnly);

        // Assert
        assert!(no_prefix.is_err());
        assert!(nested.is_err());
        assert!(empty.is_err());
    }

    #[test]
    fn test_ipc_windows_impersonate_and_overlapped_io_under_normal_user() {
        // Arrange
        let pipe_name = unique_test_pipe_name("peer-sid");
        let server = SecuredPipeServer::bind(&pipe_name, PipeAclMode::ReadOnly, true);
        assert!(server.is_ok(), "pipe bind failed: {server:?}");
        let Ok(server) = server else {
            return;
        };

        let client_name = pipe_name.clone();
        let client_thread = thread::spawn(move || -> std::io::Result<[u8; 4]> {
            let mut client = OpenOptions::new()
                .read(true)
                .write(true)
                .open(client_name)?;
            client.write_all(b"ping")?;
            let mut reply = [0_u8; 4];
            client.read_exact(&mut reply)?;
            Ok(reply)
        });

        // Act: accept, check process-token fallback BEFORE read AND impersonation AFTER read.
        let accept_res = server.accept_blocking();
        assert!(accept_res.is_ok(), "accept_blocking failed: {accept_res:?}");

        let pre_read_creds = inspect_named_pipe_peer(server.as_handle());
        assert!(
            pre_read_creds.is_ok(),
            "zero-byte process token peer check failed: {pre_read_creds:?}"
        );

        let mut req = [0_u8; 4];
        let read_res = server.read_blocking(&mut req);
        assert!(
            matches!(read_res, Ok(4)),
            "read_blocking failed: {read_res:?}"
        );
        assert_eq!(&req, b"ping");

        let post_read_creds = server.inspect_peer();
        let write_res = server.write_blocking(b"pong");
        let client_res = client_thread.join();

        // Assert
        assert!(matches!(write_res, Ok(4)));
        assert!(matches!(client_res, Ok(Ok([b'p', b'o', b'n', b'g']))));
        assert!(
            post_read_creds.is_ok(),
            "inspect_peer after read failed: {post_read_creds:?}"
        );
        if let Ok(creds) = post_read_creds {
            assert!(
                creds.principal.starts_with("S-1-5-"),
                "expected Windows NT SID, got {}",
                creds.principal
            );
            assert!(!creds.is_local_system);
        }
    }
}
