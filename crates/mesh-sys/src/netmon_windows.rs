//! Windows `NotifyIpInterfaceChange`, `GetBestInterfaceEx`, and `GetSystemDirectoryW` helpers (`WP-S1-04`).

use std::ffi::{OsString, c_void};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, HANDLE, MAX_PATH, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, GetBestInterfaceEx,
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_PPPMULTILINKBUNDLE,
    IF_TYPE_PROP_VIRTUAL, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    MIB_UNICASTIPADDRESS_ROW, MibInitialNotification, NotifyIpInterfaceChange,
    NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::error::{SysError, SysResult};

const VIRTUAL_ADAPTER_KEYWORDS: [&str; 18] = [
    "wintun",
    "wireguard",
    "meshvpn",
    "tailscale",
    "zerotier",
    "vethernet",
    "hyper-v",
    "wsl",
    "loopback",
    "vmware",
    "virtualbox",
    "vbox",
    "tap-windows",
    "openvpn",
    "wan miniport",
    "teredo",
    "isatap",
    "docker",
];

/// Snapshot of a Windows network adapter returned by `GetAdaptersAddresses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsAdapterInfo {
    /// IPv4 interface index (`0` if IPv4 is disabled on this adapter).
    pub if_index: u32,
    /// IPv6 interface index (`0` if IPv6 is disabled on this adapter).
    pub ipv6_if_index: u32,
    /// NDIS interface type (`IF_TYPE_*`).
    pub if_type: u32,
    /// Reported link MTU.
    pub mtu: u32,
    /// IPv4 automatic or configured route metric.
    pub ipv4_metric: u32,
    /// IPv6 automatic or configured route metric.
    pub ipv6_metric: u32,
    /// Human-readable Windows adapter friendly name (e.g., `"Ethernet"` or `"MeshVPN"`).
    pub friendly_name: String,
    /// Driver description string.
    pub description: String,
    /// Whether operational status is `IfOperStatusUp`.
    pub is_up: bool,
    /// Whether this adapter is virtual/tunnel/loopback and must be excluded as physical uplink.
    pub is_virtual: bool,
    /// Whether Windows lists at least one default gateway on this adapter.
    pub has_gateway: bool,
}

/// Unicast IP address and on-link prefix snapshot for a Windows adapter (`US-036`, `US-037`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsInterfaceAddress {
    /// Interface index (`IfIndex` for IPv4, `Ipv6IfIndex` for IPv6).
    pub if_index: u32,
    /// Human-readable Windows adapter friendly name (e.g., `"Wi-Fi"`, `"Ethernet"`).
    pub friendly_name: String,
    /// Unicast IPv4 or IPv6 address assigned to this interface.
    pub ip: IpAddr,
    /// On-link subnet prefix length (`0..=32` IPv4, `0..=128` IPv6).
    pub prefix_len: u8,
    /// Whether operational status is `IfOperStatusUp`.
    pub is_up: bool,
    /// Whether this adapter is virtual/tunnel/loopback and must be excluded as physical uplink.
    pub is_virtual: bool,
    /// Whether Windows lists at least one default gateway on this adapter.
    pub has_gateway: bool,
}

#[derive(Debug)]
struct IpChangeContext {
    change_count: AtomicU64,
    tx: SyncSender<()>,
}

/// Active subscription to Windows `NotifyIpInterfaceChange` and `NotifyUnicastIpAddressChange`;
/// dropping cancels all kernel callbacks synchronously.
pub struct IpChangeSubscription {
    iface_handle: HANDLE,
    unicast_handle: HANDLE,
    raw_ctx: *const IpChangeContext,
}

// SAFETY: Kernel notification handles are thread-safe to cancel and clean up from any thread.
unsafe impl Send for IpChangeSubscription {}
// SAFETY: `&self` only reads the atomic counter backed by the pinned `Arc<IpChangeContext>`.
unsafe impl Sync for IpChangeSubscription {}

impl fmt::Debug for IpChangeSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpChangeSubscription")
            .field("change_count", &self.change_count())
            .finish_non_exhaustive()
    }
}

impl Drop for IpChangeSubscription {
    fn drop(&mut self) {
        for (label, handle) in [
            ("iface", self.iface_handle),
            ("unicast", self.unicast_handle),
        ] {
            if !handle.is_null() {
                // SAFETY: `CancelMibChangeNotify2` synchronously drains and waits for any active
                // callback invocation before returning, so reclaiming `raw_ctx` afterwards cannot
                // trigger a use-after-free.
                let rc = unsafe { CancelMibChangeNotify2(handle) };
                if rc != NO_ERROR {
                    tracing::warn!(
                        target: "mesh::sys::netmon_windows",
                        subscription = label,
                        error_code = rc,
                        "CancelMibChangeNotify2 returned non-zero status on drop"
                    );
                }
            }
        }
        if !self.raw_ctx.is_null() {
            // SAFETY: `self.raw_ctx` was created via `Arc::into_raw` when registering and all
            // kernel notifications have completed `CancelMibChangeNotify2` above.
            let reclaimed = unsafe { Arc::from_raw(self.raw_ctx) };
            drop(reclaimed);
        }
    }
}

impl IpChangeSubscription {
    /// Returns the total number of non-initial interface change events observed so far.
    #[must_use]
    pub fn change_count(&self) -> u64 {
        if self.raw_ctx.is_null() {
            return 0;
        }
        // SAFETY: `self.raw_ctx` stays valid until `Drop` reclaims the `Arc`.
        let ctx = unsafe { &*self.raw_ctx };
        ctx.change_count.load(Ordering::Acquire)
    }
}

/// Resolves Windows `System32` directory via `GetSystemDirectoryW` (never hardcoded drive letters).
pub fn windows_system_directory() -> SysResult<PathBuf> {
    const OP: &str = "netmon_windows::windows_system_directory";
    let mut buf = [0_u16; MAX_PATH as usize];
    let buf_cap = u32::try_from(buf.len()).unwrap_or(MAX_PATH);
    // SAFETY: `buf` provides `buf_cap` writable UTF-16 code units to `GetSystemDirectoryW`.
    let written = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf_cap) };
    if written == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }

    let written_usize = usize::try_from(written).unwrap_or(usize::MAX);
    let path = if written_usize < buf.len() {
        let Some(slice) = buf.get(..written_usize) else {
            return Err(SysError::io(
                OP,
                io::Error::other("system dir slice overflow"),
            ));
        };
        PathBuf::from(OsString::from_wide(slice))
    } else {
        let mut big = vec![0_u16; written_usize];
        let big_cap = u32::try_from(big.len()).unwrap_or(written);
        // SAFETY: `big` has `big_cap` UTF-16 code units as requested by the first call.
        let written2 = unsafe { GetSystemDirectoryW(big.as_mut_ptr(), big_cap) };
        let written2_usize = usize::try_from(written2).unwrap_or(0);
        if written2 == 0 || written2_usize >= big.len() {
            return Err(SysError::io(OP, io::Error::last_os_error()));
        }
        let Some(slice) = big.get(..written2_usize) else {
            return Err(SysError::io(
                OP,
                io::Error::other("system dir slice overflow"),
            ));
        };
        PathBuf::from(OsString::from_wide(slice))
    };

    if !path.is_absolute() {
        return Err(SysError::SecurityViolation {
            operation: OP,
            detail: "GetSystemDirectoryW returned a non-absolute path".to_owned(),
        });
    }
    Ok(path)
}

/// Classifies whether an adapter is virtual, loopback, or a tunnel interface (`US-020`, `REL-09`).
#[must_use]
pub fn is_virtual_adapter(if_type: u32, friendly_name: &str, description: &str) -> bool {
    if matches!(
        if_type,
        IF_TYPE_SOFTWARE_LOOPBACK
            | IF_TYPE_TUNNEL
            | IF_TYPE_PROP_VIRTUAL
            | IF_TYPE_PPP
            | IF_TYPE_PPPMULTILINKBUNDLE
    ) {
        return true;
    }

    let friendly_lower = friendly_name.to_ascii_lowercase();
    let desc_lower = description.to_ascii_lowercase();
    VIRTUAL_ADAPTER_KEYWORDS
        .iter()
        .any(|kw| friendly_lower.contains(kw) || desc_lower.contains(kw))
}

fn fetch_adapters_raw_buffer(op: &'static str) -> SysResult<Vec<u64>> {
    let mut size: u32 = 16 * 1024;
    let mut aligned_buf: Vec<u64> = Vec::new();
    let mut attempts: u8 = 0;

    loop {
        let words = usize::try_from(size)
            .unwrap_or(usize::MAX)
            .div_ceil(size_of::<u64>())
            .max(1);
        aligned_buf.resize(words, 0);
        let ptr = aligned_buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `aligned_buf` is `u64`-aligned and zeroed with byte capacity >= `size`.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                GAA_FLAG_INCLUDE_GATEWAYS,
                ptr::null(),
                ptr,
                &raw mut size,
            )
        };
        if status == NO_ERROR {
            return Ok(aligned_buf);
        }
        if status == ERROR_BUFFER_OVERFLOW && attempts < 4 {
            attempts += 1;
            continue;
        }
        let err = io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX));
        return Err(SysError::io(op, err));
    }
}

/// Enumerates Windows network adapters using `GetAdaptersAddresses`.
pub fn list_adapters() -> SysResult<Vec<WindowsAdapterInfo>> {
    const OP: &str = "netmon_windows::list_adapters";
    let aligned_buf = fetch_adapters_raw_buffer(OP)?;

    let mut out = Vec::new();
    let mut current: *const IP_ADAPTER_ADDRESSES_LH =
        aligned_buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut visited: usize = 0;

    while !current.is_null() && visited < 4096 {
        visited += 1;
        // SAFETY: `GetAdaptersAddresses` succeeded and wrote a linked list inside `aligned_buf`.
        let node = unsafe { &*current };
        // SAFETY: `Anonymous1.Anonymous` is the active Win32 union variant populated by IP Helper.
        let if_index = unsafe { node.Anonymous1.Anonymous.IfIndex };
        let friendly_name = decode_wide_ptr(node.FriendlyName);
        let description = decode_wide_ptr(node.Description);
        let is_virtual = is_virtual_adapter(node.IfType, &friendly_name, &description);

        out.push(WindowsAdapterInfo {
            if_index,
            ipv6_if_index: node.Ipv6IfIndex,
            if_type: node.IfType,
            mtu: node.Mtu,
            ipv4_metric: node.Ipv4Metric,
            ipv6_metric: node.Ipv6Metric,
            friendly_name,
            description,
            is_up: node.OperStatus == IfOperStatusUp,
            is_virtual,
            has_gateway: !node.FirstGatewayAddress.is_null(),
        });
        current = node.Next.cast_const();
    }
    Ok(out)
}

/// Enumerates unicast IPv4/IPv6 addresses and on-link prefix lengths for all Windows adapters
/// (`US-036` DHCP wait, `US-037` CGNAT overlap detection).
pub fn list_interface_addresses() -> SysResult<Vec<WindowsInterfaceAddress>> {
    const OP: &str = "netmon_windows::list_interface_addresses";
    let aligned_buf = fetch_adapters_raw_buffer(OP)?;

    let mut out = Vec::new();
    let mut current: *const IP_ADAPTER_ADDRESSES_LH =
        aligned_buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut visited_adapters: usize = 0;

    while !current.is_null() && visited_adapters < 4096 {
        visited_adapters += 1;
        // SAFETY: `GetAdaptersAddresses` succeeded and wrote a linked list inside `aligned_buf`.
        let node = unsafe { &*current };
        // SAFETY: `Anonymous1.Anonymous` is the active Win32 union variant populated by IP Helper.
        let ipv4_if_index = unsafe { node.Anonymous1.Anonymous.IfIndex };
        let ipv6_if_index = node.Ipv6IfIndex;
        let friendly_name = decode_wide_ptr(node.FriendlyName);
        let description = decode_wide_ptr(node.Description);
        let is_virtual = is_virtual_adapter(node.IfType, &friendly_name, &description);
        let is_up = node.OperStatus == IfOperStatusUp;
        let has_gateway = !node.FirstGatewayAddress.is_null();

        let mut ucast: *const IP_ADAPTER_UNICAST_ADDRESS_LH = node.FirstUnicastAddress.cast_const();
        let mut visited_ucast: usize = 0;
        while !ucast.is_null() && visited_ucast < 256 {
            visited_ucast += 1;
            // SAFETY: `ucast` traverses valid unicast address nodes owned by `aligned_buf`.
            let entry = unsafe { &*ucast };
            if let Some(ip) =
                extract_windows_sockaddr_ip(entry.Address.lpSockaddr, entry.Address.iSockaddrLength)
            {
                let (if_index, max_prefix) = match ip {
                    IpAddr::V4(_) => (ipv4_if_index, 32_u8),
                    IpAddr::V6(_) => (
                        if ipv6_if_index != 0 {
                            ipv6_if_index
                        } else {
                            ipv4_if_index
                        },
                        128_u8,
                    ),
                };
                out.push(WindowsInterfaceAddress {
                    if_index,
                    friendly_name: friendly_name.clone(),
                    ip,
                    prefix_len: entry.OnLinkPrefixLength.min(max_prefix),
                    is_up,
                    is_virtual,
                    has_gateway,
                });
            }
            ucast = entry.Next.cast_const();
        }

        current = node.Next.cast_const();
    }

    Ok(out)
}

fn extract_windows_sockaddr_ip(sockaddr_ptr: *const SOCKADDR, sockaddr_len: i32) -> Option<IpAddr> {
    if sockaddr_ptr.is_null() || sockaddr_len < i32::try_from(size_of::<SOCKADDR>()).ok()? {
        return None;
    }
    // SAFETY: Caller verified non-null `sockaddr_ptr` with byte length >= `size_of::<SOCKADDR>()`.
    let family = unsafe { (*sockaddr_ptr).sa_family };
    if family == AF_INET {
        let min_len = i32::try_from(size_of::<SOCKADDR_IN>()).ok()?;
        if sockaddr_len < min_len {
            return None;
        }
        // SAFETY: `sa_family == AF_INET` and length >= `size_of::<SOCKADDR_IN>()`.
        let sa_in = unsafe { ptr::read_unaligned(sockaddr_ptr.cast::<SOCKADDR_IN>()) };
        // SAFETY: `IN_ADDR_0::S_addr` stores IPv4 octets in network byte order.
        let octets = unsafe { sa_in.sin_addr.S_un.S_addr }.to_ne_bytes();
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if family == AF_INET6 {
        let min_len = i32::try_from(size_of::<SOCKADDR_IN6>()).ok()?;
        if sockaddr_len < min_len {
            return None;
        }
        // SAFETY: `sa_family == AF_INET6` and length >= `size_of::<SOCKADDR_IN6>()`.
        let sa_in6 = unsafe { ptr::read_unaligned(sockaddr_ptr.cast::<SOCKADDR_IN6>()) };
        // SAFETY: `IN6_ADDR_0::Byte` stores the 16 IPv6 octets in network order.
        let octets = unsafe { sa_in6.sin6_addr.u.Byte };
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    None
}

/// Returns `true` when `ip` is a routable/usable interface address (excludes unspecified,
/// loopback, IPv4 APIPA `169.254.0.0/16`, and IPv6 link-local `fe80::/10`).
#[must_use]
pub fn is_usable_dhcp_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            let first_seg = v6.segments().first().copied().unwrap_or(0);
            !v6.is_unspecified() && !v6.is_loopback() && (first_seg & 0xffc0) != 0xfe80
        }
    }
}

/// Queries the best Windows interface index for reaching `dest_ipv4` via `GetBestInterfaceEx`.
pub fn query_best_interface_for_ipv4(dest_ipv4: [u8; 4]) -> SysResult<u32> {
    const OP: &str = "netmon_windows::query_best_interface_for_ipv4";
    let sockaddr = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(dest_ipv4),
            },
        },
        sin_zero: [0; 8],
    };
    let mut best_index: u32 = 0;
    // SAFETY: `SOCKADDR_IN` begins with `sin_family: ADDRESS_FAMILY`, matching `SOCKADDR`, and
    // is valid for synchronous `GetBestInterfaceEx`.
    let status = unsafe {
        GetBestInterfaceEx(
            (&raw const sockaddr).cast::<SOCKADDR>(),
            &raw mut best_index,
        )
    };
    if status != NO_ERROR || best_index == 0 {
        let code = if status == 0 { 1168 } else { status };
        let err = io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX));
        return Err(SysError::io(OP, err));
    }
    Ok(best_index)
}

/// Queries the current primary physical egress `(if_index, friendly_name)` on Windows,
/// filtering out Wintun/virtual/WSL/Hyper-V/loopback interfaces (`US-016`, `US-036`, `REL-09`).
pub fn query_primary_physical_interface() -> SysResult<(u32, String)> {
    const OP: &str = "netmon_windows::query_primary_physical_interface";
    let adapters = list_adapters()?;
    select_primary_physical_adapter(&adapters)
        .map(|a| (a.if_index, a.friendly_name.clone()))
        .ok_or_else(|| {
            SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no active physical Windows network interface found",
                ),
            )
        })
}

/// Queries the current primary physical egress interface index on Windows, filtering out
/// Wintun/virtual/WSL/Hyper-V/loopback interfaces (`US-016`, `REL-09`).
pub fn query_primary_physical_if_index() -> SysResult<u32> {
    query_primary_physical_interface().map(|(idx, _)| idx)
}

#[cfg(test)]
fn select_primary_physical_if_index(adapters: &[WindowsAdapterInfo]) -> Option<u32> {
    select_primary_physical_adapter(adapters).map(|a| a.if_index)
}

fn select_primary_physical_adapter(adapters: &[WindowsAdapterInfo]) -> Option<&WindowsAdapterInfo> {
    if let Ok(best_idx) = query_best_interface_for_ipv4([1, 1, 1, 1])
        && let Some(found) = adapters
            .iter()
            .find(|a| a.if_index == best_idx && a.is_up && !a.is_virtual)
    {
        return Some(found);
    }

    adapters
        .iter()
        .filter(|a| a.is_up && !a.is_virtual && a.if_index != 0)
        .min_by_key(|a| {
            let prefer_physical_media = u8::from(!matches!(
                a.if_type,
                IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211
            ));
            (
                !a.has_gateway,
                prefer_physical_media,
                a.ipv4_metric,
                a.if_index,
            )
        })
}

/// Subscribes to Windows IP interface and unicast IP add/delete/parameter changes
/// (`NotifyIpInterfaceChange` + `NotifyUnicastIpAddressChange`).
pub fn subscribe_ip_interface_changes() -> SysResult<(IpChangeSubscription, Receiver<()>)> {
    const OP: &str = "netmon_windows::subscribe_ip_interface_changes";
    let (tx, rx) = mpsc::sync_channel(16);
    let ctx = Arc::new(IpChangeContext {
        change_count: AtomicU64::new(0),
        tx,
    });
    let raw_ctx = Arc::into_raw(ctx);
    let mut iface_handle: HANDLE = ptr::null_mut();

    // SAFETY: `ip_interface_change_callback` never blocks, and `raw_ctx` stays valid until
    // `IpChangeSubscription::drop` completes `CancelMibChangeNotify2`.
    let status = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(ip_interface_change_callback),
            raw_ctx.cast::<c_void>(),
            0,
            &raw mut iface_handle,
        )
    };
    if status != NO_ERROR {
        // SAFETY: Registration failed, so no OS callback retains `raw_ctx`; reclaim ownership cleanly.
        let reclaimed = unsafe { Arc::from_raw(raw_ctx) };
        drop(reclaimed);
        let err = io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX));
        return Err(SysError::io(OP, err));
    }

    let mut unicast_handle: HANDLE = ptr::null_mut();
    // SAFETY: `unicast_ip_change_callback` shares `raw_ctx`, which remains live until both
    // `iface_handle` and `unicast_handle` finish `CancelMibChangeNotify2` in `Drop`.
    let unicast_status = unsafe {
        NotifyUnicastIpAddressChange(
            AF_UNSPEC,
            Some(unicast_ip_change_callback),
            raw_ctx.cast::<c_void>(),
            0,
            &raw mut unicast_handle,
        )
    };
    if unicast_status != NO_ERROR {
        unicast_handle = ptr::null_mut();
        tracing::debug!(
            target: "mesh::sys::netmon_windows",
            error_code = unicast_status,
            "NotifyUnicastIpAddressChange registration failed; falling back to NotifyIpInterfaceChange only"
        );
    }

    Ok((
        IpChangeSubscription {
            iface_handle,
            unicast_handle,
            raw_ctx,
        },
        rx,
    ))
}

unsafe extern "system" fn ip_interface_change_callback(
    caller_context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    notify_ip_change(caller_context, notification_type);
}

unsafe extern "system" fn unicast_ip_change_callback(
    caller_context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    notify_ip_change(caller_context, notification_type);
}

fn notify_ip_change(caller_context: *const c_void, notification_type: MIB_NOTIFICATION_TYPE) {
    if caller_context.is_null() || notification_type == MibInitialNotification {
        return;
    }
    // SAFETY: `caller_context` is an `Arc::into_raw(IpChangeContext)` live until
    // `CancelMibChangeNotify2` completes for all registered handles in `IpChangeSubscription::drop`.
    let ctx = unsafe { &*caller_context.cast::<IpChangeContext>() };
    ctx.change_count.fetch_add(1, Ordering::AcqRel);
    match ctx.tx.try_send(()) {
        Ok(()) | Err(TrySendError::Full(()) | TrySendError::Disconnected(())) => {}
    }
}

fn decode_wide_ptr(ptr_w: *const u16) -> String {
    if ptr_w.is_null() {
        return String::new();
    }
    let mut len: usize = 0;
    while len < 512 {
        // SAFETY: Scanning Win32-allocated NUL-terminated UTF-16 string inside bounded length.
        let ch = unsafe { *ptr_w.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `ptr_w` points to `len` valid UTF-16 code units before the NUL terminator.
    let slice = unsafe { std::slice::from_raw_parts(ptr_w, len) };
    String::from_utf16_lossy(slice)
}

/// Computes the used space percentage (`0..=100`) of the volume containing `path` using
/// `GetDiskFreeSpaceExW` (`HR-S1-05`).
pub fn filesystem_usage_percent(path: &Path) -> SysResult<u8> {
    const OP: &str = "filesystem_usage_percent";
    let target = if path.is_file() {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    } else {
        path
    };

    let mut wide: Vec<u16> = Vec::new();
    for unit in target.as_os_str().encode_wide() {
        if unit == 0 {
            return Err(SysError::io(
                OP,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "filesystem path contains interior NUL code unit",
                ),
            ));
        }
        wide.push(unit);
    }
    wide.push(0);

    let mut free_available: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free: u64 = 0;
    // SAFETY: `wide` is NUL-terminated UTF-16 and the three output pointers reference
    // distinct aligned stack `u64` locals valid for the synchronous Win32 call.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut free_available,
            &raw mut total_bytes,
            &raw mut total_free,
        )
    };
    if ok == 0 {
        return Err(SysError::io(OP, io::Error::last_os_error()));
    }
    if total_bytes == 0 {
        return Err(SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "volume reported zero total bytes",
            ),
        ));
    }
    let avail = free_available.min(total_bytes);
    let used = total_bytes.saturating_sub(avail);
    let pct = u128::from(used).saturating_mul(100) / u128::from(total_bytes);
    u8::try_from(pct.min(100)).map_err(|_| {
        SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "filesystem percentage out of range",
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PROP_VIRTUAL,
        IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL,
    };

    use super::{
        WindowsAdapterInfo, filesystem_usage_percent, is_virtual_adapter, list_adapters,
        select_primary_physical_if_index, subscribe_ip_interface_changes, windows_system_directory,
    };

    #[test]
    fn test_netmon_windows_system_directory_resolves_system32() {
        // Arrange / Act
        let dir = windows_system_directory();

        // Assert
        assert!(dir.is_ok(), "GetSystemDirectoryW failed: {dir:?}");
        if let Ok(path) = dir {
            assert!(path.is_absolute());
            assert!(path.is_dir());
            assert!(path.join("ipconfig.exe").is_file());
        }
    }

    #[test]
    fn test_netmon_windows_virtual_adapter_filter_excludes_wintun_wsl_hyperv() {
        // Arrange / Act / Assert
        assert!(is_virtual_adapter(
            IF_TYPE_PROP_VIRTUAL,
            "MeshVPN",
            "Wintun Userspace Tunnel"
        ));
        assert!(is_virtual_adapter(
            IF_TYPE_ETHERNET_CSMACD,
            "vEthernet (WSL)",
            "Hyper-V Virtual Ethernet Adapter"
        ));
        assert!(is_virtual_adapter(
            IF_TYPE_SOFTWARE_LOOPBACK,
            "Loopback Pseudo-Interface 1",
            "Software Loopback Interface"
        ));
        assert!(is_virtual_adapter(
            IF_TYPE_TUNNEL,
            "Tailscale",
            "WireGuard Tunnel"
        ));
        assert!(!is_virtual_adapter(
            IF_TYPE_IEEE80211,
            "Wi-Fi",
            "Intel(R) Wi-Fi 6E AX211 160MHz"
        ));
        assert!(!is_virtual_adapter(
            IF_TYPE_ETHERNET_CSMACD,
            "Ethernet",
            "Realtek Gaming GbE Family Controller"
        ));
    }

    #[test]
    fn test_netmon_windows_list_adapters_and_selection_excludes_virtual() {
        // Arrange
        let synthetic = vec![
            WindowsAdapterInfo {
                if_index: 99,
                ipv6_if_index: 99,
                if_type: IF_TYPE_PROP_VIRTUAL,
                mtu: 1280,
                ipv4_metric: 5,
                ipv6_metric: 5,
                friendly_name: "MeshVPN".to_owned(),
                description: "Wintun Userspace Tunnel".to_owned(),
                is_up: true,
                is_virtual: true,
                has_gateway: true,
            },
            WindowsAdapterInfo {
                if_index: 12,
                ipv6_if_index: 12,
                if_type: IF_TYPE_IEEE80211,
                mtu: 1500,
                ipv4_metric: 35,
                ipv6_metric: 35,
                friendly_name: "Wi-Fi".to_owned(),
                description: "Intel Wi-Fi".to_owned(),
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            },
        ];

        // Act
        let adapters = list_adapters();
        let selected = select_primary_physical_if_index(&synthetic);

        // Assert
        assert!(
            adapters.is_ok(),
            "GetAdaptersAddresses failed: {adapters:?}"
        );
        if let Ok(list) = adapters {
            assert!(!list.is_empty());
            assert!(list.iter().any(|a| a.is_virtual));
        }
        assert!(selected.is_some());
    }

    #[test]
    fn test_netmon_windows_ip_change_subscription_registers_and_cancels_cleanly() {
        // Arrange / Act
        let sub = subscribe_ip_interface_changes();

        // Assert
        assert!(sub.is_ok(), "NotifyIpInterfaceChange failed: {sub:?}");
        if let Ok((subscription, _rx)) = sub {
            assert_eq!(subscription.change_count(), 0);
            drop(subscription);
        }
    }

    #[test]
    fn test_netmon_windows_filesystem_usage_percent_reads_dir_and_file() {
        // Arrange
        let dir_res = tempdir();
        assert!(dir_res.is_ok(), "tempdir failed: {dir_res:?}");
        let Ok(dir) = dir_res else {
            return;
        };
        let file = dir.path().join("control.redb");
        assert!(std::fs::write(&file, b"db").is_ok());

        // Act
        let dir_pct = filesystem_usage_percent(dir.path());
        let file_pct = filesystem_usage_percent(&file);
        let missing = filesystem_usage_percent(&dir.path().join("missing-subdir"));

        // Assert
        assert!(dir_pct.is_ok(), "dir usage failed: {dir_pct:?}");
        assert!(file_pct.is_ok(), "file usage failed: {file_pct:?}");
        if let Ok(pct) = dir_pct {
            assert!(pct <= 100);
        }
        if let Ok(pct) = file_pct {
            assert!(pct <= 100);
        }
        assert!(missing.is_err());
    }

    #[test]
    fn test_netmon_windows_list_interface_addresses_and_dhcp_filter() {
        // Arrange / Act
        let addrs = super::list_interface_addresses();

        // Assert
        assert!(addrs.is_ok(), "list_interface_addresses failed: {addrs:?}");
        if let Ok(list) = addrs {
            assert!(!list.is_empty());
        }
        assert!(!super::is_usable_dhcp_ip(super::IpAddr::V4(
            super::Ipv4Addr::new(169, 254, 10, 20)
        )));
        assert!(!super::is_usable_dhcp_ip(super::IpAddr::V4(
            super::Ipv4Addr::LOCALHOST
        )));
        assert!(super::is_usable_dhcp_ip(super::IpAddr::V4(
            super::Ipv4Addr::new(192, 168, 1, 25)
        )));
    }
}
