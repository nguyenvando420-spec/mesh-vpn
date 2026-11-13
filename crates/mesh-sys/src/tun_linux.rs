//! Linux `/dev/net/tun` `IFF_TUN | IFF_NO_PI` descriptor management (`WP-S1-03`).

use crate::error::{SysError, SysResult};

/// Opens a non-blocking Linux TUN device returning `(interface_name, raw_fd)`.
pub fn open_tun_device(_preferred_name: Option<&str>) -> SysResult<(String, i32)> {
    Err(SysError::NotImplemented("tun_linux::open_tun_device"))
}
