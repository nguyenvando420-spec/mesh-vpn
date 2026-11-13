//! Windows `IP_UNICAST_IF` / `IPV6_UNICAST_IF` and `IP_DONTFRAGMENT` socket controls (`REL-09`, `WP-S1-04`).

use std::io;
use std::os::windows::io::RawSocket;

use windows_sys::Win32::Networking::WinSock::{
    IP_DONTFRAGMENT, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET,
    SOCKET_ERROR, WSAGetLastError, setsockopt,
};

use crate::error::{SysError, SysResult};

/// Encodes an IPv4 interface index in network byte order (`htonl`) as required by WinSock `IP_UNICAST_IF`.
#[must_use]
pub const fn encode_ipv4_unicast_if(if_index: u32) -> [u8; 4] {
    if_index.to_be_bytes()
}

/// Encodes an IPv6 interface index in host byte order as required by WinSock `IPV6_UNICAST_IF`.
#[must_use]
pub const fn encode_ipv6_unicast_if(if_index: u32) -> [u8; 4] {
    if_index.to_ne_bytes()
}

/// Binds an outbound socket directly to physical interface index `if_index` via WinSock `setsockopt`.
///
/// WinSock requires `IP_UNICAST_IF` (IPv4) in network byte order and `IPV6_UNICAST_IF` (IPv6)
/// in host byte order.
pub fn bind_socket_to_interface_index(
    socket: RawSocket,
    is_ipv6: bool,
    if_index: u32,
) -> SysResult<()> {
    const OP: &str = "socket_windows::bind_socket_to_interface_index";
    if if_index == 0 {
        return Err(SysError::io(
            OP,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface index must be non-zero",
            ),
        ));
    }

    if is_ipv6 {
        let optval = encode_ipv6_unicast_if(if_index);
        set_socket_option(socket, IPPROTO_IPV6, IPV6_UNICAST_IF, &optval, OP)
    } else {
        let optval = encode_ipv4_unicast_if(if_index);
        set_socket_option(socket, IPPROTO_IP, IP_UNICAST_IF, &optval, OP)
    }
}

/// Clears forced IPv4 Don't Fragment (`IP_DONTFRAGMENT = 0`) via WinSock `setsockopt` (`US-017 AC3`).
pub fn disable_ipv4_dont_fragment(socket: RawSocket) -> SysResult<()> {
    const OP: &str = "socket_windows::disable_ipv4_dont_fragment";
    let optval = 0_i32.to_ne_bytes();
    set_socket_option(socket, IPPROTO_IP, IP_DONTFRAGMENT, &optval, OP)
}

fn raw_socket_to_winsock(socket: RawSocket, operation: &'static str) -> SysResult<SOCKET> {
    if socket == u64::MAX {
        return Err(SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "invalid socket handle"),
        ));
    }
    usize::try_from(socket).map_err(|_| {
        SysError::io(
            operation,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket handle exceeds pointer width",
            ),
        )
    })
}

fn set_socket_option(
    socket: RawSocket,
    level: i32,
    optname: i32,
    optval: &[u8],
    operation: &'static str,
) -> SysResult<()> {
    let winsock = raw_socket_to_winsock(socket, operation)?;
    let optlen = i32::try_from(optval.len()).map_err(|_| {
        SysError::io(
            operation,
            io::Error::new(io::ErrorKind::InvalidInput, "socket option length overflow"),
        )
    })?;

    // SAFETY: `winsock` is a caller-owned WinSock handle, and `optval.as_ptr()` points to
    // `optlen` initialized stack bytes that remain valid for the synchronous `setsockopt` call.
    let rc = unsafe { setsockopt(winsock, level, optname, optval.as_ptr(), optlen) };
    if rc == SOCKET_ERROR {
        // SAFETY: `WSAGetLastError` reads the calling thread's last WinSock error without pointers.
        let code = unsafe { WSAGetLastError() };
        return Err(SysError::io(operation, io::Error::from_raw_os_error(code)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket as _;

    use windows_sys::Win32::Networking::WinSock::{
        IP_DONTFRAGMENT, IP_UNICAST_IF, IPPROTO_IP, SOCKET_ERROR, WSAGetLastError, getsockopt,
    };

    use super::{
        bind_socket_to_interface_index, disable_ipv4_dont_fragment, encode_ipv4_unicast_if,
        encode_ipv6_unicast_if, raw_socket_to_winsock,
    };

    fn get_socket_opt_4(socket: &UdpSocket, level: i32, optname: i32) -> io::Result<[u8; 4]> {
        let winsock = raw_socket_to_winsock(socket.as_raw_socket(), "test::getsockopt")
            .map_err(|err| io::Error::other(err.to_string()))?;
        let mut buf = [0_u8; 4];
        let mut len: i32 = 4;
        // SAFETY: `buf` is 4 writable bytes and `len` is initialized to 4 for synchronous `getsockopt`.
        let rc = unsafe { getsockopt(winsock, level, optname, buf.as_mut_ptr(), &raw mut len) };
        if rc == SOCKET_ERROR {
            // SAFETY: `WSAGetLastError` has no preconditions.
            let code = unsafe { WSAGetLastError() };
            return Err(io::Error::from_raw_os_error(code));
        }
        assert_eq!(len, 4);
        Ok(buf)
    }

    #[test]
    fn test_socket_windows_unicast_if_byte_order_ipv4_be_vs_ipv6_host() {
        // Arrange
        let sample_index: u32 = 0x0102_0304;

        // Act
        let ipv4_bytes = encode_ipv4_unicast_if(sample_index);
        let ipv6_bytes = encode_ipv6_unicast_if(sample_index);

        // Assert: WinSock expects IP_UNICAST_IF in network order (BE) and IPV6_UNICAST_IF in host order.
        assert_eq!(ipv4_bytes, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(ipv6_bytes, sample_index.to_ne_bytes());
        assert_ne!(ipv4_bytes, ipv6_bytes);
    }

    #[test]
    fn test_socket_windows_zero_if_index_and_invalid_socket_rejected() {
        // Arrange
        let sock = UdpSocket::bind("127.0.0.1:0");
        assert!(sock.is_ok(), "loopback UDP bind should initialize WinSock");
        let Ok(sock) = sock else {
            return;
        };

        // Act
        let zero_res = bind_socket_to_interface_index(sock.as_raw_socket(), false, 0);
        let bad_sock_res = bind_socket_to_interface_index(u64::MAX, false, 1);

        // Assert
        assert!(zero_res.is_err());
        assert!(bad_sock_res.is_err());
    }

    #[test]
    fn test_socket_windows_live_udp_bind_interface_and_disable_dont_fragment() {
        // Arrange
        let sock = UdpSocket::bind("127.0.0.1:0");
        assert!(sock.is_ok(), "loopback UDP bind should succeed");
        let Ok(sock) = sock else {
            return;
        };
        let target_if_index: u32 = 1;

        // Act
        let bind_res = bind_socket_to_interface_index(sock.as_raw_socket(), false, target_if_index);
        let df_res = disable_ipv4_dont_fragment(sock.as_raw_socket());

        // Assert
        assert!(
            bind_res.is_ok(),
            "IP_UNICAST_IF setsockopt failed: {bind_res:?}"
        );
        assert!(
            df_res.is_ok(),
            "IP_DONTFRAGMENT setsockopt failed: {df_res:?}"
        );

        let observed_if = get_socket_opt_4(&sock, IPPROTO_IP, IP_UNICAST_IF);
        assert!(
            observed_if.is_ok(),
            "getsockopt(IP_UNICAST_IF) failed: {observed_if:?}"
        );
        if let Ok(bytes) = observed_if {
            // WinSock accepts IP_UNICAST_IF in network order (`to_be_bytes`) via setsockopt
            // and reports the resolved interface index back in host order via getsockopt.
            assert_eq!(u32::from_ne_bytes(bytes), target_if_index);
        }

        let observed_df = get_socket_opt_4(&sock, IPPROTO_IP, IP_DONTFRAGMENT);
        assert!(
            observed_df.is_ok(),
            "getsockopt(IP_DONTFRAGMENT) failed: {observed_df:?}"
        );
        if let Ok(bytes) = observed_df {
            assert_eq!(i32::from_ne_bytes(bytes), 0);
        }
    }
}
