//! Single authoritative source of network port, buffer, timing, and OS path defaults.
//!
//! All production code outside `mesh-core` is forbidden from hardcoding default ports
//! (`443`, `3478`) and must reference the constants and helpers exported here.

use std::num::NonZeroU16;

use crate::types::Port;

/// Default TCP port for the HTTPS Control & Relay endpoint.
pub const DEFAULT_CONTROL_TCP_PORT: u16 = 443;

/// Default UDP port for the embedded RFC 5389 STUN endpoint.
pub const DEFAULT_STUN_UDP_PORT: u16 = 3478;

/// Default loopback bind address for the Prometheus/health observability listener.
pub const DEFAULT_OBS_BIND_ADDR: &str = "127.0.0.1:9091";

/// Default IPv4 overlay CIDR block allocated to newly initialized networks.
pub const DEFAULT_OVERLAY_CIDR: &str = "100.115.0.0/16";

/// Default TUN interface MTU across platforms.
pub const DEFAULT_TUN_MTU: u16 = 1280;

/// Minimum allowed TUN interface MTU.
pub const MIN_TUN_MTU: u16 = 576;

/// Maximum allowed TUN interface MTU.
pub const MAX_TUN_MTU: u16 = 1420;

/// Fixed per-packet dataplane frame buffer size in bytes.
pub const MAX_FRAME_SIZE: usize = 2048;

/// Maximum Control HTTP request body size in bytes (64 KiB).
pub const MAX_HTTP_BODY_BYTES: usize = 65_536;

/// Maximum read-only IPC response payload in bytes (4 KiB).
pub const MAX_RO_IPC_BODY_BYTES: usize = 4_096;

/// Maximum Admin IPC request/response payload in bytes (64 KiB).
pub const MAX_ADMIN_IPC_BODY_BYTES: usize = 65_536;

/// Fixed bounded queue capacity per destination peer inside the Blind Relay.
pub const RELAY_QUEUE_CAPACITY: usize = 256;

/// Linux `SO_MARK` fwmark value excluding daemon outer sockets from overlay routing.
pub const LINUX_FWMARK: u32 = 0x5d56;

/// Linux custom routing table identifier for overlay routes.
pub const LINUX_ROUTING_TABLE: u32 = 51820;

/// Linux `ip rule` priority matching unmarked traffic into the overlay routing table.
pub const LINUX_RULE_PRIORITY_OVERLAY: u32 = 51820;

/// Linux `ip rule` priority preserving specific LAN routes via `suppress_prefixlength 0`.
pub const LINUX_RULE_PRIORITY_MAIN_SUPPRESS: u32 = 51810;

/// Maximum graceful shutdown duration in milliseconds.
pub const GRACEFUL_SHUTDOWN_BUDGET_MS: u64 = 5_000;

/// Maximum TCP/TLS/WebSocket initial connect timeout in milliseconds.
pub const CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Maximum application heartbeat timeout in milliseconds.
pub const HEARTBEAT_TIMEOUT_MS: u64 = 60_000;

/// Maximum allowed discrepancy between wall-clock and monotonic elapsed time (ms).
pub const CLOCK_JUMP_THRESHOLD_MS: i64 = 30_000;

/// Initial reconnect backoff delay in milliseconds.
pub const BACKOFF_INITIAL_MS: u64 = 500;

/// Maximum reconnect backoff cap for transient network errors (60 seconds).
pub const BACKOFF_NETWORK_MAX_MS: u64 = 60_000;

/// Maximum reconnect backoff cap for TLS/clock-skew/pin errors (5 minutes).
pub const BACKOFF_TLS_MAX_MS: u64 = 300_000;

/// Lifetime of a challenge nonce issued by the control server in seconds.
pub const CHALLENGE_TTL_SECS: u64 = 30;

/// Maximum tolerated client/server clock skew on control proofs in seconds.
pub const CONTROL_MAX_SKEW_SECS: u64 = 60;

/// Default cumulative log directory size limit in bytes (100 MiB).
pub const DEFAULT_LOG_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// Default single log file rotation threshold in bytes (10 MiB).
pub const DEFAULT_LOG_FILE_ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// macOS `admin` group numeric GID verified on privileged IPC sockets.
pub const MACOS_ADMIN_GID: u32 = 80;

/// Linux group authorized for server and daemon admin IPC sockets.
pub const LINUX_ADMIN_GROUP_NAME: &str = "mesh-admin";

/// Linux server runtime directory (`0750 mesh:mesh-admin`).
pub const LINUX_RUN_SERVER_DIR: &str = "/run/mesh-server";

/// Linux server Admin Unix domain socket path (`0660 mesh:mesh-admin`).
pub const LINUX_SERVER_ADMIN_SOCKET: &str = "/run/mesh-server/admin.sock";

/// Unix daemon runtime directory (`0755 root:wheel` or `root:root`).
pub const UNIX_RUN_DAEMON_DIR: &str = "/var/run/meshd";

/// Unix daemon privileged Admin IPC socket path.
pub const UNIX_AGENT_ADMIN_SOCKET: &str = "/var/run/meshd/meshd-admin.sock";

/// Unix daemon unprivileged read-only IPC socket path (`0666`).
pub const UNIX_AGENT_RO_SOCKET: &str = "/var/run/meshd/meshd-ro.sock";

/// Windows daemon privileged Admin named pipe path.
pub const WINDOWS_AGENT_ADMIN_PIPE: &str = r"\\.\pipe\mesh-agent-admin";

/// Windows daemon unprivileged read-only named pipe path.
pub const WINDOWS_AGENT_RO_PIPE: &str = r"\\.\pipe\mesh-agent-ro";

const DEFAULT_CONTROL_NONZERO: NonZeroU16 = match NonZeroU16::new(DEFAULT_CONTROL_TCP_PORT) {
    Some(value) => value,
    None => NonZeroU16::MIN,
};

const DEFAULT_STUN_NONZERO: NonZeroU16 = match NonZeroU16::new(DEFAULT_STUN_UDP_PORT) {
    Some(value) => value,
    None => NonZeroU16::MIN,
};

/// Returns the default Control HTTPS port as a validated [`Port`].
#[must_use]
pub const fn default_control_port() -> Port {
    Port::from_non_zero(DEFAULT_CONTROL_NONZERO)
}

/// Returns the default STUN UDP port as a validated [`Port`].
#[must_use]
pub const fn default_stun_port() -> Port {
    Port::from_non_zero(DEFAULT_STUN_NONZERO)
}

/// Maximum WebSocket control frame size accepted on mobile targets (256 KiB, `ADR-016`).
pub const DEFAULT_MOBILE_MAX_WS_FRAME_BYTES: usize = 262_144;

/// Idle debounce window in milliseconds before mobile enters `IdleAware` coalescing (`ADR-016`).
pub const DEFAULT_IDLE_ENTRY_WINDOW_MS: u64 = 10_000;

/// Coalesced heartbeat interval in milliseconds when mobile `IdleAware` power saving is active.
pub const DEFAULT_MOBILE_COALESCED_HEARTBEAT_MS: u64 = 45_000;

/// Maximum streamed mobile bugreport archive size in bytes (1 MiB, `ADR-016`).
pub const DEFAULT_MOBILE_MAX_BUGREPORT_BYTES: usize = 1_048_576;

/// Maximum desktop diagnostic bugreport archive size in bytes (`20 MiB`, `ADR-023`).
pub const MAX_BUGREPORT_ARCHIVE_BYTES: usize = 20 * 1024 * 1024;
