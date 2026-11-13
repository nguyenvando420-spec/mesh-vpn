//! macOS `utun[0-9]+` asynchronous TUN backend (implemented in `WP-S1-02`).

use mesh_core::{AppError, AppResult};

use crate::tun::{BoxFuture, TunConfig, TunDevice};

/// macOS `AF_SYSTEM` `com.apple.net.utun_control` adapter (`utunN`).
#[derive(Debug)]
pub struct MacOsTunDevice {
    config: TunConfig,
}

impl MacOsTunDevice {
    /// Opens a kernel-assigned `utunN` interface and records it in `ResourceLedger` before routing.
    pub fn open(config: TunConfig) -> AppResult<Self> {
        let _cfg = &config;
        Err(AppError::unavailable(
            "macOS utun opening will be implemented in WP-S1-02",
        ))
    }
}

impl TunDevice for MacOsTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, _buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async {
            Err(AppError::unavailable(
                "macOS utun packet read will be implemented in WP-S1-02",
            ))
        })
    }

    fn write_packet<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async {
            Err(AppError::unavailable(
                "macOS utun packet write will be implemented in WP-S1-02",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
