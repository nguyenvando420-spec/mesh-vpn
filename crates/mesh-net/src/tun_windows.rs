//! Windows Wintun asynchronous TUN backend with SHA-256 DLL verification (implemented in `WP-S1-04`).

use mesh_core::{AppError, AppResult};

use crate::tun::{BoxFuture, TunConfig, TunDevice};

/// Windows Wintun ring-buffer adapter (`MeshVPN`) with fixed adapter GUID.
#[derive(Debug)]
pub struct WindowsTunDevice {
    config: TunConfig,
}

impl WindowsTunDevice {
    /// Verifies `wintun.dll` SHA-256 and opens the fixed-GUID Wintun adapter.
    pub fn open(config: TunConfig) -> AppResult<Self> {
        let _cfg = &config;
        Err(AppError::unavailable(
            "Windows Wintun opening will be implemented in WP-S1-04",
        ))
    }
}

impl TunDevice for WindowsTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, _buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async {
            Err(AppError::unavailable(
                "Windows Wintun read will be implemented in WP-S1-04",
            ))
        })
    }

    fn write_packet<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async {
            Err(AppError::unavailable(
                "Windows Wintun write will be implemented in WP-S1-04",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
