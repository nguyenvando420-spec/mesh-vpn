//! Linux `/dev/net/tun` asynchronous TUN backend (implemented in `WP-S1-03`).

use mesh_core::{AppError, AppResult};

use crate::tun::{BoxFuture, TunConfig, TunDevice};

/// Linux `/dev/net/tun` async adapter handle (`IFF_TUN | IFF_NO_PI`).
#[derive(Debug)]
pub struct LinuxTunDevice {
    config: TunConfig,
}

impl LinuxTunDevice {
    /// Opens `/dev/net/tun` and allocates a session interface (`mesh0`).
    pub fn open(config: TunConfig) -> AppResult<Self> {
        let _cfg = &config;
        Err(AppError::unavailable(
            "Linux /dev/net/tun opening will be implemented in WP-S1-03",
        ))
    }
}

impl TunDevice for LinuxTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, _buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async {
            Err(AppError::unavailable(
                "Linux TUN packet read will be implemented in WP-S1-03",
            ))
        })
    }

    fn write_packet<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async {
            Err(AppError::unavailable(
                "Linux TUN packet write will be implemented in WP-S1-03",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
