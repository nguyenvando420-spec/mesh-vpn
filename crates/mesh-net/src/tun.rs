//! Abstract TUN network interface trait and in-memory fake for unprivileged tests.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use mesh_core::defaults::{DEFAULT_TUN_MTU, MAX_FRAME_SIZE, MAX_TUN_MTU, MIN_TUN_MTU};
use mesh_core::{AppError, AppResult, OverlayCidr, OverlayIp};
use tokio::sync::Mutex;

/// Object-safe boxed future alias used across async OS trait boundaries.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Validated TUN adapter configuration passed to platform backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Requested or OS-assigned adapter name (`utun`, `mesh0`, `MeshVPN`).
    pub interface_name: String,
    /// Local overlay IPv4 address assigned to this interface.
    pub overlay_ip: OverlayIp,
    /// Active overlay CIDR subnet.
    pub overlay_cidr: OverlayCidr,
    /// Validated link MTU (`576..=1420`, default `1280`).
    pub mtu: u16,
}

impl TunConfig {
    /// Validates interface name, IP containment in CIDR, and MTU bounds.
    pub fn new(
        interface_name: impl Into<String>,
        overlay_ip: OverlayIp,
        overlay_cidr: OverlayCidr,
        mtu: u16,
    ) -> AppResult<Self> {
        let name = interface_name.into();
        if name.trim().is_empty() || name.len() > 64 {
            return Err(AppError::invalid_argument(
                "TUN interface name must be 1..=64 characters",
            ));
        }
        if !overlay_cidr.contains(overlay_ip) {
            return Err(AppError::invalid_argument(
                "TUN overlay IP must belong to configured overlay CIDR",
            ));
        }
        if !(MIN_TUN_MTU..=MAX_TUN_MTU).contains(&mtu) {
            return Err(AppError::invalid_argument(format!(
                "TUN MTU {mtu} outside allowed range {MIN_TUN_MTU}..={MAX_TUN_MTU}"
            )));
        }
        Ok(Self {
            interface_name: name,
            overlay_ip,
            overlay_cidr,
            mtu,
        })
    }

    /// Creates a config with [`DEFAULT_TUN_MTU`].
    pub fn with_default_mtu(
        interface_name: impl Into<String>,
        overlay_ip: OverlayIp,
        overlay_cidr: OverlayCidr,
    ) -> AppResult<Self> {
        Self::new(interface_name, overlay_ip, overlay_cidr, DEFAULT_TUN_MTU)
    }
}

/// Asynchronous OS-agnostic TUN device interface implemented by Linux, macOS, Windows, and Fake backends.
pub trait TunDevice: Send + Sync + std::fmt::Debug {
    /// Actual OS interface name allocated for this session (e.g., `utun7`, `mesh0`, `MeshVPN`).
    fn interface_name(&self) -> &str;

    /// Configured MTU of this interface.
    fn mtu(&self) -> u16;

    /// Reads the next plaintext L3 IP packet from the kernel into `buf`, returning byte length.
    fn read_packet<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>>;

    /// Writes a decrypted plaintext L3 IP packet back to the kernel TUN device.
    fn write_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>>;

    /// Closes the underlying OS TUN handle idempotently.
    fn close(&self) -> BoxFuture<'_, AppResult<()>>;
}

/// In-memory fake TUN adapter allowing full data-plane unit tests without root/Admin privileges.
#[derive(Debug, Clone)]
pub struct FakeTunDevice {
    config: TunConfig,
    closed: Arc<AtomicBool>,
    inbound_to_daemon: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound_to_kernel: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl FakeTunDevice {
    /// Creates an open [`FakeTunDevice`] with empty packet queues.
    #[must_use]
    pub fn new(config: TunConfig) -> Self {
        Self {
            config,
            closed: Arc::new(AtomicBool::new(false)),
            inbound_to_daemon: Arc::new(Mutex::new(VecDeque::new())),
            outbound_to_kernel: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Enqueues a synthetic plaintext IP packet as if the local OS wrote it into the TUN device.
    pub async fn inject_inbound_packet(&self, packet: Vec<u8>) -> AppResult<()> {
        if packet.len() > MAX_FRAME_SIZE {
            return Err(AppError::invalid_argument(
                "injected fake TUN packet exceeds MAX_FRAME_SIZE",
            ));
        }
        let mut queue = self.inbound_to_daemon.lock().await;
        queue.push_back(packet);
        Ok(())
    }

    /// Pops all plaintext IP packets written by the daemon into this fake TUN adapter.
    pub async fn drain_outbound_packets(&self) -> Vec<Vec<u8>> {
        let mut queue = self.outbound_to_kernel.lock().await;
        queue.drain(..).collect()
    }

    /// Returns `true` if `close()` has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl TunDevice for FakeTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(AppError::unavailable("fake TUN device is closed"));
            }
            let maybe_pkt = {
                let mut queue = self.inbound_to_daemon.lock().await;
                queue.pop_front()
            };
            let Some(pkt) = maybe_pkt else {
                return Err(AppError::unavailable("no queued packet in fake TUN device"));
            };
            let Some(dst) = buf.get_mut(..pkt.len()) else {
                return Err(AppError::invalid_argument(
                    "destination TUN buffer smaller than packet length",
                ));
            };
            dst.copy_from_slice(&pkt);
            Ok(pkt.len())
        })
    }

    fn write_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(AppError::unavailable("fake TUN device is closed"));
            }
            if packet.is_empty() || packet.len() > MAX_FRAME_SIZE {
                return Err(AppError::invalid_argument(
                    "TUN write packet size must be 1..=MAX_FRAME_SIZE",
                ));
            }
            let mut queue = self.outbound_to_kernel.lock().await;
            queue.push_back(packet.to_vec());
            Ok(())
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::Release);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use mesh_core::{OverlayCidr, OverlayIp};

    use super::{FakeTunDevice, TunConfig, TunDevice};

    #[tokio::test]
    async fn test_tun_fake_device_round_trip_and_mtu_validation() {
        // Arrange
        let cidr = match "100.115.0.0/16".parse::<OverlayCidr>() {
            Ok(c) => c,
            Err(err) => {
                assert_eq!(err.to_string(), "cidr parse failed");
                return;
            }
        };
        let Ok(ip) = OverlayIp::from_ipv4(Ipv4Addr::new(100, 115, 0, 2)) else {
            return;
        };
        assert!(TunConfig::new("utun7", ip, cidr, 2000).is_err());

        let config = match TunConfig::with_default_mtu("utun7", ip, cidr) {
            Ok(cfg) => cfg,
            Err(err) => {
                assert_eq!(err.to_string(), "config init failed");
                return;
            }
        };
        let dev = FakeTunDevice::new(config);
        let sample = vec![0x45_u8, 0x00, 0x00, 0x14];

        // Act
        assert!(dev.inject_inbound_packet(sample.clone()).await.is_ok());
        let mut buf = [0_u8; 2048];
        let n = dev.read_packet(&mut buf).await.unwrap_or(0);
        assert_eq!(buf.get(..n), Some(sample.as_slice()));
        assert!(dev.write_packet(&sample).await.is_ok());
        let outbound = dev.drain_outbound_packets().await;
        assert!(dev.close().await.is_ok());

        // Assert
        assert_eq!(dev.interface_name(), "utun7");
        assert_eq!(outbound, vec![sample]);
        assert!(dev.is_closed());
        assert!(dev.write_packet(&[0x45]).await.is_err());
    }
}
