//! Linux `/dev/net/tun` async device backend implementing [`TunDevice`] (`US-014`).

use std::fmt;
use std::io::ErrorKind;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult};
use tokio::net::unix::pipe;

use crate::ledger::ResourceLedger;
use crate::sysexec::{AllowedBinary, CommandExecutor, CommandSpec};
use crate::tun::{BoxFuture, TunConfig, TunDevice};

struct LinuxTunIo {
    rx: pipe::Receiver,
    tx: pipe::Sender,
}

/// Linux `/dev/net/tun` asynchronous TUN adapter backed by Tokio `pipe` readiness streams.
pub struct LinuxTunDevice {
    config: TunConfig,
    io: Mutex<Option<Arc<LinuxTunIo>>>,
}

impl fmt::Debug for LinuxTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active = self.io.lock().map(|guard| guard.is_some()).unwrap_or(false);
        f.debug_struct("LinuxTunDevice")
            .field("config", &self.config)
            .field("active", &active)
            .finish()
    }
}

impl LinuxTunDevice {
    /// Opens `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`) using the requested configuration.
    pub fn open(config: TunConfig) -> AppResult<Self> {
        let preferred = if config.interface_name.is_empty() {
            None
        } else {
            Some(config.interface_name.as_str())
        };
        let (assigned_name, owned_fd) = mesh_sys::tun_linux::open_tun_owned(preferred)?;
        let actual_config = TunConfig::new(
            assigned_name.clone(),
            config.overlay_ip,
            config.overlay_cidr,
            config.mtu,
        )?;
        let device = Self::from_owned_fd(actual_config, owned_fd)?;

        tracing::info!(
            component = "tun_linux",
            event = "tun_opened",
            interface = %device.config.interface_name,
            mtu = device.config.mtu,
            "opened Linux TUN device"
        );

        Ok(device)
    }

    fn from_owned_fd(actual_config: TunConfig, owned_fd: OwnedFd) -> AppResult<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(AppError::unavailable(
                "TUN device registration requires an active Tokio runtime reactor",
            ));
        }
        let tx_owned = owned_fd.try_clone().map_err(|err| {
            AppError::unavailable(format!(
                "failed duplicating Linux TUN {} descriptor: {err}",
                actual_config.interface_name
            ))
        })?;
        let rx = pipe::Receiver::from_owned_fd_unchecked(owned_fd).map_err(|err| {
            AppError::unavailable(format!(
                "failed registering Linux TUN {} reader with Tokio: {err}",
                actual_config.interface_name
            ))
        })?;
        let tx = pipe::Sender::from_owned_fd_unchecked(tx_owned).map_err(|err| {
            AppError::unavailable(format!(
                "failed registering Linux TUN {} writer with Tokio: {err}",
                actual_config.interface_name
            ))
        })?;

        Ok(Self {
            config: actual_config,
            io: Mutex::new(Some(Arc::new(LinuxTunIo { rx, tx }))),
        })
    }

    /// Persists the interface name in `ResourceLedger` before assigning its IP, MTU, and UP state
    /// via `/usr/sbin/ip` (with `/sbin/ip` fallback).
    pub fn configure_with_ledger(
        &self,
        executor: &dyn CommandExecutor,
        ledger: &mut ResourceLedger,
        started_at_ms: u64,
    ) -> AppResult<()> {
        ledger.record_tun_before_create(
            self.config.interface_name.clone(),
            None,
            std::process::id(),
            started_at_ms,
        )?;
        configure_linux_link(executor, &self.config)
    }

    fn active_io(&self) -> AppResult<Arc<LinuxTunIo>> {
        let guard = self
            .io
            .lock()
            .map_err(|_| AppError::internal("Linux TUN fd mutex poisoned"))?;
        guard
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| AppError::unavailable("Linux TUN device is closed"))
    }
}

/// Applies the overlay address, MTU, and `UP` link state using allowlisted `ip` binary paths.
pub fn configure_linux_link(executor: &dyn CommandExecutor, config: &TunConfig) -> AppResult<()> {
    mesh_sys::tun_linux::validate_linux_ifname(&config.interface_name)?;
    let addr_cidr = format!("{}/{}", config.overlay_ip, config.overlay_cidr.prefix_len());
    let mtu_str = config.mtu.to_string();

    execute_ip_with_fallback(
        executor,
        [
            "addr".to_owned(),
            "replace".to_owned(),
            addr_cidr,
            "dev".to_owned(),
            config.interface_name.clone(),
        ],
    )?;
    execute_ip_with_fallback(
        executor,
        [
            "link".to_owned(),
            "set".to_owned(),
            "dev".to_owned(),
            config.interface_name.clone(),
            "mtu".to_owned(),
            mtu_str,
            "up".to_owned(),
        ],
    )?;

    tracing::info!(
        component = "tun_linux",
        event = "tun_configured",
        interface = %config.interface_name,
        overlay_ip = %config.overlay_ip,
        mtu = config.mtu,
        "configured Linux TUN overlay IP and MTU"
    );
    Ok(())
}

pub(crate) fn execute_ip_with_fallback<I>(executor: &dyn CommandExecutor, args: I) -> AppResult<()>
where
    I: IntoIterator<Item = String>,
{
    let arg_vec: Vec<String> = args.into_iter().collect();
    let primary = CommandSpec::new(AllowedBinary::LinuxIpUsrSbin, arg_vec.clone())?;
    let output = match executor.execute(&primary) {
        Ok(out) => out,
        Err(err) => {
            let fallback = CommandSpec::new(AllowedBinary::LinuxIpSbin, arg_vec)?;
            executor.execute(&fallback).map_err(|fallback_err| {
                AppError::internal(format!(
                    "failed executing /usr/sbin/ip ({err}) and /sbin/ip ({fallback_err})"
                ))
            })?
        }
    };
    if !output.success() {
        return Err(AppError::internal(format!(
            "ip command exited with {}: {}",
            output.status_code,
            output.stderr.trim()
        )));
    }
    Ok(())
}

impl TunDevice for LinuxTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async move {
            if buf.is_empty() {
                return Err(AppError::invalid_argument(
                    "TUN read buffer cannot be empty",
                ));
            }
            let io = self.active_io()?;
            loop {
                io.rx.readable().await.map_err(|err| {
                    AppError::unavailable(format!("Linux TUN readability wait failed: {err}"))
                })?;
                match io
                    .rx
                    .try_io(|| mesh_sys::tun_linux::read_tun_packet(&io.rx, buf))
                {
                    Ok(0) => continue,
                    Ok(n) => return Ok(n),
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        continue;
                    }
                    Err(err) => {
                        return Err(AppError::internal(format!("Linux TUN read error: {err}")));
                    }
                }
            }
        })
    }

    fn write_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async move {
            if packet.is_empty() || packet.len() > MAX_FRAME_SIZE {
                return Err(AppError::invalid_argument(format!(
                    "TUN packet length {} outside 1..={MAX_FRAME_SIZE}",
                    packet.len()
                )));
            }
            let io = self.active_io()?;
            loop {
                io.tx.writable().await.map_err(|err| {
                    AppError::unavailable(format!("Linux TUN writability wait failed: {err}"))
                })?;
                match io
                    .tx
                    .try_io(|| mesh_sys::tun_linux::write_tun_packet(&io.tx, packet))
                {
                    Ok(_) => return Ok(()),
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        continue;
                    }
                    Err(err) => {
                        return Err(AppError::internal(format!("Linux TUN write error: {err}")));
                    }
                }
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async move {
            let mut guard = self
                .io
                .lock()
                .map_err(|_| AppError::internal("Linux TUN fd mutex poisoned"))?;
            let dropped = guard.take();
            drop(guard);
            drop(dropped);
            tracing::info!(
                component = "tun_linux",
                event = "tun_closed",
                interface = %self.config.interface_name,
                "closed Linux TUN device"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use mesh_core::{AppError, OverlayCidr, OverlayIp};
    use tempfile::tempdir;

    use super::{LinuxTunDevice, configure_linux_link};
    use crate::ledger::ResourceLedger;
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};
    use crate::tun::TunConfig;

    #[test]
    fn test_tun_linux_configure_link_issues_addr_and_mtu_commands() {
        // Arrange
        let executor = FakeCommandExecutor::new();
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue addr output");
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue link output");
        let config = TunConfig::new(
            "mesh0",
            OverlayIp::from_str("100.115.0.10").expect("ip"),
            OverlayCidr::from_str("100.115.0.0/16").expect("cidr"),
            1280,
        )
        .expect("config");

        // Act
        configure_linux_link(&executor, &config).expect("configure link");

        // Assert
        let recorded = executor.recorded().expect("recorded");
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded.first().map(|c| c.binary),
            Some(AllowedBinary::LinuxIpUsrSbin)
        );
        assert!(
            recorded
                .get(1)
                .is_some_and(|c| c.args == ["link", "set", "dev", "mesh0", "mtu", "1280", "up"])
        );
    }

    #[test]
    fn test_tun_linux_fallback_to_sbin_ip_on_usr_sbin_failure() {
        // Arrange
        let executor = FakeCommandExecutor::new();
        executor
            .push_result(Err(AppError::unavailable("missing /usr/sbin/ip")))
            .expect("queue missing primary");
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue fallback addr output");
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue link output");
        let config = TunConfig::with_default_mtu(
            "mesh0",
            OverlayIp::from_str("100.115.0.10").expect("ip"),
            OverlayCidr::from_str("100.115.0.0/16").expect("cidr"),
        )
        .expect("config");

        // Act
        configure_linux_link(&executor, &config).expect("fallback to /sbin/ip");

        // Assert
        let recorded = executor.recorded().expect("recorded");
        assert_eq!(recorded.len(), 3);
        assert_eq!(
            recorded.get(1).map(|c| c.binary),
            Some(AllowedBinary::LinuxIpSbin)
        );
    }

    #[tokio::test]
    #[ignore = "privileged"]
    async fn test_tun_linux_open_and_close_with_ledger() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let mut ledger =
            ResourceLedger::load_or_init(dir.path().join("ledger.json")).expect("ledger");
        let config = TunConfig::with_default_mtu(
            "mesh9",
            OverlayIp::from_str("100.115.0.9").expect("ip"),
            OverlayCidr::from_str("100.115.0.0/16").expect("cidr"),
        )
        .expect("config");
        let executor = FakeCommandExecutor::new();
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue addr");
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue link");

        // Act
        let dev = LinuxTunDevice::open(config).expect("open TUN");
        dev.configure_with_ledger(&executor, &mut ledger, 1_700_000_000_000)
            .expect("configure with ledger");
        assert_eq!(ledger.data().tun_interface_name.as_deref(), Some("mesh9"));

        // Assert
        crate::tun::TunDevice::close(&dev).await.expect("close TUN");
    }

    #[tokio::test]
    async fn test_tun_linux_read_skips_zero_byte_frames_and_formats_debug_cleanly() {
        // Arrange
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram as StdUnixDatagram;
        use std::time::Duration;

        use crate::tun::TunDevice;

        let (sock_a, sock_b) = StdUnixDatagram::pair().expect("socketpair");
        sock_a.set_nonblocking(true).expect("nonblocking");
        let config = TunConfig::with_default_mtu(
            "mesh0",
            OverlayIp::from_str("100.115.0.10").expect("ip"),
            OverlayCidr::from_str("100.115.0.0/16").expect("cidr"),
        )
        .expect("config");
        let dev = LinuxTunDevice::from_owned_fd(config, OwnedFd::from(sock_a)).expect("wrap fd");

        let payload = [0x45_u8, 0x00, 0x00, 0x14];
        sock_b.send(&[]).expect("send zero-byte frame");
        sock_b.send(&payload).expect("send real packet");

        // Act
        let dbg_text = format!("{dev:?}");
        let mut recv_buf = [0_u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), dev.read_packet(&mut recv_buf))
            .await
            .expect("read timeout")
            .expect("read packet");
        dev.write_packet(&payload).await.expect("write packet");
        let mut echoed = [0_u8; 16];
        let m = sock_b.recv(&mut echoed).expect("recv written packet");
        dev.close().await.expect("close");

        // Assert
        assert!(dbg_text.contains("LinuxTunDevice"));
        assert_eq!(n, 4);
        assert_eq!(recv_buf.get(..4), Some(payload.as_slice()));
        assert_eq!(m, 4);
        assert_eq!(echoed.get(..4), Some(payload.as_slice()));
    }
}
