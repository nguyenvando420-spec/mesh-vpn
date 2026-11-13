//! macOS kernel `utun` async device backend implementing [`TunDevice`] (`US-060`).

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

struct MacOsTunIo {
    rx: pipe::Receiver,
    tx: pipe::Sender,
}

/// macOS `AF_SYSTEM`/`SYSPROTO_CONTROL` asynchronous `utunN` adapter backed by Tokio `pipe`
/// readiness streams.
pub struct MacOsTunDevice {
    config: TunConfig,
    io: Mutex<Option<Arc<MacOsTunIo>>>,
}

impl fmt::Debug for MacOsTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active = self.io.lock().map(|guard| guard.is_some()).unwrap_or(false);
        f.debug_struct("MacOsTunDevice")
            .field("config", &self.config)
            .field("active", &active)
            .finish()
    }
}

impl MacOsTunDevice {
    /// Opens a macOS `utunN` interface (`"utun"` requests the next free unit from the kernel).
    pub fn open(config: TunConfig) -> AppResult<Self> {
        let unit_hint = parse_utun_unit_hint(&config.interface_name)?;
        let (assigned_name, owned_fd) = mesh_sys::tun_macos::open_utun_owned(unit_hint)?;
        mesh_sys::tun_macos::validate_utun_name(&assigned_name)?;

        let actual_config = TunConfig::new(
            assigned_name.clone(),
            config.overlay_ip,
            config.overlay_cidr,
            config.mtu,
        )?;
        let device = Self::from_owned_fd(actual_config, owned_fd)?;

        tracing::info!(
            component = "tun_macos",
            event = "utun_opened",
            interface = %device.config.interface_name,
            mtu = device.config.mtu,
            "opened macOS kernel utun interface"
        );

        Ok(device)
    }

    fn from_owned_fd(actual_config: TunConfig, owned_fd: OwnedFd) -> AppResult<Self> {
        let tx_owned = owned_fd.try_clone().map_err(|err| {
            AppError::unavailable(format!(
                "failed duplicating macOS {} descriptor: {err}",
                actual_config.interface_name
            ))
        })?;
        let rx = pipe::Receiver::from_owned_fd_unchecked(owned_fd).map_err(|err| {
            AppError::unavailable(format!(
                "failed registering macOS {} reader with Tokio: {err}",
                actual_config.interface_name
            ))
        })?;
        let tx = pipe::Sender::from_owned_fd_unchecked(tx_owned).map_err(|err| {
            AppError::unavailable(format!(
                "failed registering macOS {} writer with Tokio: {err}",
                actual_config.interface_name
            ))
        })?;

        Ok(Self {
            config: actual_config,
            io: Mutex::new(Some(Arc::new(MacOsTunIo { rx, tx }))),
        })
    }

    /// Writes `utunN` into `ResourceLedger` **before** running `/sbin/ifconfig` (`US-060`, `G4`).
    pub fn configure_with_ledger(
        &self,
        executor: &dyn CommandExecutor,
        ledger: &mut ResourceLedger,
        started_at_ms: u64,
    ) -> AppResult<()> {
        mesh_sys::tun_macos::validate_utun_name(&self.config.interface_name)?;
        ledger.record_tun_before_create(
            self.config.interface_name.clone(),
            None,
            std::process::id(),
            started_at_ms,
        )?;
        configure_macos_utun_link(executor, &self.config)
    }

    fn active_io(&self) -> AppResult<Arc<MacOsTunIo>> {
        let guard = self
            .io
            .lock()
            .map_err(|_| AppError::internal("macOS utun fd mutex poisoned"))?;
        guard
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| AppError::unavailable("macOS utun device is closed"))
    }
}

/// Parses `"utun"` (dynamic) or `"utun<N>"` (specific hint) while rejecting arbitrary names.
pub fn parse_utun_unit_hint(raw_name: &str) -> AppResult<Option<u32>> {
    let trimmed = raw_name.trim();
    if trimmed.is_empty() || trimmed == "utun" {
        return Ok(None);
    }
    let Some(suffix) = trimmed.strip_prefix("utun") else {
        return Err(AppError::invalid_argument(format!(
            "macOS TUN interface name '{raw_name}' must be 'utun' or 'utun<N>'"
        )));
    };
    let unit = suffix.parse::<u32>().map_err(|_| {
        AppError::invalid_argument(format!(
            "macOS TUN interface name '{raw_name}' has invalid unit suffix"
        ))
    })?;
    Ok(Some(unit))
}

/// Configures point-to-point overlay IPv4 address and MTU strictly on the owned `utunN` device.
pub fn configure_macos_utun_link(
    executor: &dyn CommandExecutor,
    config: &TunConfig,
) -> AppResult<()> {
    mesh_sys::tun_macos::validate_utun_name(&config.interface_name)?;
    let ip_str = config.overlay_ip.to_string();
    let mtu_str = config.mtu.to_string();

    let spec = CommandSpec::new(
        AllowedBinary::MacOsIfconfig,
        [
            config.interface_name.clone(),
            "inet".to_owned(),
            ip_str.clone(),
            ip_str,
            "mtu".to_owned(),
            mtu_str,
            "up".to_owned(),
        ],
    )?;
    let output = executor.execute(&spec)?;
    if !output.success() {
        return Err(AppError::internal(format!(
            "/sbin/ifconfig failed on {} (exit {}): {}",
            config.interface_name,
            output.status_code,
            output.stderr.trim()
        )));
    }

    tracing::info!(
        component = "tun_macos",
        event = "utun_configured",
        interface = %config.interface_name,
        overlay_ip = %config.overlay_ip,
        mtu = config.mtu,
        "configured macOS utun overlay address and MTU"
    );
    Ok(())
}

impl TunDevice for MacOsTunDevice {
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
                    AppError::unavailable(format!("macOS utun readability wait failed: {err}"))
                })?;
                match io
                    .rx
                    .try_io(|| mesh_sys::tun_macos::read_utun_packet(&io.rx, buf))
                {
                    Ok(0) => continue,
                    Ok(n) => return Ok(n),
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        continue;
                    }
                    Err(err) => {
                        return Err(AppError::internal(format!("macOS utun read error: {err}")));
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
                    AppError::unavailable(format!("macOS utun writability wait failed: {err}"))
                })?;
                match io
                    .tx
                    .try_io(|| mesh_sys::tun_macos::write_utun_packet(&io.tx, packet))
                {
                    Ok(_) => return Ok(()),
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                    {
                        continue;
                    }
                    Err(err) => {
                        return Err(AppError::internal(format!("macOS utun write error: {err}")));
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
                .map_err(|_| AppError::internal("macOS utun fd mutex poisoned"))?;
            let dropped = guard.take();
            drop(guard);
            drop(dropped);
            tracing::info!(
                component = "tun_macos",
                event = "utun_closed",
                interface = %self.config.interface_name,
                "closed macOS utun device"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use mesh_core::{OverlayCidr, OverlayIp};
    use tempfile::tempdir;

    use super::{MacOsTunDevice, configure_macos_utun_link, parse_utun_unit_hint};
    use crate::ledger::ResourceLedger;
    use crate::sysexec::{AllowedBinary, CommandOutput, FakeCommandExecutor};
    use crate::tun::TunConfig;

    #[test]
    fn test_tun_macos_unit_hint_parsing_and_rejection() {
        // Arrange & Act & Assert
        assert_eq!(parse_utun_unit_hint("utun").expect("dynamic"), None);
        assert_eq!(parse_utun_unit_hint("").expect("empty dynamic"), None);
        assert_eq!(parse_utun_unit_hint("utun7").expect("unit 7"), Some(7));
        assert!(parse_utun_unit_hint("en0").is_err());
        assert!(parse_utun_unit_hint("utun-2").is_err());
    }

    #[test]
    fn test_tun_macos_configure_utun_link_issues_ifconfig() {
        // Arrange
        let executor = FakeCommandExecutor::new();
        executor
            .push_result(Ok(CommandOutput {
                status_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }))
            .expect("queue ifconfig");
        let config = TunConfig::new(
            "utun7",
            OverlayIp::from_str("100.115.0.7").expect("ip"),
            OverlayCidr::from_str("100.115.0.0/16").expect("cidr"),
            1280,
        )
        .expect("config");

        // Act
        configure_macos_utun_link(&executor, &config).expect("configure ifconfig");

        // Assert
        let recorded = executor.recorded().expect("recorded");
        assert_eq!(recorded.len(), 1);
        let cmd = recorded.first().expect("one cmd");
        assert_eq!(cmd.binary, AllowedBinary::MacOsIfconfig);
        assert_eq!(
            cmd.args,
            [
                "utun7",
                "inet",
                "100.115.0.7",
                "100.115.0.7",
                "mtu",
                "1280",
                "up"
            ]
        );
    }

    #[tokio::test]
    #[ignore = "privileged"]
    async fn test_tun_macos_open_records_ledger_and_closes_cleanly() {
        // Arrange
        let dir = tempdir().expect("tempdir");
        let mut ledger =
            ResourceLedger::load_or_init(dir.path().join("ledger.json")).expect("ledger");
        let config = TunConfig::with_default_mtu(
            "utun",
            OverlayIp::from_str("100.115.0.8").expect("ip"),
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
            .expect("queue ifconfig");

        // Act
        let dev = MacOsTunDevice::open(config).expect("open macOS utun");
        dev.configure_with_ledger(&executor, &mut ledger, 1_700_000_000_000)
            .expect("configure with ledger");

        // Assert
        let recorded_name = ledger
            .data()
            .tun_interface_name
            .as_deref()
            .expect("recorded in ledger");
        assert!(recorded_name.starts_with("utun"));
        crate::tun::TunDevice::close(&dev).await.expect("close");
    }

    #[tokio::test]
    async fn test_tun_macos_read_skips_header_only_frame_and_formats_debug_cleanly() {
        // Arrange
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram as StdUnixDatagram;
        use std::time::Duration;

        use crate::tun::TunDevice;

        let (sock_a, sock_b) = StdUnixDatagram::pair().expect("socketpair");
        sock_a.set_nonblocking(true).expect("nonblocking");
        let config = TunConfig::with_default_mtu(
            "utun7",
            OverlayIp::from_str("100.115.0.7").expect("ip"),
            OverlayCidr::from_str("100.115.0.0/16").expect("cidr"),
        )
        .expect("config");
        let dev = MacOsTunDevice::from_owned_fd(config, OwnedFd::from(sock_a)).expect("wrap fd");

        let payload = [0x45_u8, 0x00, 0x00, 0x14];
        let hdr = mesh_sys::tun_macos::encode_utun_family_header(&payload).expect("encode header");
        let mut real_frame = hdr.to_vec();
        real_frame.extend_from_slice(&payload);
        sock_b.send(&hdr).expect("send 4-byte header-only frame");
        sock_b.send(&real_frame).expect("send full utun frame");

        // Act
        let dbg_text = format!("{dev:?}");
        let mut recv_buf = [0_u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), dev.read_packet(&mut recv_buf))
            .await
            .expect("read timeout")
            .expect("read packet");
        dev.write_packet(&payload).await.expect("write packet");
        let mut echoed = [0_u8; 16];
        let m = sock_b.recv(&mut echoed).expect("recv written frame");
        dev.close().await.expect("close");

        // Assert
        assert!(dbg_text.contains("MacOsTunDevice"));
        assert_eq!(n, 4);
        assert_eq!(recv_buf.get(..4), Some(payload.as_slice()));
        assert_eq!(m, 8);
        assert_eq!(echoed.get(..8), Some(real_frame.as_slice()));
    }
}
