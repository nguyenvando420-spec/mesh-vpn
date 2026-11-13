//! Windows Wintun asynchronous TUN backend with SHA-256 DLL verification (`US-015`, `ADR-011`).

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver as StdReceiver, SyncSender as StdSyncSender, sync_channel};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::{self, JoinHandle};

use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult, Clock, ErrorKind, SystemClock};
use mesh_crypto::{ct_eq_bytes, sha256_digest, sha256_hex};
use mesh_sys::netmon_windows::windows_system_directory;
use mesh_sys::tun_windows::{
    DEFAULT_WINTUN_ADAPTER_NAME, DEFAULT_WINTUN_GUID, DEFAULT_WINTUN_RING_CAPACITY,
    LockedWintunFile, WintunAdapter, WintunDll, WintunSession, resolve_app_wintun_path,
};
use tokio::sync::{Mutex as TokioMutex, mpsc as tokio_mpsc};

use crate::ledger::ResourceLedger;
use crate::sysexec::{
    AllowedBinary, CommandExecutor, CommandOutput, CommandSpec, StdCommandExecutor,
};
use crate::tun::{BoxFuture, TunConfig, TunDevice};

const MAX_WINTUN_DLL_BYTES: u64 = 16 * 1024 * 1024;
const RX_POOL_SLOTS: usize = 64;
const RX_PREALLOC_SLOTS: usize = 16;
const RX_WAIT_TIMEOUT_MS: u32 = 1_000;

/// Verification and adapter identity options required to open a Windows Wintun device.
#[derive(Debug, Clone)]
pub struct WindowsTunOpenSpec {
    /// Explicit absolute path to `wintun.dll` in the application directory.
    pub dll_path: PathBuf,
    /// Pinned SHA-256 hex digest of the signed official `wintun.dll` binary.
    pub expected_sha256_hex: String,
    /// Fixed deterministic GUID preventing `#2` ghost adapters across restarts.
    pub adapter_guid: u128,
    /// Wintun ring buffer capacity in bytes (power of two in `[128 KiB, 64 MiB]`).
    pub ring_capacity: u32,
    /// When `true`, enforces that `dll_path` resides directly inside the running binary directory.
    pub require_app_dir: bool,
}

impl WindowsTunOpenSpec {
    /// Creates open options using the application-local `wintun.dll`, fixed GUID, and default 1 MiB ring.
    pub fn app_local(expected_sha256_hex: impl Into<String>) -> AppResult<Self> {
        let dll_path = resolve_app_wintun_path().map_err(AppError::from)?;
        Ok(Self {
            dll_path,
            expected_sha256_hex: expected_sha256_hex.into(),
            adapter_guid: DEFAULT_WINTUN_GUID,
            ring_capacity: DEFAULT_WINTUN_RING_CAPACITY,
            require_app_dir: true,
        })
    }

    /// Creates open options with an explicit `dll_path` and SHA-256 digest (primarily for tests).
    #[must_use]
    pub fn with_dll_path(dll_path: PathBuf, expected_sha256_hex: impl Into<String>) -> Self {
        Self {
            dll_path,
            expected_sha256_hex: expected_sha256_hex.into(),
            adapter_guid: DEFAULT_WINTUN_GUID,
            ring_capacity: DEFAULT_WINTUN_RING_CAPACITY,
            require_app_dir: false,
        }
    }
}

type RxPacketItem = AppResult<(Vec<u8>, usize)>;

/// Windows Wintun ring-buffer adapter (`MeshVPN`) with fixed adapter GUID, NTFS read-lock SHA-256
/// verification, and a zero-allocation recycled RX reader loop.
#[derive(Debug)]
pub struct WindowsTunDevice {
    config: TunConfig,
    interface_index: u32,
    luid_value: u64,
    closed: Arc<AtomicBool>,
    session: Arc<StdMutex<Option<Arc<WintunSession>>>>,
    rx_receiver: TokioMutex<tokio_mpsc::Receiver<RxPacketItem>>,
    recycle_tx: StdSyncSender<Vec<u8>>,
    reader_thread: StdMutex<Option<JoinHandle<()>>>,
    _adapter: Arc<WintunAdapter>,
    _dll: Arc<WintunDll>,
}

impl Drop for WindowsTunDevice {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut guard) = self.session.lock()
            && let Some(session) = guard.take()
        {
            let _woken = session.wake_reader();
        }
        if let Ok(mut guard) = self.reader_thread.lock()
            && let Some(handle) = guard.take()
        {
            let _joined = handle.join();
        }
    }
}

impl WindowsTunDevice {
    /// Fails closed unless a compile-time `MESH_WINTUN_SHA256` release pin is embedded (`ADR-011`).
    ///
    /// Prefer [`Self::open_verified`] so callers provide an explicit verified SHA-256 pin and ledger.
    pub fn open(config: TunConfig) -> AppResult<Self> {
        let Some(pinned_sha256) = option_env!("MESH_WINTUN_SHA256") else {
            return Err(AppError::new(
                ErrorKind::PermissionDenied,
                "wintun.dll SHA-256 pin is required; refusing unverified DLL load",
            ));
        };
        let spec = WindowsTunOpenSpec::app_local(pinned_sha256)?;
        Self::open_verified(config, &spec, None, None)
    }

    /// Verifies `wintun.dll` SHA-256 (`mesh-crypto` + `mesh-sys`), records the adapter in `ledger`,
    /// opens/reuses the fixed-GUID `MeshVPN` adapter, and configures IPv4 address + MTU.
    pub fn open_verified(
        config: TunConfig,
        spec: &WindowsTunOpenSpec,
        ledger: Option<&mut ResourceLedger>,
        executor: Option<&dyn CommandExecutor>,
    ) -> AppResult<Self> {
        let adapter_name = normalize_windows_adapter_name(&config)?;
        // Hold FILE_SHARE_READ kernel NTFS lock continuously across hash verification and `LoadLibraryExW` (`BLK-S1-09`).
        let mut locked_dll =
            LockedWintunFile::open(&spec.dll_path, spec.require_app_dir).map_err(AppError::from)?;
        let _digest = verify_locked_wintun_sha256(&mut locked_dll, &spec.expected_sha256_hex)?;

        if let Some(ledger_ref) = ledger {
            ledger_ref.record_tun_before_create(
                adapter_name.clone(),
                Some(format_guid_hyphenated(spec.adapter_guid)),
                std::process::id(),
                SystemClock::new().now_unix_ms(),
            )?;
        }

        let dll = WintunDll::load_with_read_lock(&locked_dll).map_err(AppError::from)?;
        drop(locked_dll);

        let adapter = WintunAdapter::open_or_create(&dll, &adapter_name, spec.adapter_guid)
            .map_err(AppError::from)?;
        let interface_index = adapter.interface_index().map_err(AppError::from)?;
        let luid_value = adapter.luid_value();
        let session = Arc::new(
            adapter
                .start_session(spec.ring_capacity)
                .map_err(AppError::from)?,
        );

        let default_exec;
        let cmd_exec: &dyn CommandExecutor = match executor {
            Some(exec) => exec,
            None => {
                let sys_dir = windows_system_directory().map_err(AppError::from)?;
                default_exec = StdCommandExecutor::with_windows_system32_dir(sys_dir)?;
                &default_exec
            }
        };
        configure_adapter_ip_and_mtu(&config, &adapter_name, cmd_exec)?;

        let closed = Arc::new(AtomicBool::new(false));
        let (rx_receiver, recycle_tx, reader_thread) =
            spawn_rx_worker(Arc::clone(&session), Arc::clone(&closed), config.mtu);

        tracing::info!(
            target: "mesh::net::tun_windows",
            adapter = %adapter_name,
            if_index = interface_index,
            luid = luid_value,
            mtu = config.mtu,
            "Windows Wintun adapter verified and started"
        );

        Ok(Self {
            config,
            interface_index,
            luid_value,
            closed,
            session: Arc::new(StdMutex::new(Some(session))),
            rx_receiver: TokioMutex::new(rx_receiver),
            recycle_tx,
            reader_thread: StdMutex::new(Some(reader_thread)),
            _adapter: adapter,
            _dll: dll,
        })
    }

    /// Returns the resolved Windows `ifIndex` of the fixed Wintun adapter.
    #[must_use]
    pub const fn interface_index(&self) -> u32 {
        self.interface_index
    }

    /// Returns the Windows `NET_LUID.Value` of the adapter.
    #[must_use]
    pub const fn luid_value(&self) -> u64 {
        self.luid_value
    }

    fn current_session(&self) -> AppResult<Arc<WintunSession>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(AppError::unavailable("Windows Wintun device is closed"));
        }
        let guard = self
            .session
            .lock()
            .map_err(|_| AppError::internal("Windows Wintun session lock poisoned"))?;
        guard
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| AppError::unavailable("Windows Wintun session has been closed"))
    }
}

/// Validates Windows Wintun DLL path hygiene and constant-time `mesh-crypto` SHA-256 integrity
/// on a kernel `FILE_SHARE_READ`-locked file before loading (`BLK-S1-09`).
pub fn verify_wintun_before_load(
    dll_path: &Path,
    expected_sha256_hex: &str,
) -> AppResult<[u8; 32]> {
    let mut locked = LockedWintunFile::open(dll_path, false).map_err(AppError::from)?;
    verify_locked_wintun_sha256(&mut locked, expected_sha256_hex)
}

fn verify_locked_wintun_sha256(
    locked: &mut LockedWintunFile,
    expected_sha256_hex: &str,
) -> AppResult<[u8; 32]> {
    let normalized_expected = normalize_sha256_hex(expected_sha256_hex)?;
    let meta = locked.file().metadata().map_err(|err| {
        AppError::internal(format!("failed reading locked wintun.dll metadata: {err}"))
    })?;
    if meta.len() > MAX_WINTUN_DLL_BYTES {
        return Err(AppError::invalid_argument(
            "wintun.dll exceeds maximum permitted size",
        ));
    }

    let file = locked.file_mut();
    file.seek(SeekFrom::Start(0))
        .map_err(|err| AppError::internal(format!("failed rewinding wintun.dll: {err}")))?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    let read_cap = usize::try_from(MAX_WINTUN_DLL_BYTES).unwrap_or(usize::MAX);
    file.take(MAX_WINTUN_DLL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| AppError::internal(format!("failed reading locked wintun.dll: {err}")))?;
    if bytes.len() > read_cap {
        return Err(AppError::invalid_argument(
            "wintun.dll exceeds maximum permitted size",
        ));
    }

    let actual_hex = sha256_hex(&bytes);
    if !ct_eq_bytes(actual_hex.as_bytes(), normalized_expected.as_bytes()) {
        return Err(AppError::pin_mismatch(format!(
            "SHA-256 mismatch for `{}`",
            locked.path().display()
        )));
    }
    Ok(sha256_digest(&bytes))
}

fn normalize_sha256_hex(expected_hex: &str) -> AppResult<String> {
    let cleaned = expected_hex
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| expected_hex.trim())
        .trim()
        .to_ascii_lowercase();
    if cleaned.len() != 64 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::invalid_argument(
            "expected SHA-256 digest must be 64 hexadecimal characters",
        ));
    }
    Ok(cleaned)
}

fn normalize_windows_adapter_name(config: &TunConfig) -> AppResult<String> {
    let trimmed = config.interface_name.trim();
    if trimmed.is_empty() {
        return Ok(DEFAULT_WINTUN_ADAPTER_NAME.to_owned());
    }
    if trimmed.len() > 63 || trimmed.contains('\0') {
        return Err(AppError::invalid_argument("invalid Windows adapter name"));
    }
    Ok(trimmed.to_owned())
}

/// Formats a `u128` GUID value using standard hyphenated Microsoft UUID string syntax.
#[must_use]
pub fn format_guid_hyphenated(value: u128) -> String {
    let p1 = (value >> 96) as u32;
    let p2 = ((value >> 80) & 0xffff) as u16;
    let p3 = ((value >> 64) & 0xffff) as u16;
    let p4 = ((value >> 48) & 0xffff) as u16;
    let p5 = value & 0xffff_ffff_ffff;
    format!("{{{p1:08x}-{p2:04x}-{p3:04x}-{p4:04x}-{p5:012x}}}")
}

fn configure_adapter_ip_and_mtu(
    config: &TunConfig,
    adapter_name: &str,
    executor: &dyn CommandExecutor,
) -> AppResult<()> {
    let ip_cidr = format!(
        "{}/{}",
        config.overlay_ip.as_ipv4(),
        config.overlay_cidr.prefix_len()
    );
    let addr_spec = CommandSpec::new(
        AllowedBinary::WindowsNetsh,
        vec![
            "interface".to_owned(),
            "ipv4".to_owned(),
            "set".to_owned(),
            "address".to_owned(),
            format!("name={adapter_name}"),
            "source=static".to_owned(),
            format!("address={ip_cidr}"),
            "store=active".to_owned(),
        ],
    )?;
    let addr_out = executor.execute(&addr_spec)?;
    check_netsh_step(&addr_out, "set adapter IPv4 address")?;

    let mtu_spec = CommandSpec::new(
        AllowedBinary::WindowsNetsh,
        vec![
            "interface".to_owned(),
            "ipv4".to_owned(),
            "set".to_owned(),
            "subinterface".to_owned(),
            format!("interface={adapter_name}"),
            format!("mtu={}", config.mtu),
            "store=active".to_owned(),
        ],
    )?;
    let mtu_out = executor.execute(&mtu_spec)?;
    check_netsh_step(&mtu_out, "set adapter MTU")?;
    Ok(())
}

fn check_netsh_step(out: &CommandOutput, action: &'static str) -> AppResult<()> {
    if out.success() {
        return Ok(());
    }
    let detail = if out.stderr.trim().is_empty() {
        out.stdout.trim()
    } else {
        out.stderr.trim()
    };
    let clipped: String = detail.chars().take(240).collect();
    Err(AppError::internal(format!(
        "Windows netsh {action} failed (exit {}): {clipped}",
        out.status_code
    )))
}

type RxChannelPair = (
    tokio_mpsc::Receiver<RxPacketItem>,
    StdSyncSender<Vec<u8>>,
    JoinHandle<()>,
);

fn spawn_rx_worker(
    session: Arc<WintunSession>,
    closed: Arc<AtomicBool>,
    mtu: u16,
) -> RxChannelPair {
    let buf_cap = MAX_FRAME_SIZE.max(usize::from(mtu));
    let (pkt_tx, pkt_rx) = tokio_mpsc::channel(RX_POOL_SLOTS);
    let (recycle_tx, recycle_rx) = sync_channel(RX_POOL_SLOTS);
    for _ in 0..RX_PREALLOC_SLOTS {
        let _seeded = recycle_tx.try_send(vec![0_u8; buf_cap]);
    }

    let handle = thread::spawn(move || {
        wintun_rx_loop(&session, &closed, buf_cap, &pkt_tx, &recycle_rx);
    });
    (pkt_rx, recycle_tx, handle)
}

fn wintun_rx_loop(
    session: &Arc<WintunSession>,
    closed: &Arc<AtomicBool>,
    buf_cap: usize,
    pkt_tx: &tokio_mpsc::Sender<RxPacketItem>,
    recycle_rx: &StdReceiver<Vec<u8>>,
) {
    let mut spare_buf: Option<Vec<u8>> = None;
    loop {
        if closed.load(Ordering::Acquire) {
            break;
        }
        let mut slot = take_rx_slot(&mut spare_buf, recycle_rx, buf_cap);
        match session.try_receive_packet(&mut slot) {
            Ok(Some(len)) => {
                if pkt_tx.blocking_send(Ok((slot, len))).is_err() {
                    break;
                }
            }
            Ok(None) => {
                spare_buf = Some(slot);
                if let Err(err) = session.wait_readable(RX_WAIT_TIMEOUT_MS) {
                    if closed.load(Ordering::Acquire) {
                        break;
                    }
                    let _sent = pkt_tx.blocking_send(Err(AppError::from(err)));
                    break;
                }
            }
            Err(err) => {
                if closed.load(Ordering::Acquire) {
                    break;
                }
                let _sent = pkt_tx.blocking_send(Err(AppError::from(err)));
                break;
            }
        }
    }
}

fn take_rx_slot(
    spare_buf: &mut Option<Vec<u8>>,
    recycle_rx: &StdReceiver<Vec<u8>>,
    buf_cap: usize,
) -> Vec<u8> {
    if let Some(mut buf) = spare_buf.take() {
        if buf.len() < buf_cap {
            buf.resize(buf_cap, 0);
        }
        return buf;
    }
    if let Ok(mut recycled) = recycle_rx.try_recv() {
        if recycled.len() < buf_cap {
            recycled.resize(buf_cap, 0);
        }
        return recycled;
    }
    vec![0_u8; buf_cap]
}

impl TunDevice for WindowsTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(AppError::unavailable("Windows Wintun device closed"));
            }
            let next_item = {
                let mut guard = self.rx_receiver.lock().await;
                guard.recv().await
            };
            let Some(packet_res) = next_item else {
                return Err(AppError::unavailable("Windows Wintun device closed"));
            };
            let (pkt_buf, pkt_len) = packet_res?;
            let result = match (pkt_buf.get(..pkt_len), buf.get_mut(..pkt_len)) {
                (Some(src), Some(dst)) => {
                    dst.copy_from_slice(src);
                    Ok(pkt_len)
                }
                _ => Err(AppError::invalid_argument(
                    "caller RX buffer is smaller than incoming Wintun IP packet",
                )),
            };
            let _recycled = self.recycle_tx.try_send(pkt_buf);
            result
        })
    }

    fn write_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async move {
            let session = self.current_session()?;
            session.send_packet(packet).map_err(AppError::from)
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async {
            self.closed.store(true, Ordering::Release);
            {
                let mut guard = self
                    .session
                    .lock()
                    .map_err(|_| AppError::internal("Windows Wintun session lock poisoned"))?;
                if let Some(session) = guard.take() {
                    let _woken = session.wake_reader();
                }
            }
            let handle = {
                let mut guard = self
                    .reader_thread
                    .lock()
                    .map_err(|_| AppError::internal("Wintun RX thread lock poisoned"))?;
                guard.take()
            };
            if let Some(join_handle) = handle {
                let _joined = tokio::task::spawn_blocking(move || join_handle.join()).await;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::Ipv4Addr;

    use mesh_core::{OverlayCidr, OverlayIp};
    use tempfile::tempdir;

    use super::{
        TunConfig, WindowsTunDevice, WindowsTunOpenSpec, configure_adapter_ip_and_mtu,
        format_guid_hyphenated, verify_wintun_before_load,
    };
    use crate::sysexec::{CommandOutput, FakeCommandExecutor};

    fn sample_tun_config() -> Option<TunConfig> {
        let cidr = "100.64.0.0/10".parse::<OverlayCidr>().ok()?;
        let overlay_ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 10)).ok()?;
        TunConfig::with_default_mtu("MeshVPN", overlay_ip, cidr).ok()
    }

    #[test]
    fn test_tun_windows_open_without_pin_fails_closed() {
        // Arrange
        let cfg = sample_tun_config();
        assert!(cfg.is_some());
        let Some(cfg) = cfg else {
            return;
        };

        // Act
        let res = WindowsTunDevice::open(cfg);

        // Assert
        if option_env!("MESH_WINTUN_SHA256").is_none() {
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_tun_windows_open_verified_rejects_bad_sha256_before_load() {
        // Arrange
        let dir = tempdir();
        assert!(dir.is_ok());
        let Ok(dir) = dir else {
            return;
        };
        let dll = dir.path().join("wintun.dll");
        assert!(fs::write(&dll, b"corrupt-wintun-binary").is_ok());
        let cfg = sample_tun_config();
        assert!(cfg.is_some());
        let Some(cfg) = cfg else {
            return;
        };
        let spec = WindowsTunOpenSpec::with_dll_path(
            dll.clone(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

        // Act
        let precheck = verify_wintun_before_load(&dll, &spec.expected_sha256_hex);
        let open_res = WindowsTunDevice::open_verified(cfg, &spec, None, None);

        // Assert
        assert!(precheck.is_err());
        assert!(open_res.is_err());
    }

    #[test]
    fn test_tun_windows_configure_adapter_invokes_netsh_address_and_mtu() {
        // Arrange
        let cfg = sample_tun_config();
        assert!(cfg.is_some());
        let Some(cfg) = cfg else {
            return;
        };
        let fake_exec = FakeCommandExecutor::new();

        // Act
        let res = configure_adapter_ip_and_mtu(&cfg, "MeshVPN", &fake_exec);

        // Assert
        assert!(res.is_ok(), "configure_adapter_ip_and_mtu failed: {res:?}");
        let calls = fake_exec.recorded();
        assert!(calls.is_ok());
        if let Ok(calls) = calls {
            assert_eq!(calls.len(), 2);
            if let Some(mtu_call) = calls.get(1) {
                assert!(mtu_call.args.iter().any(|arg| arg == "interface=MeshVPN"));
            }
        }
        assert!(
            format_guid_hyphenated(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10_u128).starts_with('{')
        );
    }

    #[test]
    fn test_tun_windows_configure_adapter_fails_on_nonzero_netsh_status() {
        // Arrange
        let cfg = sample_tun_config();
        assert!(cfg.is_some());
        let Some(cfg) = cfg else {
            return;
        };
        let fake_exec = FakeCommandExecutor::new();
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }))
                .is_ok()
        );
        assert!(
            fake_exec
                .push_result(Ok(CommandOutput {
                    status_code: 1,
                    stdout: "The filename, directory name, or volume label syntax is incorrect."
                        .to_owned(),
                    stderr: String::new(),
                }))
                .is_ok()
        );

        // Act
        let res = configure_adapter_ip_and_mtu(&cfg, "MeshVPN", &fake_exec);

        // Assert
        assert!(res.is_err());
    }
}
