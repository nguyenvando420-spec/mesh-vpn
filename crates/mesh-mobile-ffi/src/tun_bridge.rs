//! Mobile TUN adapters: iOS `NEPacketTunnelFlow` channel adapter (`PacketFlowAdapter`) and
//! Android detached TUN descriptor adapter (`AndroidTunDevice`) with zero handwritten `unsafe`.

#[cfg(any(target_os = "android", all(unix, test)))]
use std::os::fd::OwnedFd;
use std::sync::Arc;
#[cfg(any(target_os = "android", all(unix, test)))]
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(target_os = "android", all(unix, test)))]
use std::time::Duration;

use mesh_core::defaults::MAX_FRAME_SIZE;
use mesh_core::{AppError, AppResult};
use mesh_net::tun::{BoxFuture, TunConfig, TunDevice};
#[cfg(any(target_os = "android", all(unix, test)))]
use tokio::net::unix::pipe;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::debug;
#[cfg(any(target_os = "android", all(unix, test)))]
use tracing::warn;

use crate::types::PlatformNetworkBridge;

/// Fixed non-blocking channel capacity between `push_tun_packets` and `DatapathEngine` (`§3.1`).
pub(crate) const TUN_INGRESS_QUEUE_CAPACITY: usize = 128;

/// Fixed non-blocking outbound queue capacity from `DatapathEngine` to `on_tun_packets`.
pub(crate) const TUN_EGRESS_QUEUE_CAPACITY: usize = 128;

/// Maximum decrypted L3 packets coalesced per `PlatformNetworkBridge::on_tun_packets` batch.
const TUN_OUTBOUND_BATCH_LIMIT: usize = 32;

/// iOS `NEPacketTunnelFlow` (and cross-platform testable) [`TunDevice`] adapter.
pub(crate) struct PacketFlowAdapter {
    config: TunConfig,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_drops: AtomicU64,
    outbound_drops: AtomicU64,
    closed: AtomicBool,
    close_notify: Notify,
}

impl std::fmt::Debug for PacketFlowAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketFlowAdapter")
            .field("config", &self.config)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("inbound_drops", &self.inbound_drops.load(Ordering::Relaxed))
            .field(
                "outbound_drops",
                &self.outbound_drops.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

/// Asynchronous outbound batch pump forwarding `PacketFlowAdapter` writes to `PlatformNetworkBridge`.
pub(crate) struct PacketFlowOutboundPump {
    rx: mpsc::Receiver<Vec<u8>>,
    bridge: Arc<dyn PlatformNetworkBridge>,
}

impl std::fmt::Debug for PacketFlowOutboundPump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketFlowOutboundPump")
            .finish_non_exhaustive()
    }
}

impl PacketFlowOutboundPump {
    /// Runs until channel closes or `shutdown` triggers, delivering up to 32 packets per FFI call.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        loop {
            let first = tokio::select! {
                () = shutdown.cancelled() => break,
                maybe_pkt = self.rx.recv() => match maybe_pkt {
                    Some(pkt) => pkt,
                    None => break,
                },
            };
            let mut batch = Vec::with_capacity(TUN_OUTBOUND_BATCH_LIMIT);
            batch.push(first);
            while batch.len() < TUN_OUTBOUND_BATCH_LIMIT {
                match self.rx.try_recv() {
                    Ok(pkt) => batch.push(pkt),
                    Err(_) => break,
                }
            }
            self.bridge.on_tun_packets(batch);
        }
    }
}

impl PacketFlowAdapter {
    /// Creates an open adapter paired with its non-blocking outbound batch pump.
    #[must_use]
    pub(crate) fn new(
        config: TunConfig,
        bridge: Arc<dyn PlatformNetworkBridge>,
    ) -> (Arc<Self>, PacketFlowOutboundPump) {
        let (inbound_tx, inbound_rx) = mpsc::channel(TUN_INGRESS_QUEUE_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::channel(TUN_EGRESS_QUEUE_CAPACITY);
        let adapter = Arc::new(Self {
            config,
            inbound_tx,
            inbound_rx: AsyncMutex::new(inbound_rx),
            outbound_tx,
            inbound_drops: AtomicU64::new(0),
            outbound_drops: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        });
        let pump = PacketFlowOutboundPump {
            rx: outbound_rx,
            bridge,
        };
        (adapter, pump)
    }

    /// Enqueues outbound L3 IP packets from host (`push_tun_packets`) using `try_send` drop-tail.
    pub(crate) fn push_packets(&self, packets: Vec<Vec<u8>>) -> u32 {
        if self.closed.load(Ordering::SeqCst) {
            return 0;
        }
        let mut accepted = 0_u32;
        for pkt in packets {
            if pkt.is_empty() || pkt.len() > MAX_FRAME_SIZE {
                self.inbound_drops.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match self.inbound_tx.try_send(pkt) {
                Ok(()) => {
                    accepted = accepted.saturating_add(1);
                }
                Err(_) => {
                    self.inbound_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        accepted
    }

    /// Returns cumulative dropped packets (`(inbound_drops, outbound_drops)`).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn drop_counts(&self) -> (u64, u64) {
        (
            self.inbound_drops.load(Ordering::Relaxed),
            self.outbound_drops.load(Ordering::Relaxed),
        )
    }
}

impl TunDevice for PacketFlowAdapter {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async move {
            loop {
                if self.closed.load(Ordering::SeqCst) {
                    return Err(AppError::unavailable("PacketFlowAdapter is closed"));
                }
                let mut rx_guard = self.inbound_rx.lock().await;
                let pkt = tokio::select! {
                    () = self.close_notify.notified() => {
                        return Err(AppError::unavailable("PacketFlowAdapter closed"));
                    }
                    maybe_pkt = rx_guard.recv() => match maybe_pkt {
                        Some(p) => p,
                        None => return Err(AppError::unavailable("PacketFlowAdapter ingress closed")),
                    },
                };
                drop(rx_guard);

                if pkt.len() > buf.len() {
                    debug!(
                        component = "mesh_mobile_ffi.tun_bridge",
                        event = "packet_flow_oversize_ingress_dropped",
                        pkt_len = pkt.len(),
                        buf_len = buf.len(),
                        "dropping ingress packet exceeding TUN read buffer"
                    );
                    continue;
                }
                if let Some(dst) = buf.get_mut(..pkt.len()) {
                    dst.copy_from_slice(&pkt);
                    return Ok(pkt.len());
                }
            }
        })
    }

    fn write_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, AppResult<()>> {
        Box::pin(async move {
            if self.closed.load(Ordering::SeqCst) {
                return Err(AppError::unavailable("PacketFlowAdapter is closed"));
            }
            if packet.is_empty() || packet.len() > MAX_FRAME_SIZE {
                return Err(AppError::invalid_argument(format!(
                    "TUN packet length {} outside 1..={MAX_FRAME_SIZE}",
                    packet.len()
                )));
            }
            if self.outbound_tx.try_send(packet.to_vec()).is_err() {
                self.outbound_drops.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::SeqCst);
            self.close_notify.notify_waiters();
            Ok(())
        })
    }
}

#[cfg(any(target_os = "android", all(unix, test)))]
struct ActiveUnixTunFd {
    rx: pipe::Receiver,
    tx: pipe::Sender,
}

/// Android detached `VpnService` TUN descriptor adapter supporting zero-copy atomic FD swaps
/// across interface reconfigurations (`mobile-ffi-and-storage-design.md` §3.2).
pub(crate) struct AndroidTunDevice {
    config: TunConfig,
    closed: AtomicBool,
    swap_notify: Notify,
    #[cfg(any(target_os = "android", all(unix, test)))]
    inner: StdMutex<Option<Arc<ActiveUnixTunFd>>>,
}

impl std::fmt::Debug for AndroidTunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidTunDevice")
            .field("config", &self.config)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl AndroidTunDevice {
    /// Opens an [`AndroidTunDevice`] from a detached raw Android `ParcelFileDescriptor` FD.
    #[cfg(target_os = "android")]
    pub(crate) fn from_raw_fd(config: TunConfig, raw_fd: i32) -> AppResult<Self> {
        let owned = mesh_sys::tun_android::adopt_raw_tun_fd(raw_fd).map_err(AppError::from)?;
        Self::from_owned_fd(config, owned)
    }

    /// Rejects raw Android TUN FD adoption when compiled for non-Android hosts.
    #[cfg(not(target_os = "android"))]
    pub(crate) fn from_raw_fd(_config: TunConfig, _raw_fd: i32) -> AppResult<Self> {
        Err(AppError::invalid_argument(
            "android_tun_fd is supported only on target_os = \"android\"",
        ))
    }

    /// Wraps an already-validated, `O_NONBLOCK` Unix `OwnedFd` without any `unsafe` blocks.
    #[cfg(any(target_os = "android", all(unix, test)))]
    pub(crate) fn from_owned_fd(config: TunConfig, owned_fd: OwnedFd) -> AppResult<Self> {
        let slot = register_unix_tun_fd(owned_fd)?;
        Ok(Self {
            config,
            closed: AtomicBool::new(false),
            swap_notify: Notify::new(),
            inner: StdMutex::new(Some(slot)),
        })
    }

    /// Atomically swaps in a new detached Android `VpnService` TUN descriptor after route changes.
    #[cfg(target_os = "android")]
    pub(crate) fn swap_raw_fd(&self, new_raw_fd: i32) -> AppResult<()> {
        let owned = mesh_sys::tun_android::adopt_raw_tun_fd(new_raw_fd).map_err(AppError::from)?;
        self.swap_owned_fd(owned)
    }

    /// Non-Android stub returning clean error if raw Android FD swap is attempted on host OS.
    #[cfg(not(target_os = "android"))]
    pub(crate) fn swap_raw_fd(&self, _new_raw_fd: i32) -> AppResult<()> {
        Err(AppError::invalid_argument(
            "new_android_tun_fd is supported only on target_os = \"android\"",
        ))
    }

    /// Atomically installs a replacement Unix `OwnedFd`, closing the prior descriptor cleanly
    /// outside the mutex guard.
    #[cfg(any(target_os = "android", all(unix, test)))]
    pub(crate) fn swap_owned_fd(&self, new_fd: OwnedFd) -> AppResult<()> {
        let new_slot = register_unix_tun_fd(new_fd)?;
        let old_slot = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| AppError::internal("Android TUN fd mutex poisoned"))?;
            guard.replace(new_slot)
        };
        drop(old_slot);
        self.swap_notify.notify_waiters();
        Ok(())
    }

    #[cfg(any(target_os = "android", all(unix, test)))]
    fn current_slot(&self) -> AppResult<Arc<ActiveUnixTunFd>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(AppError::unavailable("Android TUN device is closed"));
        }
        let guard = self
            .inner
            .lock()
            .map_err(|_| AppError::internal("Android TUN fd mutex poisoned"))?;
        guard
            .clone()
            .ok_or_else(|| AppError::unavailable("Android TUN descriptor unavailable"))
    }
}

#[cfg(any(target_os = "android", all(unix, test)))]
fn register_unix_tun_fd(owned_fd: OwnedFd) -> AppResult<Arc<ActiveUnixTunFd>> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(AppError::unavailable(
            "Android TUN descriptor registration requires active Tokio reactor",
        ));
    }
    let tx_owned = owned_fd.try_clone().map_err(|err| {
        AppError::unavailable(format!(
            "failed duplicating Android TUN descriptor for writer: {err}"
        ))
    })?;
    let rx = pipe::Receiver::from_owned_fd_unchecked(owned_fd).map_err(|err| {
        AppError::unavailable(format!(
            "failed registering Android TUN reader with Tokio: {err}"
        ))
    })?;
    let tx = pipe::Sender::from_owned_fd_unchecked(tx_owned).map_err(|err| {
        AppError::unavailable(format!(
            "failed registering Android TUN writer with Tokio: {err}"
        ))
    })?;
    Ok(Arc::new(ActiveUnixTunFd { rx, tx }))
}

impl TunDevice for AndroidTunDevice {
    fn interface_name(&self) -> &str {
        &self.config.interface_name
    }

    fn mtu(&self) -> u16 {
        self.config.mtu
    }

    fn read_packet<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, AppResult<usize>> {
        Box::pin(async move {
            #[cfg(any(target_os = "android", all(unix, test)))]
            {
                if buf.is_empty() {
                    return Err(AppError::invalid_argument(
                        "TUN read buffer cannot be empty",
                    ));
                }
                loop {
                    let slot = self.current_slot()?;
                    let ready_res = tokio::select! {
                        () = self.swap_notify.notified() => continue,
                        res = slot.rx.readable() => res,
                    };
                    ready_res.map_err(|err| {
                        AppError::unavailable(format!("Android TUN readability error: {err}"))
                    })?;
                    match slot.rx.try_read(buf) {
                        Ok(0) => {
                            if self.closed.load(Ordering::SeqCst) {
                                return Err(AppError::unavailable("Android TUN closed"));
                            }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        Ok(n) => return Ok(n),
                        Err(err)
                            if matches!(
                                err.kind(),
                                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                            ) =>
                        {
                            continue;
                        }
                        Err(err) => {
                            return Err(AppError::internal(format!(
                                "Android TUN read error: {err}"
                            )));
                        }
                    }
                }
            }
            #[cfg(not(any(target_os = "android", all(unix, test))))]
            {
                let _unused = buf;
                Err(AppError::unavailable(
                    "Android TUN read is unavailable on non-Android targets",
                ))
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
            #[cfg(any(target_os = "android", all(unix, test)))]
            {
                loop {
                    let slot = self.current_slot()?;
                    let ready_res = tokio::select! {
                        () = self.swap_notify.notified() => continue,
                        res = slot.tx.writable() => res,
                    };
                    ready_res.map_err(|err| {
                        AppError::unavailable(format!("Android TUN writability error: {err}"))
                    })?;
                    match slot.tx.try_write(packet) {
                        Ok(n) => {
                            if n != packet.len() {
                                warn!(
                                    component = "mesh_mobile_ffi.tun_bridge",
                                    event = "android_tun_short_write",
                                    written = n,
                                    expected = packet.len(),
                                    "short write to Android TUN device"
                                );
                            }
                            return Ok(());
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                            ) =>
                        {
                            continue;
                        }
                        Err(err) => {
                            return Err(AppError::internal(format!(
                                "Android TUN write error: {err}"
                            )));
                        }
                    }
                }
            }
            #[cfg(not(any(target_os = "android", all(unix, test))))]
            {
                Err(AppError::unavailable(
                    "Android TUN write is unavailable on non-Android targets",
                ))
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, AppResult<()>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::SeqCst);
            #[cfg(any(target_os = "android", all(unix, test)))]
            {
                let dropped = {
                    let mut guard = self
                        .inner
                        .lock()
                        .map_err(|_| AppError::internal("Android TUN fd mutex poisoned"))?;
                    guard.take()
                };
                drop(dropped);
            }
            self.swap_notify.notify_waiters();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use mesh_core::{OverlayCidr, OverlayIp};
    use mesh_net::tun::{TunConfig, TunDevice as _};
    use tokio_util::sync::CancellationToken;

    use super::PacketFlowAdapter;
    use crate::types::{
        MobileError, MobilePlatformWarning, MobileStatusSnapshot, MobileTunnelNetworkConfig,
        MobileUnderlayState, PlatformNetworkBridge,
    };

    #[derive(Debug, Default)]
    struct RecordingBridge {
        written_batches: Mutex<Vec<Vec<Vec<u8>>>>,
    }

    impl PlatformNetworkBridge for RecordingBridge {
        fn protect_socket(&self, _raw_fd: i32) -> Result<bool, MobileError> {
            Ok(true)
        }

        fn on_tun_packets(&self, packets: Vec<Vec<u8>>) {
            if let Ok(mut g) = self.written_batches.lock() {
                g.push(packets);
            }
        }

        fn on_route_changed(&self, _op_id: u64, _config: MobileTunnelNetworkConfig) {}

        fn on_status_changed(&self, _status: MobileStatusSnapshot) {}

        fn on_platform_warning(&self, _warning: MobilePlatformWarning) {}

        fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError> {
            Ok(MobileUnderlayState::default())
        }

        fn load_or_create_platform_dek(&self) -> Result<Vec<u8>, MobileError> {
            Ok(vec![0x11_u8; 32])
        }

        fn load_state_file(&self, _file_name: String) -> Result<Option<Vec<u8>>, MobileError> {
            Ok(None)
        }

        fn save_state_file(
            &self,
            _file_name: String,
            _content: Vec<u8>,
        ) -> Result<(), MobileError> {
            Ok(())
        }

        fn delete_state_file(&self, _file_name: String) -> Result<(), MobileError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_packet_flow_adapter_roundtrip_and_nonblocking_drop_tail() -> Result<(), String> {
        // Arrange
        let cidr = OverlayCidr::parse("100.64.0.0/16").map_err(|e| e.to_string())?;
        let ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 2)).map_err(|e| e.to_string())?;
        let cfg =
            TunConfig::with_default_mtu("utun-mobile", ip, cidr).map_err(|e| e.to_string())?;
        let bridge = Arc::new(RecordingBridge::default());
        let (adapter, pump) = PacketFlowAdapter::new(cfg, bridge.clone());
        let cancel = CancellationToken::new();
        let pump_handle = tokio::spawn(pump.run(cancel.clone()));

        // Act: push 140 packets (queue cap = 128 -> 128 accepted, 12 dropped non-blocking)
        let batch: Vec<Vec<u8>> = (0..140_u8).map(|i| vec![0x45, 0x00, 0x00, i]).collect();
        let accepted = adapter.push_packets(batch);
        assert_eq!(accepted, 128);
        assert_eq!(adapter.drop_counts().0, 12);

        let mut buf = [0_u8; 2048];
        let n = adapter
            .read_packet(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(n, 4);

        adapter
            .write_packet(&[0x45, 0x00, 0x00, 0x20, 0xaa])
            .await
            .map_err(|e| e.to_string())?;
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        cancel.cancel();
        drop(pump_handle.await);

        // Assert
        let recorded = bridge
            .written_batches
            .lock()
            .map_err(|_| "lock poisoned".to_owned())?
            .clone();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded.first().and_then(|b| b.first()).map(Vec::len),
            Some(5)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_android_tun_device_atomic_fd_swap_zero_unsafe() -> Result<(), String> {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixDatagram;

        use super::AndroidTunDevice;

        // Arrange: create two safe non-blocking datagram pairs simulating TUN fd handoff
        let (k1, a1) = UnixDatagram::pair().map_err(|e| e.to_string())?;
        k1.set_nonblocking(true).map_err(|e| e.to_string())?;
        a1.set_nonblocking(true).map_err(|e| e.to_string())?;

        let (k2, a2) = UnixDatagram::pair().map_err(|e| e.to_string())?;
        k2.set_nonblocking(true).map_err(|e| e.to_string())?;
        a2.set_nonblocking(true).map_err(|e| e.to_string())?;

        let cidr = OverlayCidr::parse("100.64.0.0/16").map_err(|e| e.to_string())?;
        let ip = OverlayIp::from_ipv4(Ipv4Addr::new(100, 64, 0, 5)).map_err(|e| e.to_string())?;
        let cfg = TunConfig::with_default_mtu("tun0", ip, cidr).map_err(|e| e.to_string())?;
        let dev = Arc::new(
            AndroidTunDevice::from_owned_fd(cfg, OwnedFd::from(a1)).map_err(|e| e.to_string())?,
        );

        // Act 1: read from initial fd
        assert_eq!(k1.send(b"pkt-old-fd").map_err(|e| e.to_string())?, 10);
        let mut buf = [0_u8; 64];
        let n1 = dev.read_packet(&mut buf).await.map_err(|e| e.to_string())?;
        assert_eq!(buf.get(..n1), Some(&b"pkt-old-fd"[..]));

        // Act 2: swap fd atomically and read from replacement fd
        dev.swap_owned_fd(OwnedFd::from(a2))
            .map_err(|e| e.to_string())?;
        assert_eq!(k2.send(b"pkt-new-fd").map_err(|e| e.to_string())?, 10);
        let n2 = dev.read_packet(&mut buf).await.map_err(|e| e.to_string())?;
        assert_eq!(buf.get(..n2), Some(&b"pkt-new-fd"[..]));

        dev.close().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
