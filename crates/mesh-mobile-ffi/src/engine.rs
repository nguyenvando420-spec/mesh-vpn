//! UniFFI `MobileEngine`, zero-TUN enrollment entrypoint, bounded mobile Tokio pools,
//! iOS Jetsam pressure hysteresis controller, and graceful shutdown (`<= 5 s`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use mesh_client::{
    ClientCommand, ClientPlatformHooks, ClientRuntimeConfig, ClientRuntimeState,
    ClientSessionOptions, ClientSessionSupervisor, ClientStateStore, EnrollOrRotateRequest,
    PingProbe,
};
use mesh_core::defaults::GRACEFUL_SHUTDOWN_BUDGET_MS;
use mesh_core::{Clock, SystemClock};
use mesh_datapath::TimerMode;
use mesh_net::FakeNetMonitor;
use mesh_proto::agent_ipc::{
    AgentRotateKeyRequest, AgentSetRequest, AgentUpRequest, DaemonState, PingRequest,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::bridge::{FfiPlatformHooks, FfiStateStore};
use crate::bugreport::{
    LogRingBuffer, MOBILE_LOG_RING_TRIMMED_BYTES, MobileBugreportParams,
    export_scrubbed_bugreport_to_path,
};
use crate::dns_responder::MobileSplitDnsInterceptor;
use crate::types::{
    MobileBugreportResult, MobileDaemonState, MobileEngineInitConfig, MobileEnrollConfig,
    MobileError, MobileNetEventKind, MobileNetcheckResponse, MobilePingRequest, MobilePingResponse,
    MobilePlatformKind, MobileRotateKeyConfig, MobileSetConfig, MobileStatusSnapshot,
    MobileUnderlayState, MobileUpConfig, MobileWarningKind, PlatformNetworkBridge,
    netcheck_response_from_core, parse_optional_node_name, parse_optional_port,
    parse_optional_spki_pin, ping_response_from_core, status_from_agent_response,
};

const BYTES_PER_MIB: u64 = 1024 * 1024;
const JETSAM_TRIM_THRESHOLD_BYTES: u64 = 15 * BYTES_PER_MIB;
const JETSAM_TRIM_RECOVER_BYTES: u64 = 18 * BYTES_PER_MIB;
const JETSAM_SHED_THRESHOLD_BYTES: u64 = 6 * BYTES_PER_MIB;
const JETSAM_SHED_RECOVER_BYTES: u64 = 8 * BYTES_PER_MIB;
const JETSAM_CRITICAL_SHUTDOWN_BYTES: u64 = 4 * BYTES_PER_MIB;
const JETSAM_COOLDOWN_MS: u64 = 10_000;
const JETSAM_POLL_INTERVAL_MS: u64 = 2_000;
const STATUS_BROADCAST_INTERVAL_MS: u64 = 1_500;
const STATUS_IDLE_AWARE_TICK_DIVISOR: u32 = 4;
const COMMAND_WAIT_TIMEOUT_MS: u64 = 15_000;
const ENGINE_STOP_WAIT_MS: u64 = 3_500;

/// Discrete iOS Jetsam memory-pressure state machine stage (`mobile-system-architecture.md` §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JetsamPressureStage {
    /// Headroom `>= 15 MiB` (recovered cleanly above hysteresis thresholds).
    Normal,
    /// Headroom `< 15 MiB`: trim in-memory log ring and caches (`>= 18 MiB` to recover).
    TrimCaches,
    /// Headroom `< 6 MiB`: force `TimerMode::IdleAware`, shed idle relays, emit low-mem warning
    /// (`>= 8 MiB` AND `>= 10 s` cooldown to recover).
    ShedIdle,
    /// Headroom `< 4 MiB`: initiate graceful shutdown (`<= 5 s`) to avoid OS `SIGKILL`.
    CriticalShutdown,
}

/// Actions returned when evaluating [`JetsamPressureController`] for one headroom reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JetsamEvaluation {
    /// Current stage after applying threshold + hysteresis transition rules.
    pub stage: JetsamPressureStage,
    /// Whether in-memory ring logs should be trimmed (`< 15 MiB`) or restored.
    pub trim_logs: bool,
    /// Whether `TimerMode::IdleAware` should be enforced due to pressure.
    pub force_idle_aware: bool,
    /// Whether `MobileWarningKind::IosLowMemoryPressure` should remain active.
    pub emit_low_memory_warning: bool,
    /// Whether emergency graceful shutdown must start immediately.
    pub trigger_graceful_shutdown: bool,
    /// Whether this transition just changed `stage` from the previous sample.
    pub stage_changed: bool,
}

/// Schmitt-trigger hysteresis + cooldown controller for iOS Network Extension 50 MiB Jetsam guard.
#[derive(Debug)]
pub struct JetsamPressureController {
    stage: JetsamPressureStage,
    shed_entered_at_ms: Option<u64>,
    shutdown_dispatched: bool,
}

impl Default for JetsamPressureController {
    fn default() -> Self {
        Self::new()
    }
}

impl JetsamPressureController {
    /// Initializes controller in [`JetsamPressureStage::Normal`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stage: JetsamPressureStage::Normal,
            shed_entered_at_ms: None,
            shutdown_dispatched: false,
        }
    }

    /// Evaluates `available_bytes` at `now_monotonic_ms`, obeying entry thresholds and exit
    /// hysteresis + cooldowns to prevent oscillation near 6 MiB / 15 MiB boundaries.
    pub fn evaluate(&mut self, available_bytes: u64, now_monotonic_ms: u64) -> JetsamEvaluation {
        let prev = self.stage;
        let next = if available_bytes < JETSAM_CRITICAL_SHUTDOWN_BYTES {
            JetsamPressureStage::CriticalShutdown
        } else {
            match prev {
                JetsamPressureStage::CriticalShutdown => JetsamPressureStage::CriticalShutdown,
                JetsamPressureStage::ShedIdle => {
                    let cooled_down = self
                        .shed_entered_at_ms
                        .is_some_and(|t| now_monotonic_ms.saturating_sub(t) >= JETSAM_COOLDOWN_MS);
                    if cooled_down && available_bytes >= JETSAM_SHED_RECOVER_BYTES {
                        self.shed_entered_at_ms = None;
                        if available_bytes >= JETSAM_TRIM_RECOVER_BYTES {
                            JetsamPressureStage::Normal
                        } else {
                            JetsamPressureStage::TrimCaches
                        }
                    } else {
                        JetsamPressureStage::ShedIdle
                    }
                }
                JetsamPressureStage::TrimCaches => {
                    if available_bytes < JETSAM_SHED_THRESHOLD_BYTES {
                        self.shed_entered_at_ms = Some(now_monotonic_ms);
                        JetsamPressureStage::ShedIdle
                    } else if available_bytes >= JETSAM_TRIM_RECOVER_BYTES {
                        JetsamPressureStage::Normal
                    } else {
                        JetsamPressureStage::TrimCaches
                    }
                }
                JetsamPressureStage::Normal => {
                    if available_bytes < JETSAM_SHED_THRESHOLD_BYTES {
                        self.shed_entered_at_ms = Some(now_monotonic_ms);
                        JetsamPressureStage::ShedIdle
                    } else if available_bytes < JETSAM_TRIM_THRESHOLD_BYTES {
                        JetsamPressureStage::TrimCaches
                    } else {
                        JetsamPressureStage::Normal
                    }
                }
            }
        };

        self.stage = next;
        let trigger_graceful_shutdown =
            next == JetsamPressureStage::CriticalShutdown && !self.shutdown_dispatched;
        if trigger_graceful_shutdown {
            self.shutdown_dispatched = true;
        }

        JetsamEvaluation {
            stage: next,
            trim_logs: matches!(
                next,
                JetsamPressureStage::TrimCaches
                    | JetsamPressureStage::ShedIdle
                    | JetsamPressureStage::CriticalShutdown
            ),
            force_idle_aware: matches!(
                next,
                JetsamPressureStage::ShedIdle | JetsamPressureStage::CriticalShutdown
            ),
            emit_low_memory_warning: matches!(
                next,
                JetsamPressureStage::ShedIdle | JetsamPressureStage::CriticalShutdown
            ),
            trigger_graceful_shutdown,
            stage_changed: prev != next,
        }
    }
}

/// Core UniFFI-exported Mobile Engine coordinating `mesh-client` supervisor, L3 Split-DNS,
/// iOS Jetsam pressure defense, and Android/iOS TUN lifecycle (`ADR-014`).
#[derive(uniffi::Object)]
pub struct MobileEngine {
    init: MobileEngineInitConfig,
    runtime: StdMutex<Option<tokio::runtime::Runtime>>,
    rt_handle: tokio::runtime::Handle,
    clock: Arc<dyn Clock>,
    bridge: Arc<dyn PlatformNetworkBridge>,
    state_store: Arc<FfiStateStore>,
    platform_hooks: Arc<FfiPlatformHooks>,
    runtime_state: Arc<ClientRuntimeState>,
    command_tx: mpsc::Sender<ClientCommand>,
    log_ring: LogRingBuffer,
    jetsam: StdMutex<JetsamPressureController>,
    root_shutdown: CancellationToken,
    manual_power_save: AtomicBool,
    last_emitted_status: StdMutex<Option<MobileStatusSnapshot>>,
    bg_tasks: StdMutex<Vec<JoinHandle<()>>>,
    jetsam_watcher_handle: StdMutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for MobileEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobileEngine")
            .field("platform", &self.init.platform)
            .field("agent_version", &self.init.agent_version)
            .finish_non_exhaustive()
    }
}

impl Drop for MobileEngine {
    fn drop(&mut self) {
        self.root_shutdown.cancel();
        if let Ok(mut watcher) = self.jetsam_watcher_handle.lock()
            && let Some(handle) = watcher.take()
        {
            handle.abort();
        }
        if let Ok(mut tasks) = self.bg_tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        // `shutdown_background()` never blocks the dropping thread, so dropping inside
        // an existing Tokio async test worker cannot panic.
        if let Ok(mut rt_guard) = self.runtime.lock()
            && let Some(rt) = rt_guard.take()
        {
            rt.shutdown_background();
        }
    }
}

#[uniffi::export]
impl MobileEngine {
    /// Initializes bounded mobile Tokio pools, encrypted storage bridge, and supervisor loop.
    #[uniffi::constructor]
    pub fn new(
        init: MobileEngineInitConfig,
        bridge: Box<dyn PlatformNetworkBridge>,
    ) -> Result<Arc<Self>, MobileError> {
        #[cfg(target_os = "android")]
        mesh_sys::jni_android::ensure_jni_symbols_linked();

        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        Self::new_with_clock(init, Arc::from(bridge), clock)
    }

    /// Starts or resumes the VPN tunnel (`POST /v1/agent/up` equivalent).
    pub async fn start_tunnel(
        &self,
        cfg: MobileUpConfig,
    ) -> Result<MobileStatusSnapshot, MobileError> {
        self.log_ring
            .push_line("component=mesh_mobile_ffi event=start_tunnel_requested");
        let port_override = parse_optional_port(cfg.port_override)?;
        let server_pin = parse_optional_spki_pin(cfg.tls_auth_mode, cfg.server_pin.as_deref())?;
        let mut node_name = parse_optional_node_name(cfg.node_name.as_deref())?;
        if node_name.is_none() {
            node_name = parse_optional_node_name(self.init.default_node_name.as_deref())?;
        }

        let mut preauth_opt: Option<Zeroizing<String>> = None;
        if let Some(ref session) = cfg.pending_join {
            preauth_opt = Some(session.take_preauth_key()?);
        }

        let hooks = Arc::clone(&self.platform_hooks);
        hooks.set_initial_android_tun_fd(cfg.android_tun_fd);
        hooks.set_requested_tun_ifname(cfg.tun_interface_name);

        let cmd_tx = self.command_tx.clone();
        let req = AgentUpRequest {
            server_endpoint: cfg.server_endpoint,
            port_override,
            server_pin,
            preauth_key: preauth_opt.as_ref().map(|z| z.as_str().to_owned()),
            node_name,
        };
        drop(preauth_opt);

        let res = self
            .run_on_engine(async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                cmd_tx
                    .send(ClientCommand::Up {
                        req,
                        reply: reply_tx,
                    })
                    .await
                    .map_err(|_| MobileError::unavailable("supervisor command channel closed"))?;
                let outcome =
                    tokio::time::timeout(Duration::from_millis(COMMAND_WAIT_TIMEOUT_MS), reply_rx)
                        .await
                        .map_err(|_| MobileError::unavailable("start_tunnel timed out"))?
                        .map_err(|_| MobileError::unavailable("supervisor dropped up reply"))?;
                outcome.map(|_| ()).map_err(MobileError::from)
            })
            .await;

        let snap = self.emit_status_snapshot().await;
        res.map(|()| snap)
    }

    /// Gracefully stops the active tunnel session (`POST /v1/agent/down` equivalent).
    pub async fn stop_tunnel(&self) -> Result<MobileStatusSnapshot, MobileError> {
        let cmd_tx = self.command_tx.clone();
        let res = self
            .run_on_engine(async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                cmd_tx
                    .send(ClientCommand::Down { reply: reply_tx })
                    .await
                    .map_err(|_| MobileError::unavailable("supervisor command channel closed"))?;
                let outcome =
                    tokio::time::timeout(Duration::from_millis(COMMAND_WAIT_TIMEOUT_MS), reply_rx)
                        .await
                        .map_err(|_| MobileError::unavailable("stop_tunnel timed out"))?
                        .map_err(|_| MobileError::unavailable("supervisor dropped down reply"))?;
                outcome.map(|_| ()).map_err(MobileError::from)
            })
            .await;

        let snap = self.emit_status_snapshot().await;
        res.map(|()| snap)
    }

    /// Rotates WireGuard identity keypair using `previous_node_pubkey` (`US-032`).
    pub async fn rotate_key(
        &self,
        cfg: MobileRotateKeyConfig,
    ) -> Result<MobileStatusSnapshot, MobileError> {
        let raw_key = cfg.pending_join.take_preauth_key()?;
        let req = AgentRotateKeyRequest {
            preauth_key: (*raw_key).clone(),
        };
        drop(raw_key);

        let cmd_tx = self.command_tx.clone();
        let res = self
            .run_on_engine(async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                cmd_tx
                    .send(ClientCommand::RotateKey {
                        req,
                        reply: reply_tx,
                    })
                    .await
                    .map_err(|_| MobileError::unavailable("supervisor command channel closed"))?;
                let outcome =
                    tokio::time::timeout(Duration::from_millis(COMMAND_WAIT_TIMEOUT_MS), reply_rx)
                        .await
                        .map_err(|_| MobileError::unavailable("rotate_key timed out"))?
                        .map_err(|_| {
                            MobileError::unavailable("supervisor dropped rotate_key reply")
                        })?;
                outcome.map(|_| ()).map_err(MobileError::from)
            })
            .await;

        let snap = self.emit_status_snapshot().await;
        res.map(|()| snap)
    }

    /// Atomically updates Control server endpoint and optional SPKI pin (`US-074 AC5`).
    pub async fn update_server_config(
        &self,
        cfg: MobileSetConfig,
    ) -> Result<MobileStatusSnapshot, MobileError> {
        let server_pin = parse_optional_spki_pin(cfg.tls_auth_mode, cfg.server_pin.as_deref())?;
        let req = AgentSetRequest {
            server_endpoint: cfg.server_endpoint,
            server_pin,
        };
        let cmd_tx = self.command_tx.clone();
        let res = self
            .run_on_engine(async move {
                let (reply_tx, reply_rx) = oneshot::channel();
                cmd_tx
                    .send(ClientCommand::Set {
                        req,
                        reply: reply_tx,
                    })
                    .await
                    .map_err(|_| MobileError::unavailable("supervisor command channel closed"))?;
                let outcome =
                    tokio::time::timeout(Duration::from_millis(COMMAND_WAIT_TIMEOUT_MS), reply_rx)
                        .await
                        .map_err(|_| MobileError::unavailable("update_server_config timed out"))?
                        .map_err(|_| MobileError::unavailable("supervisor dropped set reply"))?;
                outcome.map(|_| ()).map_err(MobileError::from)
            })
            .await;

        let snap = self.emit_status_snapshot().await;
        res.map(|()| snap)
    }

    /// Builds a secret-scrubbed, `<= 4096 B` [`MobileStatusSnapshot`] and persists App Group IPC JSON.
    pub async fn status_snapshot(&self) -> Result<MobileStatusSnapshot, MobileError> {
        let snap = self.build_status_snapshot().await;
        self.persist_snapshot_ipc_offthread(snap.clone()).await;
        Ok(snap)
    }

    /// Probes an active peer directly / via Blind Relay using Disco pings.
    pub async fn ping_peer(
        &self,
        req: MobilePingRequest,
    ) -> Result<MobilePingResponse, MobileError> {
        let state = Arc::clone(&self.runtime_state);
        self.run_on_engine(async move {
            let core_req = PingRequest {
                target: req.target.clone(),
                count: req.count.clamp(1, 64),
                force_direct: req.force_direct,
                timeout_ms: req.timeout_ms.clamp(100, 10_000),
            };
            let peer_id = state
                .find_peer(&req.target)
                .await
                .map_or_else(String::new, |(id, _, _, _)| id.to_string());
            let resp = PingProbe::execute_ping(&state, &core_req)
                .await
                .map_err(MobileError::from)?;
            Ok(ping_response_from_core(peer_id, resp))
        })
        .await
    }

    /// Evaluates STUN UDP reachability, NAT mapping, and Control/Relay egress under SocketProtector.
    pub async fn netcheck(&self) -> Result<MobileNetcheckResponse, MobileError> {
        let state = Arc::clone(&self.runtime_state);
        let hooks = Arc::clone(&self.platform_hooks);
        self.run_on_engine(async move {
            let resp = PingProbe::execute_netcheck_with_protector(&state, hooks.socket_protector())
                .await
                .map_err(MobileError::from)?;
            let nat64 = hooks.nat64_prefix();
            Ok(netcheck_response_from_core(resp, nat64))
        })
        .await
    }

    /// Non-blocking ingress path delivering L3 IP packets from iOS `NEPacketTunnelFlow.readPackets`.
    pub fn push_tun_packets(&self, packets: Vec<Vec<u8>>) -> u32 {
        self.platform_hooks.push_ios_tun_packets(packets)
    }

    /// Host callback completing an asynchronous `PlatformNetworkBridge::on_route_changed` request.
    pub fn complete_route_change(
        &self,
        op_id: u64,
        ok: bool,
        new_android_tun_fd: Option<i32>,
        error_message: Option<String>,
    ) {
        if let Err(err) =
            self.platform_hooks
                .complete_route_change(op_id, ok, new_android_tun_fd, error_message)
        {
            warn!(
                component = "mesh_mobile_ffi.engine",
                event = "complete_route_change_failed",
                op_id,
                error = %err,
                "failed completing mobile route change callback"
            );
        }
    }

    /// Notifies core engine of an underlay network switch, DNS change, or NAT64 transition.
    pub fn on_network_change(&self, kind: MobileNetEventKind, underlay: MobileUnderlayState) {
        let hooks = Arc::clone(&self.platform_hooks);
        let state = Arc::clone(&self.runtime_state);
        let cancel = self.root_shutdown.clone();
        let _spawned = self.rt_handle.spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = hooks.notify_network_change(kind, underlay) => {
                    state.set_nat64_prefix(hooks.nat64_prefix()).await;
                }
            }
        });
    }

    /// Switches Control heartbeat / Keepalive pacing between `IdleAware` (power save) and `Responsive`.
    pub fn set_power_saving_mode(&self, enabled: bool) {
        self.manual_power_save.store(enabled, Ordering::SeqCst);
        let desired_mode = self.effective_timer_mode();
        let state = Arc::clone(&self.runtime_state);
        let cancel = self.root_shutdown.clone();
        let _spawned = self.rt_handle.spawn(async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = state.set_timer_mode(desired_mode) => {}
            }
        });
    }

    /// Streams a scrubbed `<= 1 MiB` POSIX `.tar` diagnostic archive to `dest_path` (`0 sysexec`).
    pub async fn export_bugreport_to_file(
        &self,
        dest_path: String,
    ) -> Result<MobileBugreportResult, MobileError> {
        if self.init.platform == MobilePlatformKind::Ios
            && let Some(available) = self.platform_hooks.available_memory_bytes()
            && available < JETSAM_SHED_THRESHOLD_BYTES
        {
            return Err(MobileError::unavailable(format!(
                "insufficient iOS memory headroom ({available} bytes < {JETSAM_SHED_THRESHOLD_BYTES} bytes) to export bugreport"
            )));
        }

        let rt_state = Arc::clone(&self.runtime_state);
        let store = Arc::clone(&self.state_store);
        let hooks = Arc::clone(&self.platform_hooks);
        let ring = self.log_ring.clone();
        let clock = Arc::clone(&self.clock);
        let bin_name = format!("{}-mobile", platform_slug(self.init.platform));
        let agent_version = self.init.agent_version.clone();
        let log_dir = PathBuf::from(&self.init.log_dir_path);

        self.run_on_engine(async move {
            let status = rt_state.build_status_response().await;
            let store_for_bootstrap = Arc::clone(&store);
            let bootstrap =
                tokio::task::spawn_blocking(move || store_for_bootstrap.load_bootstrap())
                    .await
                    .map_err(|err| {
                        MobileError::internal(format!("bootstrap load task panicked: {err}"))
                    })?
                    .map_err(MobileError::from)?;
            let netcheck_res = match tokio::time::timeout(
                Duration::from_millis(1_500),
                PingProbe::execute_netcheck_with_protector(&rt_state, hooks.socket_protector()),
            )
            .await
            {
                Ok(Ok(nc)) => Ok(nc),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err("netcheck skipped due to 1500 ms mobile budget".to_owned()),
            };
            let log_dirs = if log_dir.as_os_str().is_empty() {
                Vec::new()
            } else {
                vec![log_dir]
            };
            let target_path = PathBuf::from(&dest_path);
            let (size_bytes, scrubbed_items) =
                export_scrubbed_bugreport_to_path(MobileBugreportParams {
                    dest_path: target_path,
                    status,
                    netcheck: netcheck_res,
                    bootstrap,
                    platform_hooks: hooks,
                    log_dirs,
                    in_memory_logs: Some(ring.dump_text()),
                    now_unix_ms: clock.now_unix_ms(),
                    binary_name: bin_name,
                    agent_version,
                })
                .await
                .map_err(MobileError::from)?;

            Ok(MobileBugreportResult {
                bundle_path: dest_path,
                size_bytes,
                scrubbed_items,
            })
        })
        .await
    }

    /// Gracefully stops supervisor, TUN, Split-DNS forwarder, and runtime within `<= 5_000 ms`.
    pub fn shutdown(&self) -> Result<(), MobileError> {
        self.root_shutdown.cancel();

        let owned_rt = self
            .runtime
            .lock()
            .map_err(|_| MobileError::internal("mobile runtime mutex poisoned"))?
            .take();
        let Some(rt) = owned_rt else {
            return Ok(());
        };

        let mut tasks = self
            .bg_tasks
            .lock()
            .map(|mut g| g.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        if let Ok(mut watcher) = self.jetsam_watcher_handle.lock()
            && let Some(handle) = watcher.take()
        {
            tasks.push(handle);
        }

        let hooks = Arc::clone(&self.platform_hooks);
        let cmd_tx = self.command_tx.clone();
        let finish_shutdown = move || {
            rt.block_on(async move {
                let _down = tokio::time::timeout(Duration::from_millis(800), async {
                    let (tx, rx) = oneshot::channel();
                    if cmd_tx.send(ClientCommand::Down { reply: tx }).await.is_ok() {
                        let _reply = rx.await;
                    }
                })
                .await;

                if tokio::time::timeout(Duration::from_millis(ENGINE_STOP_WAIT_MS), async {
                    for handle in &mut tasks {
                        let _joined = handle.await;
                    }
                })
                .await
                .is_err()
                {
                    for handle in &tasks {
                        handle.abort();
                    }
                }

                let _cleaned = tokio::time::timeout(
                    Duration::from_millis(GRACEFUL_SHUTDOWN_BUDGET_MS),
                    hooks.deactivate_and_cleanup(),
                )
                .await;
            });
            rt.shutdown_timeout(Duration::from_secs(1));
        };

        if tokio::runtime::Handle::try_current().is_ok() {
            let join = std::thread::Builder::new()
                .name("mesh-mobile-shutdown".to_owned())
                .stack_size(512 * 1024)
                .spawn(finish_shutdown)
                .map_err(|err| {
                    MobileError::internal(format!("failed spawning mobile shutdown helper: {err}"))
                })?;
            join.join()
                .map_err(|_| MobileError::internal("mobile shutdown helper thread panicked"))?;
        } else {
            finish_shutdown();
        }
        Ok(())
    }
}

impl MobileEngine {
    /// Internal test-capable constructor accepting explicit `clock`.
    pub(crate) fn new_with_clock(
        init: MobileEngineInitConfig,
        bridge: Arc<dyn PlatformNetworkBridge>,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, MobileError> {
        let rt = build_mobile_runtime(init.platform)?;
        let rt_handle = rt.handle().clone();

        let state_dir =
            (!init.log_dir_path.trim().is_empty()).then(|| PathBuf::from(init.log_dir_path.trim()));
        let state_store = Arc::new(FfiStateStore::new(Arc::clone(&bridge), state_dir.clone()));
        let dns_interceptor = Arc::new(MobileSplitDnsInterceptor::new(Arc::clone(&clock)));
        let platform_hooks = Arc::new(FfiPlatformHooks::new(
            init.platform,
            Arc::clone(&bridge),
            Arc::clone(&dns_interceptor),
        ));
        let log_ring = LogRingBuffer::default();

        let mut runtime_cfg = ClientRuntimeConfig::for_mobile();
        if !init.agent_version.trim().is_empty() {
            runtime_cfg.agent_version = init.agent_version.trim().to_owned();
        }
        let tun_hint = match init.platform {
            MobilePlatformKind::Android => "tun0",
            MobilePlatformKind::Ios => "utun",
        };
        let mut opts = ClientSessionOptions::new(runtime_cfg)
            .with_default_tun_ifname(tun_hint)
            .with_dns_interceptor(dns_interceptor);
        if let Some(ref dir) = state_dir {
            opts = opts.with_bugreport(
                dir.clone(),
                format!("{}-mobile", platform_slug(init.platform)),
                vec![dir.clone()],
                None,
            );
        }

        let supervisor = ClientSessionSupervisor::boot(
            opts,
            Arc::clone(&clock),
            platform_hooks.clone(),
            state_store.clone(),
        )
        .map_err(MobileError::from)?;

        let runtime_state = supervisor.runtime_state();
        let command_tx = supervisor.command_sender();
        let root_shutdown = CancellationToken::new();

        let engine = Arc::new(Self {
            init,
            runtime: StdMutex::new(Some(rt)),
            rt_handle,
            clock,
            bridge,
            state_store,
            platform_hooks,
            runtime_state,
            command_tx,
            log_ring,
            jetsam: StdMutex::new(JetsamPressureController::new()),
            root_shutdown: root_shutdown.clone(),
            manual_power_save: AtomicBool::new(true),
            last_emitted_status: StdMutex::new(None),
            bg_tasks: StdMutex::new(Vec::new()),
            jetsam_watcher_handle: StdMutex::new(None),
        });

        let sup_monitor = engine.platform_hooks.net_monitor();
        let sup_shutdown = root_shutdown.clone();
        let sup_handle = engine.rt_handle.spawn(async move {
            if let Err(err) = supervisor.run(sup_monitor, sup_shutdown).await {
                warn!(
                    component = "mesh_mobile_ffi.engine",
                    event = "supervisor_run_exited_with_error",
                    error = %err,
                    "mobile ClientSessionSupervisor exited with error"
                );
            }
        });

        let status_handle = engine.spawn_status_observer();
        if let Ok(mut guard) = engine.bg_tasks.lock() {
            guard.extend([sup_handle, status_handle]);
        }
        if engine.init.platform == MobilePlatformKind::Ios
            && let Ok(mut watcher_guard) = engine.jetsam_watcher_handle.lock()
        {
            *watcher_guard = Some(engine.spawn_ios_jetsam_watcher());
        }

        Ok(engine)
    }

    fn effective_timer_mode(&self) -> TimerMode {
        let manual = self.manual_power_save.load(Ordering::SeqCst);
        let normal_pressure = self
            .jetsam
            .lock()
            .map(|ctrl| ctrl.stage == JetsamPressureStage::Normal)
            .unwrap_or(false);
        if !manual && normal_pressure {
            TimerMode::Responsive
        } else {
            TimerMode::IdleAware
        }
    }

    async fn stop_active_tunnel_for_jetsam(&self) {
        let cmd_tx = self.command_tx.clone();
        let hooks = Arc::clone(&self.platform_hooks);
        let _stopped = self
            .run_on_engine(async move {
                let _down = tokio::time::timeout(Duration::from_millis(800), async {
                    let (tx, rx) = oneshot::channel();
                    if cmd_tx.send(ClientCommand::Down { reply: tx }).await.is_ok() {
                        let _reply = rx.await;
                    }
                })
                .await;
                let _cleaned = tokio::time::timeout(
                    Duration::from_millis(2_000),
                    hooks.deactivate_and_cleanup(),
                )
                .await;
                Ok::<(), MobileError>(())
            })
            .await;
        self.root_shutdown.cancel();
    }

    /// Evaluates one iOS Jetsam headroom reading immediately (exposed for deterministic tests).
    pub async fn evaluate_memory_pressure_once(&self) -> Option<JetsamEvaluation> {
        let available = self.platform_hooks.available_memory_bytes()?;
        let now_mono = self.clock.monotonic_ms();
        let eval = {
            let Ok(mut ctrl) = self.jetsam.lock() else {
                return None;
            };
            ctrl.evaluate(available, now_mono)
        };

        if eval.trim_logs {
            self.log_ring
                .trim_to_max_bytes(MOBILE_LOG_RING_TRIMMED_BYTES);
        } else {
            self.log_ring.restore_default_budget();
        }

        if eval.emit_low_memory_warning {
            self.platform_hooks.set_warning(
                MobileWarningKind::IosLowMemoryPressure,
                Some(format!(
                    "iOS memory headroom low ({:.1} MiB free); reduced keepalives and caches",
                    (available as f64) / (BYTES_PER_MIB as f64)
                )),
            );
        } else if eval.stage_changed {
            self.platform_hooks
                .set_warning(MobileWarningKind::IosLowMemoryPressure, None);
        }

        if eval.stage_changed {
            let desired_mode = self.effective_timer_mode();
            let state = Arc::clone(&self.runtime_state);
            let _ignored = self
                .run_on_engine(async move {
                    state.set_timer_mode(desired_mode).await;
                    Ok::<(), MobileError>(())
                })
                .await;
        }

        if eval.trigger_graceful_shutdown {
            warn!(
                component = "mesh_mobile_ffi.jetsam",
                event = "ios_jetsam_critical_graceful_shutdown",
                available_bytes = available,
                "iOS available memory < 4 MiB; triggering graceful tunnel stop without self-await"
            );
            self.stop_active_tunnel_for_jetsam().await;
        }
        Some(eval)
    }

    fn spawn_status_observer(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        let cancel = self.root_shutdown.clone();
        self.rt_handle.spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_millis(STATUS_BROADCAST_INTERVAL_MS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut idle_ticks: u32 = 0;
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let Some(engine) = weak.upgrade() else {
                            break;
                        };
                        let (daemon_state, timer_mode) = {
                            let guard = engine.runtime_state.inner.read().await;
                            (guard.daemon_state, guard.timer_mode)
                        };
                        let already_stopped_or_unstarted = engine
                            .last_emitted_status
                            .lock()
                            .ok()
                            .is_some_and(|g| {
                                g.as_ref()
                                    .is_none_or(|s| s.daemon_state == MobileDaemonState::Stopped)
                            });
                        if daemon_state == DaemonState::Stopped && already_stopped_or_unstarted {
                            continue;
                        }
                        if timer_mode == TimerMode::IdleAware {
                            idle_ticks = idle_ticks.wrapping_add(1);
                            if !idle_ticks.is_multiple_of(STATUS_IDLE_AWARE_TICK_DIVISOR) {
                                continue;
                            }
                        } else {
                            idle_ticks = 0;
                        }
                        drop(engine.emit_status_snapshot().await);
                    }
                }
            }
        })
    }

    fn spawn_ios_jetsam_watcher(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        let cancel = self.root_shutdown.clone();
        self.rt_handle.spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(JETSAM_POLL_INTERVAL_MS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        let Some(engine) = weak.upgrade() else {
                            break;
                        };
                        if let Some(eval) = engine.evaluate_memory_pressure_once().await
                            && eval.trigger_graceful_shutdown
                        {
                            break;
                        }
                    }
                }
            }
        })
    }

    async fn build_status_snapshot(&self) -> MobileStatusSnapshot {
        let resp = self.runtime_state.build_status_response().await;
        let incompat = self.runtime_state.is_protocol_incompatible().await;
        let dns_ip = self.platform_hooks.latest_overlay_dns_ip();
        let nat64 = self.platform_hooks.nat64_prefix();
        let warnings = self.platform_hooks.snapshot_warnings();
        status_from_agent_response(resp, dns_ip, nat64, warnings, incompat, None)
    }

    async fn persist_snapshot_ipc_offthread(&self, snap: MobileStatusSnapshot) {
        let should_write = self
            .last_emitted_status
            .lock()
            .ok()
            .is_some_and(|mut slot| {
                if slot.as_ref() == Some(&snap) {
                    false
                } else {
                    *slot = Some(snap.clone());
                    true
                }
            });
        if !should_write {
            return;
        }
        let store = Arc::clone(&self.state_store);
        let _ignored = self
            .rt_handle
            .spawn_blocking(move || store.write_status_snapshot_ipc(&snap))
            .await;
    }

    async fn emit_status_snapshot(&self) -> MobileStatusSnapshot {
        let snap = self.build_status_snapshot().await;
        let changed = self
            .last_emitted_status
            .lock()
            .ok()
            .is_some_and(|mut slot| {
                if slot.as_ref() == Some(&snap) {
                    false
                } else {
                    *slot = Some(snap.clone());
                    true
                }
            });
        if !changed {
            return snap;
        }
        let store = Arc::clone(&self.state_store);
        let bridge = Arc::clone(&self.bridge);
        let snap_for_io = snap.clone();
        let _ignored = self
            .rt_handle
            .spawn_blocking(move || {
                let _write_res = store.write_status_snapshot_ipc(&snap_for_io);
                bridge.on_status_changed(snap_for_io);
            })
            .await;
        snap
    }

    async fn run_on_engine<F, T>(&self, fut: F) -> Result<T, MobileError>
    where
        F: std::future::Future<Output = Result<T, MobileError>> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let _handle = self.rt_handle.spawn(async move {
            let outcome = fut.await;
            let _ignored = tx.send(outcome);
        });
        rx.await
            .map_err(|_| MobileError::unavailable("engine runtime task cancelled"))?
    }
}

/// Executes standalone zero-TUN Control registration or key rotation (`ADR-014`, iOS Container App).
#[uniffi::export]
pub async fn mobile_enroll_or_rotate_node(
    init: MobileEngineInitConfig,
    bridge: Box<dyn PlatformNetworkBridge>,
    cfg: MobileEnrollConfig,
) -> Result<MobileStatusSnapshot, MobileError> {
    let port_override = parse_optional_port(cfg.port_override)?;
    let server_pin = parse_optional_spki_pin(cfg.tls_auth_mode, cfg.server_pin.as_deref())?;
    let mut node_name = parse_optional_node_name(cfg.node_name.as_deref())?;
    if node_name.is_none() {
        node_name = parse_optional_node_name(init.default_node_name.as_deref())?;
    }
    let raw_key = cfg.pending_join.take_preauth_key()?;
    let bridge_arc: Arc<dyn PlatformNetworkBridge> = Arc::from(bridge);
    let (tx, rx) = oneshot::channel();

    let spawn_res = std::thread::Builder::new()
        .name("mesh-mobile-enroll".to_owned())
        .stack_size(512 * 1024)
        .spawn(move || {
            let result = execute_enroll_blocking(BlockingEnrollParams {
                init,
                server_endpoint: cfg.server_endpoint,
                port_override,
                server_pin,
                node_name,
                raw_preauth_key: raw_key,
                rotate_existing_keypair: cfg.rotate_existing_identity,
                bridge: bridge_arc,
            });
            drop(tx.send(result));
        });

    if let Err(err) = spawn_res {
        return Err(MobileError::internal(format!(
            "failed spawning enrollment thread: {err}"
        )));
    }

    rx.await
        .map_err(|_| MobileError::unavailable("enrollment helper thread terminated unexpectedly"))?
}

struct BlockingEnrollParams {
    init: MobileEngineInitConfig,
    server_endpoint: String,
    port_override: Option<mesh_core::Port>,
    server_pin: Option<mesh_core::SpkiPin>,
    node_name: Option<mesh_core::NodeName>,
    raw_preauth_key: Zeroizing<String>,
    rotate_existing_keypair: bool,
    bridge: Arc<dyn PlatformNetworkBridge>,
}

fn execute_enroll_blocking(
    params: BlockingEnrollParams,
) -> Result<MobileStatusSnapshot, MobileError> {
    let BlockingEnrollParams {
        init,
        server_endpoint,
        port_override,
        server_pin,
        node_name,
        raw_preauth_key,
        rotate_existing_keypair,
        bridge,
    } = params;
    let rt = build_mobile_runtime(init.platform)?;
    let outcome = rt.block_on(async move {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let state_dir =
            (!init.log_dir_path.trim().is_empty()).then(|| PathBuf::from(init.log_dir_path.trim()));
        let state_store = Arc::new(FfiStateStore::new(Arc::clone(&bridge), state_dir));
        let dns_interceptor = Arc::new(MobileSplitDnsInterceptor::new(Arc::clone(&clock)));
        let platform_hooks = Arc::new(FfiPlatformHooks::new(
            init.platform,
            Arc::clone(&bridge),
            dns_interceptor,
        ));
        let mut rt_cfg = ClientRuntimeConfig::for_mobile();
        if !init.agent_version.trim().is_empty() {
            rt_cfg.agent_version = init.agent_version.trim().to_owned();
        }
        let opts = ClientSessionOptions::new(rt_cfg);
        let supervisor = ClientSessionSupervisor::boot(
            opts,
            Arc::clone(&clock),
            platform_hooks.clone(),
            state_store.clone(),
        )
        .map_err(MobileError::from)?;

        let runtime_state = supervisor.runtime_state();
        let cmd_tx = supervisor.command_sender();
        let shutdown = CancellationToken::new();
        let sup_shutdown = shutdown.clone();
        let monitor = Arc::new(FakeNetMonitor::new());
        let sup_join = tokio::spawn(async move { supervisor.run(monitor, sup_shutdown).await });

        let req = EnrollOrRotateRequest {
            server_endpoint,
            port_override,
            server_pin,
            node_name,
            preauth_key: Some((*raw_preauth_key).clone()),
            rotate_existing_keypair,
        };
        drop(raw_preauth_key);

        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx
            .send(ClientCommand::EnrollOrRotate {
                req,
                reply: reply_tx,
            })
            .await
            .map_err(|_| MobileError::unavailable("enrollment supervisor channel closed"))?;

        let enroll_res =
            tokio::time::timeout(Duration::from_millis(COMMAND_WAIT_TIMEOUT_MS), reply_rx).await;

        shutdown.cancel();
        let _joined =
            tokio::time::timeout(Duration::from_millis(GRACEFUL_SHUTDOWN_BUDGET_MS), sup_join)
                .await;

        let enrolled = enroll_res
            .map_err(|_| MobileError::unavailable("enrollment request timed out"))?
            .map_err(|_| MobileError::unavailable("enrollment reply channel closed"))?
            .map_err(MobileError::from)?;

        let status = runtime_state.build_status_response().await;
        let incompat = runtime_state.is_protocol_incompatible().await;
        let snap = status_from_agent_response(
            status,
            None,
            platform_hooks.nat64_prefix(),
            Vec::new(),
            incompat,
            Some(MobileDaemonState::Stopped),
        );
        let _ignored = state_store.write_status_snapshot_ipc(&snap);
        info!(
            component = "mesh_mobile_ffi.enroll",
            event = "mobile_zero_tun_enroll_success",
            node_id = %enrolled.node_id,
            overlay_ip = %enrolled.overlay_ip,
            "completed mobile zero-TUN enrollment/rotation"
        );
        Ok(snap)
    });
    rt.shutdown_timeout(Duration::from_secs(1));
    outcome
}

fn build_mobile_runtime(
    platform: MobilePlatformKind,
) -> Result<tokio::runtime::Runtime, MobileError> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().thread_stack_size(512 * 1024);
    match platform {
        MobilePlatformKind::Android => {
            builder
                .thread_name("mesh-android")
                .worker_threads(2)
                .max_blocking_threads(6);
        }
        MobilePlatformKind::Ios => {
            builder
                .thread_name("mesh-ios")
                .worker_threads(1)
                .max_blocking_threads(4)
                .thread_keep_alive(Duration::from_secs(10));
        }
    }
    builder.build().map_err(|err| {
        MobileError::internal(format!("failed starting mobile Tokio runtime: {err}"))
    })
}

const fn platform_slug(platform: MobilePlatformKind) -> &'static str {
    match platform {
        MobilePlatformKind::Android => "android",
        MobilePlatformKind::Ios => "ios",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    use mesh_core::FakeClock;
    use mesh_crypto::random_bytes;
    use mesh_datapath::TimerMode;
    use tempfile::TempDir;
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    use super::{
        BYTES_PER_MIB, JETSAM_COOLDOWN_MS, JetsamPressureController, JetsamPressureStage,
        MobileEngine,
    };
    use crate::bugreport::LogRingBuffer;
    use crate::types::{
        MobileEngineInitConfig, MobileError, MobilePlatformKind, MobilePlatformWarning,
        MobileStatusSnapshot, MobileTunnelNetworkConfig, MobileUnderlayState,
        PlatformNetworkBridge, create_pending_join_session, parse_mobile_join_uri,
    };

    #[derive(Debug, Default)]
    struct TestMobileBridge {
        dek: StdMutex<Option<Vec<u8>>>,
        files: StdMutex<HashMap<String, Vec<u8>>>,
        warnings: StdMutex<Vec<MobilePlatformWarning>>,
        status_callbacks: AtomicUsize,
        status_file_saves: AtomicUsize,
    }

    impl PlatformNetworkBridge for TestMobileBridge {
        fn protect_socket(&self, _raw_fd: i32) -> Result<bool, MobileError> {
            Ok(true)
        }

        fn on_tun_packets(&self, _packets: Vec<Vec<u8>>) {}

        fn on_route_changed(&self, _op_id: u64, _config: MobileTunnelNetworkConfig) {}

        fn on_status_changed(&self, _status: MobileStatusSnapshot) {
            self.status_callbacks.fetch_add(1, Ordering::Relaxed);
        }

        fn on_platform_warning(&self, warning: MobilePlatformWarning) {
            if let Ok(mut g) = self.warnings.lock() {
                g.push(warning);
            }
        }

        fn query_underlay_state(&self) -> Result<MobileUnderlayState, MobileError> {
            Ok(MobileUnderlayState::default())
        }

        fn load_or_create_platform_dek(&self) -> Result<Vec<u8>, MobileError> {
            let Ok(mut g) = self.dek.lock() else {
                return Err(MobileError::internal("dek lock poisoned"));
            };
            if let Some(ref existing) = *g {
                return Ok(existing.clone());
            }
            let fresh = random_bytes::<32>().to_vec();
            *g = Some(fresh.clone());
            Ok(fresh)
        }

        fn load_state_file(&self, file_name: String) -> Result<Option<Vec<u8>>, MobileError> {
            Ok(self
                .files
                .lock()
                .ok()
                .and_then(|g| g.get(&file_name).cloned()))
        }

        fn save_state_file(&self, file_name: String, content: Vec<u8>) -> Result<(), MobileError> {
            if file_name == "status-snapshot.json" {
                self.status_file_saves.fetch_add(1, Ordering::Relaxed);
            }
            if let Ok(mut g) = self.files.lock() {
                g.insert(file_name, content);
            }
            Ok(())
        }

        fn delete_state_file(&self, file_name: String) -> Result<(), MobileError> {
            if let Ok(mut g) = self.files.lock() {
                let _removed = g.remove(&file_name);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct CapturingVisitor {
        buf: String,
    }

    impl tracing::field::Visit for CapturingVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.buf.push_str(&format!("{}={value:?} ", field.name()));
        }
    }

    struct DebugLogCaptureLayer {
        logs: Arc<StdMutex<Vec<String>>>,
        ring: LogRingBuffer,
    }

    impl<S: Subscriber> tracing_subscriber::Layer<S> for DebugLogCaptureLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = CapturingVisitor::default();
            event.record(&mut visitor);
            let line = format!("level={:?} {}", event.metadata().level(), visitor.buf);
            self.ring.push_line(&line);
            if let Ok(mut g) = self.logs.lock() {
                g.push(line);
            }
        }
    }

    #[test]
    fn test_jetsam_pressure_hysteresis_and_anti_flap_cooldown() {
        // Arrange
        let mut ctrl = JetsamPressureController::new();

        // Act & Assert 1: Normal at 20 MiB
        let e1 = ctrl.evaluate(20 * BYTES_PER_MIB, 1_000);
        assert_eq!(e1.stage, JetsamPressureStage::Normal);
        assert!(!e1.trim_logs);
        assert!(!e1.force_idle_aware);

        // Act & Assert 2: < 15 MiB enters TrimCaches, stays in TrimCaches at 16 MiB (hysteresis < 18 MiB)
        let e2 = ctrl.evaluate(14 * BYTES_PER_MIB, 2_000);
        assert_eq!(e2.stage, JetsamPressureStage::TrimCaches);
        assert!(e2.trim_logs);
        assert!(!e2.force_idle_aware);

        let e3 = ctrl.evaluate(16 * BYTES_PER_MIB, 3_000);
        assert_eq!(e3.stage, JetsamPressureStage::TrimCaches);

        // Act & Assert 3: < 6 MiB enters ShedIdle + warning + IdleAware
        let e4 = ctrl.evaluate(5 * BYTES_PER_MIB + 512 * 1024, 5_000);
        assert_eq!(e4.stage, JetsamPressureStage::ShedIdle);
        assert!(e4.force_idle_aware);
        assert!(e4.emit_low_memory_warning);
        assert!(!e4.trigger_graceful_shutdown);

        // 7 MiB fails exit hysteresis (< 8 MiB); 9 MiB at +2s fails 10s cooldown
        let e5 = ctrl.evaluate(7 * BYTES_PER_MIB, 18_000);
        assert_eq!(e5.stage, JetsamPressureStage::ShedIdle);
        let e6 = ctrl.evaluate(9 * BYTES_PER_MIB, 7_000);
        assert_eq!(e6.stage, JetsamPressureStage::ShedIdle);

        // 9 MiB after >= 10s cooldown transitions out cleanly to TrimCaches, 19 MiB -> Normal
        let e7 = ctrl.evaluate(9 * BYTES_PER_MIB, 5_000 + JETSAM_COOLDOWN_MS);
        assert_eq!(e7.stage, JetsamPressureStage::TrimCaches);
        let e8 = ctrl.evaluate(19 * BYTES_PER_MIB, 20_000);
        assert_eq!(e8.stage, JetsamPressureStage::Normal);

        // Act & Assert 4: < 4 MiB triggers single graceful shutdown
        let e9 = ctrl.evaluate(3 * BYTES_PER_MIB + 512 * 1024, 21_000);
        assert_eq!(e9.stage, JetsamPressureStage::CriticalShutdown);
        assert!(e9.trigger_graceful_shutdown);
        let e10 = ctrl.evaluate(3 * BYTES_PER_MIB, 22_000);
        assert!(!e10.trigger_graceful_shutdown);
    }

    #[tokio::test]
    async fn test_mobile_engine_jetsam_critical_triggers_shutdown_and_exports_status_and_tar()
    -> Result<(), String> {
        // Arrange
        let dir = TempDir::new().map_err(|e| e.to_string())?;
        let bridge = Arc::new(TestMobileBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let engine = MobileEngine::new_with_clock(
            MobileEngineInitConfig {
                platform: MobilePlatformKind::Ios,
                agent_version: "0.1.0-mobile".to_owned(),
                default_node_name: Some("iphone-dev".to_owned()),
                log_dir_path: dir.path().to_string_lossy().into_owned(),
            },
            bridge.clone(),
            Arc::clone(&clock) as Arc<dyn mesh_core::Clock>,
        )
        .map_err(|e| e.to_string())?;

        // Act 1: Trigger soft pressure < 6 MiB then verify status, warning, and <6 MiB bugreport guard
        engine
            .platform_hooks
            .set_test_available_memory_bytes(Some(5 * BYTES_PER_MIB));
        let eval_shed = engine
            .evaluate_memory_pressure_once()
            .await
            .ok_or("missing eval")?;
        assert_eq!(eval_shed.stage, JetsamPressureStage::ShedIdle);

        let snap = engine.status_snapshot().await.map_err(|e| e.to_string())?;
        let ipc_json = snap.to_bounded_ipc_json().map_err(|e| e.to_string())?;
        assert!(ipc_json.len() <= 4096);

        let tar_path = dir.path().join("diag.tar");
        let low_mem_bugreport = engine
            .export_bugreport_to_file(tar_path.to_string_lossy().into_owned())
            .await;
        assert!(matches!(
            low_mem_bugreport,
            Err(MobileError::Unavailable { .. })
        ));

        // Recover above 18 MiB after 10s cooldown -> Normal allows bugreport export
        clock.advance(JETSAM_COOLDOWN_MS + 1_000);
        engine
            .platform_hooks
            .set_test_available_memory_bytes(Some(20 * BYTES_PER_MIB));
        let _eval_normal = engine
            .evaluate_memory_pressure_once()
            .await
            .ok_or("missing normal eval")?;
        let export = engine
            .export_bugreport_to_file(tar_path.to_string_lossy().into_owned())
            .await
            .map_err(|e| e.to_string())?;
        assert!(export.size_bytes > 0 && export.size_bytes <= 1_048_576);

        // Act 2: Trigger critical pressure < 4 MiB -> rapid graceful stop with 0 self-deadlock
        clock.advance(5_000);
        engine
            .platform_hooks
            .set_test_available_memory_bytes(Some(3 * BYTES_PER_MIB));
        let t0 = Instant::now();
        let eval_crit = engine
            .evaluate_memory_pressure_once()
            .await
            .ok_or("missing critical eval")?;
        let elapsed = t0.elapsed();
        assert!(eval_crit.trigger_graceful_shutdown);
        assert!(engine.root_shutdown.is_cancelled());
        assert!(
            elapsed < Duration::from_millis(2_000),
            "critical Jetsam evaluation took {elapsed:?}, expected fast return without 5s self-deadlock"
        );
        engine.shutdown().map_err(|e| e.to_string())?;
        engine.shutdown().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[tokio::test]
    async fn test_mobile_engine_defaults_idle_aware_and_never_forces_responsive_on_trim_caches()
    -> Result<(), String> {
        // Arrange
        let dir = TempDir::new().map_err(|e| e.to_string())?;
        let bridge = Arc::new(TestMobileBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let engine = MobileEngine::new_with_clock(
            MobileEngineInitConfig {
                platform: MobilePlatformKind::Ios,
                agent_version: "0.1.0-mobile".to_owned(),
                default_node_name: Some("iphone-dev".to_owned()),
                log_dir_path: dir.path().to_string_lossy().into_owned(),
            },
            bridge,
            clock,
        )
        .map_err(|e| e.to_string())?;

        // Assert initial mobile default is IdleAware
        assert!(engine.manual_power_save.load(Ordering::SeqCst));
        assert_eq!(engine.effective_timer_mode(), TimerMode::IdleAware);

        // Act 1: Host disables power saving while Jetsam is Normal -> Responsive
        engine.set_power_saving_mode(false);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            engine.runtime_state.inner.read().await.timer_mode,
            TimerMode::Responsive
        );

        // Act 2: RAM drops into TrimCaches (< 15 MiB) -> never drops to Responsive; forces IdleAware
        engine
            .platform_hooks
            .set_test_available_memory_bytes(Some(12 * BYTES_PER_MIB));
        let eval_trim = engine
            .evaluate_memory_pressure_once()
            .await
            .ok_or("missing trim eval")?;
        assert_eq!(eval_trim.stage, JetsamPressureStage::TrimCaches);
        assert_eq!(
            engine.runtime_state.inner.read().await.timer_mode,
            TimerMode::IdleAware
        );

        // Act 3: Host turns manual power save back on, then RAM recovers -> remains IdleAware
        engine.set_power_saving_mode(true);
        engine
            .platform_hooks
            .set_test_available_memory_bytes(Some(22 * BYTES_PER_MIB));
        let eval_rec = engine
            .evaluate_memory_pressure_once()
            .await
            .ok_or("missing recover eval")?;
        assert_eq!(eval_rec.stage, JetsamPressureStage::Normal);
        assert_eq!(
            engine.runtime_state.inner.read().await.timer_mode,
            TimerMode::IdleAware
        );

        engine.shutdown().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[tokio::test]
    async fn test_status_observer_skips_stopped_and_coalesces_unchanged_writes()
    -> Result<(), String> {
        // Arrange
        let dir = TempDir::new().map_err(|e| e.to_string())?;
        let bridge = Arc::new(TestMobileBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let engine = MobileEngine::new_with_clock(
            MobileEngineInitConfig {
                platform: MobilePlatformKind::Android,
                agent_version: "0.1.0-mobile".to_owned(),
                default_node_name: Some("pixel-idle".to_owned()),
                log_dir_path: dir.path().to_string_lossy().into_owned(),
            },
            bridge.clone(),
            clock,
        )
        .map_err(|e| e.to_string())?;

        // Act: wait past one 1.5s interval while Stopped, call emit twice -> only 1 change written
        tokio::time::sleep(Duration::from_millis(1_700)).await;
        let writes_while_stopped = bridge.status_file_saves.load(Ordering::Relaxed);
        let callbacks_while_stopped = bridge.status_callbacks.load(Ordering::Relaxed);

        let _s1 = engine.emit_status_snapshot().await;
        let _s2 = engine.emit_status_snapshot().await;
        let writes_after_two_emits = bridge.status_file_saves.load(Ordering::Relaxed);
        let callbacks_after_two_emits = bridge.status_callbacks.load(Ordering::Relaxed);

        // Assert
        assert_eq!(writes_while_stopped, 0);
        assert_eq!(callbacks_while_stopped, 0);
        assert_eq!(writes_after_two_emits, 1);
        assert_eq!(callbacks_after_two_emits, 1);

        engine.shutdown().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[tokio::test]
    async fn test_no_secrets_in_outputs() -> Result<(), String> {
        // Arrange
        let dir = TempDir::new().map_err(|e| e.to_string())?;
        let raw_preauth = "mpk_Q2FuYXJ5VG9rZW4zMkJ5dGVzQ2FuYXJ5VG9rZW4zMkI";
        let pin = mesh_core::SpkiPin::from_sha256_bytes([0_u8; 32]);
        let node_name = mesh_core::NodeName::parse("pixel-pro").map_err(|e| e.to_string())?;
        let raw_uri = mesh_core::format_join_uri(
            "198.51.100.10:8443",
            &mesh_core::MobileJoinTlsAuth::SpkiPin(pin),
            raw_preauth,
            Some(&node_name),
        )
        .map_err(|e| e.to_string())?;
        let logs = Arc::new(StdMutex::new(Vec::<String>::new()));
        let ring = LogRingBuffer::default();
        let subscriber = tracing_subscriber::registry().with(DebugLogCaptureLayer {
            logs: Arc::clone(&logs),
            ring: ring.clone(),
        });

        let _guard = tracing::subscriber::set_default(subscriber);
        let bridge = Arc::new(TestMobileBridge::default());
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let engine = MobileEngine::new_with_clock(
            MobileEngineInitConfig {
                platform: MobilePlatformKind::Android,
                agent_version: "0.1.0-mobile".to_owned(),
                default_node_name: Some("pixel-pro".to_owned()),
                log_dir_path: dir.path().to_string_lossy().into_owned(),
            },
            bridge.clone(),
            clock,
        )
        .map_err(|e| e.to_string())?;

        // Act: Exercise URI parser, pending session, status IPC, error messages, and bugreport export.
        let parsed = parse_mobile_join_uri(raw_uri).map_err(|e| e.to_string())?;
        let parsed_dbg = format!("{parsed:?}");
        let session_dbg = format!("{:?}", parsed.session);
        let masked_preview = parsed.session.masked_preview();
        let manual_session =
            create_pending_join_session(raw_preauth.to_owned()).map_err(|e| e.to_string())?;
        let manual_dbg = format!("{manual_session:?}");

        tracing::debug!(
            component = "mesh_mobile_ffi.test",
            event = "debug_secret_check",
            summary = %parsed_dbg,
            session = %session_dbg,
            "verifying debug logs contain zero preauth secrets"
        );
        let err_with_secret =
            MobileError::invalid_argument(format!("bad header bearer {raw_preauth}"));
        assert!(!err_with_secret.to_string().contains(raw_preauth));

        let status = engine.status_snapshot().await.map_err(|e| e.to_string())?;
        let status_json =
            String::from_utf8_lossy(&status.to_bounded_ipc_json().map_err(|e| e.to_string())?)
                .into_owned();
        engine
            .log_ring
            .push_line(&format!("secret leaked input preauth_key={raw_preauth}"));

        let bug_path = dir.path().join("no-secrets.tar");
        drop(
            engine
                .export_bugreport_to_file(bug_path.to_string_lossy().into_owned())
                .await
                .map_err(|e| e.to_string())?,
        );
        let tar_bytes = std::fs::read(&bug_path).map_err(|e| e.to_string())?;
        let tar_text = String::from_utf8_lossy(&tar_bytes);

        let sealed_identity = bridge
            .files
            .lock()
            .map_err(|_| "lock poisoned".to_owned())?
            .get("identity.sealed.bin")
            .cloned()
            .unwrap_or_default();
        let sealed_text = String::from_utf8_lossy(&sealed_identity);

        let captured_logs = logs
            .lock()
            .map_err(|_| "logs lock poisoned".to_owned())?
            .join("\n");

        // Assert
        for surface in [
            parsed_dbg.as_str(),
            session_dbg.as_str(),
            masked_preview.as_str(),
            manual_dbg.as_str(),
            status_json.as_str(),
            tar_text.as_ref(),
            sealed_text.as_ref(),
            captured_logs.as_str(),
        ] {
            assert!(!surface.contains(raw_preauth));
            assert!(!surface.contains("node_privkey_hex"));
            assert!(!surface.contains("disco_privkey_hex"));
        }

        engine.shutdown().map_err(|e| e.to_string())?;
        Ok(())
    }
}
