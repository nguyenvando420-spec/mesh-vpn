//! Background IPC polling, `PollingSuspensionGuard` (`IG-DGUI-WA-03`), adaptive 2s/8s cadence,
//! `LegacyPre030` detection (`ADR-022`), and non-blocking Win32 UI dispatch (`ADR-024`).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::thread::JoinHandle;

#[cfg(target_os = "windows")]
use hyper::Method;
#[cfg(target_os = "windows")]
use mesh_core::defaults::{MAX_RO_IPC_BODY_BYTES, WINDOWS_AGENT_RO_PIPE};
use mesh_net::ipc::AgentVersionStatus;
#[cfg(target_os = "windows")]
use mesh_net::ipc::{
    IPC_NETCHECK_TIMEOUT, IPC_RO_QUERY_TIMEOUT, classify_agent_version_probe,
    connect_agent_named_pipe, ping_request_timeout, send_ipc_json_request_with_timeout,
    send_ipc_json_with_meta,
};
#[cfg(target_os = "windows")]
use mesh_proto::agent_ipc::{
    AgentStatusResponse, AgentVersionResponse, NetcheckResponse, PingRequest, PingResponse,
};
#[cfg(not(target_os = "windows"))]
use mesh_proto::agent_ipc::{AgentStatusResponse, NetcheckResponse, PingResponse};
#[cfg(target_os = "windows")]
use mesh_sys::gui_windows::{
    WINDOWS_SERVICE_NAME, WM_APP_BUGREPORT_DONE, WM_APP_NETCHECK_DONE, WM_APP_PING_DONE,
    WM_APP_STATE_REFRESH, WM_APP_WORKER_DONE, WindowsServiceProbeState, post_app_message,
    query_service_status_readonly,
};
use tokio::sync::Notify;
#[cfg(target_os = "windows")]
use tokio_util::sync::CancellationToken;
#[cfg(target_os = "windows")]
use zeroize::Zeroizing;

use crate::app::ServiceProbeKind;
#[cfg(target_os = "windows")]
use crate::elevation_worker::{run_bugreport_stream_handoff, run_privileged_handoff};

/// Adaptive polling cadence when the Dashboard window is visible (2 seconds).
pub(crate) const DASHBOARD_POLL_INTERVAL_MS: u64 = 2_000;

/// Adaptive polling cadence when minimized to System Tray (8 seconds).
pub(crate) const TRAY_IDLE_POLL_INTERVAL_MS: u64 = 8_000;

/// Returns the active polling interval (`2_000 ms` visible vs `8_000 ms` hidden).
#[must_use]
pub(crate) const fn next_poll_interval_ms(dashboard_visible: bool) -> u64 {
    if dashboard_visible {
        DASHBOARD_POLL_INTERVAL_MS
    } else {
        TRAY_IDLE_POLL_INTERVAL_MS
    }
}

/// Coordinates adaptive interval switching and `PollingSuspensionGuard` pauses (`IG-DGUI-WA-03`).
#[derive(Debug)]
pub(crate) struct PollingControl {
    paused_count: AtomicUsize,
    dashboard_visible: AtomicBool,
    wake_notify: Notify,
}

impl PollingControl {
    /// Creates a new polling coordinator with initial `dashboard_visible` state.
    #[must_use]
    pub(crate) fn new(dashboard_visible: bool) -> Arc<Self> {
        Arc::new(Self {
            paused_count: AtomicUsize::new(0),
            dashboard_visible: AtomicBool::new(dashboard_visible),
            wake_notify: Notify::new(),
        })
    }

    /// Returns whether background `meshd-ro` polling is currently suspended.
    #[must_use]
    pub(crate) fn is_paused(&self) -> bool {
        self.paused_count.load(Ordering::Acquire) > 0
    }

    /// Updates whether the main Dashboard window is visible and wakes the poller to adjust cadence.
    pub(crate) fn set_dashboard_visible(&self, visible: bool) {
        self.dashboard_visible.store(visible, Ordering::Release);
        self.wake_notify.notify_one();
    }

    /// Returns whether Dashboard polling cadence is active.
    #[must_use]
    pub(crate) fn dashboard_visible(&self) -> bool {
        self.dashboard_visible.load(Ordering::Acquire)
    }

    /// Triggers an out-of-band immediate refresh poll when not paused.
    pub(crate) fn trigger_refresh(&self) {
        self.wake_notify.notify_one();
    }

    /// Suspends background `meshd-ro` polling until the returned RAII guard drops (`ADR-021`,
    /// `IG-DGUI-WA-03`: invoke ONLY AFTER `GetSaveFileNameW` confirms a destination path).
    #[must_use]
    pub(crate) fn suspend(self: &Arc<Self>) -> PollingSuspensionGuard {
        self.paused_count.fetch_add(1, Ordering::AcqRel);
        PollingSuspensionGuard {
            control: Arc::clone(self),
        }
    }
}

/// RAII guard keeping background IPC polling suspended for the duration of a streamed export or
/// UAC elevation handoff, resuming immediately upon drop (`IG-DGUI-WA-03`).
#[derive(Debug)]
pub(crate) struct PollingSuspensionGuard {
    control: Arc<PollingControl>,
}

impl Drop for PollingSuspensionGuard {
    fn drop(&mut self) {
        let prev = self.control.paused_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            self.control.wake_notify.notify_one();
        }
    }
}

/// Latest poll snapshot posted from the background Tokio poller to the Win32 UI thread.
#[derive(Debug, Clone)]
pub(crate) struct PolledStateUpdate {
    pub(crate) service_probe: ServiceProbeKind,
    pub(crate) ipc_connected: bool,
    pub(crate) status: Option<AgentStatusResponse>,
    pub(crate) version_status: Option<AgentVersionStatus>,
    pub(crate) ipc_error: Option<String>,
}

/// Asynchronous one-shot action completion dispatched back to the Win32 UI thread.
#[derive(Debug, Clone)]
pub(crate) enum UiAsyncEvent {
    Netcheck(Result<NetcheckResponse, String>),
    Ping(Result<PingResponse, String>),
    WorkerAction {
        action_label: String,
        result: Result<String, String>,
    },
    Bugreport(Result<(u32, u64, String), String>),
}

/// Shared queues drained safely on the Win32 UI thread (`std::sync::Mutex` is never held across
/// `.await`).
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct EventQueues {
    latest_poll: Option<PolledStateUpdate>,
    async_events: VecDeque<UiAsyncEvent>,
}

#[cfg(not(target_os = "windows"))]
#[derive(Debug, Default)]
pub(crate) struct EventQueues {
    latest_poll: Option<PolledStateUpdate>,
    async_events: VecDeque<UiAsyncEvent>,
}

impl EventQueues {
    pub(crate) fn push_poll(&mut self, update: PolledStateUpdate) {
        self.latest_poll = Some(update);
    }

    pub(crate) fn take_latest_poll(&mut self) -> Option<PolledStateUpdate> {
        self.latest_poll.take()
    }

    pub(crate) fn push_event(&mut self, ev: UiAsyncEvent) {
        self.async_events.push_back(ev);
    }

    pub(crate) fn pop_event(&mut self) -> Option<UiAsyncEvent> {
        self.async_events.pop_front()
    }
}

/// Background IPC & UAC task coordinator for `MeshVPN.exe`.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(crate) struct BackgroundIpcController {
    hwnd: isize,
    poll_control: Arc<PollingControl>,
    queues: Arc<Mutex<EventQueues>>,
    cancel: CancellationToken,
    handle: Option<tokio::runtime::Handle>,
    worker_thread: Option<JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl BackgroundIpcController {
    /// Spawns a single-threaded Tokio runtime dedicated to IPC polling and async handoffs.
    pub(crate) fn start(hwnd: isize, dashboard_visible: bool) -> Self {
        let poll_control = PollingControl::new(dashboard_visible);
        let queues = Arc::new(Mutex::new(EventQueues::default()));
        let cancel = CancellationToken::new();

        let (tx, rx) = std::sync::mpsc::channel();
        let control_clone = Arc::clone(&poll_control);
        let queues_clone = Arc::clone(&queues);
        let cancel_clone = cancel.clone();

        let thread_res = std::thread::Builder::new()
            .name("mesh-gui-ipc".to_owned())
            .stack_size(512 * 1024)
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                let _sent = tx.send(rt.handle().clone());
                rt.block_on(run_polling_loop(
                    hwnd,
                    control_clone,
                    queues_clone,
                    cancel_clone,
                ));
            });

        let handle = rx.recv_timeout(Duration::from_secs(2)).ok();
        let worker_thread = thread_res.ok();
        Self {
            hwnd,
            poll_control,
            queues,
            cancel,
            handle,
            worker_thread,
        }
    }

    /// Updates adaptive cadence when the Dashboard window hides or restores.
    pub(crate) fn set_dashboard_visible(&self, visible: bool) {
        self.poll_control.set_dashboard_visible(visible);
    }

    /// Triggers an immediate poll cycle.
    pub(crate) fn trigger_immediate_poll(&self) {
        self.poll_control.trigger_refresh();
    }

    /// Drains the latest polled state update, if any.
    #[must_use]
    pub(crate) fn take_latest_poll(&self) -> Option<PolledStateUpdate> {
        self.queues
            .lock()
            .ok()
            .and_then(|mut q| q.take_latest_poll())
    }

    /// Pops one completed async UI action result.
    #[must_use]
    pub(crate) fn pop_async_event(&self) -> Option<UiAsyncEvent> {
        self.queues.lock().ok().and_then(|mut q| q.pop_event())
    }

    /// Launches `POST /v1/agent/netcheck` (`IPC_NETCHECK_TIMEOUT = 10 s`) on `meshd-ro`.
    pub(crate) fn spawn_netcheck(&self) {
        let Some(handle) = &self.handle else {
            return;
        };
        let queues = Arc::clone(&self.queues);
        let hwnd = self.hwnd;
        handle.spawn(async move {
            let res = run_netcheck_probe().await;
            if let Ok(mut q) = queues.lock() {
                q.push_event(UiAsyncEvent::Netcheck(res));
            }
            post_app_message(hwnd, WM_APP_NETCHECK_DONE, 0, 0);
        });
    }

    /// Launches `POST /v1/agent/ping` on `meshd-ro` (`US-106`).
    pub(crate) fn spawn_ping(&self, target: String, count: u16, force_direct: bool) {
        let Some(handle) = &self.handle else {
            return;
        };
        let queues = Arc::clone(&self.queues);
        let hwnd = self.hwnd;
        handle.spawn(async move {
            let res = run_ping_probe(target, count, force_direct).await;
            if let Ok(mut q) = queues.lock() {
                q.push_event(UiAsyncEvent::Ping(res));
            }
            post_app_message(hwnd, WM_APP_PING_DONE, 0, 0);
        });
    }

    /// Runs an admin/service `HandoffRequest` (direct IPC/in-process if elevated, else UAC `MGH1`)
    /// on a dedicated worker thread so polling & Win32 UI stay responsive.
    pub(crate) fn spawn_handoff_action(&self, action_label: String, payload: Zeroizing<Vec<u8>>) {
        let queues = Arc::clone(&self.queues);
        let poll_control = Arc::clone(&self.poll_control);
        let hwnd = self.hwnd;
        let _spawned = std::thread::Builder::new()
            .name("mesh-gui-uac".to_owned())
            .spawn(move || {
                let res = run_privileged_handoff(payload).map(|resp| {
                    resp.message
                        .unwrap_or_else(|| "Operation completed".to_owned())
                });
                if let Ok(mut q) = queues.lock() {
                    q.push_event(UiAsyncEvent::WorkerAction {
                        action_label,
                        result: res,
                    });
                }
                poll_control.trigger_refresh();
                post_app_message(hwnd, WM_APP_WORKER_DONE, 0, 0);
            });
    }

    /// Streams `POST /v1/agent/bugreport/stream` into `dest_path` via `UnprivilegedSinkWriter`,
    /// activating `PollingSuspensionGuard` ONLY HERE after `GetSaveFileNameW` has confirmed
    /// `dest_path` (`IG-DGUI-WA-03`).
    pub(crate) fn spawn_bugreport_export(&self, dest_path: PathBuf) {
        let queues = Arc::clone(&self.queues);
        let poll_control = Arc::clone(&self.poll_control);
        let hwnd = self.hwnd;
        let _spawned = std::thread::Builder::new()
            .name("mesh-gui-bugreport".to_owned())
            .spawn(move || {
                let _pause_guard = poll_control.suspend();
                let display_path = dest_path.display().to_string();
                let res = run_bugreport_stream_handoff(&dest_path)
                    .map(|(scrubbed, bytes)| (scrubbed, bytes, display_path));
                if let Ok(mut q) = queues.lock() {
                    q.push_event(UiAsyncEvent::Bugreport(res));
                }
                drop(_pause_guard);
                post_app_message(hwnd, WM_APP_BUGREPORT_DONE, 0, 0);
            });
    }

    /// Signals background polling shutdown and joins within a strict <= 2s budget (`US-107`).
    pub(crate) fn shutdown(&mut self) {
        self.cancel.cancel();
        self.poll_control.wake_notify.notify_waiters();
        if let Some(join) = self.worker_thread.take() {
            let _joined = join.join();
        }
    }
}

#[cfg(target_os = "windows")]
async fn run_polling_loop(
    hwnd: isize,
    control: Arc<PollingControl>,
    queues: Arc<Mutex<EventQueues>>,
    cancel: CancellationToken,
) {
    while !cancel.is_cancelled() {
        if !control.is_paused() {
            let update = probe_agent_snapshot().await;
            if let Ok(mut q) = queues.lock() {
                q.push_poll(update);
            }
            post_app_message(hwnd, WM_APP_STATE_REFRESH, 0, 0);
        }

        let wait_dur = Duration::from_millis(next_poll_interval_ms(control.dashboard_visible()));
        tokio::select! {
            () = cancel.cancelled() => break,
            () = control.wake_notify.notified() => {},
            () = tokio::time::sleep(wait_dur) => {},
        }
    }
}

#[cfg(target_os = "windows")]
async fn probe_agent_snapshot() -> PolledStateUpdate {
    let pipe_res = connect_agent_named_pipe(WINDOWS_AGENT_RO_PIPE, false).await;
    let Ok(pipe) = pipe_res else {
        let err_msg = pipe_res.err().map(|e| e.to_string());
        let service_probe = probe_scm_service_kind();
        return PolledStateUpdate {
            service_probe,
            ipc_connected: false,
            status: None,
            version_status: None,
            ipc_error: err_msg,
        };
    };

    let status_res = send_ipc_json_with_meta::<_, (), AgentStatusResponse>(
        pipe,
        Method::GET,
        "/v1/agent/status",
        None,
        MAX_RO_IPC_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await;

    match status_res {
        Ok(resp) => {
            let version_status = resolve_agent_version(resp.agent_version.as_deref()).await;
            PolledStateUpdate {
                service_probe: ServiceProbeKind::Running,
                ipc_connected: true,
                status: Some(resp.body),
                version_status,
                ipc_error: None,
            }
        }
        Err(err) => {
            let service_probe = probe_scm_service_kind();
            let msg = err.to_string();
            PolledStateUpdate {
                service_probe,
                ipc_connected: false,
                status: None,
                version_status: None,
                ipc_error: Some(msg),
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn resolve_agent_version(header_version: Option<&str>) -> Option<AgentVersionStatus> {
    if let Some(ver) = header_version.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(AgentVersionStatus::Version(ver.to_owned()));
    }
    let Ok(pipe) = connect_agent_named_pipe(WINDOWS_AGENT_RO_PIPE, false).await else {
        return None;
    };
    let ver_res = send_ipc_json_request_with_timeout::<_, (), AgentVersionResponse>(
        pipe,
        Method::GET,
        "/v1/agent/version",
        None,
        MAX_RO_IPC_BODY_BYTES,
        IPC_RO_QUERY_TIMEOUT,
    )
    .await;
    classify_agent_version_probe(header_version, ver_res).ok()
}

#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn probe_scm_service_kind() -> ServiceProbeKind {
    match query_service_status_readonly(WINDOWS_SERVICE_NAME) {
        Ok(WindowsServiceProbeState::Running | WindowsServiceProbeState::Pending) => {
            ServiceProbeKind::Running
        }
        Ok(WindowsServiceProbeState::Stopped) => ServiceProbeKind::Stopped,
        Ok(WindowsServiceProbeState::NotInstalled) => ServiceProbeKind::NotInstalled,
        Err(_) => ServiceProbeKind::Unknown,
    }
}

#[cfg(target_os = "windows")]
async fn run_netcheck_probe() -> Result<NetcheckResponse, String> {
    let pipe = connect_agent_named_pipe(WINDOWS_AGENT_RO_PIPE, false)
        .await
        .map_err(|err| err.to_string())?;
    send_ipc_json_request_with_timeout::<_, (), NetcheckResponse>(
        pipe,
        Method::POST,
        "/v1/agent/netcheck",
        None,
        MAX_RO_IPC_BODY_BYTES,
        IPC_NETCHECK_TIMEOUT,
    )
    .await
    .map_err(|err| err.to_string())
}

#[cfg(target_os = "windows")]
async fn run_ping_probe(
    target: String,
    count: u16,
    force_direct: bool,
) -> Result<PingResponse, String> {
    let per_probe_ms = 2_500_u64;
    let clamped_count = count.clamp(1, 64);
    let req = PingRequest {
        target,
        count: clamped_count,
        force_direct,
        timeout_ms: per_probe_ms,
    };
    let pipe = connect_agent_named_pipe(WINDOWS_AGENT_RO_PIPE, false)
        .await
        .map_err(|err| err.to_string())?;
    send_ipc_json_request_with_timeout(
        pipe,
        Method::POST,
        "/v1/agent/ping",
        Some(&req),
        MAX_RO_IPC_BODY_BYTES,
        ping_request_timeout(clamped_count, per_probe_ms),
    )
    .await
    .map_err(|err| err.to_string())
}
