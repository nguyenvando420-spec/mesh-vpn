//! Windows `NotifyIpInterfaceChange` + PowerEvent monitor (`US-036`, `WP-S1-04`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mesh_core::{AppError, AppResult, ErrorKind};
use mesh_sys::netmon_windows::{
    IpChangeSubscription, query_primary_physical_if_index, subscribe_ip_interface_changes,
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::netmon::{NetEvent, NetMonitor, netmon_unavailable};
use crate::tun::BoxFuture;

const POLL_TIMEOUT_MS: u64 = 250;

/// Power management notifications delivered by `windows-service` control handler (`US-036 AC1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsPowerEvent {
    /// OS is entering suspend/hibernate.
    Suspend,
    /// OS woke automatically from sleep/hibernate without user input.
    ResumeAutomatic,
    /// OS woke interactively from sleep/hibernate.
    ResumeSuspend,
}

/// Windows IP Helper [`NetMonitor`] bridging `NotifyIpInterfaceChange` and Windows power-resume
/// events into asynchronous [`NetEvent`] updates.
pub struct WindowsNetMonitor {
    rx: tokio::sync::Mutex<Receiver<NetEvent>>,
    power_rx: tokio::sync::Mutex<Receiver<WindowsPowerEvent>>,
    power_tx: Sender<WindowsPowerEvent>,
    stop: Arc<AtomicBool>,
    _subscription: Option<IpChangeSubscription>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for WindowsNetMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsNetMonitor")
            .field("active_os_subscription", &self._subscription.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for WindowsNetMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut guard) = self.worker.lock()
            && let Some(handle) = guard.take()
        {
            let _joined = handle.join();
        }
    }
}

impl WindowsNetMonitor {
    /// Creates an inactive stub monitor matching baseline [`Default`].
    #[must_use]
    pub fn new() -> Self {
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (power_tx, power_rx) = mpsc::channel(1);
        Self {
            rx: tokio::sync::Mutex::new(event_rx),
            power_rx: tokio::sync::Mutex::new(power_rx),
            power_tx,
            stop: Arc::new(AtomicBool::new(true)),
            _subscription: None,
            worker: Mutex::new(None),
        }
    }

    /// Starts live monitoring via `NotifyIpInterfaceChange` + physical interface polling.
    pub fn start_live() -> AppResult<Self> {
        let (subscription, os_rx) = subscribe_ip_interface_changes().map_err(AppError::from)?;
        let initial_if = query_primary_physical_if_index().ok();
        let (event_tx, event_rx) = mpsc::channel(32);
        let (power_tx, power_rx) = mpsc::channel::<WindowsPowerEvent>(16);
        let stop = Arc::new(AtomicBool::new(false));

        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut last_if = initial_if;
            while !stop_flag.load(Ordering::Acquire) {
                match os_rx.recv_timeout(Duration::from_millis(POLL_TIMEOUT_MS)) {
                    Ok(()) => {
                        let new_if = query_primary_physical_if_index().ok();
                        let ev = classify_interface_transition(last_if, new_if);
                        last_if = new_if;
                        if event_tx.blocking_send(ev).is_err() {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        Ok(Self {
            rx: tokio::sync::Mutex::new(event_rx),
            power_rx: tokio::sync::Mutex::new(power_rx),
            power_tx,
            stop,
            _subscription: Some(subscription),
            worker: Mutex::new(Some(handle)),
        })
    }

    /// Injects a [`WindowsPowerEvent`] from the Windows Service control handler (`US-036 AC1`).
    pub fn notify_power_event(&self, event: WindowsPowerEvent) -> AppResult<()> {
        if matches!(
            event,
            WindowsPowerEvent::ResumeAutomatic | WindowsPowerEvent::ResumeSuspend
        ) {
            return self
                .power_tx
                .try_send(event)
                .map_err(|_| AppError::unavailable("Windows power event channel full or closed"));
        }
        Ok(())
    }

    /// Returns a cloned sender for `windows-service` power control hooks.
    #[must_use]
    pub fn power_event_sender(&self) -> Sender<WindowsPowerEvent> {
        self.power_tx.clone()
    }
}

impl Default for WindowsNetMonitor {
    fn default() -> Self {
        Self::new()
    }
}

fn classify_interface_transition(previous: Option<u32>, current: Option<u32>) -> NetEvent {
    match (previous, current) {
        (Some(old), Some(new)) if old != new => NetEvent::RouteChanged,
        (None, Some(new_idx)) => NetEvent::InterfaceUp {
            interface: format!("if-{new_idx}"),
        },
        (Some(old_idx), None) => NetEvent::InterfaceDown {
            interface: format!("if-{old_idx}"),
        },
        (Some(idx), Some(_)) => NetEvent::AddressChanged {
            interface: format!("if-{idx}"),
        },
        (None, None) => NetEvent::RouteChanged,
    }
}

impl NetMonitor for WindowsNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async {
            if self.stop.load(Ordering::Acquire) {
                return Err(netmon_unavailable("Windows IP Helper"));
            }
            let mut os_guard = self.rx.lock().await;
            let mut pwr_guard = self.power_rx.lock().await;
            loop {
                tokio::select! {
                    maybe_os = os_guard.recv() => {
                        return maybe_os.ok_or_else(|| {
                            AppError::new(ErrorKind::Unavailable, "Windows IP Helper monitor closed")
                        });
                    }
                    maybe_pwr = pwr_guard.recv() => {
                        match maybe_pwr {
                            Some(WindowsPowerEvent::ResumeAutomatic | WindowsPowerEvent::ResumeSuspend) => {
                                return Ok(NetEvent::WakeFromSleep);
                            }
                            Some(WindowsPowerEvent::Suspend) => {}
                            None => {
                                return Err(AppError::new(
                                    ErrorKind::Unavailable,
                                    "Windows power monitor closed",
                                ));
                            }
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{WindowsNetMonitor, WindowsPowerEvent, classify_interface_transition};
    use crate::netmon::{NetEvent, NetMonitor};

    #[test]
    fn test_netmon_windows_transition_classification() {
        // Arrange / Act / Assert
        assert!(matches!(
            classify_interface_transition(Some(10), Some(14)),
            NetEvent::RouteChanged
        ));
        assert!(matches!(
            classify_interface_transition(None, Some(14)),
            NetEvent::InterfaceUp { .. }
        ));
        assert!(matches!(
            classify_interface_transition(Some(10), None),
            NetEvent::InterfaceDown { .. }
        ));
        assert!(matches!(
            classify_interface_transition(Some(10), Some(10)),
            NetEvent::AddressChanged { .. }
        ));
    }

    #[tokio::test]
    async fn test_netmon_windows_live_monitor_starts_and_shuts_down_cleanly() {
        // Arrange
        let mon = WindowsNetMonitor::start_live();
        assert!(mon.is_ok(), "start_live failed: {mon:?}");
        let Ok(mon) = mon else {
            return;
        };

        // Act: deliver PowerResume event via windows-service hook channel.
        let send_res = mon.notify_power_event(WindowsPowerEvent::ResumeAutomatic);
        assert!(send_res.is_ok(), "notify_power_event failed: {send_res:?}");

        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), mon.next_event()).await;

        // Assert
        assert!(matches!(ev, Ok(Ok(_))));
        drop(mon);
    }
}
