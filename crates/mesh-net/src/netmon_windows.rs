//! Windows `NotifyIpInterfaceChange` + PowerEvent monitor (`US-036`, `WP-S1-04`).

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mesh_core::{AppError, AppResult, ErrorKind};
use mesh_sys::netmon_windows::{
    IpChangeSubscription, is_usable_dhcp_ip, list_interface_addresses,
    query_primary_physical_interface as sys_query_primary_physical_interface,
    subscribe_ip_interface_changes,
};
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::endpoint_filter::InterfaceSubnetSnapshot;
use crate::netmon::{NetEvent, NetMonitor, PhysicalInterface, netmon_unavailable};
use crate::tun::BoxFuture;

/// Queries the current primary Windows physical interface `(IfIndex, FriendlyName)` via IP Helper.
pub fn query_primary_physical_interface() -> AppResult<PhysicalInterface> {
    let (if_index, name) = sys_query_primary_physical_interface().map_err(AppError::from)?;
    Ok(PhysicalInterface { if_index, name })
}

/// Lists all current Windows adapter unicast addresses and on-link CIDR prefixes
/// (`US-036` DHCP wait, `US-037` CGNAT overlap detection).
pub fn list_interface_subnets() -> AppResult<Vec<InterfaceSubnetSnapshot>> {
    let items = list_interface_addresses().map_err(AppError::from)?;
    Ok(items
        .into_iter()
        .map(|item| InterfaceSubnetSnapshot {
            if_index: item.if_index,
            interface_name: item.friendly_name,
            ip: item.ip,
            prefix_len: item.prefix_len,
            is_up: item.is_up,
            is_virtual: item.is_virtual,
            has_gateway: item.has_gateway,
        })
        .collect())
}

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
    power_only: bool,
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
            power_only: false,
            _subscription: None,
            worker: Mutex::new(None),
        }
    }

    /// Creates a fallback active monitor that delivers SCM [`WindowsPowerEvent`] wakeups even when
    /// kernel IP Helper notifications are unavailable (`US-036 AC1`).
    #[must_use]
    pub fn start_power_monitor_only() -> Self {
        let (_event_tx, event_rx) = mpsc::channel(1);
        let (power_tx, power_rx) = mpsc::channel(16);
        Self {
            rx: tokio::sync::Mutex::new(event_rx),
            power_rx: tokio::sync::Mutex::new(power_rx),
            power_tx,
            stop: Arc::new(AtomicBool::new(false)),
            power_only: true,
            _subscription: None,
            worker: Mutex::new(None),
        }
    }

    /// Starts live monitoring via `NotifyIpInterfaceChange` + `NotifyUnicastIpAddressChange` and
    /// physical adapter / IP snapshot resolution.
    pub fn start_live() -> AppResult<Self> {
        let (subscription, os_rx) = subscribe_ip_interface_changes().map_err(AppError::from)?;
        let initial_if = sys_query_primary_physical_interface().ok();
        let initial_ips = capture_usable_ips(initial_if.as_ref().map(|(idx, _)| *idx));
        let (event_tx, event_rx) = mpsc::channel(32);
        let (power_tx, power_rx) = mpsc::channel::<WindowsPowerEvent>(16);
        let stop = Arc::new(AtomicBool::new(false));

        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut last_if = initial_if;
            let mut last_ips = initial_ips;
            while !stop_flag.load(Ordering::Acquire) {
                match os_rx.recv_timeout(Duration::from_millis(POLL_TIMEOUT_MS)) {
                    Ok(()) => {
                        while os_rx.try_recv().is_ok() {}
                        let new_if = sys_query_primary_physical_interface().ok();
                        let new_ips = capture_usable_ips(new_if.as_ref().map(|(idx, _)| *idx));
                        let Some(ev) = classify_live_poll_transition(
                            last_if.as_ref(),
                            &last_ips,
                            new_if.as_ref(),
                            &new_ips,
                        ) else {
                            continue;
                        };
                        last_if = new_if;
                        last_ips = new_ips;
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
            power_only: false,
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

fn capture_usable_ips(if_index: Option<u32>) -> Vec<IpAddr> {
    let Some(target_idx) = if_index else {
        return Vec::new();
    };
    let Ok(addrs) = list_interface_addresses() else {
        return Vec::new();
    };
    let mut ips: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|a| a.if_index == target_idx && a.is_up && !a.is_virtual && is_usable_dhcp_ip(a.ip))
        .map(|a| a.ip)
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn classify_live_poll_transition(
    last_if: Option<&(u32, String)>,
    last_ips: &[IpAddr],
    new_if: Option<&(u32, String)>,
    new_ips: &[IpAddr],
) -> Option<NetEvent> {
    if new_if != last_if {
        Some(classify_interface_transition_named(last_if, new_if))
    } else if new_ips != last_ips {
        match new_if {
            Some((_, iface_name)) => Some(NetEvent::AddressChanged {
                interface: iface_name.clone(),
            }),
            None => Some(NetEvent::RouteChanged),
        }
    } else {
        None
    }
}

fn classify_interface_transition_named(
    previous: Option<&(u32, String)>,
    current: Option<&(u32, String)>,
) -> NetEvent {
    match (previous, current) {
        (Some((old_idx, _)), Some((new_idx, _))) if old_idx != new_idx => NetEvent::RouteChanged,
        (None, Some((_, new_name))) => NetEvent::InterfaceUp {
            interface: new_name.clone(),
        },
        (Some((_, old_name)), None) => NetEvent::InterfaceDown {
            interface: old_name.clone(),
        },
        (Some(_), Some((_, cur_name))) => NetEvent::AddressChanged {
            interface: cur_name.clone(),
        },
        (None, None) => NetEvent::RouteChanged,
    }
}

#[cfg(test)]
fn classify_interface_transition(previous: Option<u32>, current: Option<u32>) -> NetEvent {
    let prev = previous.map(|idx| (idx, format!("if-{idx}")));
    let cur = current.map(|idx| (idx, format!("if-{idx}")));
    classify_interface_transition_named(prev.as_ref(), cur.as_ref())
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
                    maybe_os = os_guard.recv(), if !self.power_only => {
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
    use super::{
        WindowsNetMonitor, WindowsPowerEvent, classify_interface_transition,
        classify_live_poll_transition,
    };
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

    #[tokio::test]
    async fn test_netmon_windows_power_only_monitor_delivers_resume_and_ignores_suspend() {
        // Traces: US-036 AC1
        // Arrange
        let mon = WindowsNetMonitor::start_power_monitor_only();
        assert!(mon.notify_power_event(WindowsPowerEvent::Suspend).is_ok());
        assert!(
            mon.notify_power_event(WindowsPowerEvent::ResumeSuspend)
                .is_ok()
        );

        // Act
        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), mon.next_event()).await;

        // Assert
        assert!(matches!(ev, Ok(Ok(NetEvent::WakeFromSleep))));
    }

    #[test]
    fn test_netmon_windows_live_poll_ignores_unchanged_physical_interface_and_ips() {
        // Arrange: e.g. virtual MeshVPN TUN creation triggers NotifyIpInterfaceChange while physical
        // Ethernet NIC index and its usable IPv4 address are completely unchanged.
        let iface = Some((10_u32, "Ethernet".to_owned()));
        let ips = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, 1, 50,
        ))];

        // Act
        let unchanged = classify_live_poll_transition(iface.as_ref(), &ips, iface.as_ref(), &ips);
        let new_ips = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, 1, 51,
        ))];
        let ip_changed =
            classify_live_poll_transition(iface.as_ref(), &ips, iface.as_ref(), &new_ips);

        // Assert
        assert!(unchanged.is_none());
        assert!(matches!(
            ip_changed,
            Some(NetEvent::AddressChanged { interface }) if interface == "Ethernet"
        ));
    }
}
