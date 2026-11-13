//! Network roaming, sleep/wake recovery, clock-jump detection, and `RebindHandle` driver (`US-035`, `US-036`, `HR-G2-04`).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mesh_core::clock::{Clock, ClockJumpDetector};
use mesh_datapath::{RebindCommand, RebindHandle};
use mesh_net::netmon::{Debouncer, NetEvent, NetMonitor, NetworkChangeEvent, check_clock_jump};

/// Interval at which [`ClockJumpDetector`] polls wall-vs-monotonic drift (`2 s`).
const CLOCK_JUMP_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Bounded capacity for [`NetworkChangeEvent`] notifications forwarded to `control_loop`.
pub(crate) const NETWORK_CHANGE_CHANNEL_CAPACITY: usize = 32;

/// Coordinates OS network monitoring, 1-second debouncing, and clock-jump detection (`US-035`).
#[derive(Debug)]
pub(crate) struct RoamingLoop {
    monitor: Arc<dyn NetMonitor>,
    clock: Arc<dyn Clock>,
    rebind_handle: RebindHandle,
    control_events_tx: mpsc::Sender<NetworkChangeEvent>,
}

impl RoamingLoop {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub(crate) const fn status_label() -> &'static str {
        "roaming_loop:ready"
    }

    /// Creates a [`RoamingLoop`] wired to `rebind_handle` and `control_events_tx`.
    #[must_use]
    pub(crate) fn new(
        monitor: Arc<dyn NetMonitor>,
        clock: Arc<dyn Clock>,
        rebind_handle: RebindHandle,
        control_events_tx: mpsc::Sender<NetworkChangeEvent>,
    ) -> Self {
        Self {
            monitor,
            clock,
            rebind_handle,
            control_events_tx,
        }
    }

    /// Runs the monitor and clock-jump polling loop until `shutdown` fires.
    pub(crate) async fn run(self, shutdown: CancellationToken) {
        let mut debouncer = Debouncer::standard();
        let mut jump_detector = ClockJumpDetector::new(self.clock.as_ref());
        let mut clock_tick = tokio::time::interval(CLOCK_JUMP_POLL_INTERVAL);
        clock_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        info!(
            component = "meshd.roaming_loop",
            event = "roaming_loop_started",
            "network roaming and clock-jump monitor started"
        );

        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = clock_tick.tick() => {
                    if let Some(ev) = check_clock_jump(&mut jump_detector, self.clock.as_ref()) {
                        self.handle_raw_event(&mut debouncer, ev);
                    }
                }
                next_ev = self.monitor.next_event() => {
                    match next_ev {
                        Ok(ev) => {
                            let _accepted = self.handle_raw_event(&mut debouncer, ev);
                        }
                        Err(err) => {
                            warn!(
                                component = "meshd.roaming_loop",
                                event = "netmon_stream_ended",
                                error = %err,
                                "OS network monitor unavailable; keeping clock-jump monitor active"
                            );
                            // Keep waiting on clock-jump checks and shutdown rather than exiting prematurely.
                            wait_until_cancelled(&shutdown, &mut clock_tick, &mut jump_detector, &mut debouncer, &self).await;
                            break;
                        }
                    }
                }
            }
        }

        info!(
            component = "meshd.roaming_loop",
            event = "roaming_loop_stopped",
            "network roaming monitor exited"
        );
    }

    /// Applies 1s debouncing (bypassed on wake/clock jumps) and emits `RebindCommand` +
    /// `NetworkChangeEvent` toward `mesh-datapath` and `control_loop`.
    pub(crate) fn handle_raw_event(&self, debouncer: &mut Debouncer, event: NetEvent) -> bool {
        if !debouncer.should_emit(self.clock.as_ref(), &event) {
            debug!(
                component = "meshd.roaming_loop",
                event = "net_event_debounced",
                detail = ?event,
                "suppressed burst network event within 1s debounce window"
            );
            return false;
        }

        info!(
            component = "meshd.roaming_loop",
            event = "network_change_accepted",
            detail = ?event,
            "propagating network/power transition to datapath and control loop"
        );

        for cmd in map_net_event_to_rebind_commands(&event) {
            if let Err(err) = self.rebind_handle.try_send(cmd) {
                debug!(
                    component = "meshd.roaming_loop",
                    event = "rebind_queue_full",
                    error = %err,
                    "dropped duplicate RebindCommand on saturated queue"
                );
            }
        }

        if let Err(err) = self.control_events_tx.try_send(event) {
            debug!(
                component = "meshd.roaming_loop",
                event = "control_roaming_queue_full",
                error = %err,
                "control roaming event channel full or closed"
            );
        }
        true
    }
}

async fn wait_until_cancelled(
    shutdown: &CancellationToken,
    clock_tick: &mut tokio::time::Interval,
    jump_detector: &mut ClockJumpDetector,
    debouncer: &mut Debouncer,
    roaming: &RoamingLoop,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = clock_tick.tick() => {
                if let Some(ev) = check_clock_jump(jump_detector, roaming.clock.as_ref()) {
                    roaming.handle_raw_event(debouncer, ev);
                }
            }
        }
    }
}

/// Maps a normalized [`NetEvent`] into non-blocking [`RebindCommand`]s preserving `local_udp_port`.
#[must_use]
pub(crate) fn map_net_event_to_rebind_commands(event: &NetEvent) -> Vec<RebindCommand> {
    match event {
        NetEvent::InterfaceUp { interface } | NetEvent::AddressChanged { interface } => vec![
            RebindCommand::RebindInterface {
                interface_name: interface.clone(),
                if_index: None,
                is_ipv6: false,
            },
            RebindCommand::RefreshCandidates,
            RebindCommand::WakeRelay,
        ],
        NetEvent::InterfaceDown { .. } | NetEvent::RouteChanged => {
            vec![RebindCommand::RefreshCandidates, RebindCommand::WakeRelay]
        }
        NetEvent::WakeFromSleep | NetEvent::ClockJumpDetected { .. } => {
            vec![RebindCommand::WakeRelay, RebindCommand::RefreshCandidates]
        }
    }
}

/// Windows power-notification handle returned alongside the platform monitor on Windows.
#[cfg(target_os = "windows")]
pub(crate) type WindowsPowerSender = mpsc::Sender<mesh_net::netmon_windows::WindowsPowerEvent>;

/// Starts the best-effort OS [`NetMonitor`] for the current target platform.
#[cfg(target_os = "windows")]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<WindowsPowerSender>) {
    match mesh_net::netmon_windows::WindowsNetMonitor::start_live() {
        Ok(mon) => {
            let pwr = mon.power_event_sender();
            (Arc::new(mon), Some(pwr))
        }
        Err(err) => {
            warn!(
                component = "meshd.roaming_loop",
                event = "windows_netmon_fallback",
                error = %err,
                "failed subscribing Windows NotifyIpInterfaceChange; using fallback monitor"
            );
            let fallback = mesh_net::netmon_windows::WindowsNetMonitor::new();
            let pwr = fallback.power_event_sender();
            (Arc::new(fallback), Some(pwr))
        }
    }
}

/// Starts the Linux Netlink [`NetMonitor`], falling back gracefully in restricted containers.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<()>) {
    match mesh_net::netmon_linux::LinuxNetMonitor::start() {
        Ok(mon) => (Arc::new(mon), None),
        Err(err) => {
            warn!(
                component = "meshd.roaming_loop",
                event = "linux_netmon_fallback",
                error = %err,
                "failed starting Linux Netlink monitor; continuing with clock-jump detector"
            );
            (Arc::new(mesh_net::netmon::FakeNetMonitor::new()), None)
        }
    }
}

/// Starts the macOS `PF_ROUTE` [`NetMonitor`], falling back cleanly if restricted.
#[cfg(target_os = "macos")]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<()>) {
    match mesh_net::netmon_macos::MacOsNetMonitor::start() {
        Ok(mon) => (Arc::new(mon), None),
        Err(err) => {
            warn!(
                component = "meshd.roaming_loop",
                event = "macos_netmon_fallback",
                error = %err,
                "failed starting macOS PF_ROUTE monitor; continuing with clock-jump detector"
            );
            (Arc::new(mesh_net::netmon::FakeNetMonitor::new()), None)
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
#[must_use]
pub(crate) fn create_platform_net_monitor() -> (Arc<dyn NetMonitor>, Option<()>) {
    (Arc::new(mesh_net::netmon::FakeNetMonitor::new()), None)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use mesh_core::clock::FakeClock;
    use mesh_datapath::{RebindCommand, RebindHandle};
    use mesh_net::netmon::{Debouncer, FakeNetMonitor, NetEvent};

    use super::RoamingLoop;

    #[tokio::test]
    async fn test_roaming_loop_debounces_burst_and_propagates_wake_immediately() {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let monitor = Arc::new(FakeNetMonitor::new());
        let (rebind_handle, mut rebind_rx) = RebindHandle::channel();
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(16);
        let roaming = RoamingLoop::new(
            Arc::clone(&monitor) as Arc<dyn mesh_net::netmon::NetMonitor>,
            Arc::clone(&clock) as Arc<dyn mesh_core::clock::Clock>,
            rebind_handle,
            ctrl_tx,
        );
        let mut debouncer = Debouncer::standard();

        // Act: rapid address flap inside < 1s window should coalesce, WakeFromSleep bypasses window.
        let first_accepted = roaming.handle_raw_event(
            &mut debouncer,
            NetEvent::AddressChanged {
                interface: "en0".to_owned(),
            },
        );
        clock.advance(200);
        let suppressed_burst = roaming.handle_raw_event(&mut debouncer, NetEvent::RouteChanged);
        let urgent_wake = roaming.handle_raw_event(&mut debouncer, NetEvent::WakeFromSleep);

        // Also test live async run loop exit on shutdown.
        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let handle = tokio::spawn(roaming.run(task_shutdown));
        monitor.push_event(NetEvent::RouteChanged).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.cancel();

        // Assert
        assert!(first_accepted);
        assert!(!suppressed_burst);
        assert!(urgent_wake);
        assert!(matches!(
            rebind_rx.recv().await,
            Some(RebindCommand::RebindInterface { interface_name, .. }) if interface_name == "en0"
        ));
        assert!(matches!(
            ctrl_rx.recv().await,
            Some(NetEvent::AddressChanged { .. })
        ));
        assert!(matches!(
            ctrl_rx.recv().await,
            Some(NetEvent::WakeFromSleep)
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .is_ok()
        );
    }
}
