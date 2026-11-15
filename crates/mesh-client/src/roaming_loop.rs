//! OS-neutral network roaming, sleep/wake recovery, clock-jump detection, and `RebindHandle`
//! coordination (`US-035`, `US-036`, `HR-G2-04`).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use mesh_core::AppResult;
use mesh_core::clock::{Clock, ClockJumpDetector};
use mesh_datapath::{RebindCommand, RebindHandle};
use mesh_net::netmon::{
    Debouncer, DhcpWaitConfig, NetEvent, NetMonitor, NetworkChangeEvent, OsPhysicalNetworkProbe,
    PhysicalInterface, PhysicalNetworkProbe, check_clock_jump, wait_for_usable_ip_with_backoff,
};
use mesh_proto::agent_ipc::DaemonState;

use crate::state::ClientRuntimeState;

const CLOCK_JUMP_POLL_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_REBIND_RETRY_INITIAL: Duration = Duration::from_millis(500);
const DEFAULT_REBIND_RETRY_MAX: Duration = Duration::from_secs(4);
const REBIND_CONFIRM_TIMEOUT: Duration = Duration::from_secs(6);

/// Bounded capacity for [`NetworkChangeEvent`] notifications forwarded to `control_loop`.
pub const NETWORK_CHANGE_CHANNEL_CAPACITY: usize = 32;

/// Coordinates OS network monitoring, 1-second debouncing, DHCP readiness wait, and clock-jump
/// detection (`US-035`, `US-036`).
#[derive(Debug)]
pub struct RoamingLoop {
    monitor: Arc<dyn NetMonitor>,
    clock: Arc<dyn Clock>,
    probe: Arc<dyn PhysicalNetworkProbe>,
    dhcp_cfg: DhcpWaitConfig,
    runtime: Option<Arc<ClientRuntimeState>>,
    rebind_handle: RebindHandle,
    rebind_feedback_rx: Option<mpsc::Receiver<AppResult<()>>>,
    rebind_retry_initial: Duration,
    rebind_retry_max: Duration,
    control_events_tx: mpsc::Sender<NetworkChangeEvent>,
}

impl RoamingLoop {
    /// Returns diagnostic subsystem label.
    #[must_use]
    pub const fn status_label() -> &'static str {
        "roaming_loop:ready"
    }

    /// Creates a [`RoamingLoop`] wired to `rebind_handle` and `control_events_tx`.
    #[must_use]
    pub fn new(
        monitor: Arc<dyn NetMonitor>,
        clock: Arc<dyn Clock>,
        rebind_handle: RebindHandle,
        control_events_tx: mpsc::Sender<NetworkChangeEvent>,
    ) -> Self {
        Self {
            monitor,
            clock,
            probe: Arc::new(OsPhysicalNetworkProbe),
            dhcp_cfg: DhcpWaitConfig::default(),
            runtime: None,
            rebind_handle,
            rebind_feedback_rx: None,
            rebind_retry_initial: DEFAULT_REBIND_RETRY_INITIAL,
            rebind_retry_max: DEFAULT_REBIND_RETRY_MAX,
            control_events_tx,
        }
    }

    /// Attaches a confirmation channel receiving `Ok(())` or `Err(err)` after `SocketRebinder`.
    #[must_use]
    pub fn with_rebind_feedback(mut self, rx: mpsc::Receiver<AppResult<()>>) -> Self {
        self.rebind_feedback_rx = Some(rx);
        self
    }

    /// Overrides rebind retry backoff bounds.
    #[must_use]
    pub fn with_rebind_retry_window(mut self, initial: Duration, max: Duration) -> Self {
        self.rebind_retry_initial = initial;
        self.rebind_retry_max = max;
        self
    }

    /// Attaches a custom [`PhysicalNetworkProbe`].
    #[must_use]
    pub fn with_probe(mut self, probe: Arc<dyn PhysicalNetworkProbe>) -> Self {
        self.probe = probe;
        self
    }

    /// Overrides the DHCP readiness wait backoff policy (`US-036 AC4`).
    #[must_use]
    pub fn with_dhcp_config(mut self, dhcp_cfg: DhcpWaitConfig) -> Self {
        self.dhcp_cfg = dhcp_cfg;
        self
    }

    /// Attaches shared runtime state so transient connecting state surfaces during DHCP/rebind waits.
    #[must_use]
    pub fn with_runtime(mut self, runtime: Arc<ClientRuntimeState>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Runs the monitor and clock-jump polling loop until `shutdown` fires.
    pub async fn run(mut self, shutdown: CancellationToken) {
        let mut debouncer = Debouncer::standard();
        let mut jump_detector = ClockJumpDetector::new(self.clock.as_ref());
        let mut clock_tick = tokio::time::interval(CLOCK_JUMP_POLL_INTERVAL);
        clock_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        info!(
            component = "mesh_client.roaming_loop",
            event = "roaming_loop_started",
            "network roaming and clock-jump monitor started"
        );

        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = clock_tick.tick() => {
                    if let Some(ev) = check_clock_jump(&mut jump_detector, self.clock.as_ref()) {
                        self.handle_async_event(&mut debouncer, ev, &shutdown).await;
                    }
                }
                next_ev = self.monitor.next_event() => {
                    match next_ev {
                        Ok(ev) => {
                            self.handle_async_event(&mut debouncer, ev, &shutdown).await;
                        }
                        Err(err) => {
                            warn!(
                                component = "mesh_client.roaming_loop",
                                event = "netmon_stream_ended",
                                error = %err,
                                "network monitor unavailable; keeping clock-jump monitor active"
                            );
                            wait_until_cancelled(&shutdown, &mut clock_tick, &mut jump_detector, &mut debouncer, &mut self).await;
                            break;
                        }
                    }
                }
            }
        }

        info!(
            component = "mesh_client.roaming_loop",
            event = "roaming_loop_stopped",
            "network roaming monitor exited"
        );
    }

    /// Evaluates one raw OS [`NetEvent`] under debouncing, DHCP wait, socket rebind, and Control
    /// wakeup; returns `true` when dispatched upstream.
    pub async fn handle_async_event(
        &mut self,
        debouncer: &mut Debouncer,
        event: NetEvent,
        shutdown: &CancellationToken,
    ) -> bool {
        if !debouncer.should_emit(self.clock.as_ref(), &event) {
            debug!(
                component = "mesh_client.roaming_loop",
                event = "net_event_debounced",
                detail = ?event,
                "suppressed burst network event within 1s debounce window"
            );
            return false;
        }

        if let Some(ref rt) = self.runtime {
            mark_runtime_rebinding(rt, &event).await;
        }

        let ready_primary =
            wait_for_usable_ip_with_backoff(&*self.probe, self.dhcp_cfg, shutdown).await;
        if shutdown.is_cancelled() {
            return false;
        }
        let primary = ready_primary.or_else(|| self.probe.query_primary_interface().ok());

        info!(
            component = "mesh_client.roaming_loop",
            event = "network_change_accepted",
            detail = ?event,
            resolved_if_index = ?primary.as_ref().map(|p| p.if_index),
            resolved_interface = ?primary.as_ref().map(|p| p.name.as_str()),
            "propagating resolved network/power transition to datapath and control loop"
        );

        let initial_cmds = map_net_event_with_primary(&event, primary.as_ref());
        let has_rebind = initial_cmds
            .iter()
            .any(|c| matches!(c, RebindCommand::RebindInterface { .. }));

        let dispatched = if has_rebind && self.rebind_feedback_rx.is_some() {
            self.dispatch_rebind_with_feedback(&event, primary, shutdown)
                .await
        } else {
            self.dispatch_non_blocking_commands(initial_cmds).await;
            true
        };
        if !dispatched {
            return false;
        }

        if let Err(err) = self.control_events_tx.try_send(event) {
            debug!(
                component = "mesh_client.roaming_loop",
                event = "control_roaming_queue_full",
                error = %err,
                "control roaming event channel full or closed"
            );
        }
        true
    }

    async fn dispatch_non_blocking_commands(&self, cmds: Vec<RebindCommand>) {
        for cmd in cmds {
            if let Err(err) = self.rebind_handle.try_send(cmd) {
                debug!(
                    component = "mesh_client.roaming_loop",
                    event = "rebind_queue_full",
                    error = %err,
                    "dropped duplicate RebindCommand on saturated queue"
                );
            }
        }
        tokio::task::yield_now().await;
    }

    async fn dispatch_rebind_with_feedback(
        &mut self,
        event: &NetEvent,
        mut primary: Option<PhysicalInterface>,
        shutdown: &CancellationToken,
    ) -> bool {
        let mut delay = self.rebind_retry_initial;
        loop {
            if shutdown.is_cancelled() {
                return false;
            }
            if let Some(ref mut rx) = self.rebind_feedback_rx {
                while rx.try_recv().is_ok() {}
            }
            let attempt_cmds = map_net_event_with_primary(event, primary.as_ref());
            let Some(rebind_cmd) = attempt_cmds
                .into_iter()
                .find(|c| matches!(c, RebindCommand::RebindInterface { .. }))
            else {
                break;
            };
            if !send_rebind_command(&self.rebind_handle, rebind_cmd, shutdown).await {
                return false;
            }
            let retry = match self.wait_rebind_confirmation(delay, shutdown).await {
                RebindFeedbackStep::Succeeded => break,
                RebindFeedbackStep::ChannelClosed => return false,
                RebindFeedbackStep::RetryAfterDelay => true,
            };
            if !retry {
                return false;
            }
            delay = (delay.saturating_mul(2)).min(self.rebind_retry_max);
            if let Ok(next_primary) = self.probe.query_primary_interface() {
                primary = Some(next_primary);
            }
        }

        for cmd in map_net_event_with_primary(event, primary.as_ref()) {
            if !matches!(cmd, RebindCommand::RebindInterface { .. })
                && let Err(err) = self.rebind_handle.try_send(cmd)
            {
                debug!(
                    component = "mesh_client.roaming_loop",
                    event = "rebind_queue_full",
                    error = %err,
                    "dropped trailing RebindCommand on saturated queue"
                );
            }
        }
        true
    }

    async fn wait_rebind_confirmation(
        &mut self,
        delay: Duration,
        shutdown: &CancellationToken,
    ) -> RebindFeedbackStep {
        let Some(ref mut rx) = self.rebind_feedback_rx else {
            return RebindFeedbackStep::Succeeded;
        };
        let feedback = tokio::select! {
            () = shutdown.cancelled() => return RebindFeedbackStep::ChannelClosed,
            res = tokio::time::timeout(REBIND_CONFIRM_TIMEOUT, rx.recv()) => res,
        };
        match feedback {
            Ok(Some(Ok(()))) => return RebindFeedbackStep::Succeeded,
            Ok(None) => return RebindFeedbackStep::ChannelClosed,
            Ok(Some(Err(err))) => {
                warn!(
                    component = "mesh_client.roaming_loop",
                    event = "rebind_failed_scheduling_retry",
                    error = %err,
                    backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(4_000),
                    "underlay rebind failed; retrying with backoff"
                );
            }
            Err(_) => {
                warn!(
                    component = "mesh_client.roaming_loop",
                    event = "rebind_confirmation_timeout_retrying",
                    backoff_ms = u64::try_from(delay.as_millis()).unwrap_or(4_000),
                    "timed out waiting for underlay rebind confirmation; retrying with backoff"
                );
            }
        }
        tokio::select! {
            () = shutdown.cancelled() => RebindFeedbackStep::ChannelClosed,
            () = tokio::time::sleep(delay) => RebindFeedbackStep::RetryAfterDelay,
        }
    }

    /// Applies 1s debouncing (bypassed on wake/clock jumps) synchronously for deterministic unit tests.
    pub fn handle_raw_event(&self, debouncer: &mut Debouncer, event: NetEvent) -> bool {
        if !debouncer.should_emit(self.clock.as_ref(), &event) {
            return false;
        }
        for cmd in map_net_event_to_rebind_commands(&event) {
            drop(self.rebind_handle.try_send(cmd));
        }
        drop(self.control_events_tx.try_send(event));
        true
    }
}

enum RebindFeedbackStep {
    Succeeded,
    RetryAfterDelay,
    ChannelClosed,
}

async fn send_rebind_command(
    handle: &RebindHandle,
    cmd: RebindCommand,
    shutdown: &CancellationToken,
) -> bool {
    let res = tokio::select! {
        () = shutdown.cancelled() => return false,
        res = handle.send(cmd) => res,
    };
    if let Err(err) = res {
        debug!(
            component = "mesh_client.roaming_loop",
            event = "rebind_channel_closed",
            error = %err,
            "rebind handle closed while dispatching rebind"
        );
        return false;
    }
    true
}

async fn mark_runtime_rebinding(runtime: &ClientRuntimeState, event: &NetEvent) {
    let mut g = runtime.inner.write().await;
    if !g.protocol_incompatible
        && !matches!(
            g.daemon_state,
            DaemonState::Stopped | DaemonState::Revoked | DaemonState::ReauthRequired
        )
    {
        g.daemon_state = DaemonState::Connecting;
        g.control_connected = false;
        g.last_error = Some(format!("rebinding: {event:?}"));
    }
}

async fn wait_until_cancelled(
    shutdown: &CancellationToken,
    clock_tick: &mut tokio::time::Interval,
    jump_detector: &mut ClockJumpDetector,
    debouncer: &mut Debouncer,
    roaming: &mut RoamingLoop,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = clock_tick.tick() => {
                if let Some(ev) = check_clock_jump(jump_detector, roaming.clock.as_ref()) {
                    roaming.handle_async_event(debouncer, ev, shutdown).await;
                }
            }
        }
    }
}

/// Maps a normalized [`NetEvent`] + resolved active [`PhysicalInterface`] into ordered
/// [`RebindCommand`]s (`RebindInterface` FIRST so OS socket binds new NIC BEFORE probes).
#[must_use]
pub fn map_net_event_with_primary(
    event: &NetEvent,
    primary: Option<&PhysicalInterface>,
) -> Vec<RebindCommand> {
    match primary {
        Some(iface) => {
            let allow_rebind = match event {
                NetEvent::InterfaceDown { interface } => interface != &iface.name,
                NetEvent::InterfaceUp { .. }
                | NetEvent::AddressChanged { .. }
                | NetEvent::RouteChanged
                | NetEvent::WakeFromSleep
                | NetEvent::ClockJumpDetected { .. } => true,
            };
            if allow_rebind {
                vec![
                    RebindCommand::RebindInterface {
                        interface_name: iface.name.clone(),
                        if_index: Some(iface.if_index),
                        is_ipv6: false,
                    },
                    RebindCommand::RefreshCandidates,
                    RebindCommand::WakeRelay,
                ]
            } else {
                vec![RebindCommand::RefreshCandidates, RebindCommand::WakeRelay]
            }
        }
        None => map_net_event_to_rebind_commands(event),
    }
}

/// Maps a normalized [`NetEvent`] into non-blocking [`RebindCommand`]s preserving `local_udp_port`.
#[must_use]
pub fn map_net_event_to_rebind_commands(event: &NetEvent) -> Vec<RebindCommand> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use mesh_core::clock::FakeClock;
    use mesh_datapath::{RebindCommand, RebindHandle};
    use mesh_net::netmon::{Debouncer, FakeNetMonitor, NetEvent};

    use super::{NETWORK_CHANGE_CHANNEL_CAPACITY, RoamingLoop};

    #[test]
    fn test_roaming_debounces_burst_but_bypasses_on_wake_from_sleep() {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_000));
        let monitor = Arc::new(FakeNetMonitor::new());
        let (rebind_handle, _rx) = RebindHandle::channel();
        let (tx, mut rx) = mpsc::channel(NETWORK_CHANGE_CHANNEL_CAPACITY);
        let roaming = RoamingLoop::new(monitor, Arc::clone(&clock) as Arc<_>, rebind_handle, tx);
        let mut debouncer = Debouncer::standard();

        // Act
        let first = roaming.handle_raw_event(
            &mut debouncer,
            NetEvent::InterfaceUp {
                interface: "wlan0".to_owned(),
            },
        );
        clock.advance(200);
        let burst = roaming.handle_raw_event(&mut debouncer, NetEvent::RouteChanged);
        let wake = roaming.handle_raw_event(&mut debouncer, NetEvent::WakeFromSleep);

        // Assert
        assert!(first);
        assert!(!burst);
        assert!(wake);
        assert!(matches!(rx.try_recv(), Ok(NetEvent::InterfaceUp { .. })));
        assert!(matches!(rx.try_recv(), Ok(NetEvent::WakeFromSleep)));
    }

    #[tokio::test]
    async fn test_roaming_loop_resolves_physical_if_index_and_waits_for_dhcp_lease() {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let monitor = Arc::new(FakeNetMonitor::new());
        let eth = mesh_net::netmon::PhysicalInterface {
            if_index: 14,
            name: "Ethernet".to_owned(),
        };
        let probe = Arc::new(mesh_net::netmon::FakePhysicalNetworkProbe::default());
        probe.push_observation(
            Ok(eth.clone()),
            Ok(vec![mesh_net::InterfaceSubnetSnapshot {
                if_index: 14,
                interface_name: "Ethernet".to_owned(),
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 1, 2)),
                prefix_len: 16,
                is_up: true,
                is_virtual: false,
                has_gateway: false,
            }]),
        );
        probe.push_observation(
            Ok(eth),
            Ok(vec![mesh_net::InterfaceSubnetSnapshot {
                if_index: 14,
                interface_name: "Ethernet".to_owned(),
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 50, 12)),
                prefix_len: 24,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            }]),
        );

        let (rebind_handle, mut rebind_rx) = RebindHandle::channel();
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(16);
        let roaming = RoamingLoop::new(
            Arc::clone(&monitor) as Arc<dyn mesh_net::netmon::NetMonitor>,
            Arc::clone(&clock) as Arc<dyn mesh_core::clock::Clock>,
            rebind_handle,
            ctrl_tx,
        )
        .with_probe(probe)
        .with_dhcp_config(mesh_net::netmon::DhcpWaitConfig {
            initial_delay_ms: 5,
            max_delay_ms: 10,
            max_wait_ms: 500,
        });

        let shutdown = CancellationToken::new();
        let task_handle = tokio::spawn(roaming.run(shutdown.clone()));

        // Act
        monitor.push_event(NetEvent::WakeFromSleep).await;

        // Assert
        let cmd1 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv()).await;
        let cmd2 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv()).await;
        let cmd3 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv()).await;
        let ctrl_ev = tokio::time::timeout(Duration::from_secs(1), ctrl_rx.recv()).await;
        shutdown.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task_handle)
                .await
                .is_ok()
        );

        assert_eq!(
            cmd1.ok().flatten(),
            Some(RebindCommand::RebindInterface {
                interface_name: "Ethernet".to_owned(),
                if_index: Some(14),
                is_ipv6: false,
            })
        );
        assert_eq!(cmd2.ok().flatten(), Some(RebindCommand::RefreshCandidates));
        assert_eq!(cmd3.ok().flatten(), Some(RebindCommand::WakeRelay));
        assert_eq!(ctrl_ev.ok().flatten(), Some(NetEvent::WakeFromSleep));
    }

    #[tokio::test]
    async fn test_roaming_loop_retries_rebind_on_error_before_waking_control() {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let monitor = Arc::new(FakeNetMonitor::new());
        let eth = mesh_net::netmon::PhysicalInterface {
            if_index: 22,
            name: "wlan0".to_owned(),
        };
        let probe = Arc::new(mesh_net::netmon::FakePhysicalNetworkProbe::default());
        probe.push_observation(
            Ok(eth),
            Ok(vec![mesh_net::InterfaceSubnetSnapshot {
                if_index: 22,
                interface_name: "wlan0".to_owned(),
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 20)),
                prefix_len: 24,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            }]),
        );

        let (rebind_handle, mut rebind_rx) = RebindHandle::channel();
        let (feedback_tx, feedback_rx) = mpsc::channel(8);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(16);
        let roaming = RoamingLoop::new(
            Arc::clone(&monitor) as Arc<dyn mesh_net::netmon::NetMonitor>,
            Arc::clone(&clock) as Arc<dyn mesh_core::clock::Clock>,
            rebind_handle,
            ctrl_tx,
        )
        .with_probe(probe)
        .with_dhcp_config(mesh_net::netmon::DhcpWaitConfig {
            initial_delay_ms: 5,
            max_delay_ms: 10,
            max_wait_ms: 100,
        })
        .with_rebind_feedback(feedback_rx)
        .with_rebind_retry_window(Duration::from_millis(20), Duration::from_millis(60));

        let shutdown = CancellationToken::new();
        let task = tokio::spawn(roaming.run(shutdown.clone()));

        // Act
        monitor
            .push_event(NetEvent::AddressChanged {
                interface: "wlan0".to_owned(),
            })
            .await;

        let attempt1 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv())
            .await
            .expect("attempt1 timeout");
        assert!(matches!(
            attempt1,
            Some(RebindCommand::RebindInterface {
                if_index: Some(22),
                ..
            })
        ));
        feedback_tx
            .send(Err(mesh_core::AppError::unavailable("transient ENODEV")))
            .await
            .expect("send err feedback");

        let premature_ctrl = tokio::time::timeout(Duration::from_millis(15), ctrl_rx.recv()).await;
        assert!(
            premature_ctrl.is_err(),
            "ControlLoop MUST NOT receive roaming event while rebind is failing"
        );

        let attempt2 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv())
            .await
            .expect("attempt2 timeout");
        assert!(matches!(
            attempt2,
            Some(RebindCommand::RebindInterface {
                if_index: Some(22),
                ..
            })
        ));
        feedback_tx.send(Ok(())).await.expect("send ok feedback");

        let ctrl_after_ok = tokio::time::timeout(Duration::from_secs(1), ctrl_rx.recv())
            .await
            .expect("control event after rebind ok");
        assert!(matches!(
            ctrl_after_ok,
            Some(NetEvent::AddressChanged { .. })
        ));
        let trailing1 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv())
            .await
            .expect("trailing cmd1");
        let trailing2 = tokio::time::timeout(Duration::from_secs(1), rebind_rx.recv())
            .await
            .expect("trailing cmd2");
        assert_eq!(trailing1, Some(RebindCommand::RefreshCandidates));
        assert_eq!(trailing2, Some(RebindCommand::WakeRelay));

        shutdown.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_ok()
        );
    }
}
