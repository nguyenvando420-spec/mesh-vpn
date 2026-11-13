//! OS network change monitoring, 1-second event debouncer, and clock-jump integration (`US-035`).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use mesh_core::clock::{Clock, ClockJumpDetector};
use mesh_core::{AppError, AppResult};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::endpoint_filter::{
    InterfaceSubnetSnapshot, is_usable_dhcp_ip, is_virtual_interface_name,
};
use crate::tun::BoxFuture;

/// Default roaming / route-flap debounce interval in milliseconds (`1 s`).
pub const DEFAULT_NETMON_DEBOUNCE_MS: u64 = 1_000;

/// Initial backoff waiting for DHCP IP readiness on a newly active physical link (`US-036 AC4`).
pub const DEFAULT_DHCP_INITIAL_DELAY_MS: u64 = 500;
/// Maximum retry interval while waiting for DHCP lease acquisition (`US-036 AC4`).
pub const DEFAULT_DHCP_MAX_DELAY_MS: u64 = 8_000;
/// Total deadline waiting for DHCP readiness after link up (`60 s`, `US-036 AC4`).
pub const DEFAULT_DHCP_WAIT_TIMEOUT_MS: u64 = 60_000;

/// Active primary physical OS network interface resolved for underlay binding (`US-035`, `US-036`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalInterface {
    /// Numeric OS interface index (`if_nametoindex` / Windows `IfIndex`).
    pub if_index: u32,
    /// Human-readable OS adapter name (`en0`, `eth0`, `Wi-Fi`, `Ethernet`).
    pub name: String,
}

/// Configuration for capped non-blocking DHCP IP readiness retries (`US-036 AC4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpWaitConfig {
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub max_wait_ms: u64,
}

impl Default for DhcpWaitConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: DEFAULT_DHCP_INITIAL_DELAY_MS,
            max_delay_ms: DEFAULT_DHCP_MAX_DELAY_MS,
            max_wait_ms: DEFAULT_DHCP_WAIT_TIMEOUT_MS,
        }
    }
}

/// Normalized OS network and power transition events delivered to `meshd::roaming_loop`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    /// Physical interface transitioned up.
    InterfaceUp {
        /// Adapter name (`en0`, `eth0`, `Ethernet`).
        interface: String,
    },
    /// Physical interface transitioned down.
    InterfaceDown {
        /// Adapter name.
        interface: String,
    },
    /// Local IPv4/IPv6 address changed on an interface.
    AddressChanged {
        /// Adapter name.
        interface: String,
    },
    /// Default underlay gateway or OS route table changed.
    RouteChanged,
    /// Host resumed from sleep/hibernate (`US-035`).
    WakeFromSleep,
    /// Monotonic vs wall clock jumped more than threshold (`US-035 AC3`).
    ClockJumpDetected {
        /// Signed wall-vs-monotonic drift (`delta_wall - delta_mono`) in milliseconds.
        drift_ms: i64,
    },
}

/// Canonical alias for [`NetEvent`] matching `system-architecture.md` terminology (`IMP-01`).
pub type NetworkChangeEvent = NetEvent;

/// Coalesces noisy bursts of route/interface changes within a fixed debounce window (`1 s`).
#[derive(Debug, Clone)]
pub struct Debouncer {
    window_ms: u64,
    last_emitted_monotonic_ms: Option<u64>,
}

impl Debouncer {
    /// Creates a new [`Debouncer`] with window `window_ms`.
    #[must_use]
    pub const fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            last_emitted_monotonic_ms: None,
        }
    }

    /// Creates a [`Debouncer`] with the standard 1-second window.
    #[must_use]
    pub const fn standard() -> Self {
        Self::new(DEFAULT_NETMON_DEBOUNCE_MS)
    }

    /// Returns `true` if an event at `monotonic_now_ms` should propagate upstream.
    ///
    /// Urgent power/clock recovery events (`WakeFromSleep`, `ClockJumpDetected`) always emit
    /// immediately and advance the baseline timestamp.
    pub fn should_emit(&mut self, clock: &dyn Clock, event: &NetEvent) -> bool {
        let now_ms = clock.monotonic_ms();
        let urgent = matches!(
            event,
            NetEvent::WakeFromSleep | NetEvent::ClockJumpDetected { .. }
        );
        if urgent {
            self.last_emitted_monotonic_ms = Some(now_ms);
            return true;
        }
        match self.last_emitted_monotonic_ms {
            None => {
                self.last_emitted_monotonic_ms = Some(now_ms);
                true
            }
            Some(prev) => {
                if now_ms.saturating_sub(prev) >= self.window_ms {
                    self.last_emitted_monotonic_ms = Some(now_ms);
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// Evaluates [`ClockJumpDetector`] and translates jumps into a [`NetEvent`].
pub fn check_clock_jump(detector: &mut ClockJumpDetector, clock: &dyn Clock) -> Option<NetEvent> {
    detector.check(clock).map(|ev| NetEvent::ClockJumpDetected {
        drift_ms: ev.drift_ms,
    })
}

/// OS network change monitor trait implemented by Linux Netlink, macOS PF_ROUTE, Windows IP Helper,
/// and [`FakeNetMonitor`].
pub trait NetMonitor: Send + Sync + std::fmt::Debug {
    /// Waits asynchronously for the next OS network/power change event.
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>>;
}

/// In-memory fake [`NetMonitor`] enabling deterministic roaming & sleep/wake unit tests.
#[derive(Debug, Clone, Default)]
pub struct FakeNetMonitor {
    events: Arc<Mutex<VecDeque<NetEvent>>>,
    notify: Arc<Notify>,
}

impl FakeNetMonitor {
    /// Creates an empty fake monitor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueues a synthetic network event and wakes waiting consumers.
    pub async fn push_event(&self, event: NetEvent) {
        let mut guard = self.events.lock().await;
        guard.push_back(event);
        drop(guard);
        self.notify.notify_one();
    }
}

impl NetMonitor for FakeNetMonitor {
    fn next_event(&self) -> BoxFuture<'_, AppResult<NetEvent>> {
        Box::pin(async move {
            loop {
                {
                    let mut guard = self.events.lock().await;
                    if let Some(ev) = guard.pop_front() {
                        return Ok(ev);
                    }
                }
                self.notify.notified().await;
            }
        })
    }
}

/// Helper returning an explicit unavailable error for non-initialized OS monitor stubs.
pub fn netmon_unavailable(platform: &str) -> AppError {
    AppError::unavailable(format!("{platform} netmon backend is not started"))
}

/// Abstraction over OS physical interface and subnet inspection for roaming and CGNAT conflict
/// detection (`US-035`, `US-036`, `US-037`).
pub trait PhysicalNetworkProbe: Send + Sync + std::fmt::Debug {
    /// Returns the active primary physical OS interface `(if_index, name)`.
    fn query_primary_interface(&self) -> AppResult<PhysicalInterface>;

    /// Lists current host interface unicast addresses and CIDR prefix lengths.
    fn list_interface_subnets(&self) -> AppResult<Vec<InterfaceSubnetSnapshot>>;
}

/// Live OS implementation of [`PhysicalNetworkProbe`].
#[derive(Debug, Clone, Copy, Default)]
pub struct OsPhysicalNetworkProbe;

impl PhysicalNetworkProbe for OsPhysicalNetworkProbe {
    fn query_primary_interface(&self) -> AppResult<PhysicalInterface> {
        query_os_primary_physical_interface()
    }

    fn list_interface_subnets(&self) -> AppResult<Vec<InterfaceSubnetSnapshot>> {
        list_os_interface_subnets()
    }
}

/// Queries the current OS primary physical interface `(if_index, name)`.
pub fn query_os_primary_physical_interface() -> AppResult<PhysicalInterface> {
    #[cfg(target_os = "linux")]
    {
        crate::netmon_linux::query_primary_physical_interface()
    }
    #[cfg(target_os = "macos")]
    {
        crate::netmon_macos::query_primary_physical_interface()
    }
    #[cfg(target_os = "windows")]
    {
        crate::netmon_windows::query_primary_physical_interface()
    }
}

/// Lists all current OS interface addresses and CIDR prefixes (`US-036`, `US-037`).
pub fn list_os_interface_subnets() -> AppResult<Vec<InterfaceSubnetSnapshot>> {
    #[cfg(target_os = "linux")]
    {
        crate::netmon_linux::list_interface_subnets()
    }
    #[cfg(target_os = "macos")]
    {
        crate::netmon_macos::list_interface_subnets()
    }
    #[cfg(target_os = "windows")]
    {
        crate::netmon_windows::list_interface_subnets()
    }
}

#[derive(Debug, Default)]
struct FakeProbeState {
    primary_seq: VecDeque<AppResult<PhysicalInterface>>,
    subnets_seq: VecDeque<AppResult<Vec<InterfaceSubnetSnapshot>>>,
    last_primary: Option<PhysicalInterface>,
    last_subnets: Vec<InterfaceSubnetSnapshot>,
}

/// Scripted deterministic [`PhysicalNetworkProbe`] for roaming, DHCP-wait, and CGNAT tests.
#[derive(Debug, Default)]
pub struct FakePhysicalNetworkProbe {
    state: StdMutex<FakeProbeState>,
}

impl FakePhysicalNetworkProbe {
    /// Creates a fake probe seeded with an active interface and its subnet list.
    #[must_use]
    pub fn with_snapshot(
        primary: PhysicalInterface,
        subnets: Vec<InterfaceSubnetSnapshot>,
    ) -> Self {
        Self {
            state: StdMutex::new(FakeProbeState {
                primary_seq: VecDeque::new(),
                subnets_seq: VecDeque::new(),
                last_primary: Some(primary),
                last_subnets: subnets,
            }),
        }
    }

    /// Queues the next `(primary, subnets)` poll observation (returned once in FIFO order, then
    /// sticks as the latest steady-state snapshot).
    pub fn push_observation(
        &self,
        primary: AppResult<PhysicalInterface>,
        subnets: AppResult<Vec<InterfaceSubnetSnapshot>>,
    ) {
        if let Ok(mut g) = self.state.lock() {
            g.primary_seq.push_back(primary);
            g.subnets_seq.push_back(subnets);
        }
    }
}

impl PhysicalNetworkProbe for FakePhysicalNetworkProbe {
    fn query_primary_interface(&self) -> AppResult<PhysicalInterface> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| AppError::internal("FakePhysicalNetworkProbe mutex poisoned"))?;
        if let Some(next) = g.primary_seq.pop_front() {
            if let Ok(ref ok) = next {
                g.last_primary = Some(ok.clone());
            }
            return next;
        }
        g.last_primary
            .clone()
            .ok_or_else(|| AppError::unavailable("no primary physical interface scripted"))
    }

    fn list_interface_subnets(&self) -> AppResult<Vec<InterfaceSubnetSnapshot>> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| AppError::internal("FakePhysicalNetworkProbe mutex poisoned"))?;
        if let Some(next) = g.subnets_seq.pop_front() {
            if let Ok(ref ok) = next {
                g.last_subnets = ok.clone();
            }
            return next;
        }
        Ok(g.last_subnets.clone())
    }
}

/// Returns `true` if `subnets` contains an active non-virtual address on `if_index` that is
/// routable (not APIPA `169.254.0.0/16` or link-local) (`US-036 AC4`).
#[must_use]
pub fn has_usable_ip_on_interface(subnets: &[InterfaceSubnetSnapshot], if_index: u32) -> bool {
    subnets.iter().any(|s| {
        s.is_up
            && !s.is_virtual
            && !is_virtual_interface_name(&s.interface_name)
            && s.if_index == if_index
            && is_usable_dhcp_ip(s.ip)
    })
}

/// Inspects `probe` once and returns the primary physical interface if it already holds a usable
/// DHCP/static IP (or if `list_interface_subnets` is unavailable, trusts the active primary NIC).
#[must_use]
pub fn probe_ready_primary_interface(
    probe: &dyn PhysicalNetworkProbe,
) -> Option<PhysicalInterface> {
    let primary = probe.query_primary_interface().ok()?;
    match probe.list_interface_subnets() {
        Ok(subnets) => {
            if has_usable_ip_on_interface(&subnets, primary.if_index) {
                Some(primary)
            } else {
                None
            }
        }
        Err(_) => Some(primary),
    }
}

/// Waits for a usable physical uplink + DHCP address using light capped exponential backoff
/// (`0.5 s -> 8 s`, total max `60 s`) (`US-036 AC4`, `US-035 AC1`).
///
/// Immediately returns without sleeping when the primary physical NIC already has a routable IP.
/// Returns `None` if `shutdown` cancels or `max_wait_ms` elapses before a usable lease arrives.
pub async fn wait_for_usable_ip_with_backoff(
    probe: &dyn PhysicalNetworkProbe,
    cfg: DhcpWaitConfig,
    shutdown: &CancellationToken,
) -> Option<PhysicalInterface> {
    if let Some(ready) = probe_ready_primary_interface(probe) {
        return Some(ready);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_millis(cfg.max_wait_ms);
    let mut delay_ms = cfg.initial_delay_ms.max(1);
    let max_delay_ms = cfg.max_delay_ms.max(delay_ms);

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline || shutdown.is_cancelled() {
            return None;
        }
        let remaining = deadline.saturating_duration_since(now);
        let sleep_dur = Duration::from_millis(delay_ms).min(remaining);

        tokio::select! {
            () = shutdown.cancelled() => return None,
            () = tokio::time::sleep(sleep_dur) => {}
        }

        if let Some(ready) = probe_ready_primary_interface(probe) {
            return Some(ready);
        }
        delay_ms = delay_ms.saturating_mul(2).min(max_delay_ms);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use mesh_core::clock::{ClockJumpDetector, FakeClock};
    use tokio_util::sync::CancellationToken;

    use super::{
        Debouncer, DhcpWaitConfig, FakeNetMonitor, FakePhysicalNetworkProbe, NetEvent, NetMonitor,
        PhysicalInterface, check_clock_jump, wait_for_usable_ip_with_backoff,
    };
    use crate::endpoint_filter::InterfaceSubnetSnapshot;

    #[tokio::test]
    async fn test_netmon_debouncer_clock_jump_and_fake_delivery() {
        // Arrange
        let clock = Arc::new(FakeClock::new(1_700_000_000_000));
        let mut debouncer = Debouncer::standard();
        let mut jump_detector = ClockJumpDetector::new(clock.as_ref());
        let monitor = FakeNetMonitor::new();

        // Act: rapid address changes inside 1000 ms window are debounced
        assert!(debouncer.should_emit(
            clock.as_ref(),
            &NetEvent::AddressChanged {
                interface: "en0".to_owned(),
            }
        ));
        clock.advance(400);
        assert!(!debouncer.should_emit(clock.as_ref(), &NetEvent::RouteChanged));

        // Urgent wake bypasses debounce
        clock.advance(100);
        assert!(debouncer.should_emit(clock.as_ref(), &NetEvent::WakeFromSleep));

        // After 1000 ms non-urgent emits again
        clock.advance(1_000);
        assert!(debouncer.should_emit(clock.as_ref(), &NetEvent::RouteChanged));

        // Clock jump (> 30s wall jump without monotonic jump)
        clock.jump_wall_ms(60_000);
        let jump_ev = check_clock_jump(&mut jump_detector, clock.as_ref());
        assert!(matches!(jump_ev, Some(NetEvent::ClockJumpDetected { .. })));

        // Async fake monitor push + receive
        monitor.push_event(NetEvent::WakeFromSleep).await;
        let received = monitor.next_event().await;
        assert!(matches!(received, Ok(NetEvent::WakeFromSleep)));
    }

    #[tokio::test]
    async fn test_netmon_dhcp_wait_retries_past_apipa_until_lease_ready() {
        // Traces: US-036 AC4
        // Arrange: interface transitions: unreachable -> APIPA 169.254.x.x -> usable 192.168.43.10
        let eth = PhysicalInterface {
            if_index: 7,
            name: "Wi-Fi".to_owned(),
        };
        let probe = FakePhysicalNetworkProbe::default();
        probe.push_observation(
            Err(mesh_core::AppError::unavailable("link settling")),
            Ok(Vec::new()),
        );
        probe.push_observation(
            Ok(eth.clone()),
            Ok(vec![InterfaceSubnetSnapshot {
                if_index: 7,
                interface_name: "Wi-Fi".to_owned(),
                ip: IpAddr::V4(Ipv4Addr::new(169, 254, 12, 34)),
                prefix_len: 16,
                is_up: true,
                is_virtual: false,
                has_gateway: false,
            }]),
        );
        probe.push_observation(
            Ok(eth.clone()),
            Ok(vec![InterfaceSubnetSnapshot {
                if_index: 7,
                interface_name: "Wi-Fi".to_owned(),
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 43, 10)),
                prefix_len: 24,
                is_up: true,
                is_virtual: false,
                has_gateway: true,
            }]),
        );
        let cancel = CancellationToken::new();
        let cfg = DhcpWaitConfig {
            initial_delay_ms: 5,
            max_delay_ms: 20,
            max_wait_ms: 500,
        };

        // Act
        let ready = wait_for_usable_ip_with_backoff(&probe, cfg, &cancel).await;

        // Assert
        assert_eq!(ready, Some(eth));
    }
}
