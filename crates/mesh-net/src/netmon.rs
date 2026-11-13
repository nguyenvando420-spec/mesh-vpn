//! OS network change monitoring, 1-second event debouncer, and clock-jump integration (`US-035`).

use std::collections::VecDeque;
use std::sync::Arc;

use mesh_core::clock::{Clock, ClockJumpDetector};
use mesh_core::{AppError, AppResult};
use tokio::sync::{Mutex, Notify};

use crate::tun::BoxFuture;

/// Default roaming / route-flap debounce interval in milliseconds (`1 s`).
pub const DEFAULT_NETMON_DEBOUNCE_MS: u64 = 1_000;

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mesh_core::clock::{ClockJumpDetector, FakeClock};

    use super::{Debouncer, FakeNetMonitor, NetEvent, NetMonitor, check_clock_jump};

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
}
