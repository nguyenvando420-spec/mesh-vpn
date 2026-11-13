//! Injectable wall and monotonic clock abstractions plus clock-jump detection (`US-035`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::defaults::CLOCK_JUMP_THRESHOLD_MS;

/// Abstract time provider allowing deterministic fake time in tests.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Returns current UTC Unix timestamp in milliseconds.
    fn now_unix_ms(&self) -> u64;

    /// Returns monotonically non-decreasing elapsed time in milliseconds.
    fn monotonic_ms(&self) -> u64;

    /// Returns current UTC Unix timestamp truncated to whole seconds.
    fn now_unix_secs(&self) -> u64 {
        self.now_unix_ms() / 1_000
    }
}

/// Real OS wall-clock and monotonic-clock implementation.
#[derive(Debug, Clone)]
pub struct SystemClock {
    mono_epoch: Instant,
}

impl SystemClock {
    /// Creates a new [`SystemClock`] anchored at `Instant::now()`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mono_epoch: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.mono_epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Deterministic lock-free clock for testing expiry, sleep wakeups, and backward/forward jumps.
#[derive(Debug)]
pub struct FakeClock {
    wall_ms: AtomicU64,
    mono_ms: AtomicU64,
}

impl FakeClock {
    /// Creates a [`FakeClock`] initialized at `initial_unix_ms` and `0` monotonic ms.
    #[must_use]
    pub const fn new(initial_unix_ms: u64) -> Self {
        Self {
            wall_ms: AtomicU64::new(initial_unix_ms),
            mono_ms: AtomicU64::new(0),
        }
    }

    /// Advances both wall clock and monotonic clock together by `delta_ms`.
    pub fn advance(&self, delta_ms: u64) {
        self.wall_ms.fetch_add(delta_ms, Ordering::SeqCst);
        self.mono_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }

    /// Sets the wall-clock UTC timestamp independently of monotonic elapsed time.
    pub fn set_wall_ms(&self, new_unix_ms: u64) {
        self.wall_ms.store(new_unix_ms, Ordering::SeqCst);
    }

    /// Shifts the wall clock by signed `delta_ms` without altering monotonic time.
    pub fn jump_wall_ms(&self, delta_ms: i64) {
        let current = self.wall_ms.load(Ordering::SeqCst);
        let updated = if delta_ms >= 0 {
            current.saturating_add(delta_ms.unsigned_abs())
        } else {
            current.saturating_sub(delta_ms.unsigned_abs())
        };
        self.wall_ms.store(updated, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_unix_ms(&self) -> u64 {
        self.wall_ms.load(Ordering::SeqCst)
    }

    fn monotonic_ms(&self) -> u64 {
        self.mono_ms.load(Ordering::SeqCst)
    }
}

/// Recorded wall-vs-monotonic discrepancy exceeding the clock-jump threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockJumpEvent {
    /// Observed wall-clock timestamp when the jump was detected.
    pub wall_ms: u64,
    /// Observed monotonic timestamp when the jump was detected.
    pub mono_ms: u64,
    /// Signed drift (`delta_wall - delta_mono`) in milliseconds.
    pub drift_ms: i64,
}

/// Detects sudden wall-clock steps (e.g. VM suspend/resume, NTP correction, manual time edit).
#[derive(Debug, Clone)]
pub struct ClockJumpDetector {
    last_wall_ms: u64,
    last_mono_ms: u64,
    threshold_ms: i64,
}

impl ClockJumpDetector {
    /// Initializes the detector using the current reading of `clock`.
    #[must_use]
    pub fn new(clock: &dyn Clock) -> Self {
        Self::with_threshold(clock, CLOCK_JUMP_THRESHOLD_MS)
    }

    /// Initializes the detector with a custom discrepancy threshold in milliseconds.
    #[must_use]
    pub fn with_threshold(clock: &dyn Clock, threshold_ms: i64) -> Self {
        Self {
            last_wall_ms: clock.now_unix_ms(),
            last_mono_ms: clock.monotonic_ms(),
            threshold_ms: threshold_ms.abs(),
        }
    }

    /// Samples `clock` and returns `Some(ClockJumpEvent)` if `|Δwall - Δmono| > threshold_ms`.
    pub fn check(&mut self, clock: &dyn Clock) -> Option<ClockJumpEvent> {
        let now_wall = clock.now_unix_ms();
        let now_mono = clock.monotonic_ms();

        let delta_wall = i128::from(now_wall) - i128::from(self.last_wall_ms);
        let delta_mono = i128::from(now_mono) - i128::from(self.last_mono_ms);
        let drift = delta_wall - delta_mono;

        self.last_wall_ms = now_wall;
        self.last_mono_ms = now_mono;

        if drift.abs() > i128::from(self.threshold_ms) {
            let drift_ms = i64::try_from(drift).unwrap_or_else(|_| {
                if drift.is_negative() {
                    i64::MIN
                } else {
                    i64::MAX
                }
            });
            Some(ClockJumpEvent {
                wall_ms: now_wall,
                mono_ms: now_mono,
                drift_ms,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock as _, ClockJumpDetector, FakeClock};

    #[test]
    fn test_clock_jump_detector_detects_forward_and_backward_steps() {
        // Arrange
        let clock = FakeClock::new(1_731_480_000_000);
        let mut detector = ClockJumpDetector::new(&clock);

        // Act: normal progression does not trigger
        clock.advance(5_000);
        let normal = detector.check(&clock);

        // Act: sudden forward jump by 45s (> 30s threshold)
        clock.jump_wall_ms(45_000);
        let forward = detector.check(&clock);

        // Act: sudden backward jump by 60s
        clock.jump_wall_ms(-60_000);
        let backward = detector.check(&clock);

        // Assert
        assert!(normal.is_none());
        assert_eq!(forward.map(|e| e.drift_ms), Some(45_000));
        assert_eq!(backward.map(|e| e.drift_ms), Some(-60_000));
        assert_eq!(
            clock.now_unix_secs(),
            (1_731_480_000_000 + 5_000 + 45_000 - 60_000) / 1_000
        );
    }
}
