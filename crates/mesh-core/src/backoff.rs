//! Exponential backoff with OS-CSPRNG full jitter (`US-034`).

use std::time::Duration;

use rand::rngs::OsRng;

use crate::defaults::{BACKOFF_INITIAL_MS, BACKOFF_NETWORK_MAX_MS, BACKOFF_TLS_MAX_MS};

/// Configuration parameters for [`ExponentialBackoff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Initial ceiling delay in milliseconds.
    pub initial_ms: u64,
    /// Maximum delay ceiling in milliseconds.
    pub max_ms: u64,
    /// Exponential growth factor per consecutive failed attempt.
    pub factor: u32,
}

impl BackoffConfig {
    /// Default retry policy for transient network / transport failures (cap `60 s`).
    #[must_use]
    pub const fn network() -> Self {
        Self {
            initial_ms: BACKOFF_INITIAL_MS,
            max_ms: BACKOFF_NETWORK_MAX_MS,
            factor: 2,
        }
    }

    /// Slower retry ceiling for TLS / Captive Portal / `ClockSkew` / `PinMismatch` (`5 min`).
    #[must_use]
    pub const fn tls_or_security() -> Self {
        Self {
            initial_ms: 1_000,
            max_ms: BACKOFF_TLS_MAX_MS,
            factor: 2,
        }
    }
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self::network()
    }
}

/// Stateful exponential backoff generator applying full jitter per AWS backoff best practices.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    config: BackoffConfig,
    attempt: u32,
}

impl ExponentialBackoff {
    /// Constructs a new backoff state starting at attempt `0`.
    #[must_use]
    pub const fn new(config: BackoffConfig) -> Self {
        Self { config, attempt: 0 }
    }

    /// Computes the next jittered sleep duration using `OsRng` and advances the attempt counter.
    #[must_use]
    pub fn next_delay(&mut self) -> Duration {
        let mut rng = OsRng;
        self.next_delay_with_rng(&mut rng)
    }

    /// Computes the next jittered sleep duration using an explicit PRNG for deterministic tests.
    pub fn next_delay_with_rng<R: rand::Rng>(&mut self, rng: &mut R) -> Duration {
        let ceiling = self.current_ceiling_ms();
        let sampled_ms = if ceiling == 0 {
            0
        } else {
            rng.gen_range(0..=ceiling)
        };
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(sampled_ms)
    }

    /// Returns the unjittered ceiling in milliseconds for the current attempt count.
    #[must_use]
    pub fn current_ceiling_ms(&self) -> u64 {
        let factor = u64::from(self.config.factor.max(1));
        let multiplier = factor.saturating_pow(self.attempt);
        let scaled = self.config.initial_ms.saturating_mul(multiplier);
        scaled.min(self.config.max_ms)
    }

    /// Resets attempt counter back to `0` upon successful connection or network-change event.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Returns the number of consecutive retries already issued since last reset.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::{BackoffConfig, ExponentialBackoff};

    #[test]
    fn test_backoff_caps_and_resets_correctly() {
        // Arrange
        let mut net = ExponentialBackoff::new(BackoffConfig::network());
        let mut tls = ExponentialBackoff::new(BackoffConfig::tls_or_security());
        let mut rng = StdRng::seed_from_u64(42);

        // Act
        for _ in 0..16 {
            let d_net = net.next_delay_with_rng(&mut rng);
            let d_tls = tls.next_delay_with_rng(&mut rng);
            assert!(d_net.as_millis() <= 60_000);
            assert!(d_tls.as_millis() <= 300_000);
        }

        // Assert
        assert_eq!(net.current_ceiling_ms(), 60_000);
        assert_eq!(tls.current_ceiling_ms(), 300_000);
        net.reset();
        assert_eq!(net.attempts(), 0);
        assert_eq!(
            net.current_ceiling_ms(),
            BackoffConfig::network().initial_ms
        );
    }
}
