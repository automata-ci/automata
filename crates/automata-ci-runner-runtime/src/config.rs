use std::{num::NonZeroU16, time::Duration};

use automata_ci_core::RunnerCapabilities;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_runner_journal::clamp_registration_slots;
use thiserror::Error;

/// Maximum exponential-backoff ramp length for one immutable prepared request.
const MAX_EXCHANGE_ATTEMPTS: u16 = 64;
/// Largest individual retry delay accepted by the runtime.
const MAX_RETRY_DELAY: Duration = Duration::from_mins(5);
/// Largest server-directed idle delay accepted by the runtime.
const MAX_IDLE_DELAY: Duration = Duration::from_mins(5);
/// Largest cancellation grace period accepted by the runtime.
const MAX_CANCELLATION_GRACE: Duration = Duration::from_mins(10);

/// Bounded-backoff policy for one immutable prepared request.
///
/// A retryable transport outcome never causes the runtime to discard an
/// uncertain request. `maximum_attempts` bounds the exponential ramp; retries
/// after that point remain at the configured delay ceiling until the request
/// succeeds, receives a definitive response, or is cancelled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    maximum_attempts: NonZeroU16,
    initial_delay: Duration,
    maximum_delay: Duration,
}

impl RetryPolicy {
    /// Validates an exponential retry policy.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerRuntimeConfigError`] for zero/oversized attempts,
    /// zero delays, inverted delays, or delays above the hard ceiling.
    pub fn new(
        maximum_attempts: u16,
        initial_delay: Duration,
        maximum_delay: Duration,
    ) -> Result<Self, RunnerRuntimeConfigError> {
        let maximum_attempts = NonZeroU16::new(maximum_attempts)
            .filter(|value| value.get() <= MAX_EXCHANGE_ATTEMPTS)
            .ok_or(RunnerRuntimeConfigError::InvalidRetryAttempts)?;
        if initial_delay.is_zero()
            || maximum_delay.is_zero()
            || initial_delay > maximum_delay
            || maximum_delay > MAX_RETRY_DELAY
        {
            return Err(RunnerRuntimeConfigError::InvalidRetryDelay);
        }
        Ok(Self {
            maximum_attempts,
            initial_delay,
            maximum_delay,
        })
    }

    /// Returns the number of failures over which exponential backoff ramps.
    ///
    /// The request may be submitted more times during a prolonged outage. Its
    /// immutable operation identity and canonical bytes remain unchanged.
    #[must_use]
    pub const fn maximum_attempts(self) -> u16 {
        self.maximum_attempts.get()
    }

    /// Returns the delay after `failed_attempts` consecutive failures.
    #[must_use]
    pub fn delay_after(self, failed_attempts: u16) -> Duration {
        let exponent = u32::from(failed_attempts.saturating_sub(1)).min(31);
        self.initial_delay
            .checked_mul(1_u32 << exponent)
            .unwrap_or(self.maximum_delay)
            .min(self.maximum_delay)
    }

    /// Returns equal-jitter backoff within the upper half of the exponential
    /// delay window.
    ///
    /// `entropy` is deliberately supplied by the caller so tests and durable
    /// request identities can produce deterministic schedules without a
    /// process-global random-number generator. The result is always non-zero,
    /// no greater than [`Self::delay_after`], and no less than half that bound.
    #[must_use]
    pub fn jittered_delay_after(self, failed_attempts: u16, entropy: u64) -> Duration {
        let ceiling = self.delay_after(failed_attempts);
        let ceiling_nanos = ceiling.as_nanos();
        let floor_nanos = ceiling_nanos.div_ceil(2);
        let width = ceiling_nanos.saturating_sub(floor_nanos);
        let offset = if width == 0 {
            0
        } else {
            u128::from(entropy) % (width + 1)
        };
        Duration::from_nanos(
            u64::try_from(floor_nanos + offset)
                .unwrap_or(u64::MAX)
                .max(1),
        )
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            maximum_attempts: NonZeroU16::new(8).expect("eight is non-zero"),
            initial_delay: Duration::from_millis(100),
            maximum_delay: Duration::from_secs(10),
        }
    }
}

/// Resource and timing ceilings enforced independently of adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerRuntimeLimits {
    retry: RetryPolicy,
    command_gap_poll: Duration,
    idle_delay_ceiling: Duration,
    watchdog_resolution: Duration,
    cancellation_grace: Duration,
}

impl RunnerRuntimeLimits {
    /// Creates coherent runtime limits.
    ///
    /// # Errors
    ///
    /// Rejects zero durations or values above their hard ceilings.
    pub fn new(
        retry: RetryPolicy,
        command_gap_poll: Duration,
        idle_delay_ceiling: Duration,
        watchdog_resolution: Duration,
        cancellation_grace: Duration,
    ) -> Result<Self, RunnerRuntimeConfigError> {
        if command_gap_poll.is_zero()
            || watchdog_resolution.is_zero()
            || idle_delay_ceiling.is_zero()
            || cancellation_grace.is_zero()
            || command_gap_poll > MAX_RETRY_DELAY
            || watchdog_resolution > MAX_RETRY_DELAY
            || idle_delay_ceiling > MAX_IDLE_DELAY
            || cancellation_grace > MAX_CANCELLATION_GRACE
        {
            return Err(RunnerRuntimeConfigError::InvalidRuntimeDuration);
        }
        Ok(Self {
            retry,
            command_gap_poll,
            idle_delay_ceiling,
            watchdog_resolution,
            cancellation_grace,
        })
    }

    /// Returns the immutable-request retry policy.
    #[must_use]
    pub const fn retry(self) -> RetryPolicy {
        self.retry
    }

    /// Returns how often an out-of-order command checks the durable cursor.
    #[must_use]
    pub const fn command_gap_poll(self) -> Duration {
        self.command_gap_poll
    }

    /// Returns the local ceiling applied to server no-work delays.
    #[must_use]
    pub const fn idle_delay_ceiling(self) -> Duration {
        self.idle_delay_ceiling
    }

    /// Returns the maximum delay before observing an expired lease.
    #[must_use]
    pub const fn watchdog_resolution(self) -> Duration {
        self.watchdog_resolution
    }

    /// Returns the time allowed for an executor to stop after cancellation.
    #[must_use]
    pub const fn cancellation_grace(self) -> Duration {
        self.cancellation_grace
    }
}

impl Default for RunnerRuntimeLimits {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::default(),
            command_gap_poll: Duration::from_millis(25),
            idle_delay_ceiling: Duration::from_mins(5),
            watchdog_resolution: Duration::from_millis(100),
            cancellation_grace: Duration::from_secs(30),
        }
    }
}

/// Validated immutable configuration for one runner process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerRuntimeConfig {
    capabilities: RunnerCapabilities,
    protocol_limits: ProtocolLimits,
    limits: RunnerRuntimeLimits,
}

impl RunnerRuntimeConfig {
    /// Validates runner inventory and local resource ceilings.
    ///
    /// # Errors
    ///
    /// Rejects invalid capabilities, zero slots, or slot counts beyond the
    /// durable journal ceiling.
    pub fn new(
        capabilities: RunnerCapabilities,
        protocol_limits: ProtocolLimits,
        limits: RunnerRuntimeLimits,
    ) -> Result<Self, RunnerRuntimeConfigError> {
        capabilities
            .validate()
            .map_err(|_| RunnerRuntimeConfigError::InvalidCapabilities)?;
        let slots = capabilities.max_parallel_jobs();
        if slots == 0 || clamp_registration_slots(slots) != slots {
            return Err(RunnerRuntimeConfigError::InvalidSlotCount);
        }
        Ok(Self {
            capabilities,
            protocol_limits,
            limits,
        })
    }

    /// Returns the runner capability advertisement.
    #[must_use]
    pub const fn capabilities(&self) -> &RunnerCapabilities {
        &self.capabilities
    }

    /// Returns protobuf/domain resource limits.
    #[must_use]
    pub const fn protocol_limits(&self) -> &ProtocolLimits {
        &self.protocol_limits
    }

    /// Returns runtime timing and retry ceilings.
    #[must_use]
    pub const fn limits(&self) -> RunnerRuntimeLimits {
        self.limits
    }
}

/// Invalid runner-runtime configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerRuntimeConfigError {
    /// The execution inventory failed domain validation.
    #[error("runner capabilities are invalid")]
    InvalidCapabilities,
    /// The advertised slot count is zero or exceeds durable journal limits.
    #[error("runner slot count is outside durable limits")]
    InvalidSlotCount,
    /// Retry attempts are zero or above the hard ceiling.
    #[error("retry attempt count is invalid")]
    InvalidRetryAttempts,
    /// Retry delays are zero, inverted, or above the hard ceiling.
    #[error("retry delay is invalid")]
    InvalidRetryDelay,
    /// A runtime duration is zero or above its hard ceiling.
    #[error("runtime duration is invalid")]
    InvalidRuntimeDuration,
}
