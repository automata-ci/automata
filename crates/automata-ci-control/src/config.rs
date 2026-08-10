use std::num::NonZeroI64;

use automata_ci_store::RunnableScanLimit;
use thiserror::Error;

/// Positive lease lifetime measured in milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseTimeToLive(NonZeroI64);

impl LeaseTimeToLive {
    /// Creates a positive lease lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseTimeToLiveError`] for zero or a negative duration.
    pub fn from_millis(milliseconds: i64) -> Result<Self, LeaseTimeToLiveError> {
        NonZeroI64::new(milliseconds)
            .filter(|value| value.get().is_positive())
            .map(Self)
            .ok_or(LeaseTimeToLiveError::NotPositive)
    }

    /// Returns the configured lifetime in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0.get()
    }
}

/// Invalid lease lifetime configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseTimeToLiveError {
    /// A lease must have a non-empty half-open validity interval.
    #[error("lease time-to-live must be positive")]
    NotPositive,
}

/// Bounded inputs to one outbound lease-poll application service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeasePollConfig {
    scan_limit: RunnableScanLimit,
    lease_time_to_live: LeaseTimeToLive,
}

impl LeasePollConfig {
    /// Creates lease-poll limits from already-validated values.
    #[must_use]
    pub const fn new(scan_limit: RunnableScanLimit, lease_time_to_live: LeaseTimeToLive) -> Self {
        Self {
            scan_limit,
            lease_time_to_live,
        }
    }

    /// Returns the maximum durable runnable rows read by one poll.
    #[must_use]
    pub const fn scan_limit(self) -> RunnableScanLimit {
        self.scan_limit
    }

    /// Returns the lifetime applied using the trusted application clock.
    #[must_use]
    pub const fn lease_time_to_live(self) -> LeaseTimeToLive {
        self.lease_time_to_live
    }
}

impl Default for LeasePollConfig {
    fn default() -> Self {
        Self::new(
            RunnableScanLimit::new(100).expect("default scan limit is bounded"),
            LeaseTimeToLive::from_millis(60_000).expect("default lease lifetime is positive"),
        )
    }
}
