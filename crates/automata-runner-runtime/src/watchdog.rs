use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// Process-local monotonic time in milliseconds from an adapter-defined epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    /// Constructs a monotonic timestamp.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the adapter-defined millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances without wrapping.
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let millis = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(millis))
    }

    /// Returns the remaining duration, or zero after the deadline.
    #[must_use]
    pub fn remaining_until(self, deadline: Self) -> Duration {
        Duration::from_millis(deadline.0.saturating_sub(self.0))
    }
}

/// Thread-safe monotonic lease deadline updated only by valid renewals.
#[derive(Debug)]
pub struct LeaseWatchdog {
    deadline: Mutex<MonotonicMillis>,
}

impl LeaseWatchdog {
    /// Creates a watchdog with an already computed local deadline.
    #[must_use]
    pub const fn new(deadline: MonotonicMillis) -> Self {
        Self {
            deadline: Mutex::new(deadline),
        }
    }

    /// Returns the current local deadline.
    #[must_use]
    pub fn deadline(&self) -> MonotonicMillis {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Extends the deadline monotonically; stale renewals cannot shorten it.
    pub fn extend_to(&self, candidate: MonotonicMillis) {
        let mut deadline = self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        if candidate > *deadline {
            *deadline = candidate;
        }
    }

    /// Returns whether the deadline has elapsed.
    #[must_use]
    pub fn is_expired_at(&self, now: MonotonicMillis) -> bool {
        now >= self.deadline()
    }
}
