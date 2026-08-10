use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A UTC timestamp represented as whole seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UnixTimestamp(u64);

impl UnixTimestamp {
    /// Creates a timestamp from whole seconds since the Unix epoch.
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the represented whole Unix seconds.
    pub const fn as_seconds(self) -> u64 {
        self.0
    }

    /// Adds whole seconds without wrapping.
    ///
    /// # Errors
    ///
    /// Returns an error if the timestamp exceeds `u64::MAX`.
    pub fn checked_add(self, seconds: u64) -> Result<Self, TimeError> {
        self.0
            .checked_add(seconds)
            .map(Self)
            .ok_or(TimeError::Overflow)
    }
}

/// Supplies an injectable wall-clock timestamp for lifecycle decisions.
pub trait Clock: std::fmt::Debug + Send + Sync {
    /// Returns the clock's current Unix timestamp.
    fn now(&self) -> UnixTimestamp;
}

/// A clock backed by the host's system time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTimestamp {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        UnixTimestamp::from_seconds(seconds)
    }
}

/// A failure in bounded timestamp arithmetic.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TimeError {
    /// The requested timestamp cannot be represented as `u64` seconds.
    #[error("timestamp arithmetic overflowed")]
    Overflow,
}
