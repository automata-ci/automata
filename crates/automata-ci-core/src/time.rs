//! Wire-stable timestamp representation.

use serde::{Deserialize, Serialize};

/// Milliseconds since the Unix epoch.
///
/// A numeric representation avoids binding durable schemas to a date/time
/// library or accepting multiple subtly different string encodings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UnixMillis(i64);

impl UnixMillis {
    /// Creates a timestamp from milliseconds since the Unix epoch.
    #[must_use]
    pub const fn new(milliseconds: i64) -> Self {
        Self(milliseconds)
    }

    /// Returns the stored Unix timestamp in milliseconds.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl From<i64> for UnixMillis {
    fn from(milliseconds: i64) -> Self {
        Self::new(milliseconds)
    }
}
