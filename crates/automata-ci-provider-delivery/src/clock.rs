use std::time::{SystemTime, UNIX_EPOCH};

use automata_ci_core::UnixMillis;
use thiserror::Error;

/// Trusted wall clock shared by provider ingress and delivery work.
pub trait ProviderDeliveryClock: std::fmt::Debug + Send + Sync {
    /// Returns a nonnegative Unix timestamp.
    ///
    /// # Errors
    ///
    /// Fails when the platform clock is before the epoch or outside `i64`.
    fn now(&self) -> Result<UnixMillis, ProviderDeliveryClockError>;
}

/// Production provider-delivery wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProviderDeliveryClock;

impl ProviderDeliveryClock for SystemProviderDeliveryClock {
    fn now(&self) -> Result<UnixMillis, ProviderDeliveryClockError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProviderDeliveryClockError)?
            .as_millis();
        let millis = i64::try_from(millis).map_err(|_| ProviderDeliveryClockError)?;
        Ok(UnixMillis::new(millis))
    }
}

/// Platform clock could not produce a durable provider timestamp.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("provider delivery clock is unavailable")]
pub struct ProviderDeliveryClockError;
