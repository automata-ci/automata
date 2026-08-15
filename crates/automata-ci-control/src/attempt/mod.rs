//! Durable attempt lifecycle values used by runner-control services.

use automata_ci_core::UnixMillis;
use automata_ci_store::AttemptCommandError;

#[cfg(feature = "adapter-spi")]
pub(crate) mod durable;
mod renewal;
#[cfg(feature = "adapter-spi")]
pub(crate) mod snapshot;

pub use renewal::RenewLease;

fn validate_lease_interval(
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> Result<(), AttemptCommandError> {
    if expires_at <= observed_at {
        return Err(AttemptCommandError::InvalidLeaseInterval);
    }
    Ok(())
}
