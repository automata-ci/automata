use std::{fmt, time::SystemTime};

use automata_core::{LeaseId, UnixMillis};
use automata_store::{
    RunnableAttemptRepository, RunnerClaimRepository, RunnerRoutingRepository,
    RunnerSlotAvailabilityRepository,
};

/// Composite, object-safe durable port used by the G1 lease-poll service.
///
/// A database adapter may implement every supertrait on one type, while tests
/// and non-SQL providers can supply an in-memory implementation.
pub trait LeasePollRepository:
    RunnerClaimRepository
    + RunnerRoutingRepository
    + RunnerSlotAvailabilityRepository
    + RunnableAttemptRepository
    + Send
    + Sync
{
}

impl<T> LeasePollRepository for T where
    T: RunnerClaimRepository
        + RunnerRoutingRepository
        + RunnerSlotAvailabilityRepository
        + RunnableAttemptRepository
        + Send
        + Sync
{
}

/// Trusted time source for lease issuance.
pub trait LeaseClock: fmt::Debug + Send + Sync {
    /// Returns the control plane's current wall-clock observation.
    fn now(&self) -> UnixMillis;
}

/// Host wall-clock adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLeaseClock;

impl LeaseClock for SystemLeaseClock {
    fn now(&self) -> UnixMillis {
        let milliseconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        UnixMillis::new(milliseconds)
    }
}

/// Fresh identity source kept replaceable for deterministic application tests.
pub trait LeaseIdGenerator: fmt::Debug + Send + Sync {
    /// Returns a fresh lease identity for a new claim attempt.
    fn next_lease_id(&self) -> LeaseId;
}

/// Random RFC 9562 version-4 lease identity adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomLeaseIdGenerator;

impl LeaseIdGenerator for RandomLeaseIdGenerator {
    fn next_lease_id(&self) -> LeaseId {
        LeaseId::new()
    }
}
