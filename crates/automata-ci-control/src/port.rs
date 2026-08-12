use std::{fmt, time::SystemTime};

use automata_ci_core::{LeaseId, UnixMillis};
use automata_ci_store::{
    RunnableAttemptRepository, RunnerClaimRepository, RunnerRoutingRepository,
    RunnerSlotAvailabilityRepository,
};

/// Composite, object-safe durable port used by the G1 lease-poll service.
///
/// A database adapter may implement every supertrait on one type, while tests
/// and non-SQL providers can supply an in-memory implementation. Implementors
/// inherit the supertraits' bounded reads, exact request-key replay, session and
/// slot fencing, and atomic claim/no-work receipt responsibilities. The service
/// does not emulate those guarantees in memory.
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
///
/// Implementations provide control-plane wall time, not runner-supplied time.
/// Repository fencing remains authoritative when observations race or regress.
pub trait LeaseClock: fmt::Debug + Send + Sync {
    /// Returns the control plane's current wall-clock observation.
    fn now(&self) -> UnixMillis;
}

/// Host wall-clock adapter.
///
/// Times before the Unix epoch map to zero, and values beyond the durable
/// timestamp range saturate at [`i64::MAX`]. Lease-expiry overflow is rejected
/// by [`crate::LeasePollService`] before a claim is submitted.
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
///
/// The generated value is only a claim proposal. On an exact retry or race, the
/// repository's durable receipt and lease identity remain authoritative.
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
