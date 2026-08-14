//! Owned scheduler decisions and typed decline diagnostics.

use automata_ci_core::{AttemptId, JobId, RequirementMismatch, RunnerId};

use super::{RunnerSlot, SessionGuard};

/// Pure result of evaluating one scheduling snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementDecision {
    /// One candidate can be atomically leased to one stable runner slot.
    Place(Placement),
    /// No placement is possible for this snapshot.
    Decline(PlacementDecline),
}

/// Identity needed by the application layer to atomically acquire a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Placement {
    attempt_id: AttemptId,
    job_id: JobId,
    session: SessionGuard,
    slot: RunnerSlot,
}

impl Placement {
    pub(crate) const fn new(
        attempt_id: AttemptId,
        job_id: JobId,
        session: SessionGuard,
        slot: RunnerSlot,
    ) -> Self {
        Self {
            attempt_id,
            job_id,
            session,
            slot,
        }
    }

    /// Returns the attempt for the durable lease transaction.
    #[must_use]
    pub const fn attempt_id(self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the planned job identity.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    /// Returns the exact authenticated session that may receive the lease.
    #[must_use]
    pub const fn session(self) -> SessionGuard {
        self.session
    }

    /// Returns the stable runner slot reserved by the placement.
    #[must_use]
    pub const fn slot(self) -> RunnerSlot {
        self.slot
    }
}

/// Why a complete scheduler snapshot produced no placement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementDecline {
    /// The durable queue supplied no runnable attempts.
    NoRunnableCandidates,
    /// Runnable work exists, but no authenticated effective runner is present.
    NoEffectiveRunners,
    /// Every runnable candidate was either incompatible or waiting for capacity.
    Candidates(Vec<CandidateDecline>),
}

/// Typed result of evaluating one candidate against every effective runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateDecline {
    attempt_id: AttemptId,
    reason: CandidateDeclineReason,
}

impl CandidateDecline {
    pub(crate) const fn new(attempt_id: AttemptId, reason: CandidateDeclineReason) -> Self {
        Self { attempt_id, reason }
    }

    /// Returns the candidate attempt that could not be placed.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns whether the candidate waits for capacity or capabilities.
    #[must_use]
    pub const fn reason(&self) -> &CandidateDeclineReason {
        &self.reason
    }
}

/// Why one candidate cannot currently run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateDeclineReason {
    /// At least one runner matches, but all of its authorized slots are busy.
    CompatibleRunnersBusy(Vec<RunnerId>),
    /// Every effective runner failed one or more core capability requirements.
    NoCompatibleRunner(Vec<RunnerRequirementDecline>),
}

/// Aggregate capacity classification for one already-runnable candidate.
///
/// This deliberately carries no durable identity or mismatch detail so it can
/// be safely reduced into bounded operational metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateCapacity {
    /// At least one compatible effective runner has an available slot.
    Available,
    /// Compatible effective runners exist, but all authorized slots are busy.
    CompatibleRunnersBusy,
    /// No effective runner satisfies every core capability requirement.
    NoCompatibleRunner,
}

/// Complete deterministic capability mismatch for one effective runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerRequirementDecline {
    runner_id: RunnerId,
    mismatches: Vec<RequirementMismatch>,
}

impl RunnerRequirementDecline {
    pub(crate) const fn new(runner_id: RunnerId, mismatches: Vec<RequirementMismatch>) -> Self {
        Self {
            runner_id,
            mismatches,
        }
    }

    /// Returns the effective runner that failed matching.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns every core capability mismatch in deterministic order.
    #[must_use]
    pub fn mismatches(&self) -> &[RequirementMismatch] {
        &self.mismatches
    }
}
