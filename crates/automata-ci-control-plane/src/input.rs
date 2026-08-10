//! Validated, borrowed input to a scheduling policy.

use std::collections::BTreeSet;

use automata_ci_core::{AttemptId, RunnerId, RunnerSessionId};
use thiserror::Error;

use crate::{EffectiveRunner, Placement, RunnableCandidate, RunnerSlot};

/// A duplicate-free scheduling snapshot borrowed from application state.
///
/// Validation occurs once before invoking a policy. Policies therefore cannot
/// silently choose between contradictory records for the same durable identity.
#[derive(Clone, Copy, Debug)]
pub struct SchedulingInput<'a> {
    candidates: &'a [RunnableCandidate],
    runners: &'a [EffectiveRunner],
}

impl<'a> SchedulingInput<'a> {
    /// Validates uniqueness of all durable candidate and runner identities.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulingInputError`] for a duplicate attempt, runner, or
    /// authenticated session.
    pub fn new(
        candidates: &'a [RunnableCandidate],
        runners: &'a [EffectiveRunner],
    ) -> Result<Self, SchedulingInputError> {
        let mut attempt_ids = BTreeSet::new();
        for candidate in candidates {
            if !attempt_ids.insert(candidate.attempt_id()) {
                return Err(SchedulingInputError::DuplicateAttempt(
                    candidate.attempt_id(),
                ));
            }
        }

        let mut runner_ids = BTreeSet::new();
        let mut session_ids = BTreeSet::new();
        for runner in runners {
            let session = runner.session();
            if !runner_ids.insert(session.runner_id()) {
                return Err(SchedulingInputError::DuplicateRunner(session.runner_id()));
            }
            if !session_ids.insert(session.session_id()) {
                return Err(SchedulingInputError::DuplicateSession(session.session_id()));
            }
        }

        Ok(Self {
            candidates,
            runners,
        })
    }

    /// Returns immutable runnable candidates.
    #[must_use]
    pub const fn candidates(self) -> &'a [RunnableCandidate] {
        self.candidates
    }

    /// Returns server-authorized runner state.
    #[must_use]
    pub const fn runners(self) -> &'a [EffectiveRunner] {
        self.runners
    }

    /// Constructs a placement only from members of this validated snapshot.
    ///
    /// This is the public construction path for pluggable scheduler policies.
    /// Pointer membership prevents a policy from manufacturing lookalike
    /// candidates or runner evidence outside the snapshot, while the
    /// application layer still revalidates every returned identity before its
    /// durable claim transaction.
    ///
    /// # Errors
    ///
    /// Rejects foreign snapshot values, unavailable slots, and incompatible
    /// candidate/runner pairs.
    pub fn place(
        self,
        candidate: &RunnableCandidate,
        runner: &EffectiveRunner,
        slot: RunnerSlot,
    ) -> Result<Placement, PlacementFactoryError> {
        if !self
            .candidates
            .iter()
            .any(|member| std::ptr::eq(member, candidate))
        {
            return Err(PlacementFactoryError::ForeignCandidate);
        }
        if !self
            .runners
            .iter()
            .any(|member| std::ptr::eq(member, runner))
        {
            return Err(PlacementFactoryError::ForeignRunner);
        }
        if !runner.available_slots().contains(&slot) {
            return Err(PlacementFactoryError::UnavailableSlot);
        }
        if runner
            .capabilities()
            .satisfies(candidate.routing().runner())
            .is_err()
        {
            return Err(PlacementFactoryError::IncompatibleRunner);
        }
        Ok(Placement::new(
            candidate.attempt_id(),
            candidate.job_id(),
            runner.session(),
            slot,
        ))
    }
}

/// Invalid output requested by a pluggable scheduling policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PlacementFactoryError {
    /// The selected candidate was not borrowed from this validated snapshot.
    #[error("placement candidate is not a member of this scheduling snapshot")]
    ForeignCandidate,
    /// The selected runner was not borrowed from this validated snapshot.
    #[error("placement runner is not a member of this scheduling snapshot")]
    ForeignRunner,
    /// The selected stable slot was absent from the runner's availability set.
    #[error("placement slot is not currently available to this runner")]
    UnavailableSlot,
    /// The runner's effective capabilities do not satisfy the candidate.
    #[error("placement runner does not satisfy the candidate requirements")]
    IncompatibleRunner,
}

/// Contradictions in one scheduler snapshot.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SchedulingInputError {
    /// More than one candidate represents the same durable attempt.
    #[error("scheduling input contains duplicate attempt {0}")]
    DuplicateAttempt(AttemptId),
    /// More than one effective record represents the same durable runner.
    #[error("scheduling input contains duplicate runner {0}")]
    DuplicateRunner(RunnerId),
    /// An authenticated session identity is ambiguously bound to two runners.
    #[error("scheduling input contains duplicate runner session {0}")]
    DuplicateSession(RunnerSessionId),
}
