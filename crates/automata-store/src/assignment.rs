use automata_core::{Lease, RunnerId};
use thiserror::Error;

use crate::{RunnerSessionFence, StableRunnerSlot};

/// Stable runner-session slot bound to an active attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttemptAssignment {
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
}

impl AttemptAssignment {
    #[must_use]
    pub const fn new(session: RunnerSessionFence, slot: StableRunnerSlot) -> Self {
        Self { session, slot }
    }

    #[must_use]
    pub const fn session(self) -> RunnerSessionFence {
        self.session
    }

    #[must_use]
    pub const fn slot(self) -> StableRunnerSlot {
        self.slot
    }

    /// Verifies that the lease and session identify the same runner.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptAssignmentError::RunnerMismatch`] for a foreign lease.
    pub fn validate_lease(self, lease: &Lease) -> Result<(), AttemptAssignmentError> {
        if lease.runner_id() != self.session.runner_id() {
            return Err(AttemptAssignmentError::RunnerMismatch {
                lease_runner_id: lease.runner_id(),
                session_runner_id: self.session.runner_id(),
            });
        }
        Ok(())
    }
}

/// Invalid relationship between a lease and its connection assignment.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AttemptAssignmentError {
    #[error("lease runner {lease_runner_id} does not match session runner {session_runner_id}")]
    RunnerMismatch {
        lease_runner_id: RunnerId,
        session_runner_id: RunnerId,
    },
}
