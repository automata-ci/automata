//! The explicit state machine for a job attempt.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Lifecycle state for one job attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLifecycle {
    /// The attempt is eligible for scheduler matching and has no active lease.
    Queued,
    /// A runner holds the lease but has not begun environment preparation.
    Leased,
    /// The runner is preparing the execution environment and evaluating gates.
    Preparing,
    /// User workload is executing.
    Running,
    /// Cancellation has been requested and cooperative shutdown is in progress.
    Cancelling,
    /// Execution has stopped and terminal results are being durably committed.
    Finalizing,
    /// The attempt completed successfully.
    Succeeded,
    /// The attempt completed with a non-timeout execution or finalization failure.
    Failed,
    /// The attempt honored a cancellation request.
    Cancelled,
    /// The attempt exceeded an enforced time limit.
    TimedOut,
    /// Admission or a job condition resolved false without executing workload.
    Skipped,
    /// Runner ownership was lost and the attempt cannot safely continue.
    Lost,
}

impl JobLifecycle {
    /// Whether no further execution-state transitions are valid.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::TimedOut
                | Self::Skipped
                | Self::Lost
        )
    }

    /// Validates one lifecycle edge. Lease authorization is checked separately.
    /// A leased job whose job-level condition is false resolves directly from
    /// [`Self::Preparing`] to [`Self::Skipped`] without inventing execution.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the edge is outside the declared state
    /// machine, including all transitions out of terminal states.
    pub fn validate_transition(self, next: Self) -> Result<(), TransitionError> {
        let valid = matches!(
            (self, next),
            (Self::Queued, Self::Leased | Self::Cancelled | Self::Skipped)
                | (
                    Self::Leased,
                    Self::Preparing | Self::Queued | Self::Cancelling | Self::Failed | Self::Lost
                )
                | (
                    Self::Preparing,
                    Self::Queued
                        | Self::Running
                        | Self::Cancelling
                        | Self::Failed
                        | Self::TimedOut
                        | Self::Skipped
                        | Self::Lost
                )
                | (
                    Self::Running,
                    Self::Queued
                        | Self::Cancelling
                        | Self::Finalizing
                        | Self::TimedOut
                        | Self::Lost
                )
                | (
                    Self::Cancelling,
                    Self::Finalizing | Self::Cancelled | Self::Failed | Self::TimedOut | Self::Lost
                )
                | (
                    Self::Finalizing,
                    Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Lost
                )
        );
        if valid {
            Ok(())
        } else {
            Err(TransitionError {
                from: self,
                to: next,
            })
        }
    }
}

/// An invalid lifecycle edge.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid job-attempt transition from {from:?} to {to:?}")]
pub struct TransitionError {
    from: JobLifecycle,
    to: JobLifecycle,
}

impl TransitionError {
    /// Returns the lifecycle state from which the invalid edge started.
    #[must_use]
    pub const fn from(self) -> JobLifecycle {
        self.from
    }

    /// Returns the requested lifecycle state rejected by the state machine.
    #[must_use]
    pub const fn to(self) -> JobLifecycle {
        self.to
    }
}
