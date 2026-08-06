//! The explicit state machine for a job attempt.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Lifecycle state for one job attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLifecycle {
    Queued,
    Leased,
    Preparing,
    Running,
    Cancelling,
    Finalizing,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Skipped,
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
    #[must_use]
    pub const fn from(self) -> JobLifecycle {
        self.from
    }

    #[must_use]
    pub const fn to(self) -> JobLifecycle {
        self.to
    }
}
