//! Immutable runnable scheduling candidates.

use automata_ci_core::{AttemptId, JobId, UnixMillis};

use crate::RoutingRequirements;

/// One durable attempt that all dependency and concurrency gates have made
/// runnable.
///
/// The scheduler cannot mutate a candidate. Queue state transitions and lease
/// issuance remain atomic responsibilities of the durable store adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnableCandidate {
    attempt_id: AttemptId,
    job_id: JobId,
    queued_at: UnixMillis,
    routing: RoutingRequirements,
}

impl RunnableCandidate {
    /// Creates an immutable runnable attempt from already-validated domain
    /// values.
    #[must_use]
    pub const fn new(
        attempt_id: AttemptId,
        job_id: JobId,
        queued_at: UnixMillis,
        routing: RoutingRequirements,
    ) -> Self {
        Self {
            attempt_id,
            job_id,
            queued_at,
            routing,
        }
    }

    /// Returns the durable attempt identity selected for lease acquisition.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the planned job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns when the attempt joined the runnable queue.
    #[must_use]
    pub const fn queued_at(&self) -> UnixMillis {
        self.queued_at
    }

    /// Returns trusted workflow routing requirements.
    #[must_use]
    pub const fn routing(&self) -> &RoutingRequirements {
        &self.routing
    }
}
