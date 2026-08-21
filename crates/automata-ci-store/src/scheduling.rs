//! Provider-neutral workflow scheduling policy values.

use async_trait::async_trait;
use automata_ci_auth::management::ManagementActor;
use automata_ci_core::{RunId, TrustSourceClass};
use thiserror::Error;

use crate::RepositoryId;

/// Highest value a human may request for a workflow run.
pub const MAX_USER_WORKFLOW_PRIORITY: u8 = 99;
/// Reserved value assigned to authenticated merge-queue runs.
pub const MERGE_QUEUE_WORKFLOW_PRIORITY: u8 = 100;

/// Effective scheduling priority for one workflow run.
///
/// Values increase with urgency. The merge-queue value is reserved and can
/// only be derived from authenticated provider-neutral trust evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkflowRunPriority(u8);

impl WorkflowRunPriority {
    /// The default priority for ordinary work.
    pub const NORMAL: Self = Self(0);
    /// The reserved maximum for authenticated merge-queue work.
    pub const MERGE_QUEUE: Self = Self(MERGE_QUEUE_WORKFLOW_PRIORITY);

    /// Builds a human-controlled priority level.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowRunPriorityError::Reserved`] for the merge-queue
    /// level, which is assigned only from authenticated trust evidence.
    pub const fn user(level: u8) -> Result<Self, WorkflowRunPriorityError> {
        if level <= MAX_USER_WORKFLOW_PRIORITY {
            Ok(Self(level))
        } else {
            Err(WorkflowRunPriorityError::Reserved)
        }
    }

    /// Returns the effective human-facing level.
    #[must_use]
    pub const fn level(self) -> u8 {
        self.0
    }

    /// Returns whether this value is the reserved merge-queue priority.
    #[must_use]
    pub const fn is_merge_queue(self) -> bool {
        self.0 == MERGE_QUEUE_WORKFLOW_PRIORITY
    }

    /// Returns the bounded `PostgreSQL` representation.
    #[must_use]
    pub const fn storage_value(self) -> i16 {
        self.0 as i16
    }

    /// Returns the ascending queue-key component used by SQL and Rust.
    #[must_use]
    pub const fn queue_order(self) -> i16 {
        MERGE_QUEUE_WORKFLOW_PRIORITY as i16 - self.storage_value()
    }

    /// Decodes the only persisted priority values accepted by this release.
    #[must_use]
    pub fn from_storage(value: i16) -> Option<Self> {
        if value >= 0 && value <= i16::from(MERGE_QUEUE_WORKFLOW_PRIORITY) {
            u8::try_from(value).ok().map(Self)
        } else {
            None
        }
    }

    /// Derives the effective priority from authenticated trust evidence.
    #[must_use]
    pub const fn from_trust_source(source: TrustSourceClass) -> Self {
        match source {
            TrustSourceClass::MergeQueue => Self::MERGE_QUEUE,
            TrustSourceClass::SameRepository
            | TrustSourceClass::Fork
            | TrustSourceClass::Dependabot
            | TrustSourceClass::Automation
            | TrustSourceClass::Incomplete => Self::NORMAL,
        }
    }
}

/// Closed validation failures for user-controlled priority values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowRunPriorityError {
    /// The reserved merge-queue value cannot be requested by a human.
    #[error("the merge-queue priority is reserved")]
    Reserved,
}

/// Authorized request to set the priority of one queued workflow run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateWorkflowRunPriority {
    actor: ManagementActor,
    repository_id: RepositoryId,
    run_id: RunId,
    priority: WorkflowRunPriority,
}

impl UpdateWorkflowRunPriority {
    /// Creates a human-controlled priority request.
    ///
    /// # Errors
    ///
    /// Returns [`WorkflowRunPriorityError::Reserved`] when the request tries
    /// to assign the server-managed merge-queue level.
    pub fn new(
        actor: ManagementActor,
        repository_id: RepositoryId,
        run_id: RunId,
        priority: WorkflowRunPriority,
    ) -> Result<Self, WorkflowRunPriorityError> {
        if priority.is_merge_queue() {
            return Err(WorkflowRunPriorityError::Reserved);
        }
        Ok(Self {
            actor,
            repository_id,
            run_id,
            priority,
        })
    }

    /// Returns the authority-bearing actor snapshot.
    #[must_use]
    pub const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    /// Returns the exact repository parent.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the exact workflow run.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Returns the requested effective priority.
    #[must_use]
    pub const fn priority(&self) -> WorkflowRunPriority {
        self.priority
    }
}

/// Closed result of a workflow-priority update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateWorkflowRunPriorityOutcome {
    /// The exact desired value is now durable.
    Applied(WorkflowRunPriority),
    /// The session is stale or current authority does not allow this mutation.
    AuthorityRejected,
    /// The tenant/repository/run target was not found.
    NotFound,
    /// The run has already left the mutable queue lifecycle.
    RunNotQueued,
    /// Authenticated merge-queue policy owns the priority.
    MergeQueueManaged,
}

/// Sanitized workflow-priority persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowPriorityRepositoryError {
    /// A command value crossed the port without domain validation.
    #[error("workflow priority request is invalid")]
    InvalidRequest,
    /// Durable storage is temporarily unavailable.
    #[error("workflow priority storage is unavailable")]
    Unavailable,
    /// Durable priority or authority state violates an invariant.
    #[error("durable workflow priority data violates an invariant")]
    CorruptData,
}

/// Backend-neutral mutation boundary for workflow scheduling priority.
#[async_trait]
pub trait WorkflowPriorityRepository: std::fmt::Debug + Send + Sync {
    /// Sets one queued run's exact human-controlled priority.
    async fn update_workflow_run_priority(
        &self,
        request: UpdateWorkflowRunPriority,
    ) -> Result<UpdateWorkflowRunPriorityOutcome, WorkflowPriorityRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_levels_are_bounded_before_reserved_merge_queue() {
        assert_eq!(WorkflowRunPriority::user(0).unwrap().level(), 0);
        assert_eq!(WorkflowRunPriority::user(99).unwrap().level(), 99);
        assert_eq!(
            WorkflowRunPriority::user(100),
            Err(WorkflowRunPriorityError::Reserved)
        );
    }

    #[test]
    fn queue_order_is_high_priority_first() {
        assert!(
            WorkflowRunPriority::MERGE_QUEUE.queue_order()
                < WorkflowRunPriority::NORMAL.queue_order()
        );
        assert!(
            WorkflowRunPriority::user(90).unwrap().queue_order()
                < WorkflowRunPriority::user(10).unwrap().queue_order()
        );
    }

    #[test]
    fn trust_only_elevates_complete_merge_queue_classification() {
        assert_eq!(
            WorkflowRunPriority::from_trust_source(TrustSourceClass::MergeQueue),
            WorkflowRunPriority::MERGE_QUEUE
        );
        for source in [
            TrustSourceClass::SameRepository,
            TrustSourceClass::Fork,
            TrustSourceClass::Dependabot,
            TrustSourceClass::Automation,
            TrustSourceClass::Incomplete,
        ] {
            assert_eq!(
                WorkflowRunPriority::from_trust_source(source),
                WorkflowRunPriority::NORMAL
            );
        }
    }
}
