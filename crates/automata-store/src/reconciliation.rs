use async_trait::async_trait;
use automata_core::{RunId, UnixMillis};

use crate::StoreError;

/// Durable aggregate lifecycle of one workflow run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowRunStatus {
    Queued,
    InProgress,
    Completed,
    Cancelled,
}

/// Result of reconciling latest job attempts into aggregate run state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunReconciliation {
    run_id: RunId,
    status: WorkflowRunStatus,
    promoted_run_id: Option<RunId>,
}

impl RunReconciliation {
    #[must_use]
    pub const fn new(
        run_id: RunId,
        status: WorkflowRunStatus,
        promoted_run_id: Option<RunId>,
    ) -> Self {
        Self {
            run_id,
            status,
            promoted_run_id,
        }
    }

    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn status(self) -> WorkflowRunStatus {
        self.status
    }

    /// Returns a pending concurrency run atomically promoted to the running slot.
    #[must_use]
    pub const fn promoted_run_id(self) -> Option<RunId> {
        self.promoted_run_id
    }
}

/// Neutral aggregate reconciliation boundary for crash recovery and control loops.
#[async_trait]
pub trait RunReconciliationRepository: std::fmt::Debug + Send + Sync {
    /// Recomputes run lifecycle from every job's latest attempt and atomically
    /// releases/promotes repository concurrency slots at terminal state.
    async fn reconcile_run(
        &self,
        run_id: RunId,
        observed_at: UnixMillis,
    ) -> Result<RunReconciliation, StoreError>;
}
