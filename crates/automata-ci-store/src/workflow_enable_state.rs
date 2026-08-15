//! Durable, versioned workflow enable-state used by every event admission path.

use std::num::NonZeroU64;

use async_trait::async_trait;
use automata_ci_core::{UnixMillis, WorkflowId};
use thiserror::Error;

use crate::{RepositoryId, RepositoryOperationError, TenantScope};

const MAX_WORKFLOW_PATH_BYTES: usize = 1_024;

/// Positive immutable revision of one workflow's enable-state history.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkflowEnableStateRevision(NonZeroU64);

impl WorkflowEnableStateRevision {
    /// Constructs a positive revision inside the signed durable range.
    ///
    /// # Errors
    ///
    /// Rejects zero and values larger than `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, WorkflowEnableStateValueError> {
        NonZeroU64::new(value)
            .filter(|value| i64::try_from(value.get()).is_ok())
            .map(Self)
            .ok_or(WorkflowEnableStateValueError::InvalidRevision)
    }

    /// Returns the positive revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Closed admission state for one durable workflow definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowEnableState {
    /// New event subjects may be admitted.
    Enabled,
    /// New event subjects must be rejected before run creation.
    Disabled,
}

impl WorkflowEnableState {
    /// Returns the stable persistence discriminator.
    #[must_use]
    pub const fn as_durable_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// One immutable revision from a workflow's enable-state history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowEnableStateRecord {
    tenant: TenantScope,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    workflow_path: String,
    revision: WorkflowEnableStateRevision,
    state: WorkflowEnableState,
    changed_at: UnixMillis,
}

impl WorkflowEnableStateRecord {
    /// Constructs an exact durable state revision.
    ///
    /// # Errors
    ///
    /// Rejects nil identities, unsafe paths, and pre-epoch time.
    pub fn new(
        tenant: TenantScope,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
        workflow_path: impl Into<String>,
        revision: WorkflowEnableStateRevision,
        state: WorkflowEnableState,
        changed_at: UnixMillis,
    ) -> Result<Self, WorkflowEnableStateValueError> {
        let workflow_path = workflow_path.into();
        if repository_id.as_uuid().is_nil() || workflow_id.as_uuid().is_nil() {
            return Err(WorkflowEnableStateValueError::NilIdentity);
        }
        validate_workflow_path(&workflow_path)?;
        if changed_at.get() < 0 {
            return Err(WorkflowEnableStateValueError::NegativeTimestamp);
        }
        Ok(Self {
            tenant,
            repository_id,
            workflow_id,
            workflow_path,
            revision,
            state,
            changed_at,
        })
    }

    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }
    #[must_use]
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }
    #[must_use]
    pub const fn revision(&self) -> WorkflowEnableStateRevision {
        self.revision
    }
    #[must_use]
    pub const fn state(&self) -> WorkflowEnableState {
        self.state
    }
    #[must_use]
    pub const fn changed_at(&self) -> UnixMillis {
        self.changed_at
    }
}

/// Compare-and-set request for a new immutable enable-state revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetWorkflowEnableState {
    next: WorkflowEnableStateRecord,
    expected_current_revision: Option<WorkflowEnableStateRevision>,
}

impl SetWorkflowEnableState {
    /// Constructs a fenced state transition.
    ///
    /// The first revision must be `1`. Every successor must be exactly one
    /// greater than `expected_current_revision`.
    ///
    /// # Errors
    ///
    /// Rejects a non-contiguous proposed revision.
    pub fn new(
        next: WorkflowEnableStateRecord,
        expected_current_revision: Option<WorkflowEnableStateRevision>,
    ) -> Result<Self, WorkflowEnableStateValueError> {
        let expected =
            expected_current_revision.map_or(Some(1), |revision| revision.get().checked_add(1));
        if expected != Some(next.revision().get()) {
            return Err(WorkflowEnableStateValueError::NonContiguousRevision);
        }
        Ok(Self {
            next,
            expected_current_revision,
        })
    }

    #[must_use]
    pub const fn next(&self) -> &WorkflowEnableStateRecord {
        &self.next
    }
    #[must_use]
    pub const fn expected_current_revision(&self) -> Option<WorkflowEnableStateRevision> {
        self.expected_current_revision
    }
}

/// Exact state transition receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowEnableStateReceipt {
    current: WorkflowEnableStateRecord,
    replay: bool,
}

impl WorkflowEnableStateReceipt {
    #[cfg(feature = "adapter-spi")]
    pub(crate) const fn new(current: WorkflowEnableStateRecord, replay: bool) -> Self {
        Self { current, replay }
    }

    #[must_use]
    pub const fn current(&self) -> &WorkflowEnableStateRecord {
        &self.current
    }
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

/// Portable workflow enable-state failures.
#[derive(Debug, Error)]
pub enum WorkflowEnableStateStoreError {
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    #[error("workflow enable-state transition conflicts with current revision")]
    Conflict,
    #[error("workflow enable-state was not found")]
    NotFound,
    #[error("durable workflow enable-state data is corrupt")]
    CorruptData,
}

/// Invalid enable-state values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkflowEnableStateValueError {
    #[error("workflow enable-state revision is invalid")]
    InvalidRevision,
    #[error("workflow enable-state revision is not contiguous")]
    NonContiguousRevision,
    #[error("workflow enable-state identity must not be nil")]
    NilIdentity,
    #[error("workflow enable-state path is invalid")]
    InvalidWorkflowPath,
    #[error("workflow enable-state timestamp is negative")]
    NegativeTimestamp,
}

/// Durable management and read boundary for workflow enable state.
#[async_trait]
pub trait WorkflowEnableStateRepository: Send + Sync {
    async fn set_workflow_enable_state(
        &self,
        request: SetWorkflowEnableState,
    ) -> Result<WorkflowEnableStateReceipt, WorkflowEnableStateStoreError>;

    async fn load_workflow_enable_state(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        workflow_id: WorkflowId,
    ) -> Result<WorkflowEnableStateRecord, WorkflowEnableStateStoreError>;
}

fn validate_workflow_path(value: &str) -> Result<(), WorkflowEnableStateValueError> {
    if value.is_empty()
        || value.len() > MAX_WORKFLOW_PATH_BYTES
        || value.trim() != value
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains("//")
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(WorkflowEnableStateValueError::InvalidWorkflowPath);
    }
    Ok(())
}
