use std::fmt;

use automata_core::{
    AttemptId, JobId, RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_store::{RepositoryId, TenantScope, WorkflowAdmissionIdempotency, WorkflowSnapshotId};

use crate::{
    AdmissionRepositoryCoordinates, MaterializeWorkflowRequest, MaterializedWorkflow,
    WorkflowMaterializationError,
};

/// Trusted control-plane clock used for durable admission timestamps.
pub trait AdmissionClock: fmt::Debug + Send + Sync {
    /// Returns the current server observation time.
    fn now(&self) -> UnixMillis;
}

/// Server-owned identity generation boundary.
pub trait AdmissionIdGenerator: fmt::Debug + Send + Sync {
    /// Derives the stable repository ID for provider identity.
    fn repository_id(
        &self,
        tenant: &TenantScope,
        repository: &AdmissionRepositoryCoordinates,
    ) -> RepositoryId;

    /// Derives the stable workflow definition ID for repository/path identity.
    fn workflow_id(&self, repository_id: RepositoryId, workflow_path: &str) -> WorkflowId;

    /// Derives the stable immutable source snapshot ID.
    fn snapshot_id(
        &self,
        workflow_id: WorkflowId,
        source_digest: Sha256Digest,
    ) -> WorkflowSnapshotId;

    /// Allocates one new logical run candidate.
    fn run_id(&self, tenant: &TenantScope, idempotency: &WorkflowAdmissionIdempotency) -> RunId;

    /// Derives a job identity within a server-owned run.
    fn job_id(&self, run_id: RunId, job_key: &WorkflowJobKey) -> JobId;

    /// Derives the first attempt identity within a job.
    fn attempt_id(&self, job_id: JobId) -> AttemptId;
}

/// Provider adapter that revalidates source and materializes executable jobs.
pub trait WorkflowMaterializer: fmt::Debug + Send + Sync {
    /// Revalidates and materializes the complete workflow without I/O.
    ///
    /// # Errors
    ///
    /// Fails closed on a source/compiler diagnostic, mismatch, or evaluation diagnostic.
    fn materialize(
        &self,
        request: &MaterializeWorkflowRequest<'_>,
    ) -> Result<MaterializedWorkflow, WorkflowMaterializationError>;
}
