use std::fmt;

use automata_ci_core::{RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey};
use automata_ci_store::{
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, RepositoryId, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};

use crate::{
    AdmissionRepositoryCoordinates, WorkflowAdmissionRequest, WorkflowPlanVerificationError,
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

    /// Derives the root logical invocation identity within a server-owned run.
    fn logical_invocation_id(&self, run_id: RunId) -> LogicalWorkflowInvocationId;

    /// Derives one source-level logical-job identity within a run.
    fn logical_job_id(&self, run_id: RunId, job_key: &WorkflowJobKey) -> LogicalWorkflowJobId;
}

/// Provider adapter that recompiles exact source and verifies the supplied plan.
pub trait WorkflowPlanVerifier: fmt::Debug + Send + Sync {
    /// Revalidates the source/plan boundary without performing I/O.
    ///
    /// # Errors
    ///
    /// Fails closed on a source/compiler diagnostic or any exact-plan mismatch.
    fn verify(
        &self,
        request: &WorkflowAdmissionRequest,
    ) -> Result<(), WorkflowPlanVerificationError>;
}
