//! Exact durable resolution of job-scoped GitHub repository authority.
//!
//! This port deliberately separates resolution from the runtime-authority
//! issuance state machine. Resolution authenticates the live execution and its
//! immutable historical provider evidence; the existing runtime-authority
//! repository then provides single-winner mint, protected custody,
//! reconciliation, and revocation.

use async_trait::async_trait;
use automata_ci_core::{
    JobAuthorityProfile, JobId, JobIrVersion, Lease, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, WorkflowId,
};
use thiserror::Error;

use crate::{
    GithubRepositoryName, GithubRuntimeAuthorityIdentity, JobIrMetadata, RepositoryOperationError,
    RunnerGeneration, RunnerSessionFence, StableRunnerSlot,
};

/// Exact execution and semantic policy evidence presented for durable resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubJobRuntimeAuthorityExecution {
    workflow_id: WorkflowId,
    github_repository_name: GithubRepositoryName,
    authority_profile: JobAuthorityProfile,
    permission_policy_sha256: Sha256Digest,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    job_ir: JobIrMetadata,
}

impl GithubJobRuntimeAuthorityExecution {
    /// Binds one verified current `JobIR` policy to an exact lease and session.
    ///
    /// # Errors
    ///
    /// Rejects a non-current or cross-bound `JobIR`, malformed lease, negative
    /// lease time, an all-zero policy digest, or a nil execution identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_id: WorkflowId,
        github_repository_name: GithubRepositoryName,
        authority_profile: JobAuthorityProfile,
        permission_policy_sha256: Sha256Digest,
        lease: Lease,
        session: RunnerSessionFence,
        slot: StableRunnerSlot,
        job_ir: JobIrMetadata,
    ) -> Result<Self, GithubJobRuntimeAuthorityValueError> {
        lease
            .validate()
            .map_err(|_| GithubJobRuntimeAuthorityValueError::InvalidExecution)?;
        if job_ir.version() != JobIrVersion::current()
            || job_ir.job_id().as_uuid().is_nil()
            || job_ir.run_id().as_uuid().is_nil()
            || workflow_id.as_uuid().is_nil()
            || lease.attempt_id().as_uuid().is_nil()
            || lease.lease_id().as_uuid().is_nil()
            || lease.runner_id().as_uuid().is_nil()
            || session.session_id().as_uuid().is_nil()
            || lease.runner_id() != session.runner_id()
            || lease.issued_at().get() < 0
            || lease.expires_at().get() < 0
            || permission_policy_sha256 != job_ir.digest()
            || i64::try_from(lease.fencing_token().get()).is_err()
            || i64::try_from(session.session_epoch().get()).is_err()
            || i64::try_from(session.runner_generation().get()).is_err()
        {
            return Err(GithubJobRuntimeAuthorityValueError::InvalidExecution);
        }
        Ok(Self {
            workflow_id,
            github_repository_name,
            authority_profile,
            permission_policy_sha256,
            lease,
            session,
            slot,
            job_ir,
        })
    }

    /// Returns the workflow definition encoded by the verified `JobIR`.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the exact provider repository name encoded by the `JobIR`.
    #[must_use]
    pub const fn github_repository_name(&self) -> &GithubRepositoryName {
        &self.github_repository_name
    }

    /// Returns the semantic authority profile encoded by the `JobIR`.
    #[must_use]
    pub const fn authority_profile(&self) -> JobAuthorityProfile {
        self.authority_profile
    }

    /// Returns the domain-separated digest of the exact GitHub permission request.
    #[must_use]
    pub const fn permission_policy_sha256(&self) -> Sha256Digest {
        self.permission_policy_sha256
    }

    /// Returns the exact lease proposed for authorization.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Returns the exact authenticated runner-session fence.
    #[must_use]
    pub const fn session(&self) -> RunnerSessionFence {
        self.session
    }

    /// Returns the stable runner slot that owns the lease.
    #[must_use]
    pub const fn slot(&self) -> StableRunnerSlot {
        self.slot
    }

    /// Returns immutable metadata for the verified current `JobIR` bytes.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }

    /// Returns the concrete job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_ir.job_id()
    }

    /// Returns the workflow run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.job_ir.run_id()
    }

    /// Returns the assigned runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.lease.runner_id()
    }

    /// Returns the authenticated runner session identity.
    #[must_use]
    pub const fn runner_session_id(&self) -> RunnerSessionId {
        self.session.session_id()
    }

    /// Returns the authenticated runner generation.
    #[must_use]
    pub const fn runner_generation(&self) -> RunnerGeneration {
        self.session.runner_generation()
    }
}

/// Historical authority-profile result for one exact live execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubJobRuntimeAuthorityResolution {
    /// Historical provider and activation evidence explicitly forbids credentials.
    CredentialFree,
    /// Historical Standard evidence authorizes exactly one immutable identity.
    Standard(Box<GithubJobRuntimeAuthorityEvidence>),
}

/// Exact durable Standard evidence used for issuance and subsequent revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubJobRuntimeAuthorityEvidence {
    identity: GithubRuntimeAuthorityIdentity,
    workflow_id: WorkflowId,
    job_ir: JobIrMetadata,
}

impl GithubJobRuntimeAuthorityEvidence {
    /// Reconstructs exact durable evidence after adapter validation.
    #[must_use]
    pub const fn new(
        identity: GithubRuntimeAuthorityIdentity,
        workflow_id: WorkflowId,
        job_ir: JobIrMetadata,
    ) -> Self {
        Self {
            identity,
            workflow_id,
            job_ir,
        }
    }

    /// Returns the complete immutable authority identity.
    #[must_use]
    pub const fn identity(&self) -> &GithubRuntimeAuthorityIdentity {
        &self.identity
    }

    /// Returns the exact workflow definition linked by historical subject evidence.
    #[must_use]
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Returns the exact immutable `JobIR` object metadata.
    #[must_use]
    pub const fn job_ir(&self) -> &JobIrMetadata {
        &self.job_ir
    }

    /// Decomposes the evidence without copying authority state.
    #[must_use]
    pub fn into_parts(self) -> (GithubRuntimeAuthorityIdentity, WorkflowId, JobIrMetadata) {
        (self.identity, self.workflow_id, self.job_ir)
    }
}

/// Fail-closed durable resolution failures.
#[derive(Debug, Error)]
pub enum GithubJobRuntimeAuthorityStoreError {
    /// The backing repository operation failed.
    #[error(transparent)]
    Operation(#[from] RepositoryOperationError),
    /// No exact live execution and historical evidence tuple was authorized.
    #[error("GitHub job runtime authority is not authorized")]
    Unauthorized,
    /// Durable evidence was present but could not satisfy the current contract.
    #[error("durable GitHub job runtime-authority evidence is corrupt")]
    CorruptData,
}

impl GithubJobRuntimeAuthorityStoreError {
    /// Wraps an adapter failure without exposing query or credential detail.
    #[must_use]
    pub fn operation(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        RepositoryOperationError::from_source(source).into()
    }
}

/// Invalid exact execution input at the durable boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubJobRuntimeAuthorityValueError {
    /// Execution, session, lease, or `JobIR` coordinates are inconsistent.
    #[error("GitHub job runtime-authority execution is invalid")]
    InvalidExecution,
}

/// Transactional resolver for job-scoped GitHub repository authority.
#[async_trait]
pub trait GithubJobRuntimeAuthorityRepository: Send + Sync {
    /// Derives the sole historical profile outcome for one exact live execution.
    async fn resolve_github_job_runtime_authority(
        &self,
        execution: &GithubJobRuntimeAuthorityExecution,
    ) -> Result<GithubJobRuntimeAuthorityResolution, GithubJobRuntimeAuthorityStoreError>;

    /// Revalidates a previously derived Standard identity and returns its exact
    /// immutable `JobIR` object metadata.
    async fn revalidate_github_job_runtime_authority(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityStoreError>;
}
