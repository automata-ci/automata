//! GitHub source and changed-file implementation of common trigger application.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretStringRef;
use automata_ci_core::{GitObjectId, TrustSnapshot, TrustTokenRecursion, UnixMillis};
use automata_ci_provider::{
    ClaimedProviderProcessing, ControlCredentialClaim, ControlCredentialProvider,
    ControlCredentialProviderError, ControlCredentialRequest, NormalizedTrigger,
    ProviderControlCredentialId, ProviderControlCredentialWorkerId, ProviderControlOperation,
    ProviderControlOperationSet, ProviderGitRef, ProviderGitRefKind, ProviderProcessingFailure,
    VerifiedProviderTriggerDelivery,
};
use automata_ci_provider_delivery::{
    ProviderDeliveryClock, ProviderProcessingLease, ProviderRuntimeContext, ProviderTriggerOutcome,
    ProviderTrustContext, derive_provider_trust_snapshot,
};
use automata_ci_provider_github::{
    GithubConnectionPolicy, GithubHttpEndpoint, GithubHttpLimits, GithubProviderFactory,
};
use automata_ci_scm::{
    ArchiveFormat, ArchiveLimits, ChangedFileLimits, ChangedFileRead, ChangedFileReader,
    ChangedFileRequest, RepositoryId, RepositorySource, RepositorySourceArchive,
    RepositorySourceConnection, RepositorySourceRedirectPolicy, RepositorySourceRequest,
    RevisionSpec, ScmError, ScmErrorKind, ScmProvider, SnapshotRequest,
};
use automata_ci_workflow_actions::{ProviderChangedFiles, ProviderEventMetadata};
use automata_ci_workflow_service::{
    ProviderWorkflowApplicationError, ProviderWorkflowApplicationOutcome,
    ProviderWorkflowApplicationRequest, ProviderWorkflowApplicationService,
};
use thiserror::Error;

const GITHUB_TRIGGER_PROVIDER_TAIL_MILLIS: i64 = 5 * 60 * 1_000;

/// GitHub trigger processing port composed behind the common runtime adapter.
#[async_trait]
pub trait GithubTriggerHandler: fmt::Debug + Send + Sync {
    /// Processes one authenticated GitHub trigger under exact configuration and a live lease.
    async fn process_trigger(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderTriggerOutcome;
}

/// GitHub I/O adapter feeding the provider-neutral workflow application service.
pub struct GithubWorkflowTriggerHandler {
    application: ProviderWorkflowApplicationService,
    credentials: Arc<dyn ControlCredentialProvider>,
    clock: Arc<dyn ProviderDeliveryClock>,
    factory: GithubProviderFactory,
    user_agent: String,
    limits: GithubHttpLimits,
}

impl GithubWorkflowTriggerHandler {
    /// Composes common application, exact credential authority, and GitHub HTTP policy.
    ///
    /// # Errors
    ///
    /// Rejects an empty or control-bearing user agent.
    pub fn new(
        application: ProviderWorkflowApplicationService,
        credentials: Arc<dyn ControlCredentialProvider>,
        clock: Arc<dyn ProviderDeliveryClock>,
        user_agent: impl Into<String>,
        limits: GithubHttpLimits,
    ) -> Result<Self, GithubWorkflowTriggerHandlerError> {
        let user_agent = user_agent.into();
        if user_agent.trim().is_empty() || user_agent.chars().any(char::is_control) {
            return Err(GithubWorkflowTriggerHandlerError);
        }
        Ok(Self {
            application,
            credentials,
            clock,
            factory: GithubProviderFactory::new(),
            user_agent,
            limits,
        })
    }

    async fn process(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderTriggerOutcome {
        let Ok(repository) = self.repository(context) else {
            return fail_invalid();
        };
        let normalized = trigger.trigger().trigger();
        if matches!(normalized, NormalizedTrigger::Push(push) if push.after().is_none()) {
            return ProviderTriggerOutcome::Complete;
        }
        let source = match self
            .resolve_source(context, trigger, invocation, lease, &repository)
            .await
        {
            Ok(source) => source,
            Err(outcome) => return outcome,
        };
        let recursion = match normalized {
            NormalizedTrigger::RepositoryDispatch(_) => TrustTokenRecursion::Unknown,
            NormalizedTrigger::Push(_)
            | NormalizedTrigger::PullRequest(_)
            | NormalizedTrigger::MergeQueue(_) => TrustTokenRecursion::Suppressed,
        };
        let trust_context = ProviderTrustContext::new(
            *source.archive.revision(),
            source.execution_ref.clone(),
            source.execution_revision,
            recursion,
        );
        let Ok(trust) = derive_provider_trust_snapshot(normalized, &trust_context) else {
            return fail_invalid();
        };
        Box::pin(self.apply_source(
            context,
            trigger,
            invocation,
            lease,
            &repository,
            source,
            trust,
        ))
        .await
    }

    fn repository(
        &self,
        context: &ProviderRuntimeContext,
    ) -> Result<GithubTriggerRepository, GithubWorkflowTriggerHandlerError> {
        let provider = context.provider().manifest();
        let connection = context.connection();
        let policy = GithubConnectionPolicy::decode(connection.configuration().adapter_policy())
            .map_err(|_| GithubWorkflowTriggerHandlerError)?;
        let endpoint = self
            .factory
            .repository_source(provider, &self.user_agent, self.limits)
            .map_err(|_| GithubWorkflowTriggerHandlerError)?;
        let source_connection = self
            .factory
            .source_connection(provider, connection)
            .map_err(|_| GithubWorkflowTriggerHandlerError)?;
        Ok(GithubTriggerRepository {
            endpoint,
            source_connection,
            repository: policy.repository().clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_source(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
        repository: &GithubTriggerRepository,
        source: ResolvedGithubSource,
        trust: TrustSnapshot,
    ) -> ProviderTriggerOutcome {
        let connection = context.connection();
        let normalized = trigger.trigger().trigger();
        let base_metadata = ProviderEventMetadata::from_normalized_trigger(normalized);
        let first = application_request(
            connection,
            trigger,
            invocation,
            lease,
            source.archive.clone(),
            source.execution_ref.clone(),
            trust.clone(),
            base_metadata,
        );
        let first = match first {
            Ok(request) => self.application.apply(request).await,
            Err(_) => return fail_invalid(),
        };
        match first {
            Ok(ProviderWorkflowApplicationOutcome::Applied(_)) => {
                return ProviderTriggerOutcome::Complete;
            }
            Ok(ProviderWorkflowApplicationOutcome::RequiresChangedFiles) => {}
            Err(error) => return application_outcome(&error),
        }
        let metadata = match self
            .changed_files_metadata(context, trigger, invocation, lease, repository)
            .await
        {
            Ok(metadata) => metadata,
            Err(outcome) => return outcome,
        };
        let second = application_request(
            connection,
            trigger,
            invocation,
            lease,
            source.archive,
            source.execution_ref,
            trust,
            metadata,
        );
        match second {
            Ok(request) => match self.application.apply(request).await {
                Ok(ProviderWorkflowApplicationOutcome::Applied(_)) => {
                    ProviderTriggerOutcome::Complete
                }
                Ok(ProviderWorkflowApplicationOutcome::RequiresChangedFiles) => fail_invalid(),
                Err(error) => application_outcome(&error),
            },
            Err(_) => fail_invalid(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_source(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
        repository: &GithubTriggerRepository,
    ) -> Result<ResolvedGithubSource, ProviderTriggerOutcome> {
        let requested_at = self.clock.now().map_err(|_| retry_unavailable())?;
        let operation = ProviderControlOperation::RepositoryRead;
        let request =
            credential_request(context, trigger, invocation, lease, operation, requested_at)?;
        let credential = self
            .credentials
            .acquire(&request)
            .await
            .map_err(credential_error)?;
        if credential.request_digest() != request.digest() || !credential.permits(operation) {
            credential.release().await;
            return Err(fail_invalid());
        }
        let Ok(token) = SecretStringRef::new(credential.expose_secret()) else {
            credential.release().await;
            return Err(fail_invalid());
        };
        let archive_limits = ArchiveLimits::new(
            context
                .connection()
                .configuration()
                .archive_limits()
                .compressed_bytes(),
        )
        .map_err(|_| fail_invalid())?;
        let normalized = trigger.trigger().trigger();
        let result = if let Some(revision) = normalized.workflow_source_revision() {
            fetch_exact_source(repository, normalized, revision, token, archive_limits).await
        } else {
            fetch_default_source(context, repository, token, archive_limits).await
        };
        credential.release().await;
        result.map_err(scm_error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn changed_files_metadata(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
        repository: &GithubTriggerRepository,
    ) -> Result<ProviderEventMetadata, ProviderTriggerOutcome> {
        let operation = match trigger.trigger().trigger() {
            NormalizedTrigger::Push(_) => ProviderControlOperation::CommitChangedFilesRead,
            NormalizedTrigger::PullRequest(_) => {
                ProviderControlOperation::MergeRequestChangedFilesRead
            }
            NormalizedTrigger::MergeQueue(_) | NormalizedTrigger::RepositoryDispatch(_) => {
                return Err(fail_invalid());
            }
        };
        let observed_at = self.clock.now().map_err(|_| retry_unavailable())?;
        let request =
            credential_request(context, trigger, invocation, lease, operation, observed_at)?;
        let credential = self
            .credentials
            .acquire(&request)
            .await
            .map_err(credential_error)?;
        if credential.request_digest() != request.digest() || !credential.permits(operation) {
            credential.release().await;
            return Err(fail_invalid());
        }
        let Ok(token) = SecretStringRef::new(credential.expose_secret()) else {
            credential.release().await;
            return Err(fail_invalid());
        };
        let limits = ChangedFileLimits::new(
            automata_ci_scm::MAX_CHANGED_FILE_COUNT,
            automata_ci_scm::MAX_CHANGED_FILE_PAGES,
            automata_ci_scm::MAX_CHANGED_FILE_RESPONSE_BYTES,
        )
        .map_err(|_| fail_invalid())?;
        let read_request = ChangedFileRequest::authenticated(
            context.connection(),
            trigger.trigger(),
            token,
            limits,
            observed_at,
        )
        .map_err(|_| fail_invalid())?;
        let result = repository.endpoint.read_changed_files(read_request).await;
        credential.release().await;
        let changed = match result.map_err(scm_error)? {
            ChangedFileRead::Complete { files, evidence } => {
                let count = files.len();
                let paths = files.into_iter().flat_map(|file| {
                    file.previous_path()
                        .map(|path| path.as_str().to_owned())
                        .into_iter()
                        .chain(std::iter::once(file.current_path().as_str().to_owned()))
                });
                ProviderChangedFiles::complete_selection_with_evidence(
                    paths,
                    count,
                    evidence.digest(),
                )
            }
            ChangedFileRead::Incomplete { evidence, .. } => {
                ProviderChangedFiles::bypass_path_filters_with_evidence(evidence.digest())
            }
            ChangedFileRead::NotApplicable { .. } => return Err(fail_invalid()),
        };
        ProviderEventMetadata::from_normalized_trigger(trigger.trigger().trigger())
            .with_changed_files(changed)
            .ok_or_else(fail_invalid)
    }
}

#[async_trait]
impl GithubTriggerHandler for GithubWorkflowTriggerHandler {
    async fn process_trigger(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderTriggerOutcome {
        Box::pin(self.process(context, trigger, invocation, lease)).await
    }
}

impl fmt::Debug for GithubWorkflowTriggerHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubWorkflowTriggerHandler")
            .field("application", &self.application)
            .field("credentials", &self.credentials)
            .field("clock", &self.clock)
            .field("factory", &self.factory)
            .field("user_agent", &"[configured]")
            .field("limits", &self.limits)
            .finish()
    }
}

/// Invalid GitHub workflow trigger handler configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub workflow trigger handler configuration is invalid")]
pub struct GithubWorkflowTriggerHandlerError;

struct ResolvedGithubSource {
    archive: RepositorySourceArchive,
    execution_ref: ProviderGitRef,
    execution_revision: GitObjectId,
}

struct GithubTriggerRepository {
    endpoint: GithubHttpEndpoint,
    source_connection: RepositorySourceConnection,
    repository: RepositoryId,
}

async fn fetch_exact_source(
    repository: &GithubTriggerRepository,
    trigger: &NormalizedTrigger,
    revision: GitObjectId,
    token: SecretStringRef<'_>,
    limits: ArchiveLimits,
) -> Result<ResolvedGithubSource, ScmError> {
    let archive = repository
        .endpoint
        .fetch_repository_source(RepositorySourceRequest::authenticated(
            &repository.source_connection,
            &revision,
            token,
            limits,
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ))
        .await?;
    let execution_ref = trigger
        .workflow_execution_ref()
        .cloned()
        .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
    let execution_revision = trigger
        .workflow_execution_revision()
        .ok_or_else(|| ScmError::new(ScmErrorKind::InvalidResponse))?;
    Ok(ResolvedGithubSource {
        archive,
        execution_ref,
        execution_revision,
    })
}

async fn fetch_default_source(
    context: &ProviderRuntimeContext,
    repository: &GithubTriggerRepository,
    token: SecretStringRef<'_>,
    limits: ArchiveLimits,
) -> Result<ResolvedGithubSource, ScmError> {
    let branch = context
        .connection()
        .configuration()
        .default_branch()
        .as_str();
    let revision =
        RevisionSpec::new(branch).map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
    let snapshot = repository
        .endpoint
        .fetch_snapshot(SnapshotRequest::authenticated(
            &repository.repository,
            &revision,
            token,
            limits,
        ))
        .await?;
    let resolved = snapshot.resolved_revision();
    if snapshot.repository() != &repository.repository
        || snapshot.format() != ArchiveFormat::TarGzip
    {
        return Err(ScmError::new(ScmErrorKind::InvalidResponse));
    }
    let archive = RepositorySourceArchive::from_bytes(
        repository.source_connection.clone(),
        resolved,
        snapshot.format(),
        snapshot.into_bytes(),
    );
    let execution_ref =
        ProviderGitRef::new(format!("refs/heads/{branch}"), ProviderGitRefKind::Branch)
            .map_err(|_| ScmError::new(ScmErrorKind::InvalidResponse))?;
    Ok(ResolvedGithubSource {
        archive,
        execution_ref,
        execution_revision: resolved,
    })
}

fn credential_request(
    context: &ProviderRuntimeContext,
    trigger: &VerifiedProviderTriggerDelivery,
    invocation: &ClaimedProviderProcessing,
    lease: &ProviderProcessingLease,
    operation: ProviderControlOperation,
    requested_at: UnixMillis,
) -> Result<ControlCredentialRequest, ProviderTriggerOutcome> {
    let fence = lease.current();
    let receipt = invocation.receipt();
    if fence.invocation_id() != receipt.invocation_id()
        || receipt.source_delivery_id() != Some(trigger.evidence().delivery_id())
    {
        return Err(fail_invalid());
    }
    let required_through = fence
        .expires_at()
        .get()
        .checked_add(GITHUB_TRIGGER_PROVIDER_TAIL_MILLIS)
        .map(UnixMillis::new)
        .ok_or_else(fail_invalid)?;
    let validity_millis = required_through
        .get()
        .checked_sub(requested_at.get())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(fail_invalid)?;
    let credential_id = ProviderControlCredentialId::from_uuid(receipt.invocation_id().as_uuid())
        .map_err(|_| fail_invalid())?;
    let worker_id = ProviderControlCredentialWorkerId::from_uuid(fence.worker_id().as_uuid())
        .map_err(|_| fail_invalid())?;
    let claim = ControlCredentialClaim::new(
        credential_id,
        worker_id,
        fence.token(),
        u64::from(receipt.attempts()),
        fence.expires_at(),
    )
    .map_err(|_| fail_invalid())?;
    let operations = ProviderControlOperationSet::new([operation]).map_err(|_| fail_invalid())?;
    ControlCredentialRequest::new(
        claim,
        context.connection(),
        operations,
        requested_at,
        validity_millis,
    )
    .map_err(|_| fail_invalid())
}

#[allow(clippy::too_many_arguments)]
fn application_request(
    connection: &automata_ci_provider::ProviderConnectionManifest,
    trigger: &VerifiedProviderTriggerDelivery,
    invocation: &ClaimedProviderProcessing,
    lease: &ProviderProcessingLease,
    source: RepositorySourceArchive,
    execution_ref: ProviderGitRef,
    trust: automata_ci_core::TrustSnapshot,
    metadata: ProviderEventMetadata,
) -> Result<
    ProviderWorkflowApplicationRequest,
    automata_ci_workflow_service::ProviderWorkflowApplicationRequestError,
> {
    ProviderWorkflowApplicationRequest::new(
        connection.clone(),
        trigger.clone(),
        invocation.clone(),
        Arc::new(lease.clone()),
        source,
        execution_ref,
        trust,
        metadata,
    )
}

fn application_outcome(error: &ProviderWorkflowApplicationError) -> ProviderTriggerOutcome {
    match error {
        ProviderWorkflowApplicationError::Unavailable => retry_unavailable(),
        ProviderWorkflowApplicationError::InvalidEvidence
        | ProviderWorkflowApplicationError::Inconsistent => fail_invalid(),
    }
}

const fn credential_error(error: ControlCredentialProviderError) -> ProviderTriggerOutcome {
    match error {
        ControlCredentialProviderError::RateLimited
        | ControlCredentialProviderError::Unavailable
        | ControlCredentialProviderError::Indeterminate => retry_unavailable(),
        ControlCredentialProviderError::Unauthorized
        | ControlCredentialProviderError::Forbidden => {
            ProviderTriggerOutcome::Fail(ProviderProcessingFailure::PolicyRejected)
        }
        ControlCredentialProviderError::Unsupported
        | ControlCredentialProviderError::InvalidResponse => fail_invalid(),
    }
}

const fn scm_error(error: ScmError) -> ProviderTriggerOutcome {
    match error.kind() {
        ScmErrorKind::RateLimited | ScmErrorKind::Unavailable => retry_unavailable(),
        ScmErrorKind::Unauthorized | ScmErrorKind::Forbidden => {
            ProviderTriggerOutcome::Fail(ProviderProcessingFailure::PolicyRejected)
        }
        ScmErrorKind::NotFound
        | ScmErrorKind::TooLarge
        | ScmErrorKind::InvalidResponse
        | ScmErrorKind::Integrity => fail_invalid(),
    }
}

const fn retry_unavailable() -> ProviderTriggerOutcome {
    ProviderTriggerOutcome::Retry(ProviderProcessingFailure::DependencyUnavailable)
}

const fn fail_invalid() -> ProviderTriggerOutcome {
    ProviderTriggerOutcome::Fail(ProviderProcessingFailure::InvalidEvidence)
}
