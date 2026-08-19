//! GitHub source and changed-file implementation of common trigger application.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::{GitObjectId, TrustSnapshot, TrustTokenRecursion, UnixMillis};
use automata_ci_provider::{
    ClaimedProviderProcessing, ExternalRepositoryId, NormalizedTrigger, ProviderConnectionRevision,
    ProviderGitRef, ProviderGitRefKind, ProviderProcessingClaimFence, ProviderProcessingFailure,
    RepositoryVisibility, VerifiedProviderTriggerDelivery,
};
use automata_ci_provider_delivery::{
    ProviderDeliveryClock, ProviderProcessingLease, ProviderRuntimeContext, ProviderTriggerOutcome,
    ProviderTrustContext, derive_provider_trust_snapshot,
};
use automata_ci_provider_github::{
    GithubCheckAppId, GithubConnectionPolicy, GithubHttpEndpoint, GithubHttpLimits,
    GithubInstanceConfiguration, GithubProviderFactory,
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

/// One exact GitHub repository operation requested by trigger processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubTriggerCredentialOperation {
    /// Resolve or download workflow source using repository-contents authority.
    ReadSource,
    /// Read a push comparison using repository-contents authority.
    ReadPushChangedFiles,
    /// Read pull-request files using pull-request authority.
    ReadPullRequestChangedFiles,
}

/// Borrowed least-authority request for one GitHub trigger provider operation.
#[derive(Clone, Copy)]
pub struct GithubTriggerCredentialRequest<'a> {
    context: &'a ProviderRuntimeContext,
    trigger: &'a VerifiedProviderTriggerDelivery,
    invocation: &'a ClaimedProviderProcessing,
    fence: ProviderProcessingClaimFence,
    operation: GithubTriggerCredentialOperation,
    app_id: GithubCheckAppId,
    installation_id: u64,
    repository: &'a automata_ci_scm::RepositoryId,
    required_through: UnixMillis,
}

impl GithubTriggerCredentialRequest<'_> {
    /// Returns exact provider and connection configuration.
    #[must_use]
    pub const fn context(&self) -> &ProviderRuntimeContext {
        self.context
    }

    /// Returns immutable normalized trigger evidence.
    #[must_use]
    pub const fn trigger(&self) -> &VerifiedProviderTriggerDelivery {
        self.trigger
    }

    /// Returns the claimed common processing invocation.
    #[must_use]
    pub const fn invocation(&self) -> &ClaimedProviderProcessing {
        self.invocation
    }

    /// Returns the latest processing fence observed for this operation.
    #[must_use]
    pub const fn fence(&self) -> ProviderProcessingClaimFence {
        self.fence
    }

    /// Returns the sole provider operation being authorized.
    #[must_use]
    pub const fn operation(&self) -> GithubTriggerCredentialOperation {
        self.operation
    }

    /// Returns the manifest-pinned GitHub App identity.
    #[must_use]
    pub const fn app_id(&self) -> GithubCheckAppId {
        self.app_id
    }

    /// Returns the connection-pinned installation identity.
    #[must_use]
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    /// Returns the connection-pinned owner/name route.
    #[must_use]
    pub const fn repository(&self) -> &automata_ci_scm::RepositoryId {
        self.repository
    }

    /// Returns the conservative credential lifetime requirement.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }
}

impl fmt::Debug for GithubTriggerCredentialRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubTriggerCredentialRequest")
            .field("context", &"[exact runtime context]")
            .field("trigger", &"[authenticated trigger]")
            .field("invocation", &"[claimed processing invocation]")
            .field("fence", &"[latest processing fence]")
            .field("operation", &self.operation)
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("repository", &"[redacted]")
            .field("required_through", &self.required_through)
            .finish()
    }
}

/// Exact release capability for one move-only trigger credential.
#[async_trait]
pub trait GithubTriggerCredentialRelease: fmt::Debug + Send + Sync {
    /// Releases the credential handoff after its sole provider operation.
    async fn release(self: Box<Self>);
}

/// Move-only GitHub installation credential bound to one processing fence.
#[must_use = "the trigger credential must be used and released"]
pub struct GithubTriggerCredential {
    connection_revision: ProviderConnectionRevision,
    external_repository_id: ExternalRepositoryId,
    fence: ProviderProcessingClaimFence,
    operation: GithubTriggerCredentialOperation,
    app_id: GithubCheckAppId,
    installation_id: u64,
    repository: automata_ci_scm::RepositoryId,
    token: SecretString,
    required_through: UnixMillis,
    usable_until: UnixMillis,
    release: Box<dyn GithubTriggerCredentialRelease>,
}

impl GithubTriggerCredential {
    /// Constructs one exact request-scoped credential handoff.
    ///
    /// # Errors
    ///
    /// Rejects an invalid installation identity or insufficient lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_revision: ProviderConnectionRevision,
        external_repository_id: ExternalRepositoryId,
        fence: ProviderProcessingClaimFence,
        operation: GithubTriggerCredentialOperation,
        app_id: GithubCheckAppId,
        installation_id: u64,
        repository: automata_ci_scm::RepositoryId,
        token: SecretString,
        required_through: UnixMillis,
        usable_until: UnixMillis,
        release: Box<dyn GithubTriggerCredentialRelease>,
    ) -> Result<Self, GithubTriggerCredentialValueError> {
        if installation_id == 0
            || required_through <= fence.expires_at()
            || usable_until <= required_through
        {
            return Err(GithubTriggerCredentialValueError);
        }
        Ok(Self {
            connection_revision,
            external_repository_id,
            fence,
            operation,
            app_id,
            installation_id,
            repository,
            token,
            required_through,
            usable_until,
            release,
        })
    }

    fn matches(&self, request: &GithubTriggerCredentialRequest<'_>) -> bool {
        self.connection_revision == request.context.connection().revision()
            && &self.external_repository_id
                == request
                    .context
                    .connection()
                    .configuration()
                    .repository()
                    .external_id()
            && self.fence == request.fence
            && self.operation == request.operation
            && self.app_id == request.app_id
            && self.installation_id == request.installation_id
            && &self.repository == request.repository
            && self.required_through == request.required_through
            && self.usable_until > request.required_through
    }

    fn token(&self) -> &SecretString {
        &self.token
    }

    async fn release(self) {
        let Self { token, release, .. } = self;
        drop(token);
        release.release().await;
    }
}

impl fmt::Debug for GithubTriggerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubTriggerCredential")
            .field("connection_revision", &self.connection_revision)
            .field("external_repository_id", &"[redacted]")
            .field("fence", &"[exact processing fence]")
            .field("operation", &self.operation)
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("repository", &"[redacted]")
            .field("token", &"[redacted]")
            .field("required_through", &self.required_through)
            .field("usable_until", &self.usable_until)
            .field("release", &"[exact release capability]")
            .finish()
    }
}

/// Invalid trigger credential handoff.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the GitHub trigger credential binding is invalid")]
pub struct GithubTriggerCredentialValueError;

/// Sanitized trigger credential authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubTriggerCredentialProviderError {
    /// Credential infrastructure is temporarily unavailable.
    #[error("the GitHub trigger credential authority is unavailable")]
    Unavailable,
    /// Current authority rejected the exact operation.
    #[error("the GitHub trigger credential authority rejected the operation")]
    Rejected,
    /// Credential authority returned inconsistent binding evidence.
    #[error("the GitHub trigger credential authority is inconsistent")]
    InvariantViolation,
}

/// Least-authority provider for exact GitHub trigger operations.
#[async_trait]
pub trait GithubTriggerCredentialProvider: fmt::Debug + Send + Sync {
    /// Acquires one move-only credential for the exact processing fence and operation.
    async fn acquire(
        &self,
        request: GithubTriggerCredentialRequest<'_>,
    ) -> Result<GithubTriggerCredential, GithubTriggerCredentialProviderError>;
}

/// GitHub I/O adapter feeding the provider-neutral workflow application service.
pub struct GithubWorkflowTriggerHandler {
    application: ProviderWorkflowApplicationService,
    credentials: Arc<dyn GithubTriggerCredentialProvider>,
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
        credentials: Arc<dyn GithubTriggerCredentialProvider>,
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
        let instance = GithubInstanceConfiguration::decode(provider.configuration())
            .map_err(|_| GithubWorkflowTriggerHandlerError)?;
        let policy = GithubConnectionPolicy::decode(connection.configuration().adapter_policy())
            .map_err(|_| GithubWorkflowTriggerHandlerError)?;
        let app_id = GithubCheckAppId::new(instance.app_id().get())
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
            app_id,
            installation_id: policy.installation_id().get(),
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
        let archive_limits = ArchiveLimits::new(
            context
                .connection()
                .configuration()
                .archive_limits()
                .compressed_bytes(),
        )
        .map_err(|_| fail_invalid())?;
        let normalized = trigger.trigger().trigger();
        if context.connection().configuration().visibility() == RepositoryVisibility::Public
            && let Some(revision) = normalized.workflow_source_revision()
        {
            return fetch_exact_source(repository, normalized, revision, None, archive_limits)
                .await
                .map_err(scm_error);
        }
        let request = credential_request(
            context,
            trigger,
            invocation,
            lease,
            GithubTriggerCredentialOperation::ReadSource,
            repository.app_id,
            repository.installation_id,
            &repository.repository,
        )?;
        let credential = self
            .credentials
            .acquire(request)
            .await
            .map_err(credential_error)?;
        if !credential.matches(&request) {
            credential.release().await;
            return Err(fail_invalid());
        }
        let result = if let Some(revision) = normalized.workflow_source_revision() {
            fetch_exact_source(
                repository,
                normalized,
                revision,
                Some(credential.token()),
                archive_limits,
            )
            .await
        } else {
            fetch_default_source(context, repository, credential.token(), archive_limits).await
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
            NormalizedTrigger::Push(_) => GithubTriggerCredentialOperation::ReadPushChangedFiles,
            NormalizedTrigger::PullRequest(_) => {
                GithubTriggerCredentialOperation::ReadPullRequestChangedFiles
            }
            NormalizedTrigger::MergeQueue(_) | NormalizedTrigger::RepositoryDispatch(_) => {
                return Err(fail_invalid());
            }
        };
        let request = credential_request(
            context,
            trigger,
            invocation,
            lease,
            operation,
            repository.app_id,
            repository.installation_id,
            &repository.repository,
        )?;
        let credential = self
            .credentials
            .acquire(request)
            .await
            .map_err(credential_error)?;
        if !credential.matches(&request) {
            credential.release().await;
            return Err(fail_invalid());
        }
        let limits = ChangedFileLimits::new(
            automata_ci_scm::MAX_CHANGED_FILE_COUNT,
            automata_ci_scm::MAX_CHANGED_FILE_PAGES,
            automata_ci_scm::MAX_CHANGED_FILE_RESPONSE_BYTES,
        )
        .map_err(|_| fail_invalid())?;
        let observed_at = self.clock.now().map_err(|_| retry_unavailable())?;
        let read_request = ChangedFileRequest::authenticated(
            context.connection(),
            trigger.trigger(),
            credential.token(),
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
    app_id: GithubCheckAppId,
    installation_id: u64,
    repository: RepositoryId,
}

async fn fetch_exact_source(
    repository: &GithubTriggerRepository,
    trigger: &NormalizedTrigger,
    revision: GitObjectId,
    token: Option<&SecretString>,
    limits: ArchiveLimits,
) -> Result<ResolvedGithubSource, ScmError> {
    let request = match token {
        Some(token) => RepositorySourceRequest::authenticated(
            &repository.source_connection,
            &revision,
            token,
            limits,
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ),
        None => RepositorySourceRequest::public(
            &repository.source_connection,
            &revision,
            limits,
            RepositorySourceRedirectPolicy::ConfiguredArchiveOrigin,
        ),
    };
    let archive = repository.endpoint.fetch_repository_source(request).await?;
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
    token: &SecretString,
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

#[allow(clippy::too_many_arguments)]
fn credential_request<'a>(
    context: &'a ProviderRuntimeContext,
    trigger: &'a VerifiedProviderTriggerDelivery,
    invocation: &'a ClaimedProviderProcessing,
    lease: &ProviderProcessingLease,
    operation: GithubTriggerCredentialOperation,
    app_id: GithubCheckAppId,
    installation_id: u64,
    repository: &'a automata_ci_scm::RepositoryId,
) -> Result<GithubTriggerCredentialRequest<'a>, ProviderTriggerOutcome> {
    let fence = lease.current();
    if fence.invocation_id() != invocation.receipt().invocation_id()
        || invocation.receipt().source_delivery_id() != Some(trigger.evidence().delivery_id())
    {
        return Err(fail_invalid());
    }
    let required_through = fence
        .expires_at()
        .get()
        .checked_add(GITHUB_TRIGGER_PROVIDER_TAIL_MILLIS)
        .map(UnixMillis::new)
        .ok_or_else(fail_invalid)?;
    Ok(GithubTriggerCredentialRequest {
        context,
        trigger,
        invocation,
        fence,
        operation,
        app_id,
        installation_id,
        repository,
        required_through,
    })
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

const fn credential_error(error: GithubTriggerCredentialProviderError) -> ProviderTriggerOutcome {
    match error {
        GithubTriggerCredentialProviderError::Unavailable => retry_unavailable(),
        GithubTriggerCredentialProviderError::Rejected => {
            ProviderTriggerOutcome::Fail(ProviderProcessingFailure::PolicyRejected)
        }
        GithubTriggerCredentialProviderError::InvariantViolation => fail_invalid(),
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
