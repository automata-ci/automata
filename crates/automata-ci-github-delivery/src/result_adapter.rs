//! GitHub Checks implementation of the common provider result boundary.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_provider::{
    ClaimedProviderResult, ExternalRepositoryId, ExternalResultId, ProviderCapabilities,
    ProviderConnectionId, ProviderConnectionRevision, ProviderResultAnnotationLevel,
    ProviderResultClaimFence, ProviderResultConclusion, ProviderResultContinuation,
    ProviderResultPhase, ProviderResultPublicationModel, ProviderResultRetryAfter,
    ProviderSchemaVersion, ProviderTypeId, ResultPublisherError,
};
use automata_ci_provider_delivery::{
    ProviderResultAdapter, ProviderResultAdapterOutcome, ProviderResultLease,
    ProviderResultObservation, ProviderRuntimeContext,
};
use automata_ci_provider_github::{
    GithubCheckAnnotation, GithubCheckAnnotationLevel, GithubCheckAppId, GithubCheckCompletion,
    GithubCheckConclusion, GithubCheckDetailsUrl, GithubCheckExternalId, GithubCheckName,
    GithubCheckOutput, GithubCheckRetryEvidence, GithubCheckRunCreateOutcome, GithubCheckRunId,
    GithubCheckRunIdentity, GithubCheckRunReconciliation, GithubCheckRunState,
    GithubCheckSuiteCreateOutcome, GithubCheckSuiteId, GithubCheckTimestamp, GithubChecksError,
    GithubConnectionPolicy, GithubHttpEndpoint, GithubHttpLimits, GithubInstanceConfiguration,
    GithubObservedCheckConclusion, GithubProviderFactory,
};
use automata_ci_scm::RepositoryId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const CURSOR_SCHEMA: u16 = 1;
const RESULT_STATE_DOMAIN: &[u8] = b"automata.github.common-result-state.v1\0";
const DEFAULT_VISIBILITY_MARGIN_MILLIS: i64 = 2_000;
const MAX_GITHUB_ANNOTATIONS_PER_REQUEST: usize = 50;
const GITHUB_RESULT_PROVIDER_TAIL_MILLIS: i64 = 10 * 60 * 1_000;

/// One exact GitHub Checks action requested from credential authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubResultOperation {
    /// Create or resolve the App's Check Suite.
    EnsureSuite,
    /// Create one deterministically identified Check Run.
    CreateRun,
    /// Reconcile a possibly applied Check Run creation.
    ReconcileRun,
    /// Read and validate one bound Check Run.
    ReadRun,
    /// Move one queued Check Run to in-progress.
    StartRun,
    /// Publish one terminal Check Run state and presentation.
    CompleteRun,
    /// Read and reconcile append-only Check annotations.
    ReadAnnotations,
    /// Append one exact bounded annotation batch.
    AppendAnnotations,
}

/// Borrowed exact authority request for one common result claim.
pub struct GithubResultCredentialRequest<'a> {
    context: &'a ProviderRuntimeContext,
    claimed: &'a ClaimedProviderResult,
    claim: ProviderResultClaimFence,
    operation: GithubResultOperation,
    app_id: GithubCheckAppId,
    installation_id: u64,
    repository: &'a RepositoryId,
    required_through: UnixMillis,
}

impl GithubResultCredentialRequest<'_> {
    /// Returns the exact provider runtime context.
    #[must_use]
    pub const fn context(&self) -> &ProviderRuntimeContext {
        self.context
    }

    /// Returns the claim-frozen desired result and publication payload.
    #[must_use]
    pub const fn claimed(&self) -> &ClaimedProviderResult {
        self.claimed
    }

    /// Returns the latest durable publication fence observed for this operation.
    #[must_use]
    pub const fn claim(&self) -> ProviderResultClaimFence {
        self.claim
    }

    /// Returns the sole provider operation being authorized.
    #[must_use]
    pub const fn operation(&self) -> GithubResultOperation {
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
    pub const fn repository(&self) -> &RepositoryId {
        self.repository
    }

    /// Returns the conservative credential lifetime requirement.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }
}

impl fmt::Debug for GithubResultCredentialRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubResultCredentialRequest")
            .field("context", &"[exact runtime context]")
            .field("claim", &"[exact result claim]")
            .field("operation", &self.operation)
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("repository", &"[redacted]")
            .field("required_through", &self.required_through)
            .finish()
    }
}

/// Exact release capability for one move-only result credential.
#[async_trait]
pub trait GithubResultCredentialRelease: fmt::Debug + Send + Sync {
    /// Releases the credential handoff after its one provider operation.
    async fn release(self: Box<Self>);
}

/// Move-only GitHub installation credential bound to one common result claim.
#[must_use = "the credential must be used and released"]
pub struct GithubResultCredential {
    connection_id: ProviderConnectionId,
    connection_revision: ProviderConnectionRevision,
    external_repository_id: ExternalRepositoryId,
    claim: automata_ci_provider::ProviderResultClaimFence,
    operation: GithubResultOperation,
    app_id: GithubCheckAppId,
    installation_id: u64,
    repository: RepositoryId,
    token: SecretString,
    required_through: UnixMillis,
    conservative_expires_at: UnixMillis,
    release: Box<dyn GithubResultCredentialRelease>,
}

impl GithubResultCredential {
    /// Constructs one exact request-scoped credential handoff.
    ///
    /// # Errors
    ///
    /// Rejects non-positive installation identity or an unusable lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_id: ProviderConnectionId,
        connection_revision: ProviderConnectionRevision,
        external_repository_id: ExternalRepositoryId,
        claim: automata_ci_provider::ProviderResultClaimFence,
        operation: GithubResultOperation,
        app_id: GithubCheckAppId,
        installation_id: u64,
        repository: RepositoryId,
        token: SecretString,
        required_through: UnixMillis,
        conservative_expires_at: UnixMillis,
        release: Box<dyn GithubResultCredentialRelease>,
    ) -> Result<Self, GithubResultCredentialValueError> {
        if installation_id == 0
            || required_through <= claim.expires_at()
            || conservative_expires_at <= required_through
        {
            return Err(GithubResultCredentialValueError::InvalidBinding);
        }
        Ok(Self {
            connection_id,
            connection_revision,
            external_repository_id,
            claim,
            operation,
            app_id,
            installation_id,
            repository,
            token,
            required_through,
            conservative_expires_at,
            release,
        })
    }

    fn token(&self) -> &SecretString {
        &self.token
    }

    fn start_release(self) {
        let Self { token, release, .. } = self;
        drop(token);
        tokio::spawn(release.release());
    }
}

impl fmt::Debug for GithubResultCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubResultCredential")
            .field("connection_id", &self.connection_id)
            .field("connection_revision", &self.connection_revision)
            .field("external_repository_id", &"[redacted]")
            .field("claim", &"[exact result claim]")
            .field("operation", &self.operation)
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("repository", &"[redacted]")
            .field("token", &"[redacted]")
            .field("required_through", &self.required_through)
            .field("conservative_expires_at", &self.conservative_expires_at)
            .field("release", &"[exact release capability]")
            .finish()
    }
}

/// Invalid result credential handoff.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubResultCredentialValueError {
    /// A binding or conservative lifetime is invalid.
    #[error("the GitHub result credential binding is invalid")]
    InvalidBinding,
}

/// Sanitized result credential authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubResultCredentialProviderError {
    /// Credential authority is temporarily unavailable.
    #[error("the GitHub result credential authority is unavailable")]
    Unavailable,
    /// Current policy rejected the exact operation.
    #[error("the GitHub result credential authority rejected the operation")]
    Rejected,
    /// Credential authority returned inconsistent state.
    #[error("the GitHub result credential authority is inconsistent")]
    InvariantViolation,
}

/// Least-authority provider for one request-scoped result credential.
#[async_trait]
pub trait GithubResultCredentialProvider: fmt::Debug + Send + Sync {
    /// Acquires one move-only credential for the exact claim and operation.
    async fn acquire(
        &self,
        request: GithubResultCredentialRequest<'_>,
    ) -> Result<GithubResultCredential, GithubResultCredentialProviderError>;
}

/// GitHub implementation of the common mutable rich-check result model.
pub struct GithubResultProviderAdapter {
    provider_type: ProviderTypeId,
    capabilities: ProviderCapabilities,
    factory: GithubProviderFactory,
    credentials: Arc<dyn GithubResultCredentialProvider>,
    user_agent: String,
    limits: GithubHttpLimits,
    visibility_margin_millis: i64,
}

impl GithubResultProviderAdapter {
    /// Constructs the adapter from exact credential authority and HTTP policy.
    ///
    /// # Errors
    ///
    /// Rejects an empty user agent or an invalid built-in capability declaration.
    pub fn new(
        credentials: Arc<dyn GithubResultCredentialProvider>,
        user_agent: impl Into<String>,
        limits: GithubHttpLimits,
    ) -> Result<Self, GithubResultProviderAdapterError> {
        let user_agent = user_agent.into();
        if user_agent.trim().is_empty() || user_agent.chars().any(char::is_control) {
            return Err(GithubResultProviderAdapterError::InvalidConfiguration);
        }
        Ok(Self {
            provider_type: ProviderTypeId::new("github")
                .map_err(|_| GithubResultProviderAdapterError::InvalidConfiguration)?,
            capabilities: GithubProviderFactory::capabilities()
                .map_err(|_| GithubResultProviderAdapterError::InvalidConfiguration)?,
            factory: GithubProviderFactory::new(),
            credentials,
            user_agent,
            limits,
            visibility_margin_millis: DEFAULT_VISIBILITY_MARGIN_MILLIS,
        })
    }

    async fn publish(
        &self,
        context: &ProviderRuntimeContext,
        claimed: &ClaimedProviderResult,
        lease: &ProviderResultLease,
    ) -> ProviderResultAdapterOutcome {
        let Ok(configuration) =
            GithubInstanceConfiguration::decode(context.provider().manifest().configuration())
        else {
            return failed(ResultPublisherError::Conflict);
        };
        let Ok(policy) =
            GithubConnectionPolicy::decode(context.connection().configuration().adapter_policy())
        else {
            return failed(ResultPublisherError::Conflict);
        };
        let Ok(app_id) = GithubCheckAppId::new(configuration.app_id().get()) else {
            return failed(ResultPublisherError::Conflict);
        };
        let Ok(endpoint) = self.factory.repository_source(
            context.provider().manifest(),
            &self.user_agent,
            self.limits,
        ) else {
            return failed(ResultPublisherError::Conflict);
        };
        let state = match recover_state(claimed) {
            Ok(state) => state,
            Err(error) => return failed(error),
        };
        if let GithubResultState::ReconcileRun {
            not_before_millis, ..
        } = state
            && claimed.claimed_at().get() < not_before_millis
        {
            let delay = u64::try_from(not_before_millis - claimed.claimed_at().get()).ok();
            return retry(state, delay.and_then(retry_after));
        }
        let operation = state.operation();
        let claim = lease.current();
        let Some(required_through) = claim
            .expires_at()
            .get()
            .checked_add(GITHUB_RESULT_PROVIDER_TAIL_MILLIS)
            .map(UnixMillis::new)
        else {
            return failed(ResultPublisherError::Conflict);
        };
        let request = GithubResultCredentialRequest {
            context,
            claimed,
            claim,
            operation,
            app_id,
            installation_id: policy.installation_id().get(),
            repository: policy.repository(),
            required_through,
        };
        let credential = match self.credentials.acquire(request).await {
            Ok(credential) => credential,
            Err(GithubResultCredentialProviderError::Unavailable) => return retry(state, None),
            Err(GithubResultCredentialProviderError::Rejected) => {
                return failed(ResultPublisherError::Forbidden);
            }
            Err(GithubResultCredentialProviderError::InvariantViolation) => {
                return failed(ResultPublisherError::Conflict);
            }
        };
        if !credential_matches(
            &credential,
            context,
            claim,
            operation,
            app_id,
            &policy,
            required_through,
        ) {
            credential.start_release();
            return failed(ResultPublisherError::Conflict);
        }
        if lease.current() != claim {
            credential.start_release();
            return retry(state, None);
        }
        let outcome = self
            .perform(
                &endpoint,
                policy.repository(),
                app_id,
                claimed,
                state,
                &credential,
            )
            .await;
        credential.start_release();
        outcome
    }

    #[allow(clippy::too_many_lines)]
    async fn perform(
        &self,
        endpoint: &GithubHttpEndpoint,
        repository: &RepositoryId,
        app_id: GithubCheckAppId,
        claimed: &ClaimedProviderResult,
        state: GithubResultState,
        credential: &GithubResultCredential,
    ) -> ProviderResultAdapterOutcome {
        match state {
            GithubResultState::EnsureSuite => match endpoint
                .create_check_suite(
                    repository,
                    &claimed.subject().object(),
                    app_id,
                    credential.token(),
                )
                .await
            {
                Ok(
                    GithubCheckSuiteCreateOutcome::Created(suite)
                    | GithubCheckSuiteCreateOutcome::Existing(suite),
                ) => retry(
                    GithubResultState::SuiteBound {
                        suite_id: suite.id().get(),
                    },
                    None,
                ),
                Ok(GithubCheckSuiteCreateOutcome::Indeterminate(indeterminate)) => retry(
                    GithubResultState::EnsureSuite,
                    retry_from_evidence(indeterminate.retry_evidence()),
                ),
                Err(error) => http_error(error, GithubResultState::EnsureSuite, None),
            },
            GithubResultState::SuiteBound { suite_id } => {
                let identity = match identity(claimed, app_id, suite_id) {
                    Ok(identity) => identity,
                    Err(error) => return failed(error),
                };
                match endpoint
                    .create_check_run(repository, &identity, credential.token())
                    .await
                {
                    Ok(GithubCheckRunCreateOutcome::Created(run)) => retry(
                        GithubResultState::RunBound {
                            suite_id,
                            run_id: run.id().get(),
                        },
                        None,
                    ),
                    Ok(GithubCheckRunCreateOutcome::Indeterminate(indeterminate)) => {
                        let not_before_millis = claimed
                            .claimed_at()
                            .get()
                            .saturating_add(request_timeout_millis(endpoint))
                            .saturating_add(self.visibility_margin_millis);
                        retry(
                            GithubResultState::ReconcileRun {
                                suite_id,
                                not_before_millis,
                            },
                            retry_from_evidence(indeterminate.retry_evidence()),
                        )
                    }
                    Err(error) => http_error(
                        error,
                        GithubResultState::SuiteBound { suite_id },
                        Some(GithubResultState::ReconcileRun {
                            suite_id,
                            not_before_millis: claimed
                                .claimed_at()
                                .get()
                                .saturating_add(request_timeout_millis(endpoint))
                                .saturating_add(self.visibility_margin_millis),
                        }),
                    ),
                }
            }
            GithubResultState::ReconcileRun { suite_id, .. } => {
                let identity = match identity(claimed, app_id, suite_id) {
                    Ok(identity) => identity,
                    Err(error) => return failed(error),
                };
                match endpoint
                    .reconcile_check_run_creation(repository, &identity, credential.token())
                    .await
                {
                    Ok(GithubCheckRunReconciliation::Exact(run)) => retry(
                        GithubResultState::RunBound {
                            suite_id,
                            run_id: run.id().get(),
                        },
                        None,
                    ),
                    Ok(GithubCheckRunReconciliation::Missing) => {
                        retry(GithubResultState::SuiteBound { suite_id }, None)
                    }
                    Ok(GithubCheckRunReconciliation::Ambiguous) => {
                        failed(ResultPublisherError::Conflict)
                    }
                    Err(error) => http_error(
                        error,
                        GithubResultState::ReconcileRun {
                            suite_id,
                            not_before_millis: claimed.claimed_at().get(),
                        },
                        None,
                    ),
                }
            }
            GithubResultState::RunBound { suite_id, run_id } => {
                self.read_run(
                    endpoint, repository, app_id, claimed, suite_id, run_id, credential,
                )
                .await
            }
            GithubResultState::StartRun { suite_id, run_id } => {
                let identity = match identity(claimed, app_id, suite_id) {
                    Ok(identity) => identity,
                    Err(error) => return failed(error),
                };
                let Ok(timestamp) =
                    GithubCheckTimestamp::from_unix_millis(claimed.subject().created_at().get())
                else {
                    return failed(ResultPublisherError::InvalidResponse);
                };
                match endpoint
                    .start_check_run(
                        repository,
                        github_run_id(run_id),
                        &identity,
                        &timestamp,
                        credential.token(),
                    )
                    .await
                {
                    Ok(_) => published(claimed, suite_id, run_id),
                    Err(error) => http_error(
                        error,
                        GithubResultState::StartRun { suite_id, run_id },
                        Some(GithubResultState::RunBound { suite_id, run_id }),
                    ),
                }
            }
            GithubResultState::CompleteRun { suite_id, run_id } => {
                self.complete_run(
                    endpoint, repository, app_id, claimed, suite_id, run_id, credential,
                )
                .await
            }
            GithubResultState::Annotations {
                suite_id,
                run_id,
                confirmed,
                uncertain_end,
            } => {
                self.reconcile_annotations(
                    endpoint,
                    repository,
                    claimed,
                    suite_id,
                    run_id,
                    confirmed,
                    uncertain_end,
                    credential,
                )
                .await
            }
            GithubResultState::AppendAnnotations {
                suite_id,
                run_id,
                from,
                to,
            } => {
                self.append_annotations(
                    endpoint, repository, app_id, claimed, suite_id, run_id, from, to, credential,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_run(
        &self,
        endpoint: &GithubHttpEndpoint,
        repository: &RepositoryId,
        app_id: GithubCheckAppId,
        claimed: &ClaimedProviderResult,
        suite_id: u64,
        native_run_id: u64,
        credential: &GithubResultCredential,
    ) -> ProviderResultAdapterOutcome {
        let identity = match identity(claimed, app_id, suite_id) {
            Ok(identity) => identity,
            Err(error) => return failed(error),
        };
        let current = match endpoint
            .get_check_run(
                repository,
                github_run_id(native_run_id),
                &identity,
                credential.token(),
            )
            .await
        {
            Ok(current) => current,
            Err(error) => {
                return http_error(
                    error,
                    GithubResultState::RunBound {
                        suite_id,
                        run_id: native_run_id,
                    },
                    None,
                );
            }
        };
        match claimed.desired().phase() {
            ProviderResultPhase::Queued if current.state() == GithubCheckRunState::Queued => {
                published(claimed, suite_id, native_run_id)
            }
            ProviderResultPhase::Running if current.state() == GithubCheckRunState::Queued => {
                retry(
                    GithubResultState::StartRun {
                        suite_id,
                        run_id: native_run_id,
                    },
                    None,
                )
            }
            ProviderResultPhase::Running if current.state() == GithubCheckRunState::InProgress => {
                published(claimed, suite_id, native_run_id)
            }
            ProviderResultPhase::Completed
                if current.state() == expected_completed(claimed.desired().conclusion()) =>
            {
                completed_or_annotations(claimed, suite_id, native_run_id)
            }
            ProviderResultPhase::Completed
                if matches!(
                    current.state(),
                    GithubCheckRunState::Queued | GithubCheckRunState::InProgress
                ) =>
            {
                retry(
                    GithubResultState::CompleteRun {
                        suite_id,
                        run_id: native_run_id,
                    },
                    None,
                )
            }
            _ => failed(ResultPublisherError::Conflict),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_run(
        &self,
        endpoint: &GithubHttpEndpoint,
        repository: &RepositoryId,
        app_id: GithubCheckAppId,
        claimed: &ClaimedProviderResult,
        suite_id: u64,
        native_run_id: u64,
        credential: &GithubResultCredential,
    ) -> ProviderResultAdapterOutcome {
        let identity = match identity(claimed, app_id, suite_id) {
            Ok(identity) => identity,
            Err(error) => return failed(error),
        };
        let Some(provider_conclusion) = claimed.desired().conclusion() else {
            return failed(ResultPublisherError::InvalidResponse);
        };
        let conclusion = conclusion(provider_conclusion);
        let Ok(completed_at) =
            GithubCheckTimestamp::from_unix_millis(claimed.desired().updated_at().get())
        else {
            return failed(ResultPublisherError::InvalidResponse);
        };
        let Ok(started_at) =
            GithubCheckTimestamp::from_unix_millis(claimed.subject().created_at().get())
        else {
            return failed(ResultPublisherError::InvalidResponse);
        };
        let output = match output(claimed) {
            Ok(output) => output,
            Err(error) => return failed(error),
        };
        let Ok(completion) = GithubCheckCompletion::new(
            conclusion,
            Some(&started_at),
            &completed_at,
            Some(&output),
            &[],
        ) else {
            return failed(ResultPublisherError::InvalidResponse);
        };
        match endpoint
            .complete_check_run(
                repository,
                github_run_id(native_run_id),
                &identity,
                completion,
                credential.token(),
            )
            .await
        {
            Ok(_) => completed_or_annotations(claimed, suite_id, native_run_id),
            Err(error) => http_error(
                error,
                GithubResultState::CompleteRun {
                    suite_id,
                    run_id: native_run_id,
                },
                Some(GithubResultState::RunBound {
                    suite_id,
                    run_id: native_run_id,
                }),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_annotations(
        &self,
        endpoint: &GithubHttpEndpoint,
        repository: &RepositoryId,
        claimed: &ClaimedProviderResult,
        suite_id: u64,
        native_run_id: u64,
        confirmed: usize,
        uncertain_end: Option<usize>,
        credential: &GithubResultCredential,
    ) -> ProviderResultAdapterOutcome {
        let desired = match annotations(claimed) {
            Ok(annotations) => annotations,
            Err(error) => return failed(error),
        };
        if confirmed > desired.len()
            || uncertain_end.is_some_and(|end| end <= confirmed || end > desired.len())
        {
            return failed(ResultPublisherError::Conflict);
        }
        let current = match endpoint
            .list_check_run_annotations(
                repository,
                github_run_id(native_run_id),
                credential.token(),
            )
            .await
        {
            Ok(current) => current,
            Err(error) => {
                return http_error(
                    error,
                    GithubResultState::Annotations {
                        suite_id,
                        run_id: native_run_id,
                        confirmed,
                        uncertain_end,
                    },
                    None,
                );
            }
        };
        let reconciled = match uncertain_end {
            Some(end) if current == desired[..end] => end,
            Some(_) | None if current == desired[..confirmed] => confirmed,
            _ => return failed(ResultPublisherError::Conflict),
        };
        if reconciled == desired.len() {
            return published(claimed, suite_id, native_run_id);
        }
        let end = reconciled
            .saturating_add(MAX_GITHUB_ANNOTATIONS_PER_REQUEST)
            .min(desired.len());
        retry(
            GithubResultState::AppendAnnotations {
                suite_id,
                run_id: native_run_id,
                from: reconciled,
                to: end,
            },
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_annotations(
        &self,
        endpoint: &GithubHttpEndpoint,
        repository: &RepositoryId,
        app_id: GithubCheckAppId,
        claimed: &ClaimedProviderResult,
        suite_id: u64,
        native_run_id: u64,
        from: usize,
        to: usize,
        credential: &GithubResultCredential,
    ) -> ProviderResultAdapterOutcome {
        let desired = match annotations(claimed) {
            Ok(annotations) => annotations,
            Err(error) => return failed(error),
        };
        if from >= to || to > desired.len() || to - from > MAX_GITHUB_ANNOTATIONS_PER_REQUEST {
            return failed(ResultPublisherError::Conflict);
        }
        let identity = match identity(claimed, app_id, suite_id) {
            Ok(identity) => identity,
            Err(error) => return failed(error),
        };
        let Some(provider_conclusion) = claimed.desired().conclusion() else {
            return failed(ResultPublisherError::InvalidResponse);
        };
        let conclusion = conclusion(provider_conclusion);
        let output = match output(claimed) {
            Ok(output) => output,
            Err(error) => return failed(error),
        };
        match endpoint
            .append_check_run_annotations(
                repository,
                github_run_id(native_run_id),
                &identity,
                conclusion,
                &output,
                &desired[from..to],
                credential.token(),
            )
            .await
        {
            Ok(_) if to == desired.len() => published(claimed, suite_id, native_run_id),
            Ok(_) => retry(
                GithubResultState::Annotations {
                    suite_id,
                    run_id: native_run_id,
                    confirmed: to,
                    uncertain_end: None,
                },
                None,
            ),
            Err(error) => http_error(
                error,
                GithubResultState::AppendAnnotations {
                    suite_id,
                    run_id: native_run_id,
                    from,
                    to,
                },
                Some(GithubResultState::Annotations {
                    suite_id,
                    run_id: native_run_id,
                    confirmed: from,
                    uncertain_end: Some(to),
                }),
            ),
        }
    }
}

impl fmt::Debug for GithubResultProviderAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubResultProviderAdapter")
            .field("provider_type", &self.provider_type)
            .field("capabilities", &self.capabilities)
            .field("factory", &self.factory)
            .field("credentials", &self.credentials)
            .field("user_agent", &"[configured]")
            .field("limits", &self.limits)
            .field("visibility_margin_millis", &self.visibility_margin_millis)
            .finish()
    }
}

#[async_trait]
impl ProviderResultAdapter for GithubResultProviderAdapter {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn publication_model(&self) -> ProviderResultPublicationModel {
        ProviderResultPublicationModel::MutableRichCheck
    }

    async fn publish_result(
        &self,
        context: &ProviderRuntimeContext,
        claimed: &ClaimedProviderResult,
        lease: &ProviderResultLease,
    ) -> ProviderResultAdapterOutcome {
        self.publish(context, claimed, lease).await
    }
}

/// Invalid GitHub common-result adapter construction.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubResultProviderAdapterError {
    /// Static provider capabilities or HTTP identity are invalid.
    #[error("the GitHub result adapter configuration is invalid")]
    InvalidConfiguration,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum GithubResultState {
    EnsureSuite,
    SuiteBound {
        suite_id: u64,
    },
    ReconcileRun {
        suite_id: u64,
        not_before_millis: i64,
    },
    RunBound {
        suite_id: u64,
        run_id: u64,
    },
    StartRun {
        suite_id: u64,
        run_id: u64,
    },
    CompleteRun {
        suite_id: u64,
        run_id: u64,
    },
    Annotations {
        suite_id: u64,
        run_id: u64,
        confirmed: usize,
        uncertain_end: Option<usize>,
    },
    AppendAnnotations {
        suite_id: u64,
        run_id: u64,
        from: usize,
        to: usize,
    },
}

impl GithubResultState {
    const fn operation(self) -> GithubResultOperation {
        match self {
            Self::EnsureSuite => GithubResultOperation::EnsureSuite,
            Self::SuiteBound { .. } => GithubResultOperation::CreateRun,
            Self::ReconcileRun { .. } => GithubResultOperation::ReconcileRun,
            Self::RunBound { .. } => GithubResultOperation::ReadRun,
            Self::StartRun { .. } => GithubResultOperation::StartRun,
            Self::CompleteRun { .. } => GithubResultOperation::CompleteRun,
            Self::Annotations { .. } => GithubResultOperation::ReadAnnotations,
            Self::AppendAnnotations { .. } => GithubResultOperation::AppendAnnotations,
        }
    }

    const fn binding(self) -> Option<(u64, u64)> {
        match self {
            Self::RunBound { suite_id, run_id }
            | Self::StartRun { suite_id, run_id }
            | Self::CompleteRun { suite_id, run_id }
            | Self::Annotations {
                suite_id, run_id, ..
            }
            | Self::AppendAnnotations {
                suite_id, run_id, ..
            } => Some((suite_id, run_id)),
            Self::EnsureSuite | Self::SuiteBound { .. } | Self::ReconcileRun { .. } => None,
        }
    }
}

fn recover_state(
    claimed: &ClaimedProviderResult,
) -> Result<GithubResultState, ResultPublisherError> {
    let binding = claimed
        .binding()
        .map(|binding| parse_binding(binding.external_id()))
        .transpose()?;
    let state = match claimed.continuation() {
        Some(continuation) => decode_state(continuation)?,
        None => binding.map_or(GithubResultState::EnsureSuite, |(suite_id, run_id)| {
            GithubResultState::RunBound { suite_id, run_id }
        }),
    };
    match (binding, state.binding()) {
        (Some(binding), Some(state_binding)) if binding == state_binding => {}
        (Some(_), Some(_) | None) => return Err(ResultPublisherError::Conflict),
        (None, _) => {}
    }
    if !valid_state(state) {
        return Err(ResultPublisherError::Conflict);
    }
    Ok(state)
}

fn valid_state(state: GithubResultState) -> bool {
    let valid_suite = |suite_id| GithubCheckSuiteId::new(suite_id).is_ok();
    let valid_binding =
        |suite_id, run_id| valid_suite(suite_id) && GithubCheckRunId::new(run_id).is_ok();
    match state {
        GithubResultState::EnsureSuite => true,
        GithubResultState::SuiteBound { suite_id } => valid_suite(suite_id),
        GithubResultState::ReconcileRun {
            suite_id,
            not_before_millis,
        } => valid_suite(suite_id) && not_before_millis >= 0,
        GithubResultState::RunBound { suite_id, run_id }
        | GithubResultState::StartRun { suite_id, run_id }
        | GithubResultState::CompleteRun { suite_id, run_id }
        | GithubResultState::Annotations {
            suite_id, run_id, ..
        }
        | GithubResultState::AppendAnnotations {
            suite_id, run_id, ..
        } => valid_binding(suite_id, run_id),
    }
}

fn decode_state(
    continuation: &ProviderResultContinuation,
) -> Result<GithubResultState, ResultPublisherError> {
    if continuation.schema_version().get() != CURSOR_SCHEMA {
        return Err(ResultPublisherError::Conflict);
    }
    let state = serde_json::from_slice::<GithubResultState>(continuation.bytes())
        .map_err(|_| ResultPublisherError::Conflict)?;
    let canonical = serde_json::to_vec(&state).map_err(|_| ResultPublisherError::Conflict)?;
    if canonical != continuation.bytes() {
        return Err(ResultPublisherError::Conflict);
    }
    Ok(state)
}

fn retry(
    state: GithubResultState,
    retry_after: Option<ProviderResultRetryAfter>,
) -> ProviderResultAdapterOutcome {
    let continuation = ProviderSchemaVersion::new(CURSOR_SCHEMA)
        .ok()
        .zip(serde_json::to_vec(&state).ok())
        .and_then(|(schema, bytes)| ProviderResultContinuation::new(schema, bytes).ok());
    match continuation {
        Some(continuation) => ProviderResultAdapterOutcome::Retry {
            continuation: Some(continuation),
            retry_after,
        },
        None => failed(ResultPublisherError::InvalidResponse),
    }
}

const fn failed(error: ResultPublisherError) -> ProviderResultAdapterOutcome {
    ProviderResultAdapterOutcome::Failed(error)
}

fn identity(
    claimed: &ClaimedProviderResult,
    app_id: GithubCheckAppId,
    suite_id: u64,
) -> Result<GithubCheckRunIdentity, ResultPublisherError> {
    Ok(GithubCheckRunIdentity::new(
        app_id,
        GithubCheckSuiteId::new(suite_id).map_err(|_| ResultPublisherError::Conflict)?,
        claimed.subject().object(),
        GithubCheckName::new(claimed.subject().name().as_str())
            .map_err(|_| ResultPublisherError::InvalidResponse)?,
        GithubCheckExternalId::new(claimed.marker().as_str())
            .map_err(|_| ResultPublisherError::InvalidResponse)?,
        GithubCheckDetailsUrl::new(claimed.subject().details_url().as_url().clone())
            .map_err(|_| ResultPublisherError::InvalidResponse)?,
    ))
}

fn github_run_id(value: u64) -> GithubCheckRunId {
    GithubCheckRunId::new(value).expect("validated result state retains a valid GitHub run ID")
}

fn output(claimed: &ClaimedProviderResult) -> Result<GithubCheckOutput, ResultPublisherError> {
    GithubCheckOutput::new(
        claimed.desired().title().as_str(),
        claimed.desired().summary().as_str(),
        None,
    )
    .map_err(|_| ResultPublisherError::InvalidResponse)
}

fn annotations(
    claimed: &ClaimedProviderResult,
) -> Result<Vec<GithubCheckAnnotation>, ResultPublisherError> {
    claimed
        .desired()
        .annotations()
        .iter()
        .map(|annotation| {
            GithubCheckAnnotation::new(
                annotation.path().as_str(),
                annotation.start_line(),
                annotation.end_line(),
                None,
                None,
                match annotation.level() {
                    ProviderResultAnnotationLevel::Failure => GithubCheckAnnotationLevel::Failure,
                    ProviderResultAnnotationLevel::Warning => GithubCheckAnnotationLevel::Warning,
                    ProviderResultAnnotationLevel::Notice => GithubCheckAnnotationLevel::Notice,
                },
                annotation.message().as_str(),
                Some(annotation.title().as_str().to_owned()),
            )
            .map_err(|_| ResultPublisherError::InvalidResponse)
        })
        .collect()
}

const fn conclusion(value: ProviderResultConclusion) -> GithubCheckConclusion {
    match value {
        ProviderResultConclusion::ActionRequired => GithubCheckConclusion::ActionRequired,
        ProviderResultConclusion::Cancelled => GithubCheckConclusion::Cancelled,
        ProviderResultConclusion::Failure | ProviderResultConclusion::Error => {
            GithubCheckConclusion::Failure
        }
        ProviderResultConclusion::Neutral => GithubCheckConclusion::Neutral,
        ProviderResultConclusion::Skipped => GithubCheckConclusion::Skipped,
        ProviderResultConclusion::Success => GithubCheckConclusion::Success,
        ProviderResultConclusion::TimedOut => GithubCheckConclusion::TimedOut,
    }
}

fn expected_completed(value: Option<ProviderResultConclusion>) -> GithubCheckRunState {
    let conclusion = value.map_or(GithubObservedCheckConclusion::Stale, |value| {
        GithubObservedCheckConclusion::from(conclusion(value))
    });
    GithubCheckRunState::Completed(conclusion)
}

fn completed_or_annotations(
    claimed: &ClaimedProviderResult,
    suite_id: u64,
    run_id: u64,
) -> ProviderResultAdapterOutcome {
    if claimed.desired().annotations().is_empty() {
        published(claimed, suite_id, run_id)
    } else {
        retry(
            GithubResultState::Annotations {
                suite_id,
                run_id,
                confirmed: 0,
                uncertain_end: None,
            },
            None,
        )
    }
}

fn published(
    claimed: &ClaimedProviderResult,
    suite_id: u64,
    run_id: u64,
) -> ProviderResultAdapterOutcome {
    let Ok(external_id) = ExternalResultId::new(format!("github-check:{suite_id}:{run_id}")) else {
        return failed(ResultPublisherError::InvalidResponse);
    };
    if claimed
        .binding()
        .is_some_and(|binding| binding.external_id() != &external_id)
    {
        return failed(ResultPublisherError::Conflict);
    }
    let mut hash = Sha256::new();
    hash.update(RESULT_STATE_DOMAIN);
    hash.update(claimed.desired().digest().as_bytes());
    hash.update(suite_id.to_be_bytes());
    hash.update(run_id.to_be_bytes());
    ProviderResultAdapterOutcome::Published(ProviderResultObservation::new(
        Some(external_id),
        Sha256Digest::from_bytes(hash.finalize().into()),
    ))
}

fn parse_binding(external_id: &ExternalResultId) -> Result<(u64, u64), ResultPublisherError> {
    let mut parts = external_id.as_str().split(':');
    if parts.next() != Some("github-check") {
        return Err(ResultPublisherError::Conflict);
    }
    let suite_id = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| GithubCheckSuiteId::new(value).ok().map(|_| value))
        .ok_or(ResultPublisherError::Conflict)?;
    let run_id = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| GithubCheckRunId::new(value).ok().map(|_| value))
        .ok_or(ResultPublisherError::Conflict)?;
    if parts.next().is_some() {
        return Err(ResultPublisherError::Conflict);
    }
    Ok((suite_id, run_id))
}

fn credential_matches(
    credential: &GithubResultCredential,
    context: &ProviderRuntimeContext,
    claim: ProviderResultClaimFence,
    operation: GithubResultOperation,
    app_id: GithubCheckAppId,
    policy: &GithubConnectionPolicy,
    required_through: UnixMillis,
) -> bool {
    credential.connection_id == context.connection().connection_id()
        && credential.connection_revision == context.connection().revision()
        && credential.external_repository_id
            == *context
                .connection()
                .configuration()
                .repository()
                .external_id()
        && credential.claim == claim
        && credential.operation == operation
        && credential.app_id == app_id
        && credential.installation_id == policy.installation_id().get()
        && credential.repository == *policy.repository()
        && credential.required_through == required_through
        && credential.conservative_expires_at > required_through
}

fn http_error(
    error: GithubChecksError,
    determinate_retry: GithubResultState,
    indeterminate_retry: Option<GithubResultState>,
) -> ProviderResultAdapterOutcome {
    match error {
        GithubChecksError::Unauthorized => failed(ResultPublisherError::Unauthorized),
        GithubChecksError::Forbidden => failed(ResultPublisherError::Forbidden),
        GithubChecksError::InvalidRequest | GithubChecksError::InvalidResponse => {
            failed(ResultPublisherError::InvalidResponse)
        }
        GithubChecksError::NotFound | GithubChecksError::Conflict | GithubChecksError::Rejected => {
            failed(ResultPublisherError::Conflict)
        }
        GithubChecksError::RateLimited(evidence) => {
            retry(determinate_retry, retry_from_evidence(evidence))
        }
        GithubChecksError::Unavailable(evidence) => retry(
            indeterminate_retry.unwrap_or(determinate_retry),
            retry_from_evidence(evidence),
        ),
    }
}

fn retry_from_evidence(evidence: GithubCheckRetryEvidence) -> Option<ProviderResultRetryAfter> {
    evidence
        .retry_after_seconds()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(retry_after)
}

fn retry_after(millis: u64) -> Option<ProviderResultRetryAfter> {
    ProviderResultRetryAfter::new(millis).ok()
}

fn request_timeout_millis(endpoint: &GithubHttpEndpoint) -> i64 {
    i64::try_from(
        endpoint
            .trusted_origins()
            .limits()
            .request_timeout()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use automata_ci_provider::{
        ProviderResultBinding, ProviderResultModelError, ProviderResultName,
    };

    use super::*;

    #[test]
    fn binding_round_trip_is_exact_and_provider_owned() {
        let id = ExternalResultId::new("github-check:71:83").expect("external ID");
        assert_eq!(parse_binding(&id), Ok((71, 83)));
        for invalid in [
            "71:83",
            "github-check:0:83",
            "github-check:71:0",
            "github-check:71:83:1",
            "github-check:x:83",
        ] {
            assert_eq!(
                parse_binding(&ExternalResultId::new(invalid).expect("bounded external ID")),
                Err(ResultPublisherError::Conflict)
            );
        }
    }

    #[test]
    fn cursor_is_canonical_and_rejects_schema_drift() {
        let state = GithubResultState::Annotations {
            suite_id: 71,
            run_id: 83,
            confirmed: 50,
            uncertain_end: Some(100),
        };
        let ProviderResultAdapterOutcome::Retry {
            continuation: Some(continuation),
            ..
        } = retry(state, None)
        else {
            panic!("cursor must encode");
        };
        assert_eq!(decode_state(&continuation), Ok(state));
        let noncanonical = ProviderResultContinuation::new(
            ProviderSchemaVersion::new(CURSOR_SCHEMA).expect("schema"),
            b"{ \"state\":\"ensure-suite\"}".to_vec(),
        )
        .expect("bounded continuation");
        assert_eq!(
            decode_state(&noncanonical),
            Err(ResultPublisherError::Conflict)
        );
        let future = ProviderResultContinuation::new(
            ProviderSchemaVersion::new(CURSOR_SCHEMA + 1).expect("future schema"),
            b"{\"state\":\"ensure-suite\"}".to_vec(),
        )
        .expect("bounded continuation");
        assert_eq!(decode_state(&future), Err(ResultPublisherError::Conflict));
    }

    #[test]
    fn common_name_is_independent_from_mutable_output_title() {
        assert!(ProviderResultName::new("build / test").is_ok());
        assert_eq!(
            ProviderResultName::new("\n"),
            Err(ProviderResultModelError::InvalidName)
        );
        let binding = ProviderResultBinding::new(
            ExternalResultId::new("github-check:71:83").expect("binding"),
        );
        assert_eq!(parse_binding(binding.external_id()), Ok((71, 83)));
    }
}
