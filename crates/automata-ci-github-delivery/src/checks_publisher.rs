use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{BlobStoreErrorKind, ImmutableBlobStore};
use automata_ci_core::{JobConclusion, JobResult, UnixMillis};
use automata_ci_github::{
    GithubCheckAppId as HttpAppId, GithubCheckCompletion, GithubCheckConclusion as HttpConclusion,
    GithubCheckCreateIndeterminate, GithubCheckCreateIndeterminateKind, GithubCheckDetailsUrl,
    GithubCheckExternalId, GithubCheckName as HttpCheckName, GithubCheckRequestedAction,
    GithubCheckRetryEvidence, GithubCheckRun, GithubCheckRunCreateOutcome,
    GithubCheckRunId as HttpRunId, GithubCheckRunIdentity, GithubCheckRunReconciliation,
    GithubCheckRunState, GithubCheckSuiteCreateOutcome, GithubCheckSuiteId as HttpSuiteId,
    GithubCheckTimestamp, GithubChecksError, GithubHttpEndpoint, GithubObservedCheckConclusion,
};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_scm::{ExactRevision, RepositoryId as ScmRepositoryId};
use automata_ci_store::{
    AdvanceGithubCheckAnnotations, BeginGithubCheckAnnotationBatch, BeginGithubCheckRunCreate,
    BindGithubCheckRun, BindGithubCheckSuite, BlockGithubCheckAnnotationMismatch,
    BlockGithubCheckProjectionForCredentialRejection, ClaimGithubCheckProjection,
    ClaimedGithubCheckProjection, ClearGithubCheckAnnotationUncertainty,
    CompleteGithubCheckProjection, GithubCheckAppId, GithubCheckConclusion,
    GithubCheckDesiredProjection, GithubCheckDetailsTarget, GithubCheckProjectionAction,
    GithubCheckProjectionClaimFence, GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId,
    GithubCheckRunBindingFence, GithubCheckRunCreateFence, GithubCheckRunId, GithubCheckStoreError,
    GithubCheckSubjectIdentity, GithubCheckSubjectReceipt, GithubCheckSuiteId,
    GithubCheckTerminalCause, GithubCheckValueError, GithubServerServiceAction,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId, GithubServerServiceHandoffId,
    GithubServerServiceRevision, GithubServerServiceWorkerId, InitializeGithubCheckPresentation,
    MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS, MAX_GITHUB_CHECK_PROJECTION_CLAIM_MILLIS,
    MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS, ProviderInstallationId, ProviderRepositoryId,
    ReleaseUnissuedGithubCheckAnnotationBatch, ReleaseUnissuedGithubCheckRunCreate, RepositoryId,
    ResolveGithubCheckRunCreate, RetryGithubCheckProjection, RetryUncertainGithubCheckAnnotations,
    TenantScope,
};
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use url::Url;

use crate::checks_presentation;
use crate::{GithubDeliveryClock, service::GithubServerServiceCredentialRelease};

const DEFAULT_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
const DEFAULT_VISIBILITY_MARGIN_MILLIS: i64 = 30 * 1_000;
const MAX_VISIBILITY_MARGIN_MILLIS: i64 = 2 * 60 * 1_000;
const DEFAULT_RETRY_BASE_MILLIS: i64 = 30 * 1_000;
const MAX_ANNOTATIONS_PER_PATCH: usize = 50;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Bounded claim, reconciliation, and retry policy for one Checks publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubChecksPublisherConfig {
    claim_duration: i64,
    visibility_margin: i64,
    retry_base: i64,
}

impl GithubChecksPublisherConfig {
    /// Constructs a policy within the durable outbox ceilings.
    ///
    /// # Errors
    ///
    /// Rejects non-positive or excessive claim, reconciliation, or retry
    /// durations.
    pub const fn new(
        claim_millis: i64,
        visibility_margin_millis: i64,
        retry_base_millis: i64,
    ) -> Result<Self, GithubChecksPublisherConfigurationError> {
        if claim_millis <= 0 || claim_millis > MAX_GITHUB_CHECK_PROJECTION_CLAIM_MILLIS {
            return Err(GithubChecksPublisherConfigurationError::InvalidClaimDuration);
        }
        if visibility_margin_millis <= 0 || visibility_margin_millis > MAX_VISIBILITY_MARGIN_MILLIS
        {
            return Err(GithubChecksPublisherConfigurationError::InvalidVisibilityMargin);
        }
        if retry_base_millis <= 0 || retry_base_millis > MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS {
            return Err(GithubChecksPublisherConfigurationError::InvalidRetryBackoff);
        }
        Ok(Self {
            claim_duration: claim_millis,
            visibility_margin: visibility_margin_millis,
            retry_base: retry_base_millis,
        })
    }

    /// Returns the exclusive claim duration.
    #[must_use]
    pub const fn claim_millis(self) -> i64 {
        self.claim_duration
    }

    /// Returns the recovery margin after the bounded request uncertainty drain.
    #[must_use]
    pub const fn visibility_margin_millis(self) -> i64 {
        self.visibility_margin
    }

    /// Returns the first retry delay before attempt-based backoff.
    #[must_use]
    pub const fn retry_base_millis(self) -> i64 {
        self.retry_base
    }
}

impl Default for GithubChecksPublisherConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_CLAIM_MILLIS,
            DEFAULT_VISIBILITY_MARGIN_MILLIS,
            DEFAULT_RETRY_BASE_MILLIS,
        )
        .expect("default GitHub Checks publisher policy is within durable bounds")
    }
}

/// Invalid Checks publisher policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubChecksPublisherConfigurationError {
    /// The claim duration is outside the durable bound.
    #[error("the GitHub Checks publisher claim duration is invalid")]
    InvalidClaimDuration,
    /// The post-request visibility margin is outside the durable bound.
    #[error("the GitHub Checks publisher visibility margin is invalid")]
    InvalidVisibilityMargin,
    /// The retry base is outside the durable bound.
    #[error("the GitHub Checks publisher retry backoff is invalid")]
    InvalidRetryBackoff,
    /// The dashboard origin is not a canonical credential-free HTTP(S) origin.
    #[error("the GitHub Checks dashboard origin is invalid")]
    InvalidDashboardOrigin,
}

/// Borrowed exact authority requested for one claimed provider operation.
pub struct GithubChecksCredentialRequest<'a> {
    claimed: &'a ClaimedGithubCheckProjection,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

impl GithubChecksCredentialRequest<'_> {
    /// Returns the exact tenant, delivery, connection, installation, App,
    /// repository, SHA, and Check identity frozen by the claim.
    #[must_use]
    pub const fn identity(&self) -> &GithubCheckSubjectIdentity {
        self.claimed.identity()
    }

    /// Returns the immutable manifest-pinned `checks_write` selector.
    #[must_use]
    pub const fn authority_selector(&self) -> &GithubServerServiceAuthoritySelector {
        self.claimed.checks_authority()
    }

    /// Returns the exact durable consumer claim fence.
    #[must_use]
    pub const fn claim(&self) -> GithubCheckProjectionClaimFence {
        self.claimed.claim()
    }

    /// Returns the sole provider action authorized by the claim.
    #[must_use]
    pub const fn action(&self) -> GithubCheckProjectionAction {
        self.claimed.action()
    }

    /// Returns the desired revision frozen by the claim.
    #[must_use]
    pub const fn desired_revision(&self) -> u64 {
        self.claimed.desired_revision()
    }

    /// Returns the immutable original claim time.
    #[must_use]
    pub const fn claimed_at(&self) -> UnixMillis {
        self.claimed.claimed_at()
    }

    /// Returns the exact consumer claim expiry.
    #[must_use]
    pub const fn claim_expires_at(&self) -> UnixMillis {
        self.claimed.expires_at()
    }

    /// Returns the trusted observation at which the current consumer was requested.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the conservative time through which the credential must remain usable.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }

    /// Derives the exact consumer claim from this durable outbox claim.
    ///
    /// # Errors
    ///
    /// Fails closed if an internally validated Check identifier, fence, or
    /// revision cannot be represented by the adjacent authority boundary.
    pub fn consumer_claim(
        &self,
    ) -> Result<GithubServerServiceConsumerClaim, GithubChecksCredentialValueError> {
        let claim = self.claim();
        Ok(GithubServerServiceConsumerClaim::new(
            GithubServerServiceConsumerId::from_uuid(claim.subject_id().as_uuid())
                .map_err(|_| GithubChecksCredentialValueError::InvalidClaimBinding)?,
            GithubServerServiceWorkerId::from_uuid(claim.owner().as_uuid())
                .map_err(|_| GithubChecksCredentialValueError::InvalidClaimBinding)?,
            GithubServerServiceClaimFence::new(claim.fence())
                .map_err(|_| GithubChecksCredentialValueError::InvalidClaimBinding)?,
            server_service_action(self.action()),
            GithubServerServiceRevision::new(self.desired_revision())
                .map_err(|_| GithubChecksCredentialValueError::InvalidClaimBinding)?,
        ))
    }
}

impl fmt::Debug for GithubChecksCredentialRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubChecksCredentialRequest")
            .field("identity", &"[redacted]")
            .field("claim", &"[redacted]")
            .field("action", &self.action())
            .field("desired_revision", &self.desired_revision())
            .field("observed_at", &self.observed_at)
            .field("required_through", &self.required_through)
            .finish()
    }
}

/// Move-only server-service credential bound to one exact GitHub repository authority.
#[must_use = "the credential must be used and exactly released"]
pub struct GithubChecksServerServiceCredential {
    authority_selector: GithubServerServiceAuthoritySelector,
    handoff_id: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
    required_through: UnixMillis,
    acquired_at: UnixMillis,
    tenant: TenantScope,
    repository_id: RepositoryId,
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    github_repository_id: ProviderRepositoryId,
    app_id: GithubCheckAppId,
    repository: ScmRepositoryId,
    token: SecretString,
    conservative_expires_at: UnixMillis,
    release: Box<dyn GithubServerServiceCredentialRelease>,
}

impl GithubChecksServerServiceCredential {
    /// Constructs one request-scoped server-service credential handoff.
    ///
    /// The publisher validates every binding against the claimed subject before
    /// borrowing the secret for one provider operation.
    ///
    /// # Errors
    ///
    /// Rejects an invalid acquisition/lifetime interval or cross-tenant
    /// authority selector.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_selector: GithubServerServiceAuthoritySelector,
        handoff_id: GithubServerServiceHandoffId,
        consumer: GithubServerServiceConsumerClaim,
        required_through: UnixMillis,
        acquired_at: UnixMillis,
        tenant: TenantScope,
        repository_id: RepositoryId,
        connection_id: ProviderConnectionId,
        installation_id: ProviderInstallationId,
        github_repository_id: ProviderRepositoryId,
        app_id: GithubCheckAppId,
        repository: ScmRepositoryId,
        token: SecretString,
        conservative_expires_at: UnixMillis,
        release: Box<dyn GithubServerServiceCredentialRelease>,
    ) -> Result<Self, GithubChecksCredentialValueError> {
        if authority_selector.tenant() != &tenant {
            return Err(GithubChecksCredentialValueError::AuthorityTenantMismatch);
        }
        if acquired_at.get() < 0
            || required_through.get() < 0
            || acquired_at >= required_through
            || conservative_expires_at.get() < 0
            || conservative_expires_at <= required_through
        {
            return Err(GithubChecksCredentialValueError::InvalidExpiration);
        }
        Ok(Self {
            authority_selector,
            handoff_id,
            consumer,
            required_through,
            acquired_at,
            tenant,
            repository_id,
            connection_id,
            installation_id,
            github_repository_id,
            app_id,
            repository,
            token,
            conservative_expires_at,
            release,
        })
    }

    /// Returns the immutable authority selector that granted this handoff.
    #[must_use]
    pub const fn authority_selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.authority_selector
    }

    /// Returns the durable handoff identity retained for exact release/replay.
    #[must_use]
    pub const fn handoff_id(&self) -> GithubServerServiceHandoffId {
        self.handoff_id
    }

    /// Returns the exact outbox consumer binding retained by the handoff.
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.consumer
    }

    /// Returns the exact derivative lease requested from authority storage.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }

    /// Returns the trusted observation at which Store revalidated this handoff.
    #[must_use]
    pub const fn acquired_at(&self) -> UnixMillis {
        self.acquired_at
    }

    /// Returns the authenticated tenant binding.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        &self.tenant
    }

    /// Returns the Automata repository binding.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Returns the provider connection binding.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.connection_id
    }

    /// Returns the GitHub installation binding.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.installation_id
    }

    /// Returns the stable numeric GitHub repository binding.
    #[must_use]
    pub const fn github_repository_id(&self) -> ProviderRepositoryId {
        self.github_repository_id
    }

    /// Returns the GitHub App binding.
    #[must_use]
    pub const fn app_id(&self) -> GithubCheckAppId {
        self.app_id
    }

    /// Returns the provider-native owner/name route attested for the numeric repository.
    #[must_use]
    pub const fn repository(&self) -> &ScmRepositoryId {
        &self.repository
    }

    /// Returns the conservative credential expiry.
    #[must_use]
    pub const fn conservative_expires_at(&self) -> UnixMillis {
        self.conservative_expires_at
    }

    const fn token(&self) -> &SecretString {
        &self.token
    }

    fn start_release(self) -> tokio::task::JoinHandle<()> {
        let Self { token, release, .. } = self;
        drop(token);
        tokio::spawn(release.release())
    }
}

impl fmt::Debug for GithubChecksServerServiceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubChecksServerServiceCredential")
            .field("authority_selector", &"[redacted]")
            .field("handoff_id", &self.handoff_id)
            .field("consumer", &"[redacted]")
            .field("required_through", &self.required_through)
            .field("acquired_at", &self.acquired_at)
            .field("tenant", &"[redacted]")
            .field("repository_id", &self.repository_id)
            .field("connection_id", &self.connection_id)
            .field("installation_id", &self.installation_id)
            .field("github_repository_id", &self.github_repository_id)
            .field("app_id", &self.app_id)
            .field("repository", &"[redacted]")
            .field("token", &"[redacted]")
            .field("conservative_expires_at", &self.conservative_expires_at)
            .field("release", &"[exact release capability]")
            .finish()
    }
}

/// Invalid server-service credential handoff.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubChecksCredentialValueError {
    /// The acquisition or conservative credential lifetime interval is invalid.
    #[error("the GitHub Checks credential acquisition or lifetime interval is invalid")]
    InvalidExpiration,
    /// The authority selector belongs to a different authenticated tenant.
    #[error("the GitHub Checks credential authority selector tenant is inconsistent")]
    AuthorityTenantMismatch,
    /// The exact outbox claim cannot be represented at the authority boundary.
    #[error("the GitHub Checks credential claim binding is invalid")]
    InvalidClaimBinding,
}

/// Sanitized failure from the product-owned credential authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubChecksCredentialProviderError {
    /// The authority is temporarily unavailable and the claim may be retried.
    #[error("the GitHub Checks credential authority is unavailable")]
    Unavailable,
    /// Current policy or provider authority rejected the exact request.
    #[error("the GitHub Checks credential authority rejected the request")]
    Rejected,
    /// The authority could not establish internally consistent current state.
    #[error("the GitHub Checks credential authority has inconsistent state")]
    InvariantViolation,
}

/// Least-authority provider for one request-scoped server-service credential.
///
/// Implementations resolve existing product authority. They must not delegate
/// installation-token minting, caching, or persistence to the publisher.
#[async_trait]
pub trait GithubChecksCredentialProvider: fmt::Debug + Send + Sync {
    /// Hands off a move-only credential for the exact borrowed claim identity.
    ///
    /// # Errors
    ///
    /// Returns only a sanitized unavailable, rejected, or inconsistent outcome.
    async fn acquire(
        &self,
        request: GithubChecksCredentialRequest<'_>,
    ) -> Result<GithubChecksServerServiceCredential, GithubChecksCredentialProviderError>;
}

/// Durable outcome of one bounded publisher invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GithubChecksPublisherOutcome {
    /// No eligible outbox entry existed for the selected connection.
    Idle,
    /// Exact provider evidence advanced or completed the durable projection.
    Advanced(GithubCheckSubjectReceipt),
    /// A transient failure was durably released into bounded retry.
    RetryScheduled(GithubCheckSubjectReceipt),
    /// A Check Run create may have succeeded and must be reconciled before another POST.
    ReconciliationRequired(GithubCheckRunCreateFence),
    /// Exact durable evidence made this projection permanently unpublishable.
    Blocked(GithubCheckSubjectReceipt),
}

/// Sanitized fail-closed publisher failure.
#[derive(Debug, Error)]
pub enum GithubChecksPublisherError {
    /// Durable outbox access or a fenced commit failed.
    #[error(transparent)]
    Store(#[from] GithubCheckStoreError),
    /// The repository adapter returned a claim inconsistent with the exact request.
    #[error("the GitHub Checks outbox returned an invalid claim")]
    InvalidClaim,
    /// GitHub rejected a credential after exact local authority handed it off.
    #[error("GitHub rejected the exact Checks server-service credential")]
    CredentialRejected,
    /// Returned credential binding or lifetime was not exact.
    #[error("the GitHub Checks server-service credential was not exact")]
    CredentialMismatch,
    /// Provider state was determinate but did not satisfy the requested projection.
    #[error("the GitHub Check provider state was not exact")]
    ProviderStateMismatch,
    /// A validated local value could not be represented at the adjacent boundary.
    #[error("the GitHub Checks publisher encountered inconsistent local state")]
    InvariantViolation,
    /// Provider use exceeded the exact horizon retained by its credential handoff.
    #[error("the GitHub Checks provider action exceeded its bounded deadline")]
    ProviderDeadlineExceeded,
}

/// Fenced publisher for the durable GitHub Checks outbox.
pub struct GithubChecksPublisher {
    endpoint: GithubHttpEndpoint,
    outbox: Arc<dyn GithubCheckProjectionOutbox>,
    objects: Arc<dyn ImmutableBlobStore>,
    credentials: Arc<dyn GithubChecksCredentialProvider>,
    clock: Arc<dyn GithubDeliveryClock>,
    dashboard_origin: Url,
    config: GithubChecksPublisherConfig,
}

#[derive(Clone, Copy, Debug)]
struct GithubChecksClaimHorizon {
    monotonic_started_at: Instant,
    deadline: Instant,
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
}

struct GithubTerminalUpdate<'a> {
    identity: &'a GithubCheckRunIdentity,
    current: &'a GithubCheckRun,
    cause: GithubCheckTerminalCause,
    run_id: HttpRunId,
    started_at: Option<&'a GithubCheckTimestamp>,
    completed_at: &'a GithubCheckTimestamp,
}

impl GithubChecksClaimHorizon {
    fn observed_at(self) -> Result<UnixMillis, GithubChecksPublisherError> {
        let elapsed = duration_millis_ceil(self.monotonic_started_at.elapsed())?;
        let observed_at = checked_add(self.claimed_at, elapsed)?;
        if observed_at >= self.expires_at || Instant::now() >= self.deadline {
            return Err(GithubChecksPublisherError::InvalidClaim);
        }
        Ok(observed_at)
    }

    fn observed_after(
        self,
        lower_bound: UnixMillis,
    ) -> Result<UnixMillis, GithubChecksPublisherError> {
        let observed_at = self.observed_at()?;
        if observed_at < lower_bound {
            return Err(GithubChecksPublisherError::InvariantViolation);
        }
        Ok(observed_at)
    }

    fn terminal_observed_after(
        self,
        lower_bound: UnixMillis,
    ) -> Result<UnixMillis, GithubChecksPublisherError> {
        let elapsed = duration_millis_ceil(self.monotonic_started_at.elapsed())?;
        let observed_at = checked_add(self.claimed_at, elapsed)?;
        if observed_at < lower_bound {
            return Err(GithubChecksPublisherError::InvariantViolation);
        }
        Ok(observed_at)
    }
}

impl GithubChecksPublisher {
    /// Constructs the publisher from explicit provider, durability, authority, and time ports.
    ///
    /// # Errors
    ///
    /// Returns an error when the dashboard origin is not a canonical credential-free HTTP(S)
    /// origin.
    pub fn new(
        endpoint: GithubHttpEndpoint,
        outbox: Arc<dyn GithubCheckProjectionOutbox>,
        objects: Arc<dyn ImmutableBlobStore>,
        credentials: Arc<dyn GithubChecksCredentialProvider>,
        clock: Arc<dyn GithubDeliveryClock>,
        dashboard_origin: Url,
        config: GithubChecksPublisherConfig,
    ) -> Result<Self, GithubChecksPublisherConfigurationError> {
        if dashboard_origin.cannot_be_a_base()
            || dashboard_origin.host_str().is_none()
            || !dashboard_origin.username().is_empty()
            || dashboard_origin.password().is_some()
            || dashboard_origin.query().is_some()
            || dashboard_origin.fragment().is_some()
            || dashboard_origin.path() != "/"
            || !matches!(dashboard_origin.scheme(), "http" | "https")
        {
            return Err(GithubChecksPublisherConfigurationError::InvalidDashboardOrigin);
        }
        Ok(Self {
            endpoint,
            outbox,
            objects,
            credentials,
            clock,
            dashboard_origin,
            config,
        })
    }

    /// Claims and processes at most one eligible projection for a connection.
    ///
    /// # Errors
    ///
    /// Fails closed on stale durability, handed-off credential rejection or
    /// mismatch, provider identity/state mismatch, and local invariant violations.
    pub async fn run_once(
        &self,
        connection_id: ProviderConnectionId,
        worker_id: GithubCheckProjectionWorkerId,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let monotonic_started_at = Instant::now();
        let caller_observed_at = self.now()?;
        let deadline = monotonic_started_at
            .checked_add(Duration::from_millis(
                u64::try_from(self.config.claim_millis())
                    .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
            ))
            .ok_or(GithubChecksPublisherError::InvariantViolation)?;
        let caller_expires_at = checked_add(caller_observed_at, self.config.claim_millis())?;
        let request = ClaimGithubCheckProjection::new(
            connection_id,
            worker_id,
            caller_observed_at,
            caller_expires_at,
        )
        .map_err(invariant)?;
        let Some(claimed) = self.outbox.claim_github_check_projection(request).await? else {
            return Ok(GithubChecksPublisherOutcome::Idle);
        };
        if claimed.identity().connection_id() != connection_id
            || claimed.claim().owner() != worker_id
            || claimed
                .expires_at()
                .get()
                .checked_sub(claimed.claimed_at().get())
                != Some(self.config.claim_millis())
        {
            return Err(GithubChecksPublisherError::InvalidClaim);
        }
        let horizon = GithubChecksClaimHorizon {
            monotonic_started_at,
            deadline,
            claimed_at: claimed.claimed_at(),
            expires_at: claimed.expires_at(),
        };
        let credential_observed_at = horizon.observed_at()?;
        let provider_tail_millis = server_service_action(claimed.action()).provider_tail_millis();
        let credential_required_through = checked_add(claimed.expires_at(), provider_tail_millis)?;

        let credential_request = self.credentials.acquire(GithubChecksCredentialRequest {
            claimed: &claimed,
            observed_at: credential_observed_at,
            required_through: credential_required_through,
        });
        let credential = match timeout_at(deadline, credential_request).await {
            Err(_) => return Err(GithubChecksPublisherError::ProviderDeadlineExceeded),
            Ok(Ok(credential)) => credential,
            Ok(Err(GithubChecksCredentialProviderError::Unavailable)) => {
                return self
                    .schedule_retry(&claimed, horizon, "credential_unavailable", None)
                    .await;
            }
            Ok(Err(GithubChecksCredentialProviderError::Rejected)) => {
                return self.block_credential_rejection(&claimed, horizon).await;
            }
            Ok(Err(GithubChecksCredentialProviderError::InvariantViolation)) => {
                return Err(GithubChecksPublisherError::CredentialMismatch);
            }
        };
        if let Err(error) = Self::validate_credential(
            &claimed,
            horizon,
            &credential,
            credential_observed_at,
            credential_required_through,
        ) {
            release_credential(credential, deadline).await;
            return Err(error);
        }
        if Instant::now() >= deadline {
            release_credential(credential, deadline).await;
            return Err(GithubChecksPublisherError::ProviderDeadlineExceeded);
        }

        let provider_action = async {
            match claimed.action() {
                GithubCheckProjectionAction::EnsureSuite => {
                    self.ensure_suite(&claimed, horizon, &credential).await
                }
                GithubCheckProjectionAction::PrepareRunCreate => {
                    self.create_run(&claimed, horizon, &credential).await
                }
                GithubCheckProjectionAction::ReconcileRunCreate => {
                    self.reconcile_run(&claimed, horizon, &credential).await
                }
                GithubCheckProjectionAction::Publish => {
                    self.publish(&claimed, horizon, &credential).await
                }
            }
        };
        let outcome = match timeout_at(deadline, provider_action).await {
            Ok(outcome) => outcome,
            Err(_) => Err(GithubChecksPublisherError::ProviderDeadlineExceeded),
        };
        release_credential(credential, deadline).await;
        outcome
    }

    async fn block_credential_rejection(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let request = BlockGithubCheckProjectionForCredentialRejection::new(
            claimed.claim(),
            horizon.observed_at()?,
        )
        .map_err(invariant)?;
        let receipt = self
            .outbox
            .block_github_check_projection_for_credential_rejection(request)
            .await?;
        Ok(GithubChecksPublisherOutcome::Blocked(receipt))
    }

    async fn ensure_suite(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let revision = exact_revision(claimed.identity())?;
        let app_id = http_app_id(claimed.identity().app_id())?;
        let outcome = self
            .endpoint
            .create_check_suite(
                credential.repository(),
                &revision,
                app_id,
                credential.token(),
            )
            .await;
        match outcome {
            Ok(
                GithubCheckSuiteCreateOutcome::Existing(suite)
                | GithubCheckSuiteCreateOutcome::Created(suite),
            ) => {
                let suite_id = store_suite_id(suite.id())?;
                let observed_at = horizon.observed_at()?;
                let receipt = self
                    .outbox
                    .bind_github_check_suite(
                        BindGithubCheckSuite::new(claimed.claim(), suite_id, observed_at)
                            .map_err(invariant)?,
                    )
                    .await?;
                Ok(GithubChecksPublisherOutcome::Advanced(receipt))
            }
            Ok(GithubCheckSuiteCreateOutcome::Indeterminate(indeterminate)) => {
                let kind = suite_indeterminate_kind(indeterminate);
                self.schedule_retry(claimed, horizon, kind, Some(indeterminate.retry_evidence()))
                    .await
            }
            Err(error) => self.handle_http_error(claimed, horizon, error).await,
        }
    }

    async fn create_run(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let identity = run_identity(claimed, &self.dashboard_origin)?;
        let started_at = horizon.observed_at()?;
        let request_timeout_millis =
            duration_millis_ceil(self.endpoint.trusted_origins().limits().request_timeout())?;
        let reconcile_not_before = checked_add(
            claimed.expires_at(),
            request_timeout_millis
                .checked_add(self.config.visibility_margin_millis())
                .ok_or(GithubChecksPublisherError::InvariantViolation)?,
        )?;
        let begin = BeginGithubCheckRunCreate::new(claimed, started_at, reconcile_not_before)
            .map_err(invariant)?;
        let expected_fence = begin.fence();
        let create_fence = self.outbox.begin_github_check_run_create(begin).await?;
        if create_fence != expected_fence {
            return Err(GithubChecksPublisherError::InvalidClaim);
        }
        match horizon.observed_at() {
            Ok(_) => {}
            Err(GithubChecksPublisherError::InvalidClaim) => {
                return self
                    .release_unissued_create(create_fence, horizon, claimed.attempts())
                    .await;
            }
            Err(error) => return Err(error),
        }
        let started = Arc::new(AtomicBool::new(false));
        let started_by_future = Arc::clone(&started);
        let create = async {
            if Instant::now() >= horizon.deadline {
                return None;
            }
            started_by_future.store(true, Ordering::SeqCst);
            Some(
                self.endpoint
                    .create_check_run(credential.repository(), &identity, credential.token())
                    .await,
            )
        };
        let outcome = match timeout_at(horizon.deadline, create).await {
            Ok(Some(outcome)) => outcome,
            Ok(None) => {
                return self
                    .release_unissued_create(create_fence, horizon, claimed.attempts())
                    .await;
            }
            Err(_) if !started.load(Ordering::SeqCst) => {
                return self
                    .release_unissued_create(create_fence, horizon, claimed.attempts())
                    .await;
            }
            Err(_) => {
                return Ok(GithubChecksPublisherOutcome::ReconciliationRequired(
                    create_fence,
                ));
            }
        };
        match outcome {
            Ok(GithubCheckRunCreateOutcome::Created(run)) => {
                let observed_at = horizon.observed_after(started_at)?;
                let receipt = self
                    .outbox
                    .bind_github_check_run(
                        BindGithubCheckRun::new(
                            GithubCheckRunBindingFence::Create(create_fence),
                            store_suite_id(run.identity().suite_id())?,
                            store_run_id(run.id())?,
                            observed_at,
                        )
                        .map_err(invariant)?,
                    )
                    .await?;
                Ok(GithubChecksPublisherOutcome::Advanced(receipt))
            }
            Ok(GithubCheckRunCreateOutcome::Indeterminate(_)) | Err(_) => Ok(
                GithubChecksPublisherOutcome::ReconciliationRequired(create_fence),
            ),
        }
    }

    async fn reconcile_run(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let identity = run_identity(claimed, &self.dashboard_origin)?;
        let outcome = self
            .endpoint
            .reconcile_check_run_creation(credential.repository(), &identity, credential.token())
            .await;
        match outcome {
            Ok(GithubCheckRunReconciliation::Exact(run)) => {
                if run.state() != GithubCheckRunState::Queued {
                    return Err(GithubChecksPublisherError::ProviderStateMismatch);
                }
                let observed_at = horizon.observed_at()?;
                let receipt = self
                    .outbox
                    .bind_github_check_run(
                        BindGithubCheckRun::new(
                            GithubCheckRunBindingFence::Reconciliation(claimed.claim()),
                            store_suite_id(run.identity().suite_id())?,
                            store_run_id(run.id())?,
                            observed_at,
                        )
                        .map_err(invariant)?,
                    )
                    .await?;
                Ok(GithubChecksPublisherOutcome::Advanced(receipt))
            }
            Ok(GithubCheckRunReconciliation::Missing) => {
                let observed_at = horizon.observed_at()?;
                let delay = retry_delay(
                    self.config.retry_base_millis(),
                    claimed.attempts(),
                    None,
                    observed_at,
                );
                let retry_at = checked_add(observed_at, delay)?;
                let receipt = self
                    .outbox
                    .resolve_github_check_run_create(
                        ResolveGithubCheckRunCreate::missing(
                            claimed.claim(),
                            observed_at,
                            retry_at,
                        )
                        .map_err(invariant)?,
                    )
                    .await?;
                if claimed.attempts() >= MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS {
                    Ok(GithubChecksPublisherOutcome::Blocked(receipt))
                } else {
                    Ok(GithubChecksPublisherOutcome::RetryScheduled(receipt))
                }
            }
            Ok(GithubCheckRunReconciliation::Ambiguous) => {
                let observed_at = horizon.observed_at()?;
                let receipt = self
                    .outbox
                    .resolve_github_check_run_create(
                        ResolveGithubCheckRunCreate::ambiguous(claimed.claim(), observed_at)
                            .map_err(invariant)?,
                    )
                    .await?;
                Ok(GithubChecksPublisherOutcome::Blocked(receipt))
            }
            Err(error) => self.handle_http_error(claimed, horizon, error).await,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn publish(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let identity = run_identity(claimed, &self.dashboard_origin)?;
        let run_id = claimed
            .run_id()
            .ok_or(GithubChecksPublisherError::InvalidClaim)?;
        let http_run_id = http_run_id(run_id)?;
        let started_at = claimed
            .started_at()
            .map(|value| GithubCheckTimestamp::from_unix_millis(value.get()))
            .transpose()
            .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
        let completed_at = claimed
            .completed_at()
            .map(|value| GithubCheckTimestamp::from_unix_millis(value.get()))
            .transpose()
            .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
        let current = match self
            .endpoint
            .get_check_run(
                credential.repository(),
                http_run_id,
                &identity,
                credential.token(),
            )
            .await
        {
            Ok(run) => run,
            Err(error) => return self.handle_http_error(claimed, horizon, error).await,
        };

        match claimed.desired() {
            GithubCheckDesiredProjection::Queued => {
                require_state(&current, GithubCheckRunState::Queued)?;
            }
            GithubCheckDesiredProjection::InProgress => match current.state() {
                GithubCheckRunState::Queued => {
                    if let Err(error) = self
                        .endpoint
                        .start_check_run(
                            credential.repository(),
                            http_run_id,
                            &identity,
                            started_at
                                .as_ref()
                                .ok_or(GithubChecksPublisherError::InvariantViolation)?,
                            credential.token(),
                        )
                        .await
                    {
                        return self.handle_http_error(claimed, horizon, error).await;
                    }
                }
                GithubCheckRunState::InProgress => {}
                GithubCheckRunState::Completed(_) => {
                    return Err(GithubChecksPublisherError::ProviderStateMismatch);
                }
            },
            GithubCheckDesiredProjection::Terminal(cause) => {
                let expected_terminal = GithubCheckRunState::Completed(observed_conclusion(
                    http_conclusion(cause.conclusion()),
                ));
                let presentation_needed = current.state() != expected_terminal
                    || !claimed.annotation_progress().is_complete();
                let presentation = if presentation_needed
                    && let Some(descriptor) = claimed.terminal_result()
                {
                    let result_blob = match self
                        .objects
                        .get_verified(descriptor, descriptor.size())
                        .await
                    {
                        Ok(blob) => blob,
                        Err(error) => match error.kind() {
                            BlobStoreErrorKind::Unavailable | BlobStoreErrorKind::Unauthorized => {
                                return self
                                    .schedule_retry(
                                        claimed,
                                        horizon,
                                        "job_result_unavailable",
                                        None,
                                    )
                                    .await;
                            }
                            BlobStoreErrorKind::NotFound
                            | BlobStoreErrorKind::Conflict
                            | BlobStoreErrorKind::Integrity
                            | BlobStoreErrorKind::TooLarge
                            | BlobStoreErrorKind::InvalidResponse => {
                                return Err(GithubChecksPublisherError::InvariantViolation);
                            }
                        },
                    };
                    let result: JobResult = serde_json::from_slice(result_blob.bytes())
                        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
                    result
                        .validate()
                        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
                    require_terminal_result(&result, cause.conclusion(), claimed.completed_at())?;
                    Some(
                        checks_presentation::terminal_presentation(
                            &result,
                            identity.details_url().as_str(),
                        )
                        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
                    )
                } else {
                    None
                };
                let update = GithubTerminalUpdate {
                    identity: &identity,
                    current: &current,
                    cause,
                    run_id: http_run_id,
                    started_at: started_at.as_ref(),
                    completed_at: completed_at
                        .as_ref()
                        .ok_or(GithubChecksPublisherError::InvariantViolation)?,
                };
                if let Some(outcome) = self
                    .publish_terminal_update(
                        claimed,
                        horizon,
                        credential,
                        update,
                        presentation.as_ref(),
                    )
                    .await?
                {
                    return Ok(outcome);
                }
                if let Some(presentation) = presentation.as_ref()
                    && let Some(outcome) = self
                        .publish_terminal_annotations(
                            claimed,
                            horizon,
                            credential,
                            &identity,
                            http_run_id,
                            http_conclusion(cause.conclusion()),
                            presentation,
                        )
                        .await?
                {
                    return Ok(outcome);
                }
            }
        }

        let observed_at = horizon.observed_at()?;
        let receipt = self
            .outbox
            .complete_github_check_projection(
                CompleteGithubCheckProjection::new(claimed.claim(), claimed.desired(), observed_at)
                    .map_err(invariant)?,
            )
            .await?;
        Ok(GithubChecksPublisherOutcome::Advanced(receipt))
    }

    async fn publish_terminal_update(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
        update: GithubTerminalUpdate<'_>,
        presentation: Option<&checks_presentation::GithubTerminalPresentation>,
    ) -> Result<Option<GithubChecksPublisherOutcome>, GithubChecksPublisherError> {
        let conclusion = http_conclusion(update.cause.conclusion());
        let expected = GithubCheckRunState::Completed(observed_conclusion(conclusion));
        match update.current.state() {
            state if state == expected => return Ok(None),
            GithubCheckRunState::Completed(_) => {
                return Err(GithubChecksPublisherError::ProviderStateMismatch);
            }
            GithubCheckRunState::Queued | GithubCheckRunState::InProgress => {}
        }
        let actions = requested_actions(claimed)?;
        let completion = GithubCheckCompletion::new(
            conclusion,
            update.started_at,
            update.completed_at,
            presentation.map(checks_presentation::GithubTerminalPresentation::output),
            &actions,
        )
        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
        let publish_result = self
            .endpoint
            .complete_check_run(
                credential.repository(),
                update.run_id,
                update.identity,
                completion,
                credential.token(),
            )
            .await;
        match publish_result {
            Ok(_) => Ok(None),
            Err(error) => self
                .handle_http_error(claimed, horizon, error)
                .await
                .map(Some),
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn publish_terminal_annotations(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
        identity: &GithubCheckRunIdentity,
        run_id: HttpRunId,
        conclusion: HttpConclusion,
        presentation: &checks_presentation::GithubTerminalPresentation,
    ) -> Result<Option<GithubChecksPublisherOutcome>, GithubChecksPublisherError> {
        let annotations = presentation.annotations();
        let annotation_count = u16::try_from(annotations.len())
            .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
        let mut progress = claimed.annotation_progress();
        let observed_at = horizon.observed_at()?;
        if progress.presentation_digest().is_none() {
            progress = self
                .outbox
                .initialize_github_check_presentation(
                    InitializeGithubCheckPresentation::new(
                        claimed.claim(),
                        presentation.digest(),
                        annotation_count,
                        observed_at,
                    )
                    .map_err(invariant)?,
                )
                .await?;
        }
        if progress.presentation_digest() != Some(presentation.digest())
            || progress.total() != annotation_count
        {
            let receipt = self
                .outbox
                .block_github_check_annotation_mismatch(
                    BlockGithubCheckAnnotationMismatch::new(claimed.claim(), observed_at)
                        .map_err(invariant)?,
                )
                .await?;
            return Ok(Some(GithubChecksPublisherOutcome::Blocked(receipt)));
        }

        if let Some(batch_size) = progress.uncertain_batch_size() {
            let provider = match self
                .endpoint
                .list_check_run_annotations(credential.repository(), run_id, credential.token())
                .await
            {
                Ok(provider) => provider,
                Err(error) => {
                    return self
                        .handle_http_error(claimed, horizon, error)
                        .await
                        .map(Some);
                }
            };
            let from = usize::from(progress.next());
            let to = from + usize::from(batch_size);
            let reconciled_at = horizon.observed_at()?;
            if provider.as_slice() == &annotations[..from] {
                progress = self
                    .outbox
                    .clear_github_check_annotation_uncertainty(
                        ClearGithubCheckAnnotationUncertainty::new(
                            claimed.claim(),
                            presentation.digest(),
                            progress.next(),
                            batch_size,
                            reconciled_at,
                        )
                        .map_err(invariant)?,
                    )
                    .await?;
            } else if provider.as_slice() == &annotations[..to] {
                progress = self
                    .outbox
                    .advance_github_check_annotations(
                        AdvanceGithubCheckAnnotations::new(
                            claimed.claim(),
                            presentation.digest(),
                            progress.next(),
                            u16::try_from(to)
                                .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
                            reconciled_at,
                        )
                        .map_err(invariant)?,
                    )
                    .await?;
            } else {
                let receipt = self
                    .outbox
                    .block_github_check_annotation_mismatch(
                        BlockGithubCheckAnnotationMismatch::new(claimed.claim(), reconciled_at)
                            .map_err(invariant)?,
                    )
                    .await?;
                return Ok(Some(GithubChecksPublisherOutcome::Blocked(receipt)));
            }
        }

        if progress.is_complete() {
            return Ok(None);
        }

        // An admitted PATCH must leave both the complete transport timeout and
        // the configured post-request visibility margin inside this claim.
        // That keeps timeout recovery behind the latest possible mutation.
        let visibility_margin = Duration::from_millis(
            u64::try_from(self.config.visibility_margin_millis())
                .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
        );
        let recovery_tail = self
            .endpoint
            .trusted_origins()
            .limits()
            .request_timeout()
            .checked_add(visibility_margin)
            .ok_or(GithubChecksPublisherError::InvariantViolation)?;
        let recovery_tail_millis = duration_millis_ceil(recovery_tail)?;
        let Some(issue_deadline) = horizon
            .deadline
            .checked_sub(recovery_tail)
            .filter(|deadline| *deadline > horizon.monotonic_started_at)
        else {
            return self
                .schedule_retry(
                    claimed,
                    horizon,
                    "github_annotation_issue_window_elapsed",
                    None,
                )
                .await
                .map(Some);
        };
        while !progress.is_complete() {
            if Instant::now() >= issue_deadline {
                return self
                    .schedule_retry(
                        claimed,
                        horizon,
                        "github_annotation_issue_window_elapsed",
                        None,
                    )
                    .await
                    .map(Some);
            }
            let from = usize::from(progress.next());
            let to = annotations
                .len()
                .min(from.saturating_add(MAX_ANNOTATIONS_PER_PATCH));
            let batch = &annotations[from..to];
            let batch_size = u8::try_from(batch.len())
                .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
            let batch_start = horizon.observed_at()?;
            let begin = BeginGithubCheckAnnotationBatch::new(
                claimed.claim(),
                presentation.digest(),
                u16::try_from(from).map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
                batch_size,
                batch_start,
            )
            .map_err(invariant)?;
            progress = self
                .outbox
                .begin_github_check_annotation_batch(begin)
                .await?;
            if progress.presentation_digest() != Some(presentation.digest())
                || progress.total() != annotation_count
                || progress.next()
                    != u16::try_from(from)
                        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?
                || progress.uncertain_batch_size() != Some(batch_size)
            {
                return Err(GithubChecksPublisherError::InvalidClaim);
            }
            if Instant::now() >= issue_deadline {
                let released_at = horizon.observed_after(begin.started_at())?;
                return self
                    .release_unissued_annotation_batch(begin, released_at, claimed.attempts())
                    .await
                    .map(Some);
            }
            let request_admitted_at = horizon.observed_after(begin.started_at())?;
            let mutation_visibility_not_before =
                checked_add(request_admitted_at, recovery_tail_millis)?;
            if mutation_visibility_not_before > horizon.expires_at {
                return self
                    .release_unissued_annotation_batch(
                        begin,
                        request_admitted_at,
                        claimed.attempts(),
                    )
                    .await
                    .map(Some);
            }

            // No await occurs between the final admission timestamp and
            // polling the endpoint future. Provider I/O may have issued from
            // this point, so cancellation or an ambiguous response retains
            // the marker.
            let append_outcome = self
                .endpoint
                .append_check_run_annotations(
                    credential.repository(),
                    run_id,
                    identity,
                    conclusion,
                    presentation.output(),
                    batch,
                    credential.token(),
                )
                .await;
            match append_outcome {
                Ok(_) => {
                    let observed_at = horizon.observed_at()?;
                    progress = self
                        .outbox
                        .advance_github_check_annotations(
                            AdvanceGithubCheckAnnotations::new(
                                claimed.claim(),
                                presentation.digest(),
                                u16::try_from(from)
                                    .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
                                u16::try_from(to)
                                    .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
                                observed_at,
                            )
                            .map_err(invariant)?,
                        )
                        .await?;
                }
                Err(GithubChecksError::Unavailable(evidence)) => {
                    let failed_at = horizon.observed_at()?;
                    let delay = retry_delay(
                        self.config.retry_base_millis(),
                        claimed.attempts(),
                        Some(evidence),
                        failed_at,
                    )
                    .max(self.config.visibility_margin_millis());
                    let backoff_not_before = checked_add(failed_at, delay)?;
                    // A transport failure can return before the complete
                    // request timeout while GitHub may still apply the PATCH.
                    // Reconciliation therefore stays behind the entire
                    // admitted request-and-visibility tail, not merely behind
                    // the time at which the local error became observable.
                    let retry_at = backoff_not_before.max(mutation_visibility_not_before);
                    let receipt = self
                        .outbox
                        .retry_uncertain_github_check_annotations(
                            RetryUncertainGithubCheckAnnotations::new(
                                claimed.claim(),
                                presentation.digest(),
                                u16::try_from(from)
                                    .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
                                batch_size,
                                failed_at,
                                retry_at,
                            )
                            .map_err(invariant)?,
                        )
                        .await?;
                    return Ok(Some(GithubChecksPublisherOutcome::RetryScheduled(receipt)));
                }
                Err(error) => {
                    return self
                        .handle_http_error(claimed, horizon, error)
                        .await
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    async fn release_unissued_annotation_batch(
        &self,
        batch: BeginGithubCheckAnnotationBatch,
        released_at: UnixMillis,
        attempts: u16,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let delay = retry_delay(self.config.retry_base_millis(), attempts, None, released_at);
        let retry_at = checked_add(released_at, delay)?;
        let receipt = self
            .outbox
            .release_unissued_github_check_annotation_batch(
                ReleaseUnissuedGithubCheckAnnotationBatch::new(batch, released_at, retry_at)
                    .map_err(invariant)?,
            )
            .await?;
        Ok(GithubChecksPublisherOutcome::RetryScheduled(receipt))
    }

    async fn handle_http_error(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        error: GithubChecksError,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        match error {
            GithubChecksError::RateLimited(evidence) => {
                self.schedule_retry(claimed, horizon, "github_rate_limited", Some(evidence))
                    .await
            }
            GithubChecksError::Unavailable(evidence) => {
                self.schedule_retry(claimed, horizon, "github_unavailable", Some(evidence))
                    .await
            }
            other => Err(fail_closed_http_error(other)),
        }
    }

    async fn schedule_retry(
        &self,
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        failure_kind: &'static str,
        evidence: Option<GithubCheckRetryEvidence>,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let failed_at = horizon.observed_at()?;
        let delay = retry_delay(
            self.config.retry_base_millis(),
            claimed.attempts(),
            evidence,
            failed_at,
        );
        let retry_at = checked_add(failed_at, delay)?;
        let receipt = self
            .outbox
            .retry_github_check_projection(
                RetryGithubCheckProjection::new(claimed.claim(), failure_kind, failed_at, retry_at)
                    .map_err(invariant)?,
            )
            .await?;
        Ok(GithubChecksPublisherOutcome::RetryScheduled(receipt))
    }

    async fn release_unissued_create(
        &self,
        fence: GithubCheckRunCreateFence,
        horizon: GithubChecksClaimHorizon,
        attempts: u16,
    ) -> Result<GithubChecksPublisherOutcome, GithubChecksPublisherError> {
        let released_at = horizon.terminal_observed_after(fence.started_at())?;
        let delay = retry_delay(self.config.retry_base_millis(), attempts, None, released_at);
        let retry_at = checked_add(released_at, delay)?;
        let receipt = self
            .outbox
            .release_unissued_github_check_run_create(
                ReleaseUnissuedGithubCheckRunCreate::new(fence, released_at, retry_at)
                    .map_err(invariant)?,
            )
            .await?;
        Ok(GithubChecksPublisherOutcome::RetryScheduled(receipt))
    }

    fn validate_credential(
        claimed: &ClaimedGithubCheckProjection,
        horizon: GithubChecksClaimHorizon,
        credential: &GithubChecksServerServiceCredential,
        credential_observed_at: UnixMillis,
        required_through: UnixMillis,
    ) -> Result<(), GithubChecksPublisherError> {
        let identity = claimed.identity();
        let provider_observed_at = horizon.observed_at()?;
        let expected_consumer = GithubChecksCredentialRequest {
            claimed,
            observed_at: credential_observed_at,
            required_through,
        }
        .consumer_claim()
        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?;
        if credential.authority_selector() != claimed.checks_authority()
            || credential.consumer() != expected_consumer
            || credential.required_through() != required_through
            || credential.acquired_at() < credential_observed_at
            || credential.acquired_at() > provider_observed_at
            || credential.tenant() != identity.tenant()
            || credential.repository_id() != identity.repository_id()
            || credential.connection_id() != identity.connection_id()
            || credential.installation_id() != identity.installation_id()
            || credential.github_repository_id() != identity.github_repository_id()
            || credential.repository().as_str() != identity.github_repository_name().as_str()
            || credential.app_id() != identity.app_id()
            || credential.conservative_expires_at() <= required_through
        {
            return Err(GithubChecksPublisherError::CredentialMismatch);
        }
        Ok(())
    }

    fn now(&self) -> Result<UnixMillis, GithubChecksPublisherError> {
        let now = self.clock.now();
        if now.get() < 0 {
            return Err(GithubChecksPublisherError::InvariantViolation);
        }
        Ok(now)
    }
}

fn requested_actions(
    claimed: &ClaimedGithubCheckProjection,
) -> Result<Vec<GithubCheckRequestedAction>, GithubChecksPublisherError> {
    let mut actions = Vec::with_capacity(3);
    if matches!(
        claimed.details_target(),
        GithubCheckDetailsTarget::Job { .. }
    ) {
        actions.push(
            GithubCheckRequestedAction::new(
                "Re-run this job",
                "Run this job and its dependents",
                "rerun_job",
            )
            .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
        );
    }
    actions.push(
        GithubCheckRequestedAction::new(
            "Re-run failed jobs",
            "Run failed jobs and their dependents",
            "rerun_failed",
        )
        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
    );
    actions.push(
        GithubCheckRequestedAction::new(
            "Re-run all jobs",
            "Run every job in this workflow",
            "rerun_all",
        )
        .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
    );
    Ok(actions)
}

async fn release_credential(credential: GithubChecksServerServiceCredential, deadline: Instant) {
    let release = credential.start_release();
    // Give the move-only capability one poll even at an already-reached
    // deadline. Production releases transfer custody to their supervisor on
    // that poll; dropping the join handle then detaches, rather than cancels,
    // the exact bounded attempt.
    tokio::task::yield_now().await;
    drop(timeout_at(deadline, release).await);
}

const fn server_service_action(action: GithubCheckProjectionAction) -> GithubServerServiceAction {
    match action {
        GithubCheckProjectionAction::EnsureSuite => GithubServerServiceAction::EnsureCheckSuite,
        GithubCheckProjectionAction::PrepareRunCreate => GithubServerServiceAction::CreateCheckRun,
        GithubCheckProjectionAction::ReconcileRunCreate => {
            GithubServerServiceAction::ReconcileCheckRun
        }
        GithubCheckProjectionAction::Publish => GithubServerServiceAction::PublishCheckRun,
    }
}

impl fmt::Debug for GithubChecksPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubChecksPublisher")
            .field("endpoint", &"[configured]")
            .field("outbox", &"[configured]")
            .field("objects", &"[configured]")
            .field("credentials", &"[configured]")
            .field("clock", &self.clock)
            .field("dashboard_origin", &self.dashboard_origin)
            .field("config", &self.config)
            .finish()
    }
}

fn exact_revision(
    identity: &GithubCheckSubjectIdentity,
) -> Result<ExactRevision, GithubChecksPublisherError> {
    let bytes = identity.head_sha().as_bytes();
    let mut encoded = String::with_capacity(40);
    for byte in bytes {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    ExactRevision::new(encoded).map_err(|_| GithubChecksPublisherError::InvariantViolation)
}

fn run_identity(
    claimed: &ClaimedGithubCheckProjection,
    dashboard_origin: &Url,
) -> Result<GithubCheckRunIdentity, GithubChecksPublisherError> {
    let suite_id = claimed
        .suite_id()
        .ok_or(GithubChecksPublisherError::InvalidClaim)?;
    Ok(GithubCheckRunIdentity::new(
        http_app_id(claimed.identity().app_id())?,
        http_suite_id(suite_id)?,
        exact_revision(claimed.identity())?,
        HttpCheckName::new(claimed.identity().name().as_str().to_owned())
            .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
        GithubCheckExternalId::new(claimed.external_id().to_owned())
            .map_err(|_| GithubChecksPublisherError::InvariantViolation)?,
        check_details_url(claimed, dashboard_origin)?,
    ))
}

fn check_details_url(
    claimed: &ClaimedGithubCheckProjection,
    dashboard_origin: &Url,
) -> Result<GithubCheckDetailsUrl, GithubChecksPublisherError> {
    let mut url = dashboard_origin.clone();
    let mut segments = url
        .path_segments_mut()
        .map_err(|()| GithubChecksPublisherError::InvariantViolation)?;
    segments.pop_if_empty();
    let repository = claimed.identity().github_repository_name().as_str();
    let (owner, name) = repository
        .split_once('/')
        .ok_or(GithubChecksPublisherError::InvariantViolation)?;
    segments.push(owner);
    segments.push(name);
    segments.push("actions");
    match claimed.details_target() {
        GithubCheckDetailsTarget::Repository => {}
        GithubCheckDetailsTarget::WorkflowRun(run_id) => {
            segments.push("runs");
            segments.push(&run_id.to_string());
        }
        GithubCheckDetailsTarget::Job { run_id, job_id } => {
            segments.push("runs");
            segments.push(&run_id.to_string());
            segments.push("jobs");
            segments.push(&job_id.to_string());
        }
    }
    drop(segments);
    GithubCheckDetailsUrl::new(url).map_err(|_| GithubChecksPublisherError::InvariantViolation)
}

fn require_terminal_result(
    result: &JobResult,
    conclusion: GithubCheckConclusion,
    completed_at: Option<UnixMillis>,
) -> Result<(), GithubChecksPublisherError> {
    let expected_conclusion = match conclusion {
        GithubCheckConclusion::Success => JobConclusion::Success,
        GithubCheckConclusion::Failure => JobConclusion::Failure,
        GithubCheckConclusion::Cancelled => JobConclusion::Cancelled,
        GithubCheckConclusion::TimedOut => JobConclusion::TimedOut,
        GithubCheckConclusion::Skipped => JobConclusion::Skipped,
        GithubCheckConclusion::ActionRequired => {
            return Err(GithubChecksPublisherError::InvariantViolation);
        }
    };
    if result.conclusion() != expected_conclusion || Some(result.completed_at()) != completed_at {
        return Err(GithubChecksPublisherError::InvariantViolation);
    }
    Ok(())
}

fn http_app_id(value: GithubCheckAppId) -> Result<HttpAppId, GithubChecksPublisherError> {
    HttpAppId::new(value.get()).map_err(|_| GithubChecksPublisherError::InvariantViolation)
}

fn http_suite_id(value: GithubCheckSuiteId) -> Result<HttpSuiteId, GithubChecksPublisherError> {
    HttpSuiteId::new(value.get()).map_err(|_| GithubChecksPublisherError::InvariantViolation)
}

fn http_run_id(value: GithubCheckRunId) -> Result<HttpRunId, GithubChecksPublisherError> {
    HttpRunId::new(value.get()).map_err(|_| GithubChecksPublisherError::InvariantViolation)
}

fn store_suite_id(value: HttpSuiteId) -> Result<GithubCheckSuiteId, GithubChecksPublisherError> {
    GithubCheckSuiteId::new(value.get()).map_err(invariant)
}

fn store_run_id(value: HttpRunId) -> Result<GithubCheckRunId, GithubChecksPublisherError> {
    GithubCheckRunId::new(value.get()).map_err(invariant)
}

const fn http_conclusion(value: GithubCheckConclusion) -> HttpConclusion {
    match value {
        GithubCheckConclusion::ActionRequired => HttpConclusion::ActionRequired,
        GithubCheckConclusion::Cancelled => HttpConclusion::Cancelled,
        GithubCheckConclusion::Failure => HttpConclusion::Failure,
        GithubCheckConclusion::Success => HttpConclusion::Success,
        GithubCheckConclusion::Skipped => HttpConclusion::Skipped,
        GithubCheckConclusion::TimedOut => HttpConclusion::TimedOut,
    }
}

const fn observed_conclusion(value: HttpConclusion) -> GithubObservedCheckConclusion {
    match value {
        HttpConclusion::ActionRequired => GithubObservedCheckConclusion::ActionRequired,
        HttpConclusion::Cancelled => GithubObservedCheckConclusion::Cancelled,
        HttpConclusion::Failure => GithubObservedCheckConclusion::Failure,
        HttpConclusion::Neutral => GithubObservedCheckConclusion::Neutral,
        HttpConclusion::Success => GithubObservedCheckConclusion::Success,
        HttpConclusion::Skipped => GithubObservedCheckConclusion::Skipped,
        HttpConclusion::TimedOut => GithubObservedCheckConclusion::TimedOut,
    }
}

fn require_state(
    run: &GithubCheckRun,
    expected: GithubCheckRunState,
) -> Result<(), GithubChecksPublisherError> {
    if run.state() != expected {
        return Err(GithubChecksPublisherError::ProviderStateMismatch);
    }
    Ok(())
}

const fn suite_indeterminate_kind(value: GithubCheckCreateIndeterminate) -> &'static str {
    match value.kind() {
        GithubCheckCreateIndeterminateKind::Transport => "suite_create_transport",
        GithubCheckCreateIndeterminateKind::ProviderUnavailable => "suite_create_unavailable",
        GithubCheckCreateIndeterminateKind::InvalidSuccessResponse => {
            "suite_create_invalid_response"
        }
    }
}

const fn fail_closed_http_error(error: GithubChecksError) -> GithubChecksPublisherError {
    match error {
        GithubChecksError::Unauthorized => GithubChecksPublisherError::CredentialRejected,
        GithubChecksError::InvalidRequest
        | GithubChecksError::Forbidden
        | GithubChecksError::NotFound
        | GithubChecksError::Conflict
        | GithubChecksError::Rejected
        | GithubChecksError::InvalidResponse
        | GithubChecksError::RateLimited(_)
        | GithubChecksError::Unavailable(_) => GithubChecksPublisherError::ProviderStateMismatch,
    }
}

fn retry_delay(
    base_millis: i64,
    attempts: u16,
    evidence: Option<GithubCheckRetryEvidence>,
    failed_at: UnixMillis,
) -> i64 {
    let shift = u32::from(attempts.saturating_sub(1)).min(30);
    let attempt_delay = base_millis
        .checked_mul(1_i64 << shift)
        .unwrap_or(MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS)
        .min(MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS);
    let Some(evidence) = evidence else {
        return attempt_delay;
    };
    let retry_after = evidence
        .retry_after_seconds()
        .and_then(|seconds| i64::try_from(seconds).ok())
        .and_then(|seconds| seconds.checked_mul(1_000))
        .unwrap_or_default()
        .min(MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS);
    let reset_delay = evidence
        .rate_limit_reset_at()
        .and_then(|seconds| i64::try_from(seconds).ok())
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|reset_at| reset_at.checked_sub(failed_at.get()))
        .unwrap_or_default()
        .clamp(0, MAX_GITHUB_CHECK_PROJECTION_RETRY_MILLIS);
    attempt_delay.max(retry_after).max(reset_delay)
}

fn checked_add(
    timestamp: UnixMillis,
    duration: i64,
) -> Result<UnixMillis, GithubChecksPublisherError> {
    timestamp
        .get()
        .checked_add(duration)
        .map(UnixMillis::new)
        .ok_or(GithubChecksPublisherError::InvariantViolation)
}

fn duration_millis_ceil(duration: Duration) -> Result<i64, GithubChecksPublisherError> {
    let whole = duration.as_millis();
    let rounded = whole
        .checked_add(u128::from(
            !duration.subsec_nanos().is_multiple_of(1_000_000),
        ))
        .ok_or(GithubChecksPublisherError::InvariantViolation)?;
    i64::try_from(rounded).map_err(|_| GithubChecksPublisherError::InvariantViolation)
}

fn invariant(_: GithubCheckValueError) -> GithubChecksPublisherError {
    GithubChecksPublisherError::InvariantViolation
}
