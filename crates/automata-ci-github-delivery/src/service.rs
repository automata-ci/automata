use std::{
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::ImmutableBlobStore;
use automata_ci_core::UnixMillis;
use automata_ci_provider::ProviderConnectionId;
use automata_ci_scm::{
    RepositoryId as ScmRepositoryId, RepositorySource, RepositorySourceArchive, ScmProvider,
};
use automata_ci_store::{
    ClaimProviderDelivery, GithubRepositoryDispatchEvidenceRepository, GithubServerServiceAction,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId, GithubServerServiceHandoffId,
    GithubServerServiceRevision, GithubServerServiceWorkerId, GithubSubjectEvidenceRepository,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, MAX_PROVIDER_DELIVERY_ATTEMPTS,
    MAX_PROVIDER_DELIVERY_CLAIM_MILLIS, MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS,
    ProviderDeliveryClaimRenewalRepository, ProviderDeliveryIdentity,
    ProviderDeliveryRenewalTiming, ProviderDeliveryRepository, ProviderDeliveryStoreError,
    ProviderInstallationId, ProviderProcessingWorkerId, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RenewProviderDeliveryClaim,
    RenewedProviderDeliveryClaim, TenantScope,
};
use thiserror::Error;
use tokio::{sync::OwnedMutexGuard, time::Instant};
use tokio_util::sync::CancellationToken;

use crate::{
    GithubDeliveryClock, GithubDeliverySourceAuthority, GithubDeliveryWorker,
    GithubDeliveryWorkerConfig, GithubDeliveryWorkerConfigurationError, GithubDeliveryWorkerError,
    GithubDeliveryWorkerOutcome, GithubDeliveryWorkflowProcessor,
    worker::{GithubDeliveryClaimLease, GithubDeliveryClaimSnapshot, PreparedGithubDeliveryClaim},
    worker::{GithubDeliveryClaimRenewalApplyOutcome, ProcessingFailure},
};

const DEFAULT_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
const DEFAULT_POLL_MILLIS: i64 = 1_000;
const DEFAULT_RENEW_AFTER_MILLIS: i64 = 2 * 60 * 1_000;
const SOURCE_HANDOFF_MILLIS: i64 =
    MAX_PROVIDER_DELIVERY_CLAIM_MILLIS + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS;

/// Closed repository action bound into one server-service handoff.
///
/// The actions deliberately share no replay identity. Revision archives,
/// push comparisons, and pull-request file pages each require their exact
/// provider permission and cannot substitute for one another.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GithubDeliveryRepositoryAction {
    /// Fetch an exact repository revision archive.
    FetchRepositoryRevision,
    /// Fetch an exact repository changed-file set.
    FetchRepositoryChangedFiles,
    /// Fetch an exact pull request's changed-file set.
    FetchPullRequestFiles,
}

const fn server_service_action(
    action: GithubDeliveryRepositoryAction,
) -> GithubServerServiceAction {
    match action {
        GithubDeliveryRepositoryAction::FetchRepositoryRevision => {
            GithubServerServiceAction::FetchRepositoryRevision
        }
        GithubDeliveryRepositoryAction::FetchRepositoryChangedFiles => {
            GithubServerServiceAction::FetchRepositoryChangedFiles
        }
        GithubDeliveryRepositoryAction::FetchPullRequestFiles => {
            GithubServerServiceAction::FetchPullRequestFiles
        }
    }
}

/// Move-only capability that releases one exact durable server-service handoff.
///
/// Implementations own the complete non-secret credential release binding. They must
/// make one bounded exact release attempt and retain any replayable ambiguous
/// release evidence internally until it is resolved or the immutable handoff
/// horizon expires. The delivery credential drops its bearer before invoking
/// this capability.
#[async_trait]
pub trait GithubServerServiceCredentialRelease: fmt::Debug + Send + Sync {
    /// Releases the exact handoff after its final provider future has ended.
    async fn release(self: Box<Self>);
}

/// Bounded claiming, idle polling, and claim-renewal policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubDeliveryServiceConfig {
    claim: i64,
    poll: i64,
    renew_after: i64,
}

impl GithubDeliveryServiceConfig {
    /// Constructs one service timing policy within the durable claim bounds.
    ///
    /// The polling delay is also the retry delay for an ambiguous renewal of
    /// one byte-identical request. Renewal must begin strictly before the
    /// current claim interval ends and leave at least one full retry delay
    /// before expiry.
    ///
    /// # Errors
    ///
    /// Rejects non-positive, excessive, or incoherent durations.
    pub const fn new(
        claim_millis: i64,
        poll_millis: i64,
        renew_after_millis: i64,
    ) -> Result<Self, GithubDeliveryServiceConfigurationError> {
        if claim_millis <= 0 || claim_millis > MAX_PROVIDER_DELIVERY_CLAIM_MILLIS {
            return Err(GithubDeliveryServiceConfigurationError::InvalidClaimDuration);
        }
        if poll_millis <= 0 || poll_millis > claim_millis {
            return Err(GithubDeliveryServiceConfigurationError::InvalidPollDuration);
        }
        if renew_after_millis <= 0
            || renew_after_millis >= claim_millis
            || poll_millis > renew_after_millis
            || renew_after_millis >= claim_millis - poll_millis
        {
            return Err(GithubDeliveryServiceConfigurationError::InvalidRenewalDuration);
        }
        Ok(Self {
            claim: claim_millis,
            poll: poll_millis,
            renew_after: renew_after_millis,
        })
    }

    /// Returns the requested duration of each initial or renewed claim.
    #[must_use]
    pub const fn claim_millis(self) -> i64 {
        self.claim
    }

    /// Returns the idle and ambiguous-renewal retry delay.
    #[must_use]
    pub const fn poll_millis(self) -> i64 {
        self.poll
    }

    /// Returns the monotonic delay before attempting each renewal.
    #[must_use]
    pub const fn renew_after_millis(self) -> i64 {
        self.renew_after
    }
}

impl Default for GithubDeliveryServiceConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_CLAIM_MILLIS,
            DEFAULT_POLL_MILLIS,
            DEFAULT_RENEW_AFTER_MILLIS,
        )
        .expect("default GitHub delivery service timings fit the durable bounds")
    }
}

/// Invalid delivery-service timing configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliveryServiceConfigurationError {
    /// The initial and renewed claim duration is outside its durable bound.
    #[error("the GitHub delivery service claim duration is invalid")]
    InvalidClaimDuration,
    /// The idle and renewal-retry poll duration is invalid.
    #[error("the GitHub delivery service poll duration is invalid")]
    InvalidPollDuration,
    /// Renewal would not begin strictly within the current claim interval.
    #[error("the GitHub delivery service renewal duration is invalid")]
    InvalidRenewalDuration,
}

/// Borrowed exact repository authority requested for one claimed delivery.
#[derive(Clone, Copy)]
pub struct GithubDeliverySourceCredentialRequest<'a> {
    identity: &'a ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    authority_selector: &'a GithubServerServiceAuthoritySelector,
    snapshot: GithubDeliveryClaimSnapshot,
    action: GithubDeliveryRepositoryAction,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

impl GithubDeliverySourceCredentialRequest<'_> {
    pub(crate) fn from_live_snapshot<'a>(
        identity: &'a ProviderDeliveryIdentity,
        repository_owner_id: ProviderRepositoryOwnerId,
        authority_selector: &'a GithubServerServiceAuthoritySelector,
        snapshot: GithubDeliveryClaimSnapshot,
        action: GithubDeliveryRepositoryAction,
        observed_at: UnixMillis,
    ) -> Result<GithubDeliverySourceCredentialRequest<'a>, GithubDeliverySourceCredentialValueError>
    {
        let observed_at = observed_at.max(snapshot.renewed_at());
        let required_through = provider_required_through(snapshot, observed_at)?;
        if identity.provider() != "github"
            || authority_selector.tenant() != identity.tenant()
            || snapshot.attempt() == 0
            || snapshot.attempt() > MAX_PROVIDER_DELIVERY_ATTEMPTS
        {
            return Err(GithubDeliverySourceCredentialValueError::InvalidBinding);
        }
        Ok(GithubDeliverySourceCredentialRequest {
            identity,
            repository_owner_id,
            authority_selector,
            snapshot,
            action,
            observed_at,
            required_through,
        })
    }

    /// Returns the exact tenant, connection, installation, numeric repository,
    /// and provider-native repository identity frozen by the delivery claim.
    #[must_use]
    pub const fn identity(&self) -> &ProviderDeliveryIdentity {
        self.identity
    }

    /// Returns the signed positive numeric GitHub repository-owner identity.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.repository_owner_id
    }

    /// Returns the immutable repository-source authority pinned at acceptance.
    #[must_use]
    pub const fn authority_selector(&self) -> &GithubServerServiceAuthoritySelector {
        self.authority_selector
    }

    /// Returns the exact current delivery UUID, worker, rotated fence, attempt,
    /// original claim time, renewal observation, and live lease expiry.
    #[must_use]
    pub const fn snapshot(&self) -> GithubDeliveryClaimSnapshot {
        self.snapshot
    }

    /// Returns the disjoint private-repository action requested from authority.
    #[must_use]
    pub const fn action(&self) -> GithubDeliveryRepositoryAction {
        self.action
    }

    /// Returns the trusted current acquisition observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }

    /// Returns the conservative time through which the credential must remain usable.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }

    /// Derives the exact consumer claim from this delivery lease.
    ///
    /// # Errors
    ///
    /// Fails closed if a validated delivery UUID, owner, fence, action, or
    /// attempt cannot be represented by the adjacent authority boundary.
    pub fn consumer_claim(
        &self,
    ) -> Result<GithubServerServiceConsumerClaim, GithubDeliverySourceCredentialValueError> {
        let claim = self.snapshot.claim();
        Ok(GithubServerServiceConsumerClaim::new(
            GithubServerServiceConsumerId::from_uuid(claim.delivery_id().as_uuid())
                .map_err(|_| GithubDeliverySourceCredentialValueError::InvalidBinding)?,
            GithubServerServiceWorkerId::from_uuid(claim.owner().as_uuid())
                .map_err(|_| GithubDeliverySourceCredentialValueError::InvalidBinding)?,
            GithubServerServiceClaimFence::new(claim.fence())
                .map_err(|_| GithubDeliverySourceCredentialValueError::InvalidBinding)?,
            server_service_action(self.action),
            GithubServerServiceRevision::new(u64::from(self.snapshot.attempt()))
                .map_err(|_| GithubDeliverySourceCredentialValueError::InvalidBinding)?,
        ))
    }
}

pub(crate) fn provider_required_through(
    snapshot: GithubDeliveryClaimSnapshot,
    observed_at: UnixMillis,
) -> Result<UnixMillis, GithubDeliverySourceCredentialValueError> {
    let observed_at = observed_at.max(snapshot.renewed_at());
    let required_through = snapshot
        .expires_at()
        .get()
        .checked_add(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
        .map(UnixMillis::new)
        .ok_or(GithubDeliverySourceCredentialValueError::InvalidBinding)?;
    let handoff_millis = required_through
        .get()
        .checked_sub(observed_at.get())
        .filter(|duration| *duration > 0 && *duration <= SOURCE_HANDOFF_MILLIS);
    if snapshot.attempt() == 0
        || snapshot.attempt() > MAX_PROVIDER_DELIVERY_ATTEMPTS
        || snapshot.claimed_at() > snapshot.renewed_at()
        || observed_at < snapshot.renewed_at()
        || observed_at >= snapshot.expires_at()
        || handoff_millis.is_none()
    {
        return Err(GithubDeliverySourceCredentialValueError::InvalidBinding);
    }
    Ok(required_through)
}

impl fmt::Debug for GithubDeliverySourceCredentialRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliverySourceCredentialRequest")
            .field("identity", &"[redacted]")
            .field("repository_owner_id", &"[redacted]")
            .field("authority_selector", &"[redacted]")
            .field("snapshot", &self.snapshot)
            .field("action", &self.action)
            .field("observed_at", &self.observed_at)
            .field("required_through", &self.required_through)
            .finish()
    }
}

/// Immutable non-secret authority bound into one repository source credential.
pub struct GithubDeliverySourceCredentialBinding {
    identity: ProviderDeliveryIdentity,
    repository_owner_id: ProviderRepositoryOwnerId,
    repository: ScmRepositoryId,
    authority_selector: GithubServerServiceAuthoritySelector,
    handoff_id: GithubServerServiceHandoffId,
    consumer: GithubServerServiceConsumerClaim,
    required_through: UnixMillis,
}

impl GithubDeliverySourceCredentialBinding {
    /// Constructs the exact delivery, repository, action, revision, and horizon binding.
    ///
    /// # Errors
    ///
    /// Rejects a non-GitHub identity, a mismatched repository
    /// route, or an invalid durable attempt or horizon.
    pub fn new(
        identity: ProviderDeliveryIdentity,
        repository_owner_id: ProviderRepositoryOwnerId,
        repository: ScmRepositoryId,
        authority_selector: GithubServerServiceAuthoritySelector,
        handoff_id: GithubServerServiceHandoffId,
        consumer: GithubServerServiceConsumerClaim,
        required_through: UnixMillis,
    ) -> Result<Self, GithubDeliverySourceCredentialValueError> {
        if identity.provider() != "github"
            || repository.as_str() != identity.repository_identity()
            || authority_selector.tenant() != identity.tenant()
            || !matches!(
                consumer.action(),
                GithubServerServiceAction::FetchRepositoryRevision
                    | GithubServerServiceAction::FetchRepositoryChangedFiles
                    | GithubServerServiceAction::FetchPullRequestFiles
            )
            || consumer.revision().get() > u64::from(MAX_PROVIDER_DELIVERY_ATTEMPTS)
            || required_through.get() < 0
        {
            return Err(GithubDeliverySourceCredentialValueError::InvalidBinding);
        }
        Ok(Self {
            identity,
            repository_owner_id,
            repository,
            authority_selector,
            handoff_id,
            consumer,
            required_through,
        })
    }
}

impl fmt::Debug for GithubDeliverySourceCredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliverySourceCredentialBinding")
            .field("identity", &"[redacted]")
            .field("repository_owner_id", &"[redacted]")
            .field("repository", &"[redacted]")
            .field("authority_selector", &"[redacted]")
            .field("handoff_id", &self.handoff_id)
            .field("consumer", &"[redacted]")
            .field("required_through", &self.required_through)
            .finish()
    }
}

/// Move-only source credential bound to one exact GitHub repository authority.
///
/// The product-owned issuer must mint this credential for only the bound
/// repository with exactly `contents: read`; no union with Checks, job, or
/// other installation permissions is permitted.
#[must_use = "the credential must be used and exactly released"]
pub struct GithubDeliverySourceCredential {
    binding: GithubDeliverySourceCredentialBinding,
    acquired_at: UnixMillis,
    token: SecretString,
    conservative_expires_at: UnixMillis,
    release: Box<dyn GithubServerServiceCredentialRelease>,
}

impl GithubDeliverySourceCredential {
    /// Constructs one request-scoped repository credential handoff.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent repository, consumer, time, or credential-lifetime
    /// evidence.
    pub fn new(
        binding: GithubDeliverySourceCredentialBinding,
        acquired_at: UnixMillis,
        token: SecretString,
        conservative_expires_at: UnixMillis,
        release: Box<dyn GithubServerServiceCredentialRelease>,
    ) -> Result<Self, GithubDeliverySourceCredentialValueError> {
        let handoff_millis = binding
            .required_through
            .get()
            .checked_sub(acquired_at.get())
            .filter(|duration| *duration > 0 && *duration <= SOURCE_HANDOFF_MILLIS);
        if acquired_at.get() < 0 || handoff_millis.is_none() {
            return Err(GithubDeliverySourceCredentialValueError::InvalidBinding);
        }
        if conservative_expires_at < binding.required_through {
            return Err(GithubDeliverySourceCredentialValueError::InvalidExpiration);
        }
        Ok(Self {
            binding,
            acquired_at,
            token,
            conservative_expires_at,
            release,
        })
    }

    /// Returns the authenticated tenant binding.
    #[must_use]
    pub const fn tenant(&self) -> &TenantScope {
        self.binding.identity.tenant()
    }

    /// Returns the exact authenticated delivery routing identity.
    #[must_use]
    pub const fn identity(&self) -> &ProviderDeliveryIdentity {
        &self.binding.identity
    }

    /// Returns the provider connection binding.
    #[must_use]
    pub const fn connection_id(&self) -> ProviderConnectionId {
        self.binding.identity.connection_id()
    }

    /// Returns the GitHub installation binding.
    #[must_use]
    pub const fn installation_id(&self) -> ProviderInstallationId {
        self.binding.identity.installation_id()
    }

    /// Returns the stable numeric GitHub repository binding.
    #[must_use]
    pub const fn repository_id(&self) -> ProviderRepositoryId {
        self.binding.identity.repository_id()
    }

    /// Returns the positive numeric GitHub repository-owner claimed by this binding.
    #[must_use]
    pub const fn repository_owner_id(&self) -> ProviderRepositoryOwnerId {
        self.binding.repository_owner_id
    }

    /// Returns the provider-native owner/name route attested for the numeric repository.
    #[must_use]
    pub const fn repository(&self) -> &ScmRepositoryId {
        &self.binding.repository
    }

    /// Returns the immutable authority selector that granted this handoff.
    #[must_use]
    pub const fn authority_selector(&self) -> &GithubServerServiceAuthoritySelector {
        &self.binding.authority_selector
    }

    /// Returns the durable handoff identity retained for exact release/replay.
    #[must_use]
    pub const fn handoff_id(&self) -> GithubServerServiceHandoffId {
        self.binding.handoff_id
    }

    /// Returns the exact delivery claim/action/attempt consumer binding.
    #[must_use]
    pub const fn consumer(&self) -> GithubServerServiceConsumerClaim {
        self.binding.consumer
    }

    /// Returns the immutable handoff horizon.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.binding.required_through
    }

    /// Returns the trusted acquisition or exact-replay observation.
    #[must_use]
    pub const fn acquired_at(&self) -> UnixMillis {
        self.acquired_at
    }

    /// Returns the conservative credential expiry.
    #[must_use]
    pub const fn conservative_expires_at(&self) -> UnixMillis {
        self.conservative_expires_at
    }

    pub(crate) const fn token(&self) -> &SecretString {
        &self.token
    }

    pub(crate) async fn release(self) {
        let Self { token, release, .. } = self;
        drop(token);
        release.release().await;
    }
}

impl fmt::Debug for GithubDeliverySourceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliverySourceCredential")
            .field("binding", &self.binding)
            .field("acquired_at", &self.acquired_at)
            .field("token", &"[redacted]")
            .field("conservative_expires_at", &self.conservative_expires_at)
            .field("release", &"[exact release capability]")
            .finish()
    }
}

/// Invalid source-credential handoff.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliverySourceCredentialValueError {
    /// Repository, consumer claim, action, attempt, or handoff time is invalid.
    #[error("the GitHub delivery source credential binding is invalid")]
    InvalidBinding,
    /// The conservative expiry predates the Unix epoch.
    #[error("the GitHub delivery source credential expiration is invalid")]
    InvalidExpiration,
}

/// Sanitized failure from the product-owned repository credential authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliverySourceCredentialProviderError {
    /// Existing current authority is temporarily unavailable.
    #[error("the GitHub delivery source credential authority is unavailable")]
    Unavailable,
    /// Current policy or provider authority rejected the exact request.
    #[error("the GitHub delivery source credential authority rejected the request")]
    Rejected,
    /// The authority could not establish internally consistent current state.
    #[error("the GitHub delivery source credential authority has inconsistent state")]
    InvariantViolation,
}

/// Least-authority provider for one request-scoped repository credential.
///
/// Implementations resolve existing product authority. They must not delegate
/// installation-token minting, caching, or persistence to this service.
#[async_trait]
pub trait GithubDeliverySourceCredentialProvider: fmt::Debug + Send + Sync {
    /// Hands off a move-only exact-repository `contents: read` credential for
    /// the exact borrowed private claim identity.
    ///
    /// # Errors
    ///
    /// Returns only a sanitized unavailable, rejected, or inconsistent outcome.
    async fn acquire(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError>;
}

/// Result of one bounded claim-and-process service invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubDeliveryServiceOutcome {
    /// No eligible provider delivery existed.
    Idle,
    /// One exact delivery reached a durable worker outcome.
    Processed(GithubDeliveryWorkerOutcome),
}

/// Sanitized delivery-supervision failure.
#[derive(Debug, Error)]
pub enum GithubDeliveryServiceError {
    /// Durable claim or renewal access failed.
    #[error(transparent)]
    Store(#[from] ProviderDeliveryStoreError),
    /// The durable repository returned claim evidence inconsistent with the exact request.
    #[error("the GitHub delivery service received an invalid claim")]
    InvalidClaim,
    /// The durable repository returned renewal evidence inconsistent with the exact request.
    #[error("the GitHub delivery service received an invalid claim renewal")]
    InvalidRenewal,
    /// The trusted clock returned a negative, regressed, or overflowing timestamp.
    #[error("the GitHub delivery service clock returned an invalid timestamp")]
    InvalidTrustedTime,
    /// The exact claim expired or was rejected while processing was active.
    #[error("the GitHub delivery service lost its durable claim")]
    ClaimLost,
    /// Local shutdown cancelled claiming or active processing.
    #[error("the GitHub delivery service was shut down")]
    Shutdown,
    /// The claimed-delivery worker could not safely complete its transition.
    #[error(transparent)]
    Worker(#[from] GithubDeliveryWorkerError),
}

/// Product-supervised durable GitHub delivery claim and renewal service.
pub struct GithubDeliveryService {
    worker: Arc<GithubDeliveryWorker>,
    deliveries: Arc<dyn ProviderDeliveryRepository>,
    renewals: Arc<dyn ProviderDeliveryClaimRenewalRepository>,
    credentials: Arc<dyn GithubDeliverySourceCredentialProvider>,
    clock: Arc<dyn GithubDeliveryClock>,
    worker_id: ProviderProcessingWorkerId,
    config: GithubDeliveryServiceConfig,
}

enum CredentialAcquisition {
    Credential(Box<GithubDeliverySourceCredential>),
    SnapshotRotated,
    Finished(GithubDeliveryWorkerOutcome),
}

enum RevisionFetch {
    SnapshotRotated,
    Classified {
        source: Result<RepositorySourceArchive, ProcessingFailure>,
        operation: OwnedMutexGuard<()>,
    },
}

impl GithubDeliveryService {
    /// Constructs a delivery service with request-scoped repository credentials.
    ///
    /// # Errors
    ///
    /// Rejects a worker configuration incompatible with GitHub delivery.
    #[allow(clippy::too_many_arguments)]
    pub fn new<R>(
        objects: Arc<dyn ImmutableBlobStore>,
        repository_source: Arc<dyn RepositorySource>,
        workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor>,
        deliveries: Arc<R>,
        credentials: Arc<dyn GithubDeliverySourceCredentialProvider>,
        clock: Arc<dyn GithubDeliveryClock>,
        worker_id: ProviderProcessingWorkerId,
        worker_config: GithubDeliveryWorkerConfig,
        config: GithubDeliveryServiceConfig,
    ) -> Result<Self, GithubDeliveryWorkerConfigurationError>
    where
        R: ProviderDeliveryRepository
            + ProviderDeliveryClaimRenewalRepository
            + GithubSubjectEvidenceRepository
            + 'static,
    {
        Self::new_with_optional_repository_dispatch(
            objects,
            repository_source,
            workflow_processor,
            deliveries,
            credentials,
            None,
            clock,
            worker_id,
            worker_config,
            config,
        )
    }

    /// Constructs a delivery service with custom-dispatch resolution.
    ///
    /// # Errors
    ///
    /// Rejects either source adapter when it does not identify as GitHub.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_repository_dispatch<R>(
        objects: Arc<dyn ImmutableBlobStore>,
        repository_source: Arc<dyn RepositorySource>,
        repository_dispatch_resolver: Arc<dyn ScmProvider>,
        workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor>,
        deliveries: Arc<R>,
        repository_dispatches: Arc<dyn GithubRepositoryDispatchEvidenceRepository>,
        credentials: Arc<dyn GithubDeliverySourceCredentialProvider>,
        clock: Arc<dyn GithubDeliveryClock>,
        worker_id: ProviderProcessingWorkerId,
        worker_config: GithubDeliveryWorkerConfig,
        config: GithubDeliveryServiceConfig,
    ) -> Result<Self, GithubDeliveryWorkerConfigurationError>
    where
        R: ProviderDeliveryRepository
            + ProviderDeliveryClaimRenewalRepository
            + GithubSubjectEvidenceRepository
            + 'static,
    {
        Self::new_with_optional_repository_dispatch(
            objects,
            repository_source,
            workflow_processor,
            deliveries,
            credentials,
            Some((repository_dispatches, repository_dispatch_resolver)),
            clock,
            worker_id,
            worker_config,
            config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_optional_repository_dispatch<R>(
        objects: Arc<dyn ImmutableBlobStore>,
        repository_source: Arc<dyn RepositorySource>,
        workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor>,
        deliveries: Arc<R>,
        credentials: Arc<dyn GithubDeliverySourceCredentialProvider>,
        repository_dispatch: Option<(
            Arc<dyn GithubRepositoryDispatchEvidenceRepository>,
            Arc<dyn ScmProvider>,
        )>,
        clock: Arc<dyn GithubDeliveryClock>,
        worker_id: ProviderProcessingWorkerId,
        worker_config: GithubDeliveryWorkerConfig,
        config: GithubDeliveryServiceConfig,
    ) -> Result<Self, GithubDeliveryWorkerConfigurationError>
    where
        R: ProviderDeliveryRepository
            + ProviderDeliveryClaimRenewalRepository
            + GithubSubjectEvidenceRepository
            + 'static,
    {
        let delivery_repository: Arc<dyn ProviderDeliveryRepository> = deliveries.clone();
        let subject_evidence_repository: Arc<dyn GithubSubjectEvidenceRepository> =
            deliveries.clone();
        let renewal_repository: Arc<dyn ProviderDeliveryClaimRenewalRepository> = deliveries;
        let worker = Arc::new(match repository_dispatch {
            Some((repository_dispatches, resolver)) => {
                GithubDeliveryWorker::new_with_repository_dispatch(
                    objects,
                    repository_source,
                    resolver,
                    workflow_processor,
                    delivery_repository.clone(),
                    subject_evidence_repository,
                    repository_dispatches,
                    clock.clone(),
                    worker_config,
                )?
            }
            None => GithubDeliveryWorker::new(
                objects,
                repository_source,
                workflow_processor,
                delivery_repository.clone(),
                subject_evidence_repository,
                clock.clone(),
                worker_config,
            )?,
        });
        Ok(Self {
            worker,
            deliveries: delivery_repository,
            renewals: renewal_repository,
            credentials,
            clock,
            worker_id,
            config,
        })
    }

    /// Returns the stable durable identity used by every claim from this service.
    #[must_use]
    pub const fn worker_id(&self) -> ProviderProcessingWorkerId {
        self.worker_id
    }

    /// Claims and supervises at most one eligible delivery.
    ///
    /// Processing is raced against shutdown and rotated-fence renewal. Losing the
    /// claim drops the in-flight credential/provider/processor future before it
    /// can begin another stage. Terminal writes independently recheck the
    /// latest accepted renewal snapshot.
    ///
    /// # Errors
    ///
    /// Returns a sanitized store, evidence, clock, shutdown, or worker failure.
    pub async fn run_once(
        &self,
        shutdown: CancellationToken,
    ) -> Result<GithubDeliveryServiceOutcome, GithubDeliveryServiceError> {
        if shutdown.is_cancelled() {
            return Err(GithubDeliveryServiceError::Shutdown);
        }
        let monotonic_observed_at = Instant::now();
        let observed_at = self.now()?;
        let expires_at = checked_add(observed_at, self.config.claim_millis())?;
        let deadline = monotonic_observed_at
            .checked_add(duration(self.config.claim_millis()))
            .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?;
        let request = ClaimProviderDelivery::new(self.worker_id, observed_at, expires_at)
            .map_err(|_| GithubDeliveryServiceError::InvalidTrustedTime)?;
        let claimed = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Err(GithubDeliveryServiceError::Shutdown),
            claimed = self.deliveries.claim_provider_delivery(request) => claimed?,
        };
        let Some(claimed) = claimed else {
            return Ok(GithubDeliveryServiceOutcome::Idle);
        };
        if claimed.claim().owner() != self.worker_id
            || claimed
                .expires_at()
                .get()
                .checked_sub(claimed.claimed_at().get())
                != Some(self.config.claim_millis())
            || Instant::now() >= deadline
        {
            return Err(GithubDeliveryServiceError::InvalidClaim);
        }

        let lease = GithubDeliveryClaimLease::new(claimed, deadline);
        let processing = self.process_claim(&lease);
        let renewal = self.renew_claim(&lease);
        let expiration = lease.await_expiration();
        tokio::pin!(processing);
        tokio::pin!(renewal);
        tokio::pin!(expiration);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => Err(GithubDeliveryServiceError::Shutdown),
            error = &mut expiration => Err(claim_error(error)),
            outcome = &mut processing => outcome
                .map(GithubDeliveryServiceOutcome::Processed)
                .map_err(normalize_claim_loss),
            renewal_result = &mut renewal => {
                if let Err(error) = renewal_result {
                    Err(error)
                } else {
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => Err(GithubDeliveryServiceError::Shutdown),
                        error = &mut expiration => Err(claim_error(error)),
                        outcome = &mut processing => outcome
                            .map(GithubDeliveryServiceOutcome::Processed)
                            .map_err(normalize_claim_loss),
                    }
                }
            }
        }
    }

    /// Polls and processes deliveries until shutdown or a non-recoverable failure.
    ///
    /// Transient durable unavailability uses the same bounded poll delay as
    /// idle polling. A lost claim is already fenced and starts no further work.
    ///
    /// # Errors
    ///
    /// Returns the first non-recoverable service failure.
    pub async fn run(&self, shutdown: CancellationToken) -> Result<(), GithubDeliveryServiceError> {
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match self.run_once(shutdown.child_token()).await {
                Ok(GithubDeliveryServiceOutcome::Idle) => {
                    if sleep_or_shutdown(self.poll_duration(), &shutdown).await {
                        return Ok(());
                    }
                }
                Ok(GithubDeliveryServiceOutcome::Processed(_))
                | Err(GithubDeliveryServiceError::ClaimLost) => {}
                Err(GithubDeliveryServiceError::Shutdown) if shutdown.is_cancelled() => {
                    return Ok(());
                }
                Err(error) if retryable(&error) => {
                    if sleep_or_shutdown(self.poll_duration(), &shutdown).await {
                        return Ok(());
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn process_claim(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryServiceError> {
        let prepared = self.worker.prepare_leased(lease).await?;
        let PreparedGithubDeliveryClaim::Live(prepared) = prepared else {
            let PreparedGithubDeliveryClaim::Finished(outcome) = prepared else {
                unreachable!("the prepared delivery claim has only two variants")
            };
            return Ok(outcome);
        };

        if prepared.deleted() {
            return self.worker.finish_deleted(lease).await.map_err(Into::into);
        }

        match lease.initial().identity().repository_visibility() {
            ProviderRepositoryVisibility::Public
                if prepared.pending_repository_dispatch().is_none() =>
            {
                self.process_public_claim(lease, prepared.as_ref()).await
            }
            ProviderRepositoryVisibility::Public | ProviderRepositoryVisibility::Private => {
                self.process_authenticated_claim(lease, prepared.as_ref())
                    .await
            }
        }
    }

    async fn process_public_claim(
        &self,
        lease: &GithubDeliveryClaimLease,
        prepared: &crate::worker::PreparedGithubDelivery,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryServiceError> {
        let operation = lease.lock_operation().await;
        lease.require_live_at(self.now()?)?;
        let source = self.worker.fetch_source(
            lease.initial(),
            prepared,
            GithubDeliverySourceAuthority::DirectPublicArchive {
                changed_files_credentials: self.credentials.as_ref(),
            },
        );
        tokio::pin!(source);
        let ready = poll_provider_once(lease, source.as_mut())
            .await
            .map_err(claim_error)?;
        drop(operation);
        let source = match ready {
            Some(source) => source,
            None => source.await,
        };
        let source = match source {
            Ok(source) => source,
            Err(failure) => {
                return self
                    .worker
                    .finish_failure(lease, failure)
                    .await
                    .map_err(Into::into);
            }
        };
        self.worker
            .process_fetched_source_leased(
                lease,
                prepared,
                &source,
                Some(self.credentials.as_ref()),
            )
            .await
            .map_err(Into::into)
    }

    async fn process_authenticated_claim(
        &self,
        lease: &GithubDeliveryClaimLease,
        prepared: &crate::worker::PreparedGithubDelivery,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryServiceError> {
        let credentials = Arc::clone(&self.credentials);
        let authority_selector = prepared.repository_contents_authority();
        loop {
            let (requested_snapshot, observed_at) = lease
                .require_live_observation(self.now()?)
                .map_err(claim_error)?;
            let repository_owner_id =
                ProviderRepositoryOwnerId::new(prepared.event().repository().owner_id().get())
                    .map_err(|_| {
                        GithubDeliveryServiceError::Worker(
                            GithubDeliveryWorkerError::InvariantViolation,
                        )
                    })?;
            let request = GithubDeliverySourceCredentialRequest::from_live_snapshot(
                lease.initial().identity(),
                repository_owner_id,
                authority_selector,
                requested_snapshot,
                GithubDeliveryRepositoryAction::FetchRepositoryRevision,
                observed_at,
            )
            .map_err(|_| GithubDeliveryServiceError::InvalidTrustedTime)?;
            let credential = match self
                .acquire_credential(lease, credentials.as_ref(), request, requested_snapshot)
                .await?
            {
                CredentialAcquisition::Credential(credential) => credential,
                CredentialAcquisition::SnapshotRotated => continue,
                CredentialAcquisition::Finished(outcome) => return Ok(outcome),
            };
            let RevisionFetch::Classified { source, operation } = self
                .fetch_revision(
                    lease,
                    prepared,
                    credentials.as_ref(),
                    requested_snapshot,
                    credential,
                )
                .await?
            else {
                continue;
            };
            let source = match source {
                Ok(source) => source,
                Err(failure) => {
                    return self
                        .worker
                        .finish_failure_with_operation(lease, failure, operation)
                        .await
                        .map_err(Into::into);
                }
            };
            drop(operation);
            return self
                .worker
                .process_fetched_source_leased(lease, prepared, &source, Some(credentials.as_ref()))
                .await
                .map_err(Into::into);
        }
    }

    async fn fetch_revision(
        &self,
        lease: &GithubDeliveryClaimLease,
        prepared: &crate::worker::PreparedGithubDelivery,
        credentials: &dyn GithubDeliverySourceCredentialProvider,
        requested_snapshot: GithubDeliveryClaimSnapshot,
        credential: Box<GithubDeliverySourceCredential>,
    ) -> Result<RevisionFetch, GithubDeliveryServiceError> {
        let operation = lease.lock_operation().await;
        let provider_observed_at = match self.now() {
            Ok(observed_at) => observed_at,
            Err(error) => {
                drop(operation);
                (*credential).release().await;
                return Err(error);
            }
        };
        let (latest, provider_observed_at) =
            match lease.require_live_observation(provider_observed_at) {
                Ok(observation) => observation,
                Err(error) => {
                    drop(operation);
                    (*credential).release().await;
                    return Err(claim_error(error));
                }
            };
        if latest != requested_snapshot {
            drop(operation);
            (*credential).release().await;
            return Ok(RevisionFetch::SnapshotRotated);
        }
        if credential.acquired_at() > provider_observed_at {
            drop(operation);
            (*credential).release().await;
            return Err(GithubDeliveryServiceError::InvalidTrustedTime);
        }
        let source = {
            let source = self.worker.fetch_source(
                lease.initial(),
                prepared,
                GithubDeliverySourceAuthority::InstallationContentsRead {
                    credential: credential.token(),
                    changed_files_credentials: Some(credentials),
                },
            );
            tokio::pin!(source);
            let ready = poll_provider_once(lease, source.as_mut()).await;
            drop(operation);
            match ready {
                Ok(Some(source)) => Ok(source),
                Ok(None) => Ok(source.await),
                Err(error) => Err(error),
            }
        };
        let source = match source {
            Ok(source) => source,
            Err(error) => {
                (*credential).release().await;
                return Err(claim_error(error));
            }
        };
        let operation = lease.lock_operation().await;
        let post_provider_observed_at = match self.now() {
            Ok(observed_at) => observed_at,
            Err(error) => {
                drop(operation);
                (*credential).release().await;
                return Err(error);
            }
        };
        let post_provider_snapshot = match lease.require_live_observation(post_provider_observed_at)
        {
            Ok((snapshot, _)) => snapshot,
            Err(error) => {
                drop(operation);
                (*credential).release().await;
                return Err(claim_error(error));
            }
        };
        if post_provider_snapshot != requested_snapshot {
            drop(operation);
            (*credential).release().await;
            return Ok(RevisionFetch::SnapshotRotated);
        }
        drop(operation);
        (*credential).release().await;

        let operation = lease.lock_operation().await;
        let latest = lease.require_live_at(self.now()?).map_err(claim_error)?;
        if !requested_snapshot.has_same_live_lineage(latest) {
            drop(operation);
            return Err(GithubDeliveryServiceError::ClaimLost);
        }
        Ok(RevisionFetch::Classified { source, operation })
    }

    async fn acquire_credential(
        &self,
        lease: &GithubDeliveryClaimLease,
        credentials: &dyn GithubDeliverySourceCredentialProvider,
        request: GithubDeliverySourceCredentialRequest<'_>,
        requested_snapshot: GithubDeliveryClaimSnapshot,
    ) -> Result<CredentialAcquisition, GithubDeliveryServiceError> {
        let operation = lease.lock_operation().await;
        let current = lease.require_live_at(self.now()?).map_err(claim_error)?;
        if current != requested_snapshot {
            drop(operation);
            return Ok(CredentialAcquisition::SnapshotRotated);
        }
        let credential = credentials.acquire(request);
        tokio::pin!(credential);
        let ready = poll_provider_once(lease, credential.as_mut())
            .await
            .map_err(claim_error)?;
        drop(operation);
        let failure = match match ready {
            Some(credential) => credential,
            None => credential.await,
        } {
            Ok(credential) if credential_matches_request(&credential, request) => {
                return Ok(CredentialAcquisition::Credential(Box::new(credential)));
            }
            Ok(credential) => {
                credential.release().await;
                GithubDeliverySourceCredentialProviderError::InvariantViolation
            }
            Err(failure) => failure,
        };
        let operation = lease.lock_operation().await;
        if lease.latest()? != requested_snapshot {
            drop(operation);
            return Ok(CredentialAcquisition::SnapshotRotated);
        }
        let outcome = match failure {
            GithubDeliverySourceCredentialProviderError::Unavailable => {
                self.worker
                    .finish_credential_unavailable(lease, operation)
                    .await?
            }
            GithubDeliverySourceCredentialProviderError::Rejected => {
                self.worker
                    .finish_credential_rejected(lease, operation)
                    .await?
            }
            GithubDeliverySourceCredentialProviderError::InvariantViolation => {
                self.worker
                    .finish_credential_invalid(lease, operation)
                    .await?
            }
        };
        Ok(CredentialAcquisition::Finished(outcome))
    }

    async fn renew_claim(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<(), GithubDeliveryServiceError> {
        let hard_expires_at = hard_claim_expires_at(lease)?;
        loop {
            let predecessor_deadline = lease.deadline().map_err(claim_error)?;
            let renew_at = Instant::now()
                .checked_add(duration(self.config.renew_after_millis()))
                .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?;
            let retry_guard_at = renew_at
                .checked_add(self.poll_duration())
                .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?;
            if retry_guard_at >= predecessor_deadline {
                tokio::time::sleep_until(predecessor_deadline).await;
                return Err(GithubDeliveryServiceError::ClaimLost);
            }
            tokio::time::sleep_until(renew_at).await;
            if Instant::now() >= predecessor_deadline {
                return Err(GithubDeliveryServiceError::ClaimLost);
            }

            let operation = lease.lock_operation().await;
            if lease.terminal_transition_started() {
                drop(operation);
                return Ok(());
            }
            let confirmed_predecessor_deadline = lease.deadline().map_err(claim_error)?;
            if Instant::now() >= confirmed_predecessor_deadline {
                return Err(GithubDeliveryServiceError::ClaimLost);
            }
            let monotonic_observed_at = Instant::now();
            let observed_at = self.now()?;
            if Instant::now() >= confirmed_predecessor_deadline {
                return Err(GithubDeliveryServiceError::ClaimLost);
            }
            let (latest, observed_at) = lease
                .require_live_observation(observed_at)
                .map_err(claim_error)?;
            let timing = ProviderDeliveryRenewalTiming::new(
                confirmed_predecessor_deadline,
                monotonic_observed_at,
                observed_at,
                latest.expires_at(),
            )
            .map_err(|_| {
                if Instant::now() >= confirmed_predecessor_deadline {
                    GithubDeliveryServiceError::ClaimLost
                } else {
                    GithubDeliveryServiceError::InvalidRenewal
                }
            })?;
            if !lease
                .narrow_predecessor_deadline(latest, timing.deadline())
                .map_err(claim_error)?
            {
                return Err(GithubDeliveryServiceError::InvalidRenewal);
            }
            if Instant::now() >= timing.deadline() {
                return Err(GithubDeliveryServiceError::ClaimLost);
            }
            let desired_expires_at = checked_add(observed_at, self.config.claim_millis())?;
            let expires_at = desired_expires_at.min(hard_expires_at);
            if expires_at <= latest.expires_at() {
                drop(operation);
                return match self
                    .await_predecessor_guarded(
                        lease,
                        latest,
                        observed_at,
                        std::future::pending::<()>(),
                    )
                    .await
                {
                    Ok(_) => Err(GithubDeliveryServiceError::InvalidRenewal),
                    Err(error) => Err(error),
                };
            }
            let request = RenewProviderDeliveryClaim::new(
                latest.claim(),
                latest.attempt(),
                latest.claimed_at(),
                timing,
                expires_at,
            )
            .map_err(|_| GithubDeliveryServiceError::InvalidRenewal)?;
            if Instant::now() >= request.deadline() {
                return Err(GithubDeliveryServiceError::ClaimLost);
            }
            let successor_duration = request
                .expires_at()
                .get()
                .checked_sub(request.observed_at().get())
                .and_then(|duration| u64::try_from(duration).ok())
                .ok_or(GithubDeliveryServiceError::InvalidRenewal)?;
            // The database samples its issuance time after this monotonic
            // observation. Capping the local successor at observation plus the
            // exact requested duration therefore cannot outlive the durable
            // lease, including after an ambiguous response retry.
            let successor_deadline_upper = monotonic_observed_at
                .checked_add(Duration::from_millis(successor_duration))
                .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?;
            self.renew_exact_request(lease, latest, request, successor_deadline_upper)
                .await?;
            drop(operation);
        }
    }

    async fn renew_exact_request(
        &self,
        lease: &GithubDeliveryClaimLease,
        predecessor: GithubDeliveryClaimSnapshot,
        request: RenewProviderDeliveryClaim,
        successor_deadline_upper: Instant,
    ) -> Result<(), GithubDeliveryServiceError> {
        let mut wall_floor = request.observed_at();
        loop {
            let result = self.renewals.renew_provider_delivery_claim(request);
            let (result, monotonic_response_at, response_at) = self
                .await_predecessor_guarded(lease, predecessor, wall_floor, result)
                .await?;
            wall_floor = response_at;
            match result {
                Ok(renewed) => {
                    return apply_renewed_claim(
                        lease,
                        request,
                        renewed,
                        monotonic_response_at,
                        response_at,
                        successor_deadline_upper,
                    );
                }
                Err(ProviderDeliveryStoreError::Operation(_)) => {
                    let retry_at = Instant::now()
                        .checked_add(duration(self.config.poll_millis()))
                        .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?
                        .min(lease.deadline().map_err(claim_error)?);
                    let ((), _, retry_wall) = self
                        .await_predecessor_guarded(
                            lease,
                            predecessor,
                            wall_floor,
                            tokio::time::sleep_until(retry_at),
                        )
                        .await?;
                    wall_floor = retry_wall;
                }
                Err(ProviderDeliveryStoreError::ClaimRejected) => {
                    return Err(GithubDeliveryServiceError::ClaimLost);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn refresh_predecessor_guard(
        &self,
        lease: &GithubDeliveryClaimLease,
        predecessor: GithubDeliveryClaimSnapshot,
        wall_floor: UnixMillis,
    ) -> Result<(Instant, UnixMillis), GithubDeliveryServiceError> {
        let current_deadline = lease.deadline().map_err(claim_error)?;
        let sampled_at = Instant::now();
        if sampled_at >= current_deadline {
            return Err(GithubDeliveryServiceError::ClaimLost);
        }
        let observed_at = self.now()?.max(predecessor.renewed_at());
        if observed_at < wall_floor {
            return Err(GithubDeliveryServiceError::InvalidTrustedTime);
        }
        if observed_at >= predecessor.expires_at() || Instant::now() >= current_deadline {
            return Err(GithubDeliveryServiceError::ClaimLost);
        }
        let timing = ProviderDeliveryRenewalTiming::new(
            current_deadline,
            sampled_at,
            observed_at,
            predecessor.expires_at(),
        )
        .map_err(|_| {
            if Instant::now() >= current_deadline {
                GithubDeliveryServiceError::ClaimLost
            } else {
                GithubDeliveryServiceError::InvalidRenewal
            }
        })?;
        if !lease
            .narrow_predecessor_deadline(predecessor, timing.deadline())
            .map_err(claim_error)?
        {
            return Err(GithubDeliveryServiceError::ClaimLost);
        }
        if Instant::now() >= timing.deadline() {
            return Err(GithubDeliveryServiceError::ClaimLost);
        }
        Ok((sampled_at, observed_at))
    }

    async fn await_predecessor_guarded<F>(
        &self,
        lease: &GithubDeliveryClaimLease,
        predecessor: GithubDeliveryClaimSnapshot,
        mut wall_floor: UnixMillis,
        future: F,
    ) -> Result<(F::Output, Instant, UnixMillis), GithubDeliveryServiceError>
    where
        F: Future,
    {
        tokio::pin!(future);
        loop {
            let current_deadline = lease.deadline().map_err(claim_error)?;
            let tick_at = Instant::now()
                .checked_add(self.poll_duration())
                .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?
                .min(current_deadline);
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(current_deadline) => {
                    return Err(GithubDeliveryServiceError::ClaimLost);
                }
                output = &mut future => {
                    let (sampled_at, observed_at) =
                        self.refresh_predecessor_guard(lease, predecessor, wall_floor)?;
                    return Ok((output, sampled_at, observed_at));
                }
                () = tokio::time::sleep_until(tick_at) => {
                    let (_, observed_at) =
                        self.refresh_predecessor_guard(lease, predecessor, wall_floor)?;
                    wall_floor = observed_at;
                }
            }
        }
    }

    fn now(&self) -> Result<UnixMillis, GithubDeliveryServiceError> {
        let now = self.clock.now();
        if now.get() < 0 {
            return Err(GithubDeliveryServiceError::InvalidTrustedTime);
        }
        Ok(now)
    }

    fn poll_duration(&self) -> Duration {
        duration(self.config.poll_millis())
    }
}

impl fmt::Debug for GithubDeliveryService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryService")
            .field("worker", &self.worker)
            .field("deliveries", &"[provider delivery repository]")
            .field("renewals", &"[provider delivery renewal repository]")
            .field("credentials", &"[configured]")
            .field("clock", &self.clock)
            .field("worker_id", &self.worker_id)
            .field("config", &self.config)
            .finish()
    }
}

fn apply_renewed_claim(
    lease: &GithubDeliveryClaimLease,
    request: RenewProviderDeliveryClaim,
    renewed: RenewedProviderDeliveryClaim,
    monotonic_response_at: Instant,
    response_at: UnixMillis,
    successor_deadline_upper: Instant,
) -> Result<(), GithubDeliveryServiceError> {
    if renewed.claim().delivery_id() != request.claim().delivery_id()
        || renewed.claim().owner() != request.claim().owner()
        || request.claim().fence().checked_add(1) != Some(renewed.claim().fence())
        || renewed.attempt() != request.attempt()
        || renewed.claimed_at() != request.claimed_at()
        || renewed
            .expires_at()
            .get()
            .checked_sub(renewed.renewed_at().get())
            != request
                .expires_at()
                .get()
                .checked_sub(request.observed_at().get())
    {
        return Err(GithubDeliveryServiceError::InvalidRenewal);
    }
    if response_at >= request.predecessor_expires_at() {
        return Err(GithubDeliveryServiceError::ClaimLost);
    }
    let response_remaining = renewed
        .expires_at()
        .get()
        .checked_sub(response_at.get())
        .filter(|remaining| *remaining > 0)
        .and_then(|remaining| u64::try_from(remaining).ok())
        .ok_or(GithubDeliveryServiceError::ClaimLost)?;
    let response_cap = monotonic_response_at
        .checked_add(Duration::from_millis(response_remaining))
        .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)?;
    let successor_deadline = successor_deadline_upper.min(response_cap);
    if successor_deadline <= request.deadline() || Instant::now() >= request.deadline() {
        return Err(GithubDeliveryServiceError::ClaimLost);
    }
    match lease.apply_renewal(renewed, successor_deadline)? {
        GithubDeliveryClaimRenewalApplyOutcome::Applied => Ok(()),
        GithubDeliveryClaimRenewalApplyOutcome::PredecessorExpired => {
            Err(GithubDeliveryServiceError::ClaimLost)
        }
    }
}

pub(crate) fn credential_matches_request(
    credential: &GithubDeliverySourceCredential,
    request: GithubDeliverySourceCredentialRequest<'_>,
) -> bool {
    credential.identity() == request.identity()
        && credential.repository_owner_id() == request.repository_owner_id()
        && credential.repository().as_str() == request.identity().repository_identity()
        && credential.authority_selector() == request.authority_selector()
        && request
            .consumer_claim()
            .is_ok_and(|consumer| credential.consumer() == consumer)
        && credential.required_through() == request.required_through()
        && credential.acquired_at() >= request.observed_at()
        && credential.conservative_expires_at() >= request.required_through()
}

pub(crate) async fn poll_provider_once<F>(
    lease: &GithubDeliveryClaimLease,
    mut future: Pin<&mut F>,
) -> Result<Option<F::Output>, GithubDeliveryWorkerError>
where
    F: Future + ?Sized,
{
    poll_fn(|context| {
        let deadline = match lease.deadline() {
            Ok(deadline) => deadline,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if Instant::now() >= deadline {
            return Poll::Ready(Err(GithubDeliveryWorkerError::ClaimRejected));
        }
        Poll::Ready(Ok(match future.as_mut().poll(context) {
            Poll::Ready(output) => Some(output),
            Poll::Pending => None,
        }))
    })
    .await
}

fn checked_add(
    value: UnixMillis,
    duration_millis: i64,
) -> Result<UnixMillis, GithubDeliveryServiceError> {
    value
        .get()
        .checked_add(duration_millis)
        .map(UnixMillis::new)
        .ok_or(GithubDeliveryServiceError::InvalidTrustedTime)
}

fn hard_claim_expires_at(
    lease: &GithubDeliveryClaimLease,
) -> Result<UnixMillis, GithubDeliveryServiceError> {
    checked_add(
        lease.initial().claimed_at(),
        MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS,
    )
}

fn duration(milliseconds: i64) -> Duration {
    Duration::from_millis(
        u64::try_from(milliseconds).expect("validated service duration is positive and bounded"),
    )
}

fn claim_error(error: GithubDeliveryWorkerError) -> GithubDeliveryServiceError {
    match error {
        GithubDeliveryWorkerError::ClaimRejected => GithubDeliveryServiceError::ClaimLost,
        other => GithubDeliveryServiceError::Worker(other),
    }
}

fn normalize_claim_loss(error: GithubDeliveryServiceError) -> GithubDeliveryServiceError {
    match error {
        GithubDeliveryServiceError::Worker(GithubDeliveryWorkerError::ClaimRejected) => {
            GithubDeliveryServiceError::ClaimLost
        }
        other => other,
    }
}

fn retryable(error: &GithubDeliveryServiceError) -> bool {
    matches!(
        error,
        GithubDeliveryServiceError::Store(ProviderDeliveryStoreError::Operation(_))
            | GithubDeliveryServiceError::Worker(GithubDeliveryWorkerError::InboxUnavailable)
    )
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => true,
        () = tokio::time::sleep(duration) => false,
    }
}
