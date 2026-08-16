use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github::{
    GITHUB_EVENT_ENVELOPE_SCHEMA_V1, GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
    GITHUB_EVENT_REGISTRY_SCHEMA_V1, GithubRepositoryVisibility, GithubSealedEventEnvelopeV1,
    GithubStoredWebhookError, GithubWebhookBodyDigest, StoredAuthenticatedGithubWebhook,
    VerifiedGithubPush, VerifiedGithubWebhook, rehydrate_stored_authenticated_github_webhook,
};
use automata_ci_scm::{
    ArchiveFormat, ArchiveLimits, ExactRevision, RepositoryId, RepositorySource,
    RepositorySourcePort, RepositorySourceRequest, RevisionSpec, ScmError, ScmErrorKind,
    ScmProvider, SnapshotRequest,
};
use automata_ci_store::{
    AdmissionObject, AuthenticatedGithubDeliveryClaim, ClaimedProviderDelivery,
    CompleteProviderDelivery, GITHUB_PROVIDER_API_ORIGIN, GITHUB_PROVIDER_ARCHIVE_ACCEPT,
    GITHUB_PROVIDER_ARCHIVE_FORMAT, GITHUB_PROVIDER_ARCHIVE_ORIGIN,
    GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION, GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
    GITHUB_PROVIDER_REST_ACCEPT, GITHUB_PROVIDER_REST_API_VERSION, GITHUB_PROVIDER_SOURCE_REVISION,
    GITHUB_PROVIDER_WEB_ORIGIN, GithubProviderManifest, GithubRepositoryDispatchEvidenceRepository,
    GithubRepositoryDispatchResolution, GithubRepositoryDispatchResolutionAuthority,
    GithubSubjectEvidenceRepository, GithubSubjectEvidenceStoreError,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, MAX_PROVIDER_DELIVERY_ATTEMPTS,
    MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS, MAX_PROVIDER_DELIVERY_WORKFLOW_OUTCOMES,
    ManifestPinnedGithubDeliveryEvidence, PendingGithubRepositoryDispatchEvidence,
    ProviderDeliveryClaimFence, ProviderDeliveryFailureKind, ProviderDeliveryId,
    ProviderDeliveryIdentity, ProviderDeliveryReceipt, ProviderDeliveryRepository,
    ProviderDeliveryState, ProviderDeliveryStoreError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryEntry,
    ProviderDeliveryWorkflowOutcome, ProviderDeliveryWorkflowSourceState,
    ProviderRepositoryVisibility, RecordProviderDeliveryWorkflowProgress,
    RegisterProviderDeliveryWorkflowInventory, RejectProviderDelivery,
    RenewedProviderDeliveryClaim, ResolveGithubRepositoryDispatch, RetryProviderDelivery,
};
use automata_ci_workflow_github::{
    RepositoryWorkflowDiscoveryError, RepositoryWorkflowDiscoveryFailure,
    RepositoryWorkflowDiscoveryLimits, RepositoryWorkflowDiscoveryOutcome,
    discover_github_delivery_workflows,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    sync::{Mutex as AsyncMutex, OwnedMutexGuard, watch},
    time::Instant,
};

use crate::{GithubDeliveryClock, GithubDeliverySourceCredentialProvider};

const GITHUB_PROVIDER: &str = "github";
const DEFAULT_RETRY_BACKOFF_MILLIS: i64 = 30_000;
const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Deterministic limits and retry policy for one delivery worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubDeliveryWorkerConfig {
    discovery_limits: RepositoryWorkflowDiscoveryLimits,
    retry_backoff_millis: i64,
}

impl GithubDeliveryWorkerConfig {
    /// Constructs a worker policy aligned with the durable delivery bounds.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive or excessive retry delay and a workflow count
    /// that cannot fit in one atomic provider-delivery completion.
    pub const fn new(
        discovery_limits: RepositoryWorkflowDiscoveryLimits,
        retry_backoff_millis: i64,
    ) -> Result<Self, GithubDeliveryWorkerConfigurationError> {
        if retry_backoff_millis <= 0
            || retry_backoff_millis > MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS
        {
            return Err(GithubDeliveryWorkerConfigurationError::InvalidRetryBackoff);
        }
        if discovery_limits.maximum_workflows() > MAX_PROVIDER_DELIVERY_WORKFLOW_OUTCOMES {
            return Err(GithubDeliveryWorkerConfigurationError::TooManyWorkflowOutcomes);
        }
        Ok(Self {
            discovery_limits,
            retry_backoff_millis,
        })
    }

    /// Returns the exact repository-discovery limits.
    #[must_use]
    pub const fn discovery_limits(self) -> RepositoryWorkflowDiscoveryLimits {
        self.discovery_limits
    }

    /// Returns the base durable retry delay in milliseconds.
    #[must_use]
    pub const fn retry_backoff_millis(self) -> i64 {
        self.retry_backoff_millis
    }
}

impl Default for GithubDeliveryWorkerConfig {
    fn default() -> Self {
        Self::new(
            RepositoryWorkflowDiscoveryLimits::default(),
            DEFAULT_RETRY_BACKOFF_MILLIS,
        )
        .expect("default discovery and retry limits fit the durable delivery bounds")
    }
}

/// Invalid delivery-worker configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliveryWorkerConfigurationError {
    /// The durable retry delay is outside its fixed positive bound.
    #[error("the GitHub delivery retry backoff is invalid")]
    InvalidRetryBackoff,
    /// Repository discovery could produce more outcomes than one completion.
    #[error("the GitHub workflow discovery limit exceeds the durable outcome bound")]
    TooManyWorkflowOutcomes,
    /// The source adapter does not identify itself as GitHub.
    #[error("the GitHub delivery source adapter has the wrong provider identity")]
    SourceProviderMismatch,
}

/// A prerequisite that this worker deliberately cannot synthesize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum GithubDeliveryWorkerPrerequisite {
    /// Exact provider changed-file evidence is required for path filtering.
    ProviderChangedFiles,
    /// Private pull-request files require a separately pinned `pull requests: read` authority.
    PrivatePullRequestFilesAuthority,
    /// The product has not supplied durable workflow admission.
    WorkflowAdmission,
}

/// Exact source authority selected from immutable authenticated visibility.
///
/// The private variant borrows a caller-owned installation token whose mint
/// policy is exactly one repository and `contents: read`. The token is never
/// retained by the worker. An optional reference to the same least-authority
/// broker permits the workflow processor to request a separate changed-files
/// handoff only if typed compilation demands it.
#[derive(Clone, Copy)]
pub enum GithubDeliverySourceAuthority<'credential> {
    /// Fetch the exact public repository revision anonymously.
    PublicAnonymous,
    /// Fetch the exact private repository revision using installation
    /// authority restricted to `contents: read`.
    PrivateInstallationContentsRead {
        /// Request-scoped credential for the exact revision archive.
        credential: &'credential SecretString,
        /// Broker for a distinct changed-files handoff, when configured.
        changed_files_credentials: Option<&'credential dyn GithubDeliverySourceCredentialProvider>,
    },
}

impl GithubDeliverySourceAuthority<'_> {
    fn changed_files_credentials(&self) -> Option<&dyn GithubDeliverySourceCredentialProvider> {
        match self {
            Self::PublicAnonymous => None,
            Self::PrivateInstallationContentsRead {
                changed_files_credentials,
                ..
            } => *changed_files_credentials,
        }
    }
}

impl fmt::Debug for GithubDeliverySourceAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicAnonymous => formatter.write_str("PublicAnonymous"),
            Self::PrivateInstallationContentsRead { .. } => {
                formatter.write_str("PrivateInstallationContentsRead([redacted])")
            }
        }
    }
}

/// Sanitized failure from the per-workflow processing boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GithubDeliveryWorkflowProcessorError {
    /// A transient downstream dependency prevented a deterministic outcome.
    #[error("GitHub workflow processing is temporarily unavailable")]
    Unavailable,
    /// Correct processing requires an authority or service not supplied here.
    #[error("GitHub workflow processing is missing a required prerequisite")]
    Prerequisite(GithubDeliveryWorkerPrerequisite),
    /// The exact delivery consumer claim is no longer live.
    #[error("GitHub workflow processing lost its delivery claim")]
    ClaimLost,
    /// The processor detected inconsistent trusted inputs or durable state.
    #[error("GitHub workflow processing rejected inconsistent state")]
    InvariantViolation,
}

/// Borrowed exact evidence for processing one authenticated event.
///
pub struct GithubDeliveryWorkflowRequest<'a> {
    delivery_id: ProviderDeliveryId,
    accepted_at: UnixMillis,
    identity: &'a ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    raw_event: &'a AdmissionObject,
    event_envelope: &'a GithubSealedEventEnvelopeV1,
    event: &'a VerifiedGithubWebhook,
    repository_source: &'a RepositorySource,
    workflow_path: &'a str,
    workflow_source: &'a [u8],
    evidence: &'a ManifestPinnedGithubDeliveryEvidence,
    snapshot: GithubDeliveryClaimSnapshot,
    lease: &'a GithubDeliveryClaimLease,
    clock: &'a dyn GithubDeliveryClock,
    private_credentials: Option<&'a dyn GithubDeliverySourceCredentialProvider>,
}

impl GithubDeliveryWorkflowRequest<'_> {
    /// Returns the internal immutable provider-inbox row identity.
    #[must_use]
    pub const fn delivery_id(&self) -> ProviderDeliveryId {
        self.delivery_id
    }

    /// Returns the immutable provider-inbox acceptance observation.
    #[must_use]
    pub const fn accepted_at(&self) -> UnixMillis {
        self.accepted_at
    }

    /// Returns the exact durable provider routing identity.
    #[must_use]
    pub const fn identity(&self) -> &ProviderDeliveryIdentity {
        self.identity
    }

    /// Returns the ingress digest over the authenticated request evidence.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the immutable raw-event object descriptor.
    #[must_use]
    pub const fn raw_event(&self) -> &AdmissionObject {
        self.raw_event
    }

    /// Returns the verified, facts-only event envelope bound to the raw object.
    #[must_use]
    pub const fn event_envelope(&self) -> &GithubSealedEventEnvelopeV1 {
        self.event_envelope
    }

    /// Returns the strictly rehydrated authenticated event.
    #[must_use]
    pub const fn event(&self) -> &VerifiedGithubWebhook {
        self.event
    }

    /// Returns the exact-revision repository archive containing this path.
    #[must_use]
    pub const fn repository_source(&self) -> &RepositorySource {
        self.repository_source
    }

    /// Returns the canonical repository-relative workflow path.
    #[must_use]
    pub const fn workflow_path(&self) -> &str {
        self.workflow_path
    }

    /// Returns the exact workflow bytes discovered in the verified archive.
    #[must_use]
    pub const fn workflow_source(&self) -> &[u8] {
        self.workflow_source
    }

    /// Returns the immutable manifest and authenticated-event evidence.
    #[must_use]
    pub const fn manifest_pinned_evidence(&self) -> &ManifestPinnedGithubDeliveryEvidence {
        self.evidence
    }

    /// Returns the exact live delivery consumer snapshot observed immediately
    /// before this workflow processor invocation.
    #[must_use]
    pub const fn claim_snapshot(&self) -> GithubDeliveryClaimSnapshot {
        self.snapshot
    }

    pub(crate) const fn lease(&self) -> &GithubDeliveryClaimLease {
        self.lease
    }

    pub(crate) const fn clock(&self) -> &dyn GithubDeliveryClock {
        self.clock
    }

    pub(crate) const fn private_credentials(
        &self,
    ) -> Option<&dyn GithubDeliverySourceCredentialProvider> {
        self.private_credentials
    }

    /// Transfers one completed processor result together with the exact live
    /// lease-operation guard that validated it.
    pub async fn finish(
        self,
        result: Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        self.finish_with_lineage_policy(result, false).await
    }

    pub(crate) async fn finish_same_lineage(
        self,
        result: Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        self.finish_with_lineage_policy(result, true).await
    }

    async fn finish_with_lineage_policy(
        self,
        result: Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
        accept_same_lineage_renewal: bool,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        finish_workflow_processing(
            self.lease,
            self.clock,
            self.snapshot,
            result,
            accept_same_lineage_renewal,
        )
        .await
    }
}

impl fmt::Debug for GithubDeliveryWorkflowRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryWorkflowRequest")
            .field("accepted_at", &self.accepted_at)
            .field("identity", &"[redacted]")
            .field("request_digest", &self.request_digest)
            .field("raw_event", &self.raw_event)
            .field("event", &self.event)
            .field("repository_source", &"[redacted]")
            .field("repository_source_digest", &self.repository_source.digest())
            .field("repository_source_bytes", &self.repository_source.size())
            .field("workflow_path", &"[redacted]")
            .field("workflow_source", &"[redacted]")
            .field("workflow_source_bytes", &self.workflow_source.len())
            .field("manifest_pinned_evidence", &"[redacted]")
            .field("snapshot", &self.snapshot)
            .field(
                "private_credentials",
                &self.private_credentials.map(|_| "[credential broker]"),
            )
            .finish()
    }
}

async fn finish_workflow_processing(
    lease: &GithubDeliveryClaimLease,
    clock: &dyn GithubDeliveryClock,
    snapshot: GithubDeliveryClaimSnapshot,
    result: Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
    accept_same_lineage_renewal: bool,
) -> GithubDeliveryWorkflowProcessorCompletion {
    let operation = lease.lock_operation().await;
    let latest = match lease.require_live_at(clock.now()) {
        Ok(latest) => latest,
        Err(error) => {
            drop(operation);
            return GithubDeliveryWorkflowProcessorCompletion::interrupted(processor_lease_error(
                error,
            ));
        }
    };
    if latest != snapshot
        && !(accept_same_lineage_renewal && snapshot.has_same_live_lineage(latest))
    {
        drop(operation);
        return GithubDeliveryWorkflowProcessorCompletion::interrupted(
            GithubDeliveryWorkflowProcessorError::ClaimLost,
        );
    }
    GithubDeliveryWorkflowProcessorCompletion::locked(result, operation)
}

enum GithubDeliveryWorkflowProcessorCompletionState {
    Locked {
        result: Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
        operation: OwnedMutexGuard<()>,
    },
    Interrupted(GithubDeliveryWorkflowProcessorError),
}

/// Completed workflow processing plus exclusive ownership of its terminal
/// lease transition.
///
/// Values are constructed by [`GithubDeliveryWorkflowRequest::finish`]. This prevents a claim
/// renewal from separating a completed provider/admission result from the
/// worker transition that consumes it.
pub struct GithubDeliveryWorkflowProcessorCompletion {
    state: GithubDeliveryWorkflowProcessorCompletionState,
}

impl GithubDeliveryWorkflowProcessorCompletion {
    fn locked(
        result: Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
        operation: OwnedMutexGuard<()>,
    ) -> Self {
        Self {
            state: GithubDeliveryWorkflowProcessorCompletionState::Locked { result, operation },
        }
    }

    fn interrupted(error: GithubDeliveryWorkflowProcessorError) -> Self {
        Self {
            state: GithubDeliveryWorkflowProcessorCompletionState::Interrupted(error),
        }
    }

    fn into_parts(
        self,
    ) -> Result<
        (
            Result<ProviderDeliveryWorkflowConclusion, GithubDeliveryWorkflowProcessorError>,
            OwnedMutexGuard<()>,
        ),
        GithubDeliveryWorkflowProcessorError,
    > {
        match self.state {
            GithubDeliveryWorkflowProcessorCompletionState::Locked { result, operation } => {
                Ok((result, operation))
            }
            GithubDeliveryWorkflowProcessorCompletionState::Interrupted(error) => Err(error),
        }
    }
}

impl fmt::Debug for GithubDeliveryWorkflowProcessorCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryWorkflowProcessorCompletion")
            .field(
                "state",
                &match &self.state {
                    GithubDeliveryWorkflowProcessorCompletionState::Locked { .. } => "locked",
                    GithubDeliveryWorkflowProcessorCompletionState::Interrupted(_) => "interrupted",
                },
            )
            .finish_non_exhaustive()
    }
}

/// Product-owned processing for one valid discovered workflow.
///
/// Implementations must bind every side effect to the exact delivery identity,
/// request digest, revision, archive digest, and path so a worker retry is
/// idempotent. Invalid workflow source and valid trigger non-selection are
/// path-local terminal conclusions, not processor errors. The worker never
/// supplies changed-file evidence; a processor that needs it must return the
/// corresponding typed prerequisite.
#[async_trait]
pub trait GithubDeliveryWorkflowProcessor: fmt::Debug + Send + Sync {
    /// Processes one authenticated event for a valid workflow file.
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion;
}

/// Durable state reached by one worker call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubDeliveryWorkerOutcome {
    /// All exact path outcomes were atomically retained.
    Completed(ProviderDeliveryReceipt),
    /// No path outcomes were committed and the delivery was delayed for retry.
    RetryScheduled(ProviderDeliveryReceipt),
    /// Invalid or unsafe immutable evidence was terminally rejected.
    Rejected(ProviderDeliveryReceipt),
}

impl GithubDeliveryWorkerOutcome {
    /// Returns the authoritative durable inbox receipt.
    #[must_use]
    pub const fn receipt(self) -> ProviderDeliveryReceipt {
        match self {
            Self::Completed(receipt) | Self::RetryScheduled(receipt) | Self::Rejected(receipt) => {
                receipt
            }
        }
    }
}

/// Exact current provider-delivery lease evidence bound into source authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubDeliveryClaimSnapshot {
    claim: ProviderDeliveryClaimFence,
    attempt: u16,
    claimed_at: UnixMillis,
    renewed_at: UnixMillis,
    expires_at: UnixMillis,
}

impl GithubDeliveryClaimSnapshot {
    /// Returns the internal delivery UUID, worker identity, and current fence.
    #[must_use]
    pub const fn claim(self) -> ProviderDeliveryClaimFence {
        self.claim
    }

    /// Returns the positive durable delivery attempt used as consumer revision.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt
    }

    /// Returns the immutable original claim time preserved across renewal.
    #[must_use]
    pub const fn claimed_at(self) -> UnixMillis {
        self.claimed_at
    }

    /// Returns the latest accepted renewal observation.
    #[must_use]
    pub const fn renewed_at(self) -> UnixMillis {
        self.renewed_at
    }

    /// Returns the exclusive current lease expiry.
    #[must_use]
    pub const fn expires_at(self) -> UnixMillis {
        self.expires_at
    }

    pub(crate) fn has_same_live_lineage(self, latest: Self) -> bool {
        self.claim.delivery_id() == latest.claim.delivery_id()
            && self.claim.owner() == latest.claim.owner()
            && self.claim.fence() <= latest.claim.fence()
            && self.attempt == latest.attempt
            && self.claimed_at == latest.claimed_at
            && self.renewed_at <= latest.renewed_at
            && self.expires_at <= latest.expires_at
    }
}

pub(crate) struct GithubDeliveryClaimLease {
    initial: ClaimedProviderDelivery,
    latest: Mutex<LiveGithubDeliveryClaim>,
    deadline_generation: watch::Sender<u64>,
    operation: Arc<AsyncMutex<()>>,
    terminal_transition_started: AtomicBool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveGithubDeliveryClaim {
    snapshot: GithubDeliveryClaimSnapshot,
    deadline: Instant,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GithubDeliveryClaimRenewalApplyOutcome {
    Applied,
    PredecessorExpired,
}

impl GithubDeliveryClaimLease {
    pub(crate) fn new(initial: ClaimedProviderDelivery, deadline: Instant) -> Self {
        let snapshot = GithubDeliveryClaimSnapshot {
            claim: initial.claim(),
            attempt: initial.attempt(),
            claimed_at: initial.claimed_at(),
            renewed_at: initial.claimed_at(),
            expires_at: initial.expires_at(),
        };
        let latest = LiveGithubDeliveryClaim {
            snapshot,
            deadline,
            generation: 0,
        };
        let (deadline_generation, _) = watch::channel(0);
        Self {
            initial,
            latest: Mutex::new(latest),
            deadline_generation,
            operation: Arc::new(AsyncMutex::new(())),
            terminal_transition_started: AtomicBool::new(false),
        }
    }

    pub(crate) const fn initial(&self) -> &ClaimedProviderDelivery {
        &self.initial
    }

    pub(crate) fn latest(&self) -> Result<GithubDeliveryClaimSnapshot, GithubDeliveryWorkerError> {
        self.latest
            .lock()
            .map(|latest| latest.snapshot)
            .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)
    }

    fn live_claim(&self) -> Result<LiveGithubDeliveryClaim, GithubDeliveryWorkerError> {
        self.latest
            .lock()
            .map(|latest| *latest)
            .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)
    }

    pub(crate) fn deadline(&self) -> Result<Instant, GithubDeliveryWorkerError> {
        self.live_claim().map(|live| live.deadline)
    }

    pub(crate) fn require_live_at(
        &self,
        observed_at: UnixMillis,
    ) -> Result<GithubDeliveryClaimSnapshot, GithubDeliveryWorkerError> {
        let live = self.live_claim()?;
        let latest = live.snapshot;
        if observed_at.get() < 0 {
            return Err(GithubDeliveryWorkerError::InvalidTrustedTime);
        }
        if Instant::now() >= live.deadline || observed_at >= latest.expires_at() {
            return Err(GithubDeliveryWorkerError::ClaimRejected);
        }
        Ok(latest)
    }

    pub(crate) fn require_live_observation(
        &self,
        observed_at: UnixMillis,
    ) -> Result<(GithubDeliveryClaimSnapshot, UnixMillis), GithubDeliveryWorkerError> {
        let latest = self.require_live_at(observed_at)?;
        Ok((latest, observed_at.max(latest.renewed_at())))
    }

    pub(crate) fn apply_renewal(
        &self,
        renewal: RenewedProviderDeliveryClaim,
        deadline: Instant,
    ) -> Result<GithubDeliveryClaimRenewalApplyOutcome, GithubDeliveryWorkerError> {
        if renewal.attempt() != self.initial.attempt()
            || renewal.claimed_at() != self.initial.claimed_at()
        {
            return Err(GithubDeliveryWorkerError::InboxRejected);
        }
        let replacement = GithubDeliveryClaimSnapshot {
            claim: renewal.claim(),
            attempt: renewal.attempt(),
            claimed_at: renewal.claimed_at(),
            renewed_at: renewal.renewed_at(),
            expires_at: renewal.expires_at(),
        };
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        if replacement == latest.snapshot {
            return Ok(if Instant::now() >= latest.deadline {
                GithubDeliveryClaimRenewalApplyOutcome::PredecessorExpired
            } else {
                GithubDeliveryClaimRenewalApplyOutcome::Applied
            });
        }
        if replacement.claim().delivery_id() != latest.snapshot.claim().delivery_id()
            || replacement.claim().owner() != latest.snapshot.claim().owner()
            || latest.snapshot.claim().fence().checked_add(1) != Some(replacement.claim().fence())
            || replacement.renewed_at() <= latest.snapshot.renewed_at()
            || replacement.expires_at() <= latest.snapshot.expires_at()
            || replacement.renewed_at() >= replacement.expires_at()
            || deadline <= latest.deadline
        {
            return Err(GithubDeliveryWorkerError::InboxRejected);
        }
        if Instant::now() >= latest.deadline {
            return Ok(GithubDeliveryClaimRenewalApplyOutcome::PredecessorExpired);
        }
        latest.snapshot = replacement;
        latest.deadline = deadline;
        latest.generation = latest
            .generation
            .checked_add(1)
            .ok_or(GithubDeliveryWorkerError::InvariantViolation)?;
        let generation = latest.generation;
        drop(latest);
        self.deadline_generation.send_replace(generation);
        Ok(GithubDeliveryClaimRenewalApplyOutcome::Applied)
    }

    pub(crate) fn narrow_predecessor_deadline(
        &self,
        snapshot: GithubDeliveryClaimSnapshot,
        deadline: Instant,
    ) -> Result<bool, GithubDeliveryWorkerError> {
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        if latest.snapshot != snapshot {
            return Ok(false);
        }
        if deadline == latest.deadline {
            return Ok(true);
        }
        if deadline > latest.deadline {
            return Err(GithubDeliveryWorkerError::InboxRejected);
        }
        latest.deadline = deadline;
        latest.generation = latest
            .generation
            .checked_add(1)
            .ok_or(GithubDeliveryWorkerError::InvariantViolation)?;
        let generation = latest.generation;
        drop(latest);
        self.deadline_generation.send_replace(generation);
        Ok(true)
    }

    pub(crate) async fn await_expiration(&self) -> GithubDeliveryWorkerError {
        let mut generations = self.deadline_generation.subscribe();
        loop {
            let live = match self.live_claim() {
                Ok(live) => live,
                Err(error) => return error,
            };
            if Instant::now() >= live.deadline {
                return GithubDeliveryWorkerError::ClaimRejected;
            }
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(live.deadline) => {
                    let current = match self.live_claim() {
                        Ok(current) => current,
                        Err(error) => return error,
                    };
                    if current.deadline <= Instant::now() {
                        return GithubDeliveryWorkerError::ClaimRejected;
                    }
                }
                changed = generations.changed() => {
                    if changed.is_err() {
                        return GithubDeliveryWorkerError::InvariantViolation;
                    }
                }
            }
        }
    }

    pub(crate) async fn lock_operation(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.operation).lock_owned().await
    }

    pub(crate) fn mark_terminal_transition_started(&self) {
        self.terminal_transition_started
            .store(true, Ordering::SeqCst);
    }

    pub(crate) fn terminal_transition_started(&self) -> bool {
        self.terminal_transition_started.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for GithubDeliveryClaimLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryClaimLease")
            .field("identity", &"[redacted]")
            .field("receipt", &self.initial.receipt())
            .field("claim", &self.initial.claim())
            .field("latest", &self.latest().ok())
            .field("deadline_generation", &"[claim deadline generation watch]")
            .field("operation", &"[claim operation mutex]")
            .field(
                "terminal_transition_started",
                &self.terminal_transition_started(),
            )
            .finish()
    }
}

pub(crate) struct PreparedGithubDelivery {
    event: VerifiedGithubWebhook,
    event_envelope: GithubSealedEventEnvelopeV1,
    evidence: PreparedGithubDeliveryEvidence,
}

enum PreparedGithubDeliveryEvidence {
    Resolved(ManifestPinnedGithubDeliveryEvidence),
    PendingRepositoryDispatch(PendingGithubRepositoryDispatchEvidence),
}

enum DurableRehydrationEvidence {
    Resolved(ManifestPinnedGithubDeliveryEvidence),
    PendingRepositoryDispatch(PendingGithubRepositoryDispatchEvidence),
}

impl DurableRehydrationEvidence {
    const fn manifest(&self) -> &GithubProviderManifest {
        match self {
            Self::Resolved(evidence) => evidence.manifest(),
            Self::PendingRepositoryDispatch(evidence) => evidence.manifest(),
        }
    }
}

impl PreparedGithubDelivery {
    pub(crate) const fn from_authenticated_event(
        event: VerifiedGithubWebhook,
        event_envelope: GithubSealedEventEnvelopeV1,
        evidence: ManifestPinnedGithubDeliveryEvidence,
    ) -> Self {
        Self {
            event,
            event_envelope,
            evidence: PreparedGithubDeliveryEvidence::Resolved(evidence),
        }
    }

    pub(crate) const fn from_pending_repository_dispatch(
        event: VerifiedGithubWebhook,
        event_envelope: GithubSealedEventEnvelopeV1,
        evidence: PendingGithubRepositoryDispatchEvidence,
    ) -> Self {
        Self {
            event,
            event_envelope,
            evidence: PreparedGithubDeliveryEvidence::PendingRepositoryDispatch(evidence),
        }
    }

    pub(crate) const fn event(&self) -> &VerifiedGithubWebhook {
        &self.event
    }

    pub(crate) const fn event_envelope(&self) -> &GithubSealedEventEnvelopeV1 {
        &self.event_envelope
    }

    pub(crate) const fn deleted(&self) -> bool {
        match &self.event {
            VerifiedGithubWebhook::Push(push) => push.deleted(),
            _ => false,
        }
    }

    pub(crate) const fn manifest(&self) -> &GithubProviderManifest {
        match &self.evidence {
            PreparedGithubDeliveryEvidence::Resolved(evidence) => evidence.manifest(),
            PreparedGithubDeliveryEvidence::PendingRepositoryDispatch(evidence) => {
                evidence.manifest()
            }
        }
    }

    pub(crate) const fn private_source_authority(
        &self,
    ) -> Option<&automata_ci_store::GithubServerServiceAuthoritySelector> {
        match &self.evidence {
            PreparedGithubDeliveryEvidence::Resolved(evidence) => {
                evidence.private_source_authority()
            }
            PreparedGithubDeliveryEvidence::PendingRepositoryDispatch(evidence) => {
                evidence.private_source_authority()
            }
        }
    }

    pub(crate) const fn resolved_evidence(&self) -> Option<&ManifestPinnedGithubDeliveryEvidence> {
        match &self.evidence {
            PreparedGithubDeliveryEvidence::Resolved(evidence) => Some(evidence),
            PreparedGithubDeliveryEvidence::PendingRepositoryDispatch(_) => None,
        }
    }

    pub(crate) const fn pending_repository_dispatch(
        &self,
    ) -> Option<&PendingGithubRepositoryDispatchEvidence> {
        match &self.evidence {
            PreparedGithubDeliveryEvidence::Resolved(_) => None,
            PreparedGithubDeliveryEvidence::PendingRepositoryDispatch(evidence) => Some(evidence),
        }
    }
}

pub(crate) enum PreparedGithubDeliveryClaim {
    Finished(GithubDeliveryWorkerOutcome),
    Live(Box<PreparedGithubDelivery>),
}

/// Product-composed worker for one already claimed authenticated GitHub event.
pub struct GithubDeliveryWorker {
    objects: Arc<dyn ImmutableBlobStore>,
    repository_source: Arc<dyn RepositorySourcePort>,
    workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor>,
    deliveries: Arc<dyn ProviderDeliveryRepository>,
    subject_evidence: Arc<dyn GithubSubjectEvidenceRepository>,
    repository_dispatches: Option<Arc<dyn GithubRepositoryDispatchEvidenceRepository>>,
    repository_dispatch_resolver: Option<Arc<dyn ScmProvider>>,
    clock: Arc<dyn GithubDeliveryClock>,
    config: GithubDeliveryWorkerConfig,
}

impl GithubDeliveryWorker {
    /// Constructs a worker from explicit least-authority ports.
    ///
    /// # Errors
    ///
    /// Rejects a repository-source adapter whose stable provider is not
    /// exactly `github`.
    pub fn new(
        objects: Arc<dyn ImmutableBlobStore>,
        repository_source: Arc<dyn RepositorySourcePort>,
        workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor>,
        deliveries: Arc<dyn ProviderDeliveryRepository>,
        subject_evidence: Arc<dyn GithubSubjectEvidenceRepository>,
        clock: Arc<dyn GithubDeliveryClock>,
        config: GithubDeliveryWorkerConfig,
    ) -> Result<Self, GithubDeliveryWorkerConfigurationError> {
        if repository_source.provider_id().as_str() != GITHUB_PROVIDER {
            return Err(GithubDeliveryWorkerConfigurationError::SourceProviderMismatch);
        }
        Ok(Self {
            objects,
            repository_source,
            workflow_processor,
            deliveries,
            subject_evidence,
            repository_dispatches: None,
            repository_dispatch_resolver: None,
            clock,
            config,
        })
    }

    /// Constructs a worker with bounded default-branch resolution support.
    ///
    /// # Errors
    ///
    /// Rejects either source adapter when its stable provider is not GitHub.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_repository_dispatch(
        objects: Arc<dyn ImmutableBlobStore>,
        repository_source: Arc<dyn RepositorySourcePort>,
        repository_dispatch_resolver: Arc<dyn ScmProvider>,
        workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor>,
        deliveries: Arc<dyn ProviderDeliveryRepository>,
        subject_evidence: Arc<dyn GithubSubjectEvidenceRepository>,
        repository_dispatches: Arc<dyn GithubRepositoryDispatchEvidenceRepository>,
        clock: Arc<dyn GithubDeliveryClock>,
        config: GithubDeliveryWorkerConfig,
    ) -> Result<Self, GithubDeliveryWorkerConfigurationError> {
        if repository_source.provider_id().as_str() != GITHUB_PROVIDER
            || repository_dispatch_resolver.provider_id().as_str() != GITHUB_PROVIDER
        {
            return Err(GithubDeliveryWorkerConfigurationError::SourceProviderMismatch);
        }
        Ok(Self {
            objects,
            repository_source,
            workflow_processor,
            deliveries,
            subject_evidence,
            repository_dispatches: Some(repository_dispatches),
            repository_dispatch_resolver: Some(repository_dispatch_resolver),
            clock,
            config,
        })
    }

    /// Processes one exact durable claim without claiming or renewing it.
    ///
    /// The authenticated raw object is always re-read and verified before its
    /// event fields are trusted. Deleted pushes complete with no outcomes and
    /// do not require source authority. Other supported events fetch only the
    /// exact normalized source revision, using the caller-owned credential for
    /// this call. Archive-wide failures reject the delivery; empty and oversized
    /// workflow files become isolated failed path outcomes; valid siblings are
    /// processed in deterministic path order and committed atomically.
    ///
    /// # Errors
    ///
    /// Returns a typed missing prerequisite without changing durable state, or
    /// a sanitized clock/inbox failure when the requested transition cannot be
    /// proven. Provider, object, source, archive, and processor failures are
    /// converted to bounded durable retry or rejection states.
    pub async fn process_claimed(
        &self,
        claimed: ClaimedProviderDelivery,
        source_authority: GithubDeliverySourceAuthority<'_>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        let monotonic_observed_at = Instant::now();
        let observed_at = self.clock.now();
        let remaining = claimed
            .expires_at()
            .get()
            .checked_sub(observed_at.get())
            .filter(|remaining| *remaining > 0)
            .and_then(|remaining| u64::try_from(remaining).ok())
            .ok_or(GithubDeliveryWorkerError::ClaimRejected)?;
        let deadline = monotonic_observed_at
            .checked_add(std::time::Duration::from_millis(remaining))
            .ok_or(GithubDeliveryWorkerError::InvalidTrustedTime)?;
        let lease = GithubDeliveryClaimLease::new(claimed, deadline);
        let processing = async {
            let prepared = self.prepare_leased(&lease).await?;
            let PreparedGithubDeliveryClaim::Live(prepared) = prepared else {
                let PreparedGithubDeliveryClaim::Finished(outcome) = prepared else {
                    unreachable!("the prepared delivery claim has only two variants")
                };
                return Ok(outcome);
            };
            if prepared.deleted() {
                return self.finish_deleted(&lease).await;
            }
            self.process_prepared_leased(&lease, prepared.as_ref(), source_authority)
                .await
        };
        tokio::pin!(processing);
        tokio::select! {
            biased;
            error = lease.await_expiration() => Err(error),
            outcome = &mut processing => outcome,
        }
    }

    pub(crate) async fn prepare_leased(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<PreparedGithubDeliveryClaim, GithubDeliveryWorkerError> {
        self.require_live(lease)?;
        let claimed = lease.initial();
        if claimed.identity().provider() != GITHUB_PROVIDER {
            return self
                .reject(lease, "github.delivery.invalid_provider")
                .await
                .map(PreparedGithubDeliveryClaim::Finished);
        }
        let prepared = match self.rehydrate_delivery(claimed).await {
            Ok(prepared) => prepared,
            Err(failure) => {
                return self
                    .finish_failure(lease, failure)
                    .await
                    .map(PreparedGithubDeliveryClaim::Finished);
            }
        };
        Ok(PreparedGithubDeliveryClaim::Live(Box::new(prepared)))
    }

    pub(crate) async fn finish_deleted(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.complete(lease, Vec::new()).await
    }

    pub(crate) async fn process_prepared_leased(
        &self,
        lease: &GithubDeliveryClaimLease,
        prepared: &PreparedGithubDelivery,
        source_authority: GithubDeliverySourceAuthority<'_>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.require_live(lease)?;
        let claimed = lease.initial();
        let private_credentials = source_authority.changed_files_credentials();
        let source = match self.fetch_source(claimed, prepared, source_authority).await {
            Ok(source) => source,
            Err(failure) => return self.finish_failure(lease, failure).await,
        };
        self.process_fetched_source_leased(lease, prepared, &source, private_credentials)
            .await
    }

    pub(crate) async fn process_fetched_source_leased(
        &self,
        lease: &GithubDeliveryClaimLease,
        prepared: &PreparedGithubDelivery,
        source: &RepositorySource,
        private_credentials: Option<&dyn GithubDeliverySourceCredentialProvider>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.require_live(lease)?;
        let claimed = lease.initial();
        let resolved_dispatch;
        let prepared = if prepared.pending_repository_dispatch().is_some() {
            resolved_dispatch = self
                .bind_repository_dispatch_resolution(lease, prepared, source)
                .await?;
            &resolved_dispatch
        } else {
            prepared
        };
        match self
            .workflow_outcomes(lease, claimed, prepared, source, private_credentials)
            .await
        {
            Ok(outcome) => Ok(outcome),
            Err(interruption) => self.finish_interruption(lease, interruption).await,
        }
    }

    async fn bind_repository_dispatch_resolution(
        &self,
        lease: &GithubDeliveryClaimLease,
        prepared: &PreparedGithubDelivery,
        source: &RepositorySource,
    ) -> Result<PreparedGithubDelivery, GithubDeliveryWorkerError> {
        let repository_dispatches = self
            .repository_dispatches
            .as_ref()
            .ok_or(GithubDeliveryWorkerError::InvariantViolation)?;
        let pending = prepared
            .pending_repository_dispatch()
            .ok_or(GithubDeliveryWorkerError::InvariantViolation)?;
        let source_revision = crate::check_head_sha_from_revision(source.revision().as_str())
            .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        let authority = match (
            pending.manifest().repository_visibility(),
            pending.private_source_authority(),
        ) {
            (ProviderRepositoryVisibility::Public, None) => {
                GithubRepositoryDispatchResolutionAuthority::PublicAnonymous
            }
            (ProviderRepositoryVisibility::Private, Some(_)) => {
                GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority
            }
            _ => return Err(GithubDeliveryWorkerError::InvariantViolation),
        };
        let operation = lease.lock_operation().await;
        let observed_at = self.clock.now();
        let snapshot = lease.require_live_at(observed_at)?;
        let claim = AuthenticatedGithubDeliveryClaim::new(
            snapshot.claim(),
            snapshot.attempt(),
            snapshot.claimed_at(),
            snapshot.expires_at(),
        )
        .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        let request = ResolveGithubRepositoryDispatch::new(
            pending.clone(),
            claim,
            GithubRepositoryDispatchResolution::new(source_revision, authority),
            observed_at,
        )
        .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        let evidence = repository_dispatches
            .resolve_github_repository_dispatch(request)
            .await
            .map_err(|error| repository_dispatch_resolution_store_error(&error))?;
        drop(operation);
        if evidence.delivery_id() != pending.delivery_id()
            || evidence.manifest() != pending.manifest()
            || evidence.authenticated_event() != pending.event()
            || evidence.repository_dispatch_resolution()
                != Some(GithubRepositoryDispatchResolution::new(
                    source_revision,
                    authority,
                ))
            || evidence.check_head_sha() != source_revision
        {
            return Err(GithubDeliveryWorkerError::InvariantViolation);
        }
        Ok(PreparedGithubDelivery::from_authenticated_event(
            prepared.event().clone(),
            prepared.event_envelope().clone(),
            evidence,
        ))
    }

    pub(crate) async fn finish_credential_unavailable(
        &self,
        lease: &GithubDeliveryClaimLease,
        operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.retry_with_operation(
            lease,
            "github.repository_source.credential_unavailable",
            self.config.retry_backoff_millis(),
            operation,
        )
        .await
    }

    pub(crate) async fn finish_credential_rejected(
        &self,
        lease: &GithubDeliveryClaimLease,
        operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.reject_with_operation(
            lease,
            "github.repository_source.credential_rejected",
            operation,
        )
        .await
    }

    pub(crate) async fn finish_credential_invalid(
        &self,
        lease: &GithubDeliveryClaimLease,
        operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.reject_with_operation(
            lease,
            "github.repository_source.credential_invalid",
            operation,
        )
        .await
    }

    pub(crate) async fn finish_private_source_unsupported(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        self.reject(lease, "github.repository_source.private_unsupported")
            .await
    }

    pub(crate) async fn fetch_source(
        &self,
        claimed: &ClaimedProviderDelivery,
        prepared: &PreparedGithubDelivery,
        authority: GithubDeliverySourceAuthority<'_>,
    ) -> Result<RepositorySource, ProcessingFailure> {
        if let Some(pending) = prepared.pending_repository_dispatch() {
            return self
                .fetch_repository_dispatch_source(claimed, prepared.event(), pending, authority)
                .await;
        }
        let manifest = prepared.manifest();
        let Ok(repository) = RepositoryId::new(claimed.identity().repository_identity()) else {
            return Err(ProcessingFailure::reject(
                "github.delivery.invalid_repository",
            ));
        };
        let revision_value = match prepared.event() {
            VerifiedGithubWebhook::RepositoryDispatch(_) => prepared
                .resolved_evidence()
                .and_then(ManifestPinnedGithubDeliveryEvidence::repository_dispatch_resolution)
                .map(|resolution| lowercase_hex(&resolution.source_revision().as_bytes()))
                .ok_or_else(|| {
                    ProcessingFailure::reject("github.repository_dispatch.unresolved_source")
                })?,
            _ => source_revision(prepared.event())
                .map(str::to_owned)
                .ok_or_else(|| {
                    ProcessingFailure::reject("github.delivery.unsupported_source_repository")
                })?,
        };
        let Ok(revision) = ExactRevision::new(revision_value) else {
            return Err(ProcessingFailure::reject(
                "github.delivery.invalid_source_revision",
            ));
        };
        let request = match (claimed.identity().repository_visibility(), authority) {
            (
                ProviderRepositoryVisibility::Public,
                GithubDeliverySourceAuthority::PublicAnonymous,
            ) if prepared.private_source_authority().is_none() => {
                RepositorySourceRequest::public(&repository, &revision, archive_limits(manifest)?)
            }
            (
                ProviderRepositoryVisibility::Private,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential, ..
                },
            ) if prepared.private_source_authority().is_some() => {
                RepositorySourceRequest::authenticated(
                    &repository,
                    &revision,
                    credential,
                    archive_limits(manifest)?,
                )
            }
            _ => {
                return Err(ProcessingFailure::reject(
                    "github.repository_source.authority_mismatch",
                ));
            }
        };
        let source = tokio::time::timeout(
            std::time::Duration::from_millis(
                u64::try_from(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
                    .expect("fixed GitHub provider tail is positive"),
            ),
            self.repository_source.fetch_repository_source(request),
        )
        .await
        .map_err(|_| {
            ProcessingFailure::retry(
                "github.repository_source.unavailable",
                self.config.retry_backoff_millis(),
            )
        })?
        .map_err(|error| source_failure(error, self.config.retry_backoff_millis()))?;
        if !valid_source_response(&source, &repository, &revision, archive_limits(manifest)?) {
            return Err(ProcessingFailure::reject(
                "github.repository_source.mismatch",
            ));
        }
        Ok(source)
    }

    async fn fetch_repository_dispatch_source(
        &self,
        claimed: &ClaimedProviderDelivery,
        event: &VerifiedGithubWebhook,
        pending: &PendingGithubRepositoryDispatchEvidence,
        authority: GithubDeliverySourceAuthority<'_>,
    ) -> Result<RepositorySource, ProcessingFailure> {
        let resolver = self.repository_dispatch_resolver.as_ref().ok_or_else(|| {
            ProcessingFailure::reject("github.repository_dispatch.resolver_unsupported")
        })?;
        let VerifiedGithubWebhook::RepositoryDispatch(dispatch) = event else {
            return Err(ProcessingFailure::reject(
                "github.repository_dispatch.invalid_event",
            ));
        };
        if pending.event().git_ref() != dispatch.git_ref()
            || pending.event().kind()
                != automata_ci_store::GithubAuthenticatedEventKind::RepositoryDispatch
        {
            return Err(ProcessingFailure::reject(
                "github.repository_dispatch.branch_mismatch",
            ));
        }
        let repository = RepositoryId::new(claimed.identity().repository_identity())
            .map_err(|_| ProcessingFailure::reject("github.delivery.invalid_repository"))?;
        let revision = RevisionSpec::new(dispatch.git_ref())
            .map_err(|_| ProcessingFailure::reject("github.repository_dispatch.invalid_branch"))?;
        let limits = archive_limits(pending.manifest())?;
        let request = match (claimed.identity().repository_visibility(), authority) {
            (
                ProviderRepositoryVisibility::Public,
                GithubDeliverySourceAuthority::PublicAnonymous,
            ) if pending.private_source_authority().is_none() => {
                SnapshotRequest::public(&repository, &revision, limits)
            }
            (
                ProviderRepositoryVisibility::Private,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential, ..
                },
            ) if pending.private_source_authority().is_some() => {
                SnapshotRequest::authenticated(&repository, &revision, credential, limits)
            }
            _ => {
                return Err(ProcessingFailure::reject(
                    "github.repository_source.authority_mismatch",
                ));
            }
        };
        let snapshot = tokio::time::timeout(
            std::time::Duration::from_millis(
                u64::try_from(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
                    .expect("fixed GitHub provider tail is positive"),
            ),
            resolver.fetch_snapshot(request),
        )
        .await
        .map_err(|_| {
            ProcessingFailure::retry(
                "github.repository_dispatch.resolver_unavailable",
                self.config.retry_backoff_millis(),
            )
        })?
        .map_err(|error| source_failure(error, self.config.retry_backoff_millis()))?;
        if snapshot.provider().as_str() != GITHUB_PROVIDER
            || snapshot.repository() != &repository
            || snapshot.requested_revision() != &revision
            || snapshot.format() != ArchiveFormat::TarGzip
            || snapshot.size() > limits.maximum_bytes()
        {
            return Err(ProcessingFailure::reject(
                "github.repository_dispatch.resolution_mismatch",
            ));
        }
        let exact_revision =
            ExactRevision::new(snapshot.resolved_revision().as_str()).map_err(|_| {
                ProcessingFailure::reject("github.repository_dispatch.ambiguous_revision")
            })?;
        let provider = snapshot.provider().clone();
        let resolved_repository = snapshot.repository().clone();
        let format = snapshot.format();
        let digest = snapshot.digest();
        let source = RepositorySource::from_bytes(
            provider,
            resolved_repository,
            exact_revision,
            format,
            snapshot.into_bytes(),
        );
        if source.digest() != digest {
            return Err(ProcessingFailure::reject(
                "github.repository_dispatch.resolution_mismatch",
            ));
        }
        Ok(source)
    }

    async fn workflow_outcomes(
        &self,
        lease: &GithubDeliveryClaimLease,
        claimed: &ClaimedProviderDelivery,
        prepared: &PreparedGithubDelivery,
        source: &RepositorySource,
        private_credentials: Option<&dyn GithubDeliverySourceCredentialProvider>,
    ) -> Result<GithubDeliveryWorkerOutcome, WorkerInterruption> {
        let evidence = prepared.resolved_evidence().ok_or_else(|| {
            ProcessingFailure::reject("github.repository_dispatch.unresolved_source")
        })?;
        let workflows = discover_github_delivery_workflows(
            source.bytes(),
            manifest_discovery_limits(evidence.manifest())?,
        )
        .map_err(|error| ProcessingFailure::reject(discovery_failure_kind(error)))?;
        self.all_direct_workflow_outcomes(
            lease,
            claimed,
            prepared,
            source,
            private_credentials,
            workflows,
        )
        .await
    }

    async fn all_direct_workflow_outcomes(
        &self,
        lease: &GithubDeliveryClaimLease,
        claimed: &ClaimedProviderDelivery,
        prepared: &PreparedGithubDelivery,
        source: &RepositorySource,
        private_credentials: Option<&dyn GithubDeliverySourceCredentialProvider>,
        workflows: Vec<RepositoryWorkflowDiscoveryOutcome>,
    ) -> Result<GithubDeliveryWorkerOutcome, WorkerInterruption> {
        let evidence = prepared.resolved_evidence().ok_or_else(|| {
            ProcessingFailure::reject("github.repository_dispatch.unresolved_source")
        })?;
        let (inventory, selected) = prepare_all_direct_inventory(
            evidence.manifest(),
            evidence.manifest_digest(),
            source,
            workflows,
        )?;
        let mut durable = self
            .register_all_direct_inventory(lease, &inventory)
            .await?;
        let mut outcomes = Vec::with_capacity(selected.len());
        for (path, workflow) in selected {
            if let Some(outcome) = durable.remove(&path) {
                outcomes.push(outcome);
                continue;
            }
            let (_, result) = workflow.into_parts();
            let conclusion = match result {
                Ok(workflow_source) => loop {
                    let completion = self
                        .invoke_workflow_processor(
                            lease,
                            claimed,
                            prepared,
                            source,
                            (&path, &workflow_source),
                            private_credentials,
                        )
                        .await?;
                    let (result, operation) = match completion.into_parts() {
                        Ok(parts) => parts,
                        Err(GithubDeliveryWorkflowProcessorError::ClaimLost) => continue,
                        Err(GithubDeliveryWorkflowProcessorError::Unavailable) => {
                            return Err(WorkerInterruption::Worker(
                                GithubDeliveryWorkerError::InboxUnavailable,
                            ));
                        }
                        Err(GithubDeliveryWorkflowProcessorError::Prerequisite(prerequisite)) => {
                            return Err(WorkerInterruption::Prerequisite(prerequisite));
                        }
                        Err(GithubDeliveryWorkflowProcessorError::InvariantViolation) => {
                            return Err(WorkerInterruption::Worker(
                                GithubDeliveryWorkerError::InvariantViolation,
                            ));
                        }
                    };
                    let failure = match result {
                        Ok(conclusion) => {
                            drop(operation);
                            break conclusion;
                        }
                        Err(error) => processor_failure(error, self.config.retry_backoff_millis())?,
                    };
                    let outcome = self
                        .finish_failure_with_operation(lease, failure, operation)
                        .await
                        .map_err(WorkerInterruption::Worker)?;
                    return Ok(outcome);
                },
                Err(RepositoryWorkflowDiscoveryFailure::Empty) => failed("github.workflow.empty"),
                Err(RepositoryWorkflowDiscoveryFailure::Oversized) => {
                    failed("github.workflow.oversized")
                }
                Err(_) => failed("github.workflow.unsupported_failure"),
            };
            let outcome = ProviderDeliveryWorkflowOutcome::new(path, conclusion).map_err(|_| {
                ProcessingFailure::reject("github.delivery.invalid_workflow_outcome")
            })?;
            outcomes.push(
                self.record_all_direct_progress(lease, inventory.digest(), outcome)
                    .await?,
            );
        }
        if !durable.is_empty() || outcomes.len() != inventory.entries().len() {
            return Err(WorkerInterruption::Worker(
                GithubDeliveryWorkerError::InvariantViolation,
            ));
        }
        let operation = lease.lock_operation().await;
        self.complete_with_operation(lease, outcomes, operation)
            .await
            .map_err(WorkerInterruption::Worker)
    }

    async fn register_all_direct_inventory(
        &self,
        lease: &GithubDeliveryClaimLease,
        inventory: &ProviderDeliveryWorkflowInventory,
    ) -> Result<BTreeMap<String, ProviderDeliveryWorkflowOutcome>, WorkerInterruption> {
        let operation = lease.lock_operation().await;
        let snapshot = lease
            .require_live_at(self.clock.now())
            .map_err(WorkerInterruption::Worker)?;
        let registration = RegisterProviderDeliveryWorkflowInventory::new(
            snapshot.claim(),
            inventory.clone(),
            self.clock.now(),
        )
        .map_err(|_| WorkerInterruption::Worker(GithubDeliveryWorkerError::InvariantViolation))?;
        let receipt = self
            .deliveries
            .register_provider_delivery_workflow_inventory(registration)
            .await
            .map_err(|error| WorkerInterruption::Worker(store_error(&error)))?;
        drop(operation);
        if receipt.inventory() != inventory {
            return Err(WorkerInterruption::Worker(
                GithubDeliveryWorkerError::InvariantViolation,
            ));
        }
        let outcomes = receipt.outcomes();
        let durable = outcomes
            .iter()
            .cloned()
            .map(|outcome| (outcome.workflow_path().to_owned(), outcome))
            .collect::<BTreeMap<_, _>>();
        if durable.len() != outcomes.len() {
            return Err(WorkerInterruption::Worker(
                GithubDeliveryWorkerError::InvariantViolation,
            ));
        }
        Ok(durable)
    }

    async fn record_all_direct_progress(
        &self,
        lease: &GithubDeliveryClaimLease,
        inventory_digest: Sha256Digest,
        outcome: ProviderDeliveryWorkflowOutcome,
    ) -> Result<ProviderDeliveryWorkflowOutcome, WorkerInterruption> {
        let operation = lease.lock_operation().await;
        let snapshot = lease
            .require_live_at(self.clock.now())
            .map_err(WorkerInterruption::Worker)?;
        let append = RecordProviderDeliveryWorkflowProgress::new(
            snapshot.claim(),
            inventory_digest,
            outcome.clone(),
            self.clock.now(),
        )
        .map_err(|_| WorkerInterruption::Worker(GithubDeliveryWorkerError::InvariantViolation))?;
        let recorded = self
            .deliveries
            .record_provider_delivery_workflow_progress(append)
            .await
            .map_err(|error| WorkerInterruption::Worker(store_error(&error)))?;
        drop(operation);
        if recorded != outcome {
            return Err(WorkerInterruption::Worker(
                GithubDeliveryWorkerError::InvariantViolation,
            ));
        }
        Ok(recorded)
    }

    async fn invoke_workflow_processor(
        &self,
        lease: &GithubDeliveryClaimLease,
        claimed: &ClaimedProviderDelivery,
        prepared: &PreparedGithubDelivery,
        source: &RepositorySource,
        workflow: (&str, &[u8]),
        private_credentials: Option<&dyn GithubDeliverySourceCredentialProvider>,
    ) -> Result<GithubDeliveryWorkflowProcessorCompletion, WorkerInterruption> {
        let snapshot = lease
            .require_live_at(self.clock.now())
            .map_err(WorkerInterruption::Worker)?;
        let (workflow_path, workflow_source) = workflow;
        match prepared.event() {
            VerifiedGithubWebhook::Push(_)
            | VerifiedGithubWebhook::PullRequest(_)
            | VerifiedGithubWebhook::MergeGroup(_)
            | VerifiedGithubWebhook::RepositoryDispatch(_) => Ok(self
                .workflow_processor
                .process_workflow(GithubDeliveryWorkflowRequest {
                    delivery_id: claimed.receipt().id(),
                    accepted_at: claimed.receipt().accepted_at(),
                    identity: claimed.identity(),
                    request_digest: claimed.request_digest(),
                    raw_event: claimed.raw_event(),
                    event_envelope: prepared.event_envelope(),
                    event: prepared.event(),
                    repository_source: source,
                    workflow_path,
                    workflow_source,
                    evidence: prepared.resolved_evidence().ok_or_else(|| {
                        ProcessingFailure::reject("github.repository_dispatch.unresolved_source")
                    })?,
                    snapshot,
                    lease,
                    clock: self.clock.as_ref(),
                    private_credentials,
                })
                .await),
            _ => Err(
                ProcessingFailure::reject("github.delivery.unsupported_authenticated_event").into(),
            ),
        }
    }

    async fn rehydrate_delivery(
        &self,
        claimed: &ClaimedProviderDelivery,
    ) -> Result<PreparedGithubDelivery, ProcessingFailure> {
        let event_envelope = rehydrate_event_envelope(claimed)?;
        let evidence = match self
            .subject_evidence
            .load_manifest_pinned_github_delivery_evidence(
                claimed.identity().tenant(),
                claimed.receipt().id(),
            )
            .await
        {
            Ok(evidence) => {
                validate_rehydration_evidence(claimed, &evidence, self.config.discovery_limits())?;
                DurableRehydrationEvidence::Resolved(evidence)
            }
            Err(GithubSubjectEvidenceStoreError::NotFound) => {
                let repository = self
                    .repository_dispatches
                    .as_ref()
                    .ok_or_else(|| ProcessingFailure::reject("github.subject_evidence.invalid"))?;
                let pending = repository
                    .load_pending_github_repository_dispatch_evidence(
                        claimed.identity().tenant(),
                        claimed.receipt().id(),
                    )
                    .await
                    .map_err(|error| subject_evidence_failure(&error))?;
                validate_pending_repository_dispatch_evidence(
                    claimed,
                    &pending,
                    self.config.discovery_limits(),
                )?;
                DurableRehydrationEvidence::PendingRepositoryDispatch(pending)
            }
            Err(error) => return Err(subject_evidence_failure(&error)),
        };
        let raw_event = claimed.raw_event();
        let expected_media_type = crate::GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE;
        if raw_event.media_type() != expected_media_type
            || raw_event.encoded_size() > evidence.manifest().limits().webhook_max_body_bytes()
        {
            return Err(ProcessingFailure::reject(
                "github.subject_evidence.mismatch",
            ));
        }
        let descriptor = raw_blob_descriptor(raw_event)
            .map_err(|()| ProcessingFailure::reject("github.raw_event.invalid_descriptor"))?;
        let raw_body = self
            .objects
            .get_verified(&descriptor, raw_event.encoded_size())
            .await
            .map_err(|error| raw_object_failure(error, self.config.retry_backoff_millis()))?
            .into_bytes();
        let (owner, name) = github_repository_components(claimed.identity().repository_identity())
            .ok_or_else(|| ProcessingFailure::reject("github.raw_event.invalid_identity"))?;
        let visibility = match claimed.identity().repository_visibility() {
            ProviderRepositoryVisibility::Public => GithubRepositoryVisibility::Public,
            ProviderRepositoryVisibility::Private => GithubRepositoryVisibility::Private,
        };
        match evidence {
            DurableRehydrationEvidence::Resolved(evidence) => rehydrate_stored_event(
                claimed,
                event_envelope,
                evidence,
                raw_body,
                visibility,
                owner,
                name,
            ),
            DurableRehydrationEvidence::PendingRepositoryDispatch(evidence) => {
                rehydrate_pending_repository_dispatch(
                    claimed,
                    event_envelope,
                    evidence,
                    raw_body,
                    visibility,
                    owner,
                    name,
                )
            }
        }
    }

    async fn finish_interruption(
        &self,
        lease: &GithubDeliveryClaimLease,
        interruption: WorkerInterruption,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        match interruption {
            WorkerInterruption::Failure(failure) => self.finish_failure(lease, failure).await,
            WorkerInterruption::Prerequisite(prerequisite) => {
                Err(GithubDeliveryWorkerError::Prerequisite(prerequisite))
            }
            WorkerInterruption::Worker(error) => Err(error),
        }
    }

    pub(crate) async fn finish_failure(
        &self,
        lease: &GithubDeliveryClaimLease,
        failure: ProcessingFailure,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        let operation = lease.lock_operation().await;
        self.finish_failure_with_operation(lease, failure, operation)
            .await
    }

    pub(crate) async fn finish_failure_with_operation(
        &self,
        lease: &GithubDeliveryClaimLease,
        failure: ProcessingFailure,
        operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        match failure {
            ProcessingFailure::Retry {
                failure_kind,
                delay_millis,
            } => {
                self.retry_with_operation(lease, failure_kind, delay_millis, operation)
                    .await
            }
            ProcessingFailure::Reject { failure_kind } => {
                self.reject_with_operation(lease, failure_kind, operation)
                    .await
            }
        }
    }

    async fn complete(
        &self,
        lease: &GithubDeliveryClaimLease,
        outcomes: Vec<ProviderDeliveryWorkflowOutcome>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        let operation = lease.lock_operation().await;
        self.complete_with_operation(lease, outcomes, operation)
            .await
    }

    async fn complete_with_operation(
        &self,
        lease: &GithubDeliveryClaimLease,
        outcomes: Vec<ProviderDeliveryWorkflowOutcome>,
        operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        lease.mark_terminal_transition_started();
        let (snapshot, completed_at) = self.transition_evidence(lease)?;
        let request = CompleteProviderDelivery::new(snapshot.claim(), outcomes, completed_at)
            .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        let result = self.deliveries.complete_provider_delivery(request).await;
        match result {
            Ok(receipt) => {
                drop(operation);
                validate_receipt(lease.initial(), receipt, ProviderDeliveryState::Completed)
                    .map(GithubDeliveryWorkerOutcome::Completed)
            }
            Err(ProviderDeliveryStoreError::OutcomeRunRejected) => {
                self.reject_with_operation(lease, "github.workflow.invalid_admitted_run", operation)
                    .await
            }
            Err(error) => {
                drop(operation);
                Err(store_error(&error))
            }
        }
    }

    async fn retry_with_operation(
        &self,
        lease: &GithubDeliveryClaimLease,
        failure_kind: &'static str,
        delay_millis: i64,
        operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        let claimed = lease.initial();
        if claimed.attempt() >= MAX_PROVIDER_DELIVERY_ATTEMPTS {
            return self
                .reject_with_operation(lease, "github.delivery.retry_limit", operation)
                .await;
        }
        lease.mark_terminal_transition_started();
        let (snapshot, observed_at) = self.transition_evidence(lease)?;
        let retry_at = UnixMillis::new(
            observed_at
                .get()
                .checked_add(delay_millis)
                .ok_or(GithubDeliveryWorkerError::InvalidTrustedTime)?,
        );
        let request = RetryProviderDelivery::new(
            snapshot.claim(),
            failure_kind_value(failure_kind),
            observed_at,
            retry_at,
        )
        .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        let result = self.deliveries.retry_provider_delivery(request).await;
        match result {
            Ok(receipt) => {
                drop(operation);
                validate_receipt(claimed, receipt, ProviderDeliveryState::RetryPending)
                    .map(GithubDeliveryWorkerOutcome::RetryScheduled)
            }
            Err(ProviderDeliveryStoreError::RetryLimitReached) => {
                self.reject_with_operation(lease, "github.delivery.retry_limit", operation)
                    .await
            }
            Err(error) => {
                drop(operation);
                Err(store_error(&error))
            }
        }
    }

    async fn reject(
        &self,
        lease: &GithubDeliveryClaimLease,
        failure_kind: &'static str,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        let operation = lease.lock_operation().await;
        self.reject_with_operation(lease, failure_kind, operation)
            .await
    }

    async fn reject_with_operation(
        &self,
        lease: &GithubDeliveryClaimLease,
        failure_kind: &'static str,
        _operation: OwnedMutexGuard<()>,
    ) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
        let claimed = lease.initial();
        lease.mark_terminal_transition_started();
        let (snapshot, rejected_at) = self.transition_evidence(lease)?;
        let request = RejectProviderDelivery::new(
            snapshot.claim(),
            failure_kind_value(failure_kind),
            rejected_at,
        )
        .map_err(|_| GithubDeliveryWorkerError::InvariantViolation)?;
        let receipt = self
            .deliveries
            .reject_provider_delivery(request)
            .await
            .map_err(|error| store_error(&error))?;
        validate_receipt(claimed, receipt, ProviderDeliveryState::Rejected)
            .map(GithubDeliveryWorkerOutcome::Rejected)
    }

    fn require_live(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<GithubDeliveryClaimSnapshot, GithubDeliveryWorkerError> {
        let now = self.clock.now();
        lease.require_live_at(now)
    }

    fn transition_evidence(
        &self,
        lease: &GithubDeliveryClaimLease,
    ) -> Result<(GithubDeliveryClaimSnapshot, UnixMillis), GithubDeliveryWorkerError> {
        let now = self.clock.now();
        lease.require_live_at(now).map(|snapshot| (snapshot, now))
    }
}

impl fmt::Debug for GithubDeliveryWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeliveryWorker")
            .field("objects", &"[immutable blob store]")
            .field("repository_source", &"[repository source port]")
            .field("workflow_processor", &"[workflow processor]")
            .field("deliveries", &"[provider delivery repository]")
            .field("subject_evidence", &"[GitHub subject evidence repository]")
            .field(
                "repository_dispatches",
                &self.repository_dispatches.as_ref().map(|_| "[configured]"),
            )
            .field(
                "repository_dispatch_resolver",
                &self
                    .repository_dispatch_resolver
                    .as_ref()
                    .map(|_| "[configured]"),
            )
            .field("clock", &self.clock)
            .field("config", &self.config)
            .finish()
    }
}

/// Sanitized worker failure that did not produce a durable transition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubDeliveryWorkerError {
    /// Correct processing requires an authority or service not supplied here.
    #[error("the GitHub delivery worker is missing a required prerequisite")]
    Prerequisite(GithubDeliveryWorkerPrerequisite),
    /// The trusted clock returned a negative or otherwise invalid timestamp.
    #[error("the trusted GitHub delivery worker clock returned an invalid timestamp")]
    InvalidTrustedTime,
    /// The provider-delivery repository operation was unavailable or ambiguous.
    #[error("the durable provider delivery inbox is unavailable")]
    InboxUnavailable,
    /// The claim was no longer live, exact, or owned by this worker.
    #[error("the durable provider delivery claim was rejected")]
    ClaimRejected,
    /// The inbox returned inconsistent or corrupt transition evidence.
    #[error("the durable provider delivery inbox returned invalid evidence")]
    InboxRejected,
    /// Trusted local construction violated a static cross-crate invariant.
    #[error("trusted GitHub delivery worker construction violated an invariant")]
    InvariantViolation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessingFailure {
    Retry {
        failure_kind: &'static str,
        delay_millis: i64,
    },
    Reject {
        failure_kind: &'static str,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerInterruption {
    Failure(ProcessingFailure),
    Prerequisite(GithubDeliveryWorkerPrerequisite),
    Worker(GithubDeliveryWorkerError),
}

impl From<ProcessingFailure> for WorkerInterruption {
    fn from(failure: ProcessingFailure) -> Self {
        Self::Failure(failure)
    }
}

impl ProcessingFailure {
    const fn retry(failure_kind: &'static str, delay_millis: i64) -> Self {
        Self::Retry {
            failure_kind,
            delay_millis,
        }
    }

    const fn reject(failure_kind: &'static str) -> Self {
        Self::Reject { failure_kind }
    }
}

fn processor_failure(
    error: GithubDeliveryWorkflowProcessorError,
    retry_delay_millis: i64,
) -> Result<ProcessingFailure, WorkerInterruption> {
    match error {
        GithubDeliveryWorkflowProcessorError::Unavailable => Ok(ProcessingFailure::retry(
            "github.workflow_processor.unavailable",
            retry_delay_millis,
        )),
        GithubDeliveryWorkflowProcessorError::Prerequisite(prerequisite) => {
            Err(WorkerInterruption::Prerequisite(prerequisite))
        }
        GithubDeliveryWorkflowProcessorError::ClaimLost => Err(WorkerInterruption::Worker(
            GithubDeliveryWorkerError::ClaimRejected,
        )),
        GithubDeliveryWorkflowProcessorError::InvariantViolation => Ok(ProcessingFailure::reject(
            "github.workflow_processor.invalid_state",
        )),
    }
}

fn rehydrate_stored_event(
    claimed: &ClaimedProviderDelivery,
    event_envelope: GithubSealedEventEnvelopeV1,
    evidence: ManifestPinnedGithubDeliveryEvidence,
    raw_body: bytes::Bytes,
    visibility: GithubRepositoryVisibility,
    owner: &str,
    name: &str,
) -> Result<PreparedGithubDelivery, ProcessingFailure> {
    let raw_event = claimed.raw_event();
    let authenticated_event = evidence.authenticated_event();
    let stored = StoredAuthenticatedGithubWebhook::from_durable_coordinates(
        raw_body,
        GithubWebhookBodyDigest::from_bytes(*raw_event.digest().as_bytes()),
        raw_event.encoded_size(),
        raw_event.media_type(),
        authenticated_event.kind().as_str(),
        claimed.identity().delivery_id(),
        claimed.identity().installation_id().get(),
        claimed.identity().repository_id().get(),
        evidence.repository_owner_id().get(),
        visibility,
        owner,
        name,
    );
    let event =
        rehydrate_stored_authenticated_github_webhook(stored).map_err(stored_event_failure)?;
    verify_rehydrated_event_envelope(claimed, &event_envelope, &event)?;
    let coordinates_match = match &event {
        VerifiedGithubWebhook::RepositoryDispatch(dispatch) => {
            authenticated_event.kind()
                == automata_ci_store::GithubAuthenticatedEventKind::RepositoryDispatch
                && authenticated_event.git_ref() == dispatch.git_ref()
                && dispatch.git_ref() == evidence.manifest().git_ref()
                && evidence
                    .repository_dispatch_resolution()
                    .is_some_and(|resolution| {
                        resolution.source_revision() == evidence.check_head_sha()
                    })
        }
        _ => crate::authenticated_event_coordinates(&event).is_ok_and(|coordinates| {
            coordinates.event == *authenticated_event
                && coordinates.head_sha == evidence.check_head_sha()
                && evidence.repository_dispatch_resolution().is_none()
        }),
    };
    if !coordinates_match || !valid_authenticated_event_policy(&event, evidence.manifest()) {
        return Err(ProcessingFailure::reject(
            "github.subject_evidence.mismatch",
        ));
    }
    Ok(PreparedGithubDelivery::from_authenticated_event(
        event,
        event_envelope,
        evidence,
    ))
}

fn rehydrate_pending_repository_dispatch(
    claimed: &ClaimedProviderDelivery,
    event_envelope: GithubSealedEventEnvelopeV1,
    evidence: PendingGithubRepositoryDispatchEvidence,
    raw_body: bytes::Bytes,
    visibility: GithubRepositoryVisibility,
    owner: &str,
    name: &str,
) -> Result<PreparedGithubDelivery, ProcessingFailure> {
    let raw_event = claimed.raw_event();
    let stored = StoredAuthenticatedGithubWebhook::from_durable_coordinates(
        raw_body,
        GithubWebhookBodyDigest::from_bytes(*raw_event.digest().as_bytes()),
        raw_event.encoded_size(),
        raw_event.media_type(),
        evidence.event().kind().as_str(),
        claimed.identity().delivery_id(),
        claimed.identity().installation_id().get(),
        claimed.identity().repository_id().get(),
        evidence.repository_owner_id().get(),
        visibility,
        owner,
        name,
    );
    let event =
        rehydrate_stored_authenticated_github_webhook(stored).map_err(stored_event_failure)?;
    verify_rehydrated_event_envelope(claimed, &event_envelope, &event)?;
    let VerifiedGithubWebhook::RepositoryDispatch(dispatch) = &event else {
        return Err(ProcessingFailure::reject(
            "github.repository_dispatch.invalid_event",
        ));
    };
    if evidence.event().kind()
        != automata_ci_store::GithubAuthenticatedEventKind::RepositoryDispatch
        || evidence.event().git_ref() != dispatch.git_ref()
        || dispatch.git_ref() != evidence.manifest().git_ref()
        || !valid_authenticated_event_policy(&event, evidence.manifest())
    {
        return Err(ProcessingFailure::reject(
            "github.subject_evidence.mismatch",
        ));
    }
    Ok(PreparedGithubDelivery::from_pending_repository_dispatch(
        event,
        event_envelope,
        evidence,
    ))
}

fn rehydrate_event_envelope(
    claimed: &ClaimedProviderDelivery,
) -> Result<GithubSealedEventEnvelopeV1, ProcessingFailure> {
    let durable = claimed.event_envelope();
    if durable.schema() != GITHUB_EVENT_ENVELOPE_SCHEMA_V1
        || durable.registry_schema() != GITHUB_EVENT_REGISTRY_SCHEMA_V1
        || durable.media_type() != GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE
    {
        return Err(ProcessingFailure::reject(
            "github.event_envelope.unsupported_schema",
        ));
    }
    let envelope = GithubSealedEventEnvelopeV1::from_canonical_bytes(
        durable.canonical_bytes(),
        durable.digest(),
    )
    .map_err(|_| ProcessingFailure::reject("github.event_envelope.invalid"))?;
    let expected_raw = raw_blob_descriptor(claimed.raw_event())
        .map_err(|()| ProcessingFailure::reject("github.raw_event.invalid_descriptor"))?;
    if envelope.raw_event().descriptor() != &expected_raw {
        return Err(ProcessingFailure::reject(
            "github.event_envelope.raw_identity_mismatch",
        ));
    }
    let expected_visibility = match claimed.identity().repository_visibility() {
        ProviderRepositoryVisibility::Public => GithubRepositoryVisibility::Public,
        ProviderRepositoryVisibility::Private => GithubRepositoryVisibility::Private,
    };
    let target = envelope.event().target_repository();
    if claimed.identity().provider() != GITHUB_PROVIDER
        || envelope.delivery_id() != claimed.identity().delivery_id()
        || envelope.installation_id().get() != claimed.identity().installation_id().get()
        || target.id().get() != claimed.identity().repository_id().get()
        || target.visibility() != expected_visibility
        || target.full_name() != claimed.identity().repository_identity()
    {
        return Err(ProcessingFailure::reject(
            "github.event_envelope.identity_mismatch",
        ));
    }
    Ok(envelope)
}

fn verify_rehydrated_event_envelope(
    claimed: &ClaimedProviderDelivery,
    durable: &GithubSealedEventEnvelopeV1,
    event: &VerifiedGithubWebhook,
) -> Result<(), ProcessingFailure> {
    let raw_event = raw_blob_descriptor(claimed.raw_event())
        .map_err(|()| ProcessingFailure::reject("github.raw_event.invalid_descriptor"))?;
    let reconstructed = GithubSealedEventEnvelopeV1::seal(event, raw_event)
        .map_err(|_| ProcessingFailure::reject("github.event_envelope.event_mismatch"))?;
    if reconstructed.digest() != durable.digest()
        || reconstructed.canonical_bytes() != durable.canonical_bytes()
    {
        return Err(ProcessingFailure::reject(
            "github.event_envelope.event_mismatch",
        ));
    }
    Ok(())
}

fn source_revision(event: &VerifiedGithubWebhook) -> Option<&str> {
    match event {
        VerifiedGithubWebhook::Push(push) if !push.deleted() => Some(push.after_commit_sha()),
        // A synchronize webhook can carry the previous merge-ref SHA while
        // GitHub is still rematerializing refs/pull/<n>/merge. The signed head
        // SHA is the immutable revision to which Checks are published, so use
        // that same revision for source ingestion instead of compiling stale
        // merge-ref contents under the new head's check.
        VerifiedGithubWebhook::PullRequest(pull_request) => {
            Some(pull_request.head_revision().as_str())
        }
        VerifiedGithubWebhook::MergeGroup(merge_group) => {
            Some(merge_group.head_revision().as_str())
        }
        _ => None,
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(LOWER_HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn archive_limits(manifest: &GithubProviderManifest) -> Result<ArchiveLimits, ProcessingFailure> {
    ArchiveLimits::new(manifest.limits().archive_max_compressed_bytes())
        .map_err(|_| ProcessingFailure::reject("github.provider_manifest.unsupported_policy"))
}

fn manifest_discovery_limits(
    manifest: &GithubProviderManifest,
) -> Result<RepositoryWorkflowDiscoveryLimits, ProcessingFailure> {
    let limits = manifest.limits();
    let entries = usize::try_from(limits.archive_max_entries())
        .map_err(|_| ProcessingFailure::reject("github.provider_manifest.unsupported_policy"))?;
    let entry_path_bytes = usize::try_from(limits.archive_max_entry_path_bytes())
        .map_err(|_| ProcessingFailure::reject("github.provider_manifest.unsupported_policy"))?;
    let workflows = usize::try_from(limits.archive_max_workflows())
        .map_err(|_| ProcessingFailure::reject("github.provider_manifest.unsupported_policy"))?;
    RepositoryWorkflowDiscoveryLimits::new(
        limits.archive_max_compressed_bytes(),
        limits.archive_max_decompressed_bytes(),
        entries,
        limits.archive_max_expanded_bytes(),
        entry_path_bytes,
        workflows,
        limits.workflow_max_bytes(),
    )
    .map_err(|_| ProcessingFailure::reject("github.provider_manifest.unsupported_policy"))
}

const fn discovery_limits_fit_within(
    pinned: RepositoryWorkflowDiscoveryLimits,
    ceiling: RepositoryWorkflowDiscoveryLimits,
) -> bool {
    pinned.maximum_compressed_bytes() <= ceiling.maximum_compressed_bytes()
        && pinned.maximum_decompressed_bytes() <= ceiling.maximum_decompressed_bytes()
        && pinned.maximum_entries() <= ceiling.maximum_entries()
        && pinned.maximum_expanded_bytes() <= ceiling.maximum_expanded_bytes()
        && pinned.maximum_entry_path_bytes() <= ceiling.maximum_entry_path_bytes()
        && pinned.maximum_workflows() <= ceiling.maximum_workflows()
        && pinned.maximum_workflow_bytes() <= ceiling.maximum_workflow_bytes()
}

fn validate_rehydration_evidence(
    claimed: &ClaimedProviderDelivery,
    evidence: &ManifestPinnedGithubDeliveryEvidence,
    configured_limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<(), ProcessingFailure> {
    let pinned_limits = manifest_discovery_limits(evidence.manifest())?;
    if evidence.tenant() != claimed.identity().tenant()
        || evidence.delivery_id() != claimed.receipt().id()
        || !evidence
            .manifest()
            .matches_delivery_identity(claimed.identity())
        || evidence.accepted_at() != claimed.receipt().accepted_at()
        || !valid_manifest_source_policy(evidence.manifest())
        || !discovery_limits_fit_within(pinned_limits, configured_limits)
        || !valid_visibility_authority(evidence)
    {
        return Err(ProcessingFailure::reject(
            "github.subject_evidence.mismatch",
        ));
    }
    Ok(())
}

fn validate_pending_repository_dispatch_evidence(
    claimed: &ClaimedProviderDelivery,
    evidence: &PendingGithubRepositoryDispatchEvidence,
    configured_limits: RepositoryWorkflowDiscoveryLimits,
) -> Result<(), ProcessingFailure> {
    let pinned_limits = manifest_discovery_limits(evidence.manifest())?;
    let visibility_authority_matches = matches!(
        (
            evidence.manifest().repository_visibility(),
            evidence.private_source_authority()
        ),
        (ProviderRepositoryVisibility::Public, None)
            | (ProviderRepositoryVisibility::Private, Some(_))
    );
    if evidence.tenant() != claimed.identity().tenant()
        || evidence.delivery_id() != claimed.receipt().id()
        || !evidence
            .manifest()
            .matches_delivery_identity(claimed.identity())
        || evidence.accepted_at() != claimed.receipt().accepted_at()
        || evidence.event().kind()
            != automata_ci_store::GithubAuthenticatedEventKind::RepositoryDispatch
        || evidence.event().git_ref() != evidence.manifest().git_ref()
        || !valid_manifest_source_policy(evidence.manifest())
        || !discovery_limits_fit_within(pinned_limits, configured_limits)
        || !visibility_authority_matches
    {
        return Err(ProcessingFailure::reject(
            "github.subject_evidence.mismatch",
        ));
    }
    Ok(())
}

fn valid_manifest_source_policy(manifest: &GithubProviderManifest) -> bool {
    let origins = manifest.origins();
    let expected_authentication = match manifest.repository_visibility() {
        ProviderRepositoryVisibility::Public => GITHUB_PROVIDER_PUBLIC_SOURCE_AUTHENTICATION,
        ProviderRepositoryVisibility::Private => GITHUB_PROVIDER_PRIVATE_SOURCE_AUTHENTICATION,
    };
    origins.web_origin() == GITHUB_PROVIDER_WEB_ORIGIN
        && origins.api_origin() == GITHUB_PROVIDER_API_ORIGIN
        && origins.archive_origin() == GITHUB_PROVIDER_ARCHIVE_ORIGIN
        && manifest.rest_api_version() == GITHUB_PROVIDER_REST_API_VERSION
        && manifest.rest_accept() == GITHUB_PROVIDER_REST_ACCEPT
        && manifest.archive_accept() == GITHUB_PROVIDER_ARCHIVE_ACCEPT
        && manifest.source_authentication() == expected_authentication
        && manifest.source_revision() == GITHUB_PROVIDER_SOURCE_REVISION
        && manifest.archive_format() == GITHUB_PROVIDER_ARCHIVE_FORMAT
}

fn valid_visibility_authority(evidence: &ManifestPinnedGithubDeliveryEvidence) -> bool {
    matches!(
        (
            evidence.repository_visibility(),
            evidence.private_source_authority()
        ),
        (ProviderRepositoryVisibility::Public, None)
            | (ProviderRepositoryVisibility::Private, Some(_))
    )
}

fn valid_path_filter_commit_evidence(
    push: &VerifiedGithubPush,
    manifest: &GithubProviderManifest,
) -> bool {
    let commit_count = u64::try_from(push.commit_count()).unwrap_or(u64::MAX);
    match push.complete_pushed_commit_revisions() {
        Some(revisions) => {
            commit_count <= manifest.limits().path_filter_max_commits()
                && revisions.len() == push.commit_count()
        }
        None => commit_count > manifest.limits().path_filter_max_commits(),
    }
}

fn valid_authenticated_push_policy(
    push: &VerifiedGithubPush,
    manifest: &GithubProviderManifest,
) -> bool {
    u64::try_from(push.commit_count()).unwrap_or(u64::MAX)
        <= manifest.limits().push_webhook_max_commits()
        && valid_path_filter_commit_evidence(push, manifest)
}

fn valid_authenticated_event_policy(
    event: &VerifiedGithubWebhook,
    manifest: &GithubProviderManifest,
) -> bool {
    match event {
        VerifiedGithubWebhook::Push(push) => valid_authenticated_push_policy(push, manifest),
        VerifiedGithubWebhook::PullRequest(_)
        | VerifiedGithubWebhook::MergeGroup(_)
        | VerifiedGithubWebhook::RepositoryDispatch(_) => true,
        _ => false,
    }
}

fn subject_evidence_failure(error: &GithubSubjectEvidenceStoreError) -> ProcessingFailure {
    match error {
        GithubSubjectEvidenceStoreError::Operation(_) => ProcessingFailure::retry(
            "github.subject_evidence.unavailable",
            DEFAULT_RETRY_BACKOFF_MILLIS,
        ),
        GithubSubjectEvidenceStoreError::AuthorityRejected
        | GithubSubjectEvidenceStoreError::ReplayConflict
        | GithubSubjectEvidenceStoreError::NotFound
        | GithubSubjectEvidenceStoreError::CorruptData => {
            ProcessingFailure::reject("github.subject_evidence.invalid")
        }
    }
}

fn repository_dispatch_resolution_store_error(
    error: &GithubSubjectEvidenceStoreError,
) -> GithubDeliveryWorkerError {
    match error {
        GithubSubjectEvidenceStoreError::Operation(_) => {
            GithubDeliveryWorkerError::InboxUnavailable
        }
        GithubSubjectEvidenceStoreError::AuthorityRejected => {
            GithubDeliveryWorkerError::ClaimRejected
        }
        GithubSubjectEvidenceStoreError::NotFound => GithubDeliveryWorkerError::InboxRejected,
        GithubSubjectEvidenceStoreError::ReplayConflict
        | GithubSubjectEvidenceStoreError::CorruptData => {
            GithubDeliveryWorkerError::InvariantViolation
        }
    }
}

fn raw_blob_descriptor(raw_event: &AdmissionObject) -> Result<BlobDescriptor, ()> {
    let key = BlobKey::new(raw_event.object_key().as_str()).map_err(|_| ())?;
    let media_type = MediaType::new(raw_event.media_type()).map_err(|_| ())?;
    Ok(BlobDescriptor::new(
        key,
        raw_event.digest(),
        raw_event.encoded_size(),
        media_type,
    ))
}

const fn raw_object_failure(
    error: automata_ci_blob::BlobStoreError,
    retry_delay_millis: i64,
) -> ProcessingFailure {
    match error.kind() {
        BlobStoreErrorKind::Unavailable | BlobStoreErrorKind::Unauthorized => {
            ProcessingFailure::retry("github.raw_event.unavailable", retry_delay_millis)
        }
        BlobStoreErrorKind::NotFound => ProcessingFailure::reject("github.raw_event.not_found"),
        BlobStoreErrorKind::Conflict
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::TooLarge
        | BlobStoreErrorKind::InvalidResponse => {
            ProcessingFailure::reject("github.raw_event.invalid_object")
        }
    }
}

const fn stored_event_failure(_error: GithubStoredWebhookError) -> ProcessingFailure {
    ProcessingFailure::reject("github.raw_event.invalid_event")
}

fn github_repository_components(repository: &str) -> Option<(&str, &str)> {
    let mut components = repository.split('/');
    let owner = components.next()?;
    let name = components.next()?;
    if owner.is_empty() || name.is_empty() || components.next().is_some() {
        return None;
    }
    Some((owner, name))
}

fn source_failure(error: ScmError, default_delay_millis: i64) -> ProcessingFailure {
    match error.kind() {
        ScmErrorKind::Unauthorized => ProcessingFailure::retry(
            "github.repository_source.unauthorized",
            default_delay_millis,
        ),
        ScmErrorKind::Forbidden => {
            ProcessingFailure::retry("github.repository_source.forbidden", default_delay_millis)
        }
        ScmErrorKind::RateLimited => ProcessingFailure::retry(
            "github.repository_source.rate_limited",
            retry_after_millis(error, default_delay_millis),
        ),
        ScmErrorKind::Unavailable => {
            ProcessingFailure::retry("github.repository_source.unavailable", default_delay_millis)
        }
        ScmErrorKind::NotFound => ProcessingFailure::reject("github.repository_source.not_found"),
        ScmErrorKind::TooLarge => ProcessingFailure::reject("github.repository_source.too_large"),
        ScmErrorKind::InvalidResponse => {
            ProcessingFailure::reject("github.repository_source.invalid_response")
        }
        ScmErrorKind::Integrity => ProcessingFailure::reject("github.repository_source.integrity"),
    }
}

fn retry_after_millis(error: ScmError, default_delay_millis: i64) -> i64 {
    error
        .retry_after_seconds()
        .and_then(|seconds| {
            i64::try_from(seconds)
                .ok()
                .and_then(|seconds| seconds.checked_mul(1_000))
        })
        .filter(|delay| *delay > 0)
        .map_or(default_delay_millis, |delay| {
            delay.min(MAX_PROVIDER_DELIVERY_RETRY_BACKOFF_MILLIS)
        })
}

fn valid_source_response(
    source: &RepositorySource,
    repository: &RepositoryId,
    revision: &ExactRevision,
    limits: ArchiveLimits,
) -> bool {
    source.provider().as_str() == GITHUB_PROVIDER
        && source.repository() == repository
        && source.revision() == revision
        && source.format() == ArchiveFormat::TarGzip
        && source.size() <= limits.maximum_bytes()
}

const fn discovery_failure_kind(error: RepositoryWorkflowDiscoveryError) -> &'static str {
    match error {
        RepositoryWorkflowDiscoveryError::Malformed => "github.repository_archive.malformed",
        RepositoryWorkflowDiscoveryError::ResourceLimit => {
            "github.repository_archive.resource_limit"
        }
        RepositoryWorkflowDiscoveryError::UnsafePath => "github.repository_archive.unsafe_path",
        RepositoryWorkflowDiscoveryError::UnsafeLink => "github.repository_archive.unsafe_link",
        RepositoryWorkflowDiscoveryError::DuplicatePath => {
            "github.repository_archive.duplicate_path"
        }
        RepositoryWorkflowDiscoveryError::PathAlias => "github.repository_archive.path_alias",
        RepositoryWorkflowDiscoveryError::PathTypeConflict => {
            "github.repository_archive.path_type_conflict"
        }
        RepositoryWorkflowDiscoveryError::NamespaceAlias => {
            "github.repository_archive.workflow_namespace_alias"
        }
        RepositoryWorkflowDiscoveryError::UnsupportedArchiveEntry => {
            "github.repository_archive.unsupported_entry"
        }
        RepositoryWorkflowDiscoveryError::UnsupportedWorkflowEntry => {
            "github.repository_archive.unsupported_workflow"
        }
        RepositoryWorkflowDiscoveryError::UnsupportedWorkflowLocation => {
            "github.repository_archive.unsupported_workflow_location"
        }
        RepositoryWorkflowDiscoveryError::MissingArchiveRoot => {
            "github.repository_archive.missing_root"
        }
        _ => "github.repository_archive.unsupported_failure",
    }
}

fn failed(failure_kind: &'static str) -> ProviderDeliveryWorkflowConclusion {
    ProviderDeliveryWorkflowConclusion::Failed {
        failure_kind: failure_kind_value(failure_kind),
    }
}

fn prepare_all_direct_inventory(
    manifest: &GithubProviderManifest,
    manifest_digest: Sha256Digest,
    source: &RepositorySource,
    workflows: Vec<RepositoryWorkflowDiscoveryOutcome>,
) -> Result<
    (
        ProviderDeliveryWorkflowInventory,
        BTreeMap<String, RepositoryWorkflowDiscoveryOutcome>,
    ),
    ProcessingFailure,
> {
    let mut selected = BTreeMap::new();
    let mut entries = Vec::with_capacity(workflows.len());
    for workflow in workflows {
        let path = workflow.path().to_owned();
        if !manifest.selects_workflow_path(&path) {
            continue;
        }
        let source_state = match workflow.result() {
            Ok(workflow_source) => {
                ProviderDeliveryWorkflowSourceState::Ready(sha256(workflow_source))
            }
            Err(RepositoryWorkflowDiscoveryFailure::Empty) => {
                ProviderDeliveryWorkflowSourceState::Empty
            }
            Err(RepositoryWorkflowDiscoveryFailure::Oversized) => {
                ProviderDeliveryWorkflowSourceState::Oversized
            }
            Err(_) => {
                return Err(ProcessingFailure::reject(
                    "github.workflow.unsupported_failure",
                ));
            }
        };
        entries.push(
            ProviderDeliveryWorkflowInventoryEntry::new(path.clone(), source_state).map_err(
                |_| ProcessingFailure::reject("github.delivery.invalid_workflow_inventory"),
            )?,
        );
        if selected.insert(path, workflow).is_some() {
            return Err(ProcessingFailure::reject(
                "github.delivery.duplicate_workflow_path",
            ));
        }
    }
    let inventory = ProviderDeliveryWorkflowInventory::new(
        manifest_digest,
        source.revision().as_str(),
        source.digest(),
        entries,
    )
    .map_err(|_| ProcessingFailure::reject("github.delivery.invalid_workflow_inventory"))?;
    Ok((inventory, selected))
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn failure_kind_value(value: &'static str) -> ProviderDeliveryFailureKind {
    ProviderDeliveryFailureKind::new(value)
        .expect("fixed GitHub delivery failure kind is canonical and bounded")
}

fn validate_receipt(
    claimed: &ClaimedProviderDelivery,
    receipt: ProviderDeliveryReceipt,
    expected_state: ProviderDeliveryState,
) -> Result<ProviderDeliveryReceipt, GithubDeliveryWorkerError> {
    if receipt.id() != claimed.receipt().id()
        || receipt.state() != expected_state
        || receipt.attempts() != claimed.attempt()
        || receipt.accepted_at() != claimed.receipt().accepted_at()
    {
        return Err(GithubDeliveryWorkerError::InboxRejected);
    }
    Ok(receipt)
}

fn store_error(error: &ProviderDeliveryStoreError) -> GithubDeliveryWorkerError {
    match error {
        ProviderDeliveryStoreError::Operation(_) => GithubDeliveryWorkerError::InboxUnavailable,
        ProviderDeliveryStoreError::ClaimRejected => GithubDeliveryWorkerError::ClaimRejected,
        ProviderDeliveryStoreError::ReplayConflict
        | ProviderDeliveryStoreError::RetryLimitReached
        | ProviderDeliveryStoreError::OutcomeRunRejected
        | ProviderDeliveryStoreError::WorkflowProgressUnsupported
        | ProviderDeliveryStoreError::WorkflowProgressRejected
        | ProviderDeliveryStoreError::FenceExhausted
        | ProviderDeliveryStoreError::CorruptData => GithubDeliveryWorkerError::InboxRejected,
    }
}

fn processor_lease_error(error: GithubDeliveryWorkerError) -> GithubDeliveryWorkflowProcessorError {
    match error {
        GithubDeliveryWorkerError::ClaimRejected => GithubDeliveryWorkflowProcessorError::ClaimLost,
        GithubDeliveryWorkerError::InvalidTrustedTime
        | GithubDeliveryWorkerError::InboxUnavailable
        | GithubDeliveryWorkerError::InboxRejected
        | GithubDeliveryWorkerError::InvariantViolation
        | GithubDeliveryWorkerError::Prerequisite(_) => {
            GithubDeliveryWorkflowProcessorError::InvariantViolation
        }
    }
}

#[cfg(test)]
mod lease_tests {
    use automata_ci_store::{
        ObjectKey, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
        ProviderDeliveryEventEnvelope, ProviderDeliveryId, ProviderDeliveryReceipt,
        ProviderInstallationId, ProviderRepositoryCoordinates, ProviderRepositoryId, TenantScope,
    };
    use uuid::Uuid;

    use super::*;

    #[test]
    fn archive_authority_and_graph_failures_have_specific_failure_kinds() {
        assert_eq!(
            discovery_failure_kind(RepositoryWorkflowDiscoveryError::UnsupportedWorkflowLocation),
            "github.repository_archive.unsupported_workflow_location"
        );
        assert_eq!(
            discovery_failure_kind(RepositoryWorkflowDiscoveryError::UnsafeLink),
            "github.repository_archive.unsafe_link"
        );
        assert_eq!(
            discovery_failure_kind(RepositoryWorkflowDiscoveryError::PathAlias),
            "github.repository_archive.path_alias"
        );
        assert_eq!(
            discovery_failure_kind(RepositoryWorkflowDiscoveryError::PathTypeConflict),
            "github.repository_archive.path_type_conflict"
        );
        assert_eq!(
            discovery_failure_kind(RepositoryWorkflowDiscoveryError::NamespaceAlias),
            "github.repository_archive.workflow_namespace_alias"
        );
    }

    #[test]
    fn renewal_apply_reports_only_the_exact_predecessor_expiry_race() {
        let initial = claimed_delivery();
        let successor_claim = ProviderDeliveryClaimFence::from_durable_parts(
            initial.claim().delivery_id(),
            initial.claim().owner(),
            initial.claim().fence() + 1,
        )
        .expect("successor claim");
        let renewal = RenewedProviderDeliveryClaim::from_durable_parts(
            successor_claim,
            initial.attempt(),
            initial.claimed_at(),
            UnixMillis::new(150),
            UnixMillis::new(250),
        )
        .expect("renewal");
        let lease = GithubDeliveryClaimLease::new(initial.clone(), Instant::now());
        let successor_deadline = Instant::now()
            .checked_add(std::time::Duration::from_millis(50))
            .expect("successor deadline");

        assert!(matches!(
            lease.apply_renewal(renewal, successor_deadline),
            Ok(GithubDeliveryClaimRenewalApplyOutcome::PredecessorExpired)
        ));
        assert_eq!(
            lease.latest().expect("unchanged predecessor").claim(),
            initial.claim()
        );

        let invalid_claim = ProviderDeliveryClaimFence::from_durable_parts(
            initial.claim().delivery_id(),
            initial.claim().owner(),
            initial.claim().fence() + 2,
        )
        .expect("non-successor claim");
        let invalid = RenewedProviderDeliveryClaim::from_durable_parts(
            invalid_claim,
            initial.attempt(),
            initial.claimed_at(),
            UnixMillis::new(150),
            UnixMillis::new(250),
        )
        .expect("structurally valid non-successor");
        assert_eq!(
            lease.apply_renewal(invalid, successor_deadline),
            Err(GithubDeliveryWorkerError::InboxRejected)
        );
    }

    #[test]
    fn database_issued_claim_ahead_of_worker_clock_uses_the_monotonic_deadline() {
        let initial = claimed_delivery();
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .expect("live deadline");
        let lease = GithubDeliveryClaimLease::new(initial.clone(), deadline);
        let snapshot = lease.latest().expect("initial snapshot");

        assert_eq!(
            lease.require_live_observation(UnixMillis::new(95)),
            Ok((snapshot, UnixMillis::new(100)))
        );
    }

    fn claimed_delivery() -> ClaimedProviderDelivery {
        let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(1)).expect("delivery ID");
        let receipt = ProviderDeliveryReceipt::from_durable_parts(
            delivery_id,
            ProviderDeliveryState::Claimed,
            1,
            UnixMillis::new(50),
        )
        .expect("claimed receipt");
        let repository = ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(4).expect("repository"),
            ProviderRepositoryVisibility::Private,
            "owner/repository",
        )
        .expect("repository coordinates");
        let identity = ProviderDeliveryIdentity::new(
            TenantScope::from_authenticated_tenant_id("tenant-renewal").expect("tenant"),
            "github",
            ProviderConnectionId::from_uuid(Uuid::from_u128(2)).expect("connection"),
            ProviderInstallationId::new(3).expect("installation"),
            repository,
            "provider-delivery",
        )
        .expect("identity");
        let raw_event = AdmissionObject::new(
            Sha256Digest::from_bytes([0x42; 32]),
            ObjectKey::new("provider-deliveries/github/push/fixture.json").expect("object key"),
            1,
            "application/vnd.automata.github-push+json",
        )
        .expect("raw event");
        let claim = ProviderDeliveryClaimFence::from_durable_parts(
            delivery_id,
            ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(5)).expect("claim owner"),
            7,
        )
        .expect("claim");
        ClaimedProviderDelivery::from_durable_parts(
            receipt,
            identity,
            Sha256Digest::from_bytes([0x24; 32]),
            raw_event,
            ProviderDeliveryEventEnvelope::new(
                1,
                1,
                Sha256Digest::from_bytes([0x25; 32]),
                br#"{"schema":1}"#.to_vec(),
                GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
            )
            .expect("event envelope"),
            claim,
            UnixMillis::new(100),
            UnixMillis::new(200),
        )
        .expect("claimed delivery")
    }
}
