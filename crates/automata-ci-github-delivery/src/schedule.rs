//! Durable GitHub scheduled-workflow discovery and fire processing.
//!
//! Schedules deliberately do not enter the webhook inbox. Discovery starts
//! from a current immutable provider manifest, claims its own durable fence,
//! resolves the configured default branch to an exact revision, and seals the
//! resulting archive inventory. Due work then has a second fire fence whose
//! Check registration and workflow admission are independently atomic.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
use automata_ci_core::{
    ContextValue, JobRuntimeContext, OperationId, Sha256Digest, TrustActorEvidence, TrustActorKind,
    TrustAutomationKind, TrustEventKind, TrustEvidence, TrustOriginKind, TrustPolicy,
    TrustRepositoryEvidence, TrustTokenRecursion, UnixMillis, WorkflowEventProvenance,
    WorkflowPlan,
};
use automata_ci_scm::{
    ArchiveFormat, ArchiveLimits, RepositoryId as ScmRepositoryId, RevisionSpec, ScmError,
    ScmErrorKind, ScmProvider, SnapshotRequest,
};
use automata_ci_store::{
    ClaimDueGithubScheduleFire, ClaimGithubScheduleDiscovery, ClaimedGithubScheduleFire,
    CompleteGithubScheduleFire, GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE, GITHUB_SCHEDULE_SERVICE_ACTOR,
    GithubProviderManifest, GithubProviderManifestRecord, GithubProviderManifestRepository,
    GithubProviderManifestStoreError, GithubScheduleArchive, GithubScheduleDiscoveryClaim,
    GithubScheduleFireClaim, GithubScheduleFireConclusion, GithubScheduleRegistryEntry,
    GithubScheduleRegistryId, GithubScheduleRepository, GithubScheduleSourceAuthority,
    GithubScheduleStoreError, GithubScheduleWorkerId, GithubServerServiceAction,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId, GithubServerServiceRevision,
    GithubServerServiceWorkerId, MAX_GITHUB_SCHEDULE_CLAIM_MILLIS,
    MAX_GITHUB_SCHEDULE_RETRY_MILLIS, ObjectKey, ProviderConnectionId,
    ProviderRepositoryVisibility, RegisterGithubScheduleRegistry,
    RegisterGithubScheduledCheckSubject, RetryGithubScheduleFire, WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_github::{
    CompilationDisposition, CompileWorkflowRequest, GithubEventMetadata, GithubWorkflowCompiler,
    GithubWorkflowFrontend, ParseWorkflowRequest, RepositoryWorkflowDiscoveryLimits,
    RepositoryWorkflowDiscoveryPolicy, SourceId, SourceOrigin, SourceProvenance,
    WorkflowFrontend as _, discover_repository_workflows, extract_github_schedule_entries,
};
use automata_ci_workflow_service::{
    AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE, AdmissionRepositoryCoordinates,
    GithubScheduleEvidence, RepositoryWorkflowSource, WorkflowAdmissionError,
    WorkflowAdmissionRequest, WorkflowAdmissionRequestError, WorkflowAdmissionService,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::GithubServerServiceCredentialRelease;

const GITHUB_PROVIDER: &str = "github";
const DEFAULT_POLL_MILLIS: i64 = 1_000;
const DEFAULT_DISCOVERY_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
const DEFAULT_FIRE_CLAIM_MILLIS: i64 = 5 * 60 * 1_000;
const DEFAULT_RETRY_MILLIS: i64 = 30_000;
const DEFAULT_STALENESS_MILLIS: i64 = 60 * 60 * 1_000;
const DEFAULT_MAX_MANIFESTS: u16 = 256;
const DEFAULT_MAX_FIRES: u16 = 32;
const MAX_FIRES_PER_PASS: u16 = 256;
const MAX_STALENESS_MILLIS: i64 = 24 * 60 * 60 * 1_000;
const MAX_PROVIDER_REQUEST_MILLIS: i64 = 5 * 60 * 1_000;
const ARCHIVE_KEY_PREFIX: &str = "github/schedule-archives/v1";

/// Time source used to bound scheduler-owned work outside database calls.
pub trait GithubScheduleClock: fmt::Debug + Send + Sync {
    /// Returns a trusted current wall-clock instant.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when no valid trusted instant is available.
    fn now(&self) -> Result<UnixMillis, GithubScheduleServiceError>;
}

/// Bounded runtime policy for scheduled discovery and due-fire handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubScheduleServiceConfig {
    poll_millis: i64,
    discovery_claim_millis: i64,
    fire_claim_millis: i64,
    retry_millis: i64,
    staleness_millis: i64,
    maximum_manifests: u16,
    maximum_fires_per_pass: u16,
}

impl GithubScheduleServiceConfig {
    /// Creates a bounded deterministic scheduling policy.
    ///
    /// At most `maximum_fires_per_pass` non-stale occurrences are caught up in
    /// one pass. An occurrence older than `staleness_millis` is terminally
    /// skipped and the durable cursor advances directly to the first calendar
    /// instant after the authoritative claim time.
    ///
    /// # Errors
    ///
    /// Rejects durations or work bounds outside the durable schedule limits.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        poll_millis: i64,
        discovery_claim_millis: i64,
        fire_claim_millis: i64,
        retry_millis: i64,
        staleness_millis: i64,
        maximum_manifests: u16,
        maximum_fires_per_pass: u16,
    ) -> Result<Self, GithubScheduleServiceConfigurationError> {
        if poll_millis <= 0
            || discovery_claim_millis <= 0
            || discovery_claim_millis > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS
            || fire_claim_millis <= 0
            || fire_claim_millis > MAX_GITHUB_SCHEDULE_CLAIM_MILLIS
            || retry_millis <= 0
            || retry_millis > MAX_GITHUB_SCHEDULE_RETRY_MILLIS
            || staleness_millis <= 0
            || staleness_millis > MAX_STALENESS_MILLIS
            || maximum_manifests == 0
            || maximum_fires_per_pass == 0
            || maximum_fires_per_pass > MAX_FIRES_PER_PASS
        {
            return Err(GithubScheduleServiceConfigurationError);
        }
        Ok(Self {
            poll_millis,
            discovery_claim_millis,
            fire_claim_millis,
            retry_millis,
            staleness_millis,
            maximum_manifests,
            maximum_fires_per_pass,
        })
    }

    /// Returns the idle period between bounded scheduler passes.
    #[must_use]
    pub const fn poll_millis(self) -> i64 {
        self.poll_millis
    }
    /// Returns the discovery lease requested for one manifest revision.
    #[must_use]
    pub const fn discovery_claim_millis(self) -> i64 {
        self.discovery_claim_millis
    }
    /// Returns the due-fire lease requested for one invocation.
    #[must_use]
    pub const fn fire_claim_millis(self) -> i64 {
        self.fire_claim_millis
    }
    /// Returns the durable retry delay for unavailable due-fire work.
    #[must_use]
    pub const fn retry_millis(self) -> i64 {
        self.retry_millis
    }
    /// Returns the maximum retained catch-up lateness.
    #[must_use]
    pub const fn staleness_millis(self) -> i64 {
        self.staleness_millis
    }
    /// Returns the bounded manifest scan count.
    #[must_use]
    pub const fn maximum_manifests(self) -> u16 {
        self.maximum_manifests
    }
    /// Returns the bounded due-fire count per pass.
    #[must_use]
    pub const fn maximum_fires_per_pass(self) -> u16 {
        self.maximum_fires_per_pass
    }
}

impl Default for GithubScheduleServiceConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_POLL_MILLIS,
            DEFAULT_DISCOVERY_CLAIM_MILLIS,
            DEFAULT_FIRE_CLAIM_MILLIS,
            DEFAULT_RETRY_MILLIS,
            DEFAULT_STALENESS_MILLIS,
            DEFAULT_MAX_MANIFESTS,
            DEFAULT_MAX_FIRES,
        )
        .expect("fixed schedule service configuration is valid")
    }
}

/// Invalid GitHub scheduler service configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub schedule service configuration is invalid")]
pub struct GithubScheduleServiceConfigurationError;

/// Borrowed exact private-source authority for one discovery claim.
pub struct GithubScheduleSourceCredentialRequest<'a> {
    claim: GithubScheduleDiscoveryClaim,
    manifest: &'a GithubProviderManifest,
    authority_selector: &'a GithubServerServiceAuthoritySelector,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

impl<'a> GithubScheduleSourceCredentialRequest<'a> {
    /// Creates a private source credential request for a live discovery claim.
    ///
    /// # Errors
    ///
    /// Rejects a non-private, stale, cross-tenant, or overflowing request.
    pub fn new(
        claim: GithubScheduleDiscoveryClaim,
        manifest: &'a GithubProviderManifest,
        authority_selector: &'a GithubServerServiceAuthoritySelector,
        observed_at: UnixMillis,
    ) -> Result<Self, GithubScheduleSourceCredentialValueError> {
        let required_through = claim
            .expires_at()
            .get()
            .checked_add(MAX_PROVIDER_REQUEST_MILLIS)
            .map(UnixMillis::new)
            .ok_or(GithubScheduleSourceCredentialValueError)?;
        if manifest.repository_visibility() != ProviderRepositoryVisibility::Private
            || manifest.github_repository_owner_id().is_none()
            || authority_selector.tenant() != manifest.tenant()
            || observed_at < claim.claimed_at()
            || observed_at >= claim.expires_at()
            || required_through <= observed_at
        {
            return Err(GithubScheduleSourceCredentialValueError);
        }
        Ok(Self {
            claim,
            manifest,
            authority_selector,
            observed_at,
            required_through,
        })
    }

    /// Returns the live discovery fence.
    #[must_use]
    pub const fn claim(&self) -> GithubScheduleDiscoveryClaim {
        self.claim
    }
    /// Returns the immutable manifest being resolved.
    #[must_use]
    pub const fn manifest(&self) -> &GithubProviderManifest {
        self.manifest
    }
    /// Returns the exact least-authority selector.
    #[must_use]
    pub const fn authority_selector(&self) -> &GithubServerServiceAuthoritySelector {
        self.authority_selector
    }
    /// Returns the trusted credential acquisition observation.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.observed_at
    }
    /// Returns the conservative requested credential horizon.
    #[must_use]
    pub const fn required_through(&self) -> UnixMillis {
        self.required_through
    }

    /// Derives the disjoint server-service consumer claim for schedule discovery.
    ///
    /// # Errors
    ///
    /// Returns an error only if independently validated schedule identities no
    /// longer fit the adjacent server-service identity domain.
    pub fn consumer_claim(
        &self,
    ) -> Result<GithubServerServiceConsumerClaim, GithubScheduleSourceCredentialValueError> {
        Ok(GithubServerServiceConsumerClaim::new(
            GithubServerServiceConsumerId::from_uuid(self.claim.registry_id().as_uuid())
                .map_err(|_| GithubScheduleSourceCredentialValueError)?,
            GithubServerServiceWorkerId::from_uuid(self.claim.worker_id().as_uuid())
                .map_err(|_| GithubScheduleSourceCredentialValueError)?,
            GithubServerServiceClaimFence::new(self.claim.fence().get())
                .map_err(|_| GithubScheduleSourceCredentialValueError)?,
            GithubServerServiceAction::DiscoverPrivateRepositorySchedules,
            GithubServerServiceRevision::new(self.manifest.revision().get())
                .map_err(|_| GithubScheduleSourceCredentialValueError)?,
        ))
    }
}

impl fmt::Debug for GithubScheduleSourceCredentialRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubScheduleSourceCredentialRequest")
            .field("claim", &self.claim)
            .field("manifest", &"[exact manifest]")
            .field("authority_selector", &"[exact selector]")
            .field("observed_at", &self.observed_at)
            .field("required_through", &self.required_through)
            .finish()
    }
}

/// Move-only exact private repository source credential for schedule discovery.
#[must_use = "the credential must be released after its one source operation"]
pub struct GithubScheduleSourceCredential {
    tenant: automata_ci_store::TenantScope,
    connection_id: ProviderConnectionId,
    repository_id: automata_ci_store::ProviderRepositoryId,
    repository: ScmRepositoryId,
    authority_selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    required_through: UnixMillis,
    token: SecretString,
    release: Box<dyn GithubServerServiceCredentialRelease>,
}

impl GithubScheduleSourceCredential {
    /// Creates one exact, release-bound schedule source handoff.
    ///
    /// # Errors
    ///
    /// Rejects a cross-repository, wrong-action, or invalid-horizon handoff.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &GithubScheduleSourceCredentialRequest<'_>,
        repository: ScmRepositoryId,
        authority_selector: GithubServerServiceAuthoritySelector,
        consumer: GithubServerServiceConsumerClaim,
        token: SecretString,
        release: Box<dyn GithubServerServiceCredentialRelease>,
    ) -> Result<Self, GithubScheduleSourceCredentialValueError> {
        let manifest = request.manifest();
        if repository.as_str() != manifest.github_repository_name().as_str()
            || authority_selector != *request.authority_selector()
            || consumer != request.consumer_claim()?
            || consumer.action() != GithubServerServiceAction::DiscoverPrivateRepositorySchedules
            || request.required_through() < request.observed_at()
        {
            return Err(GithubScheduleSourceCredentialValueError);
        }
        Ok(Self {
            tenant: manifest.tenant().clone(),
            connection_id: manifest.connection_id(),
            repository_id: manifest.github_repository_id(),
            repository,
            authority_selector,
            consumer,
            required_through: request.required_through(),
            token,
            release,
        })
    }

    /// Reports whether this handoff is exact for one currently live request.
    #[must_use]
    pub fn matches(&self, request: &GithubScheduleSourceCredentialRequest<'_>) -> bool {
        self.tenant == *request.manifest().tenant()
            && self.connection_id == request.manifest().connection_id()
            && self.repository_id == request.manifest().github_repository_id()
            && self.repository.as_str() == request.manifest().github_repository_name().as_str()
            && self.authority_selector == *request.authority_selector()
            && request
                .consumer_claim()
                .is_ok_and(|consumer| consumer == self.consumer)
            && self.required_through == request.required_through()
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

impl fmt::Debug for GithubScheduleSourceCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubScheduleSourceCredential")
            .field("tenant", &"[bound]")
            .field("connection_id", &self.connection_id)
            .field("repository_id", &self.repository_id)
            .field("repository", &"[bound]")
            .field("authority_selector", &"[bound]")
            .field("consumer", &self.consumer)
            .field("required_through", &self.required_through)
            .field("token", &"[redacted]")
            .field("release", &"[credential release]")
            .finish()
    }
}

/// Invalid schedule source-credential binding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GitHub schedule source credential binding is invalid")]
pub struct GithubScheduleSourceCredentialValueError;

/// Sanitized result from product-owned private schedule source authority.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GithubScheduleSourceCredentialProviderError {
    /// Current authority is temporarily unavailable.
    #[error("GitHub schedule source credential authority is unavailable")]
    Unavailable,
    /// The exact current authority rejected the discovery claim.
    #[error("GitHub schedule source credential authority rejected the request")]
    Rejected,
    /// The authority could not establish a coherent exact handoff.
    #[error("GitHub schedule source credential authority is inconsistent")]
    InvariantViolation,
}

/// Least-authority source credential provider for private schedule discovery.
#[async_trait]
pub trait GithubScheduleSourceCredentialProvider: fmt::Debug + Send + Sync {
    /// Acquires one move-only `contents:read` handoff for the exact discovery claim.
    async fn acquire(
        &self,
        request: GithubScheduleSourceCredentialRequest<'_>,
    ) -> Result<GithubScheduleSourceCredential, GithubScheduleSourceCredentialProviderError>;
}

/// Exact source selectors configured for private current manifests.
#[derive(Clone, Debug, Default)]
pub struct GithubSchedulePrivateSourceAuthorities {
    selectors: BTreeMap<ProviderConnectionId, GithubServerServiceAuthoritySelector>,
}

impl GithubSchedulePrivateSourceAuthorities {
    /// Creates an unambiguous private source selector map.
    ///
    /// # Errors
    ///
    /// Rejects duplicate connection identities.
    pub fn new(
        entries: impl IntoIterator<Item = (ProviderConnectionId, GithubServerServiceAuthoritySelector)>,
    ) -> Result<Self, GithubScheduleServiceConfigurationError> {
        let mut selectors = BTreeMap::new();
        for (connection, selector) in entries {
            if selectors.insert(connection, selector).is_some() {
                return Err(GithubScheduleServiceConfigurationError);
            }
        }
        Ok(Self { selectors })
    }

    fn selector(
        &self,
        connection: ProviderConnectionId,
    ) -> Option<&GithubServerServiceAuthoritySelector> {
        self.selectors.get(&connection)
    }
}

/// Outcome count from one bounded scheduler pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GithubScheduleServicePass {
    discovered: u16,
    due_fires: u16,
}

impl GithubScheduleServicePass {
    /// Returns manifests whose discovery claims reached registry registration.
    #[must_use]
    pub const fn discovered(self) -> u16 {
        self.discovered
    }
    /// Returns due fires claimed during this pass.
    #[must_use]
    pub const fn due_fires(self) -> u16 {
        self.due_fires
    }
}

/// Product-supervised durable schedule service.
pub struct GithubScheduleService {
    objects: Arc<dyn ImmutableBlobStore>,
    source: Arc<dyn ScmProvider>,
    manifests: Arc<dyn GithubProviderManifestRepository>,
    schedules: Arc<dyn GithubScheduleRepository>,
    admission: WorkflowAdmissionService,
    private_sources: GithubSchedulePrivateSourceAuthorities,
    credentials: Option<Arc<dyn GithubScheduleSourceCredentialProvider>>,
    clock: Arc<dyn GithubScheduleClock>,
    worker_id: GithubScheduleWorkerId,
    config: GithubScheduleServiceConfig,
}

impl GithubScheduleService {
    /// Creates a scheduler restricted to anonymous public repository discovery.
    ///
    /// A private manifest is never fetched by this constructor; it remains
    /// undiscovered until product composition provides its typed authority.
    ///
    /// # Errors
    ///
    /// Rejects an SCM provider that is not the GitHub provider.
    #[allow(clippy::too_many_arguments)]
    pub fn new_public_only<R>(
        objects: Arc<dyn ImmutableBlobStore>,
        source: Arc<dyn ScmProvider>,
        repository: Arc<R>,
        admission: WorkflowAdmissionService,
        clock: Arc<dyn GithubScheduleClock>,
        worker_id: GithubScheduleWorkerId,
        config: GithubScheduleServiceConfig,
    ) -> Result<Self, GithubScheduleServiceConfigurationError>
    where
        R: GithubProviderManifestRepository + GithubScheduleRepository + 'static,
    {
        Self::new_with_private_source_credentials(
            objects,
            source,
            repository,
            admission,
            GithubSchedulePrivateSourceAuthorities::default(),
            None,
            clock,
            worker_id,
            config,
        )
    }

    /// Creates a scheduler with explicit private `contents:read` discovery authority.
    ///
    /// # Errors
    ///
    /// Rejects an SCM provider that is not the GitHub provider.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_private_source_credentials<R>(
        objects: Arc<dyn ImmutableBlobStore>,
        source: Arc<dyn ScmProvider>,
        repository: Arc<R>,
        admission: WorkflowAdmissionService,
        private_sources: GithubSchedulePrivateSourceAuthorities,
        credentials: Option<Arc<dyn GithubScheduleSourceCredentialProvider>>,
        clock: Arc<dyn GithubScheduleClock>,
        worker_id: GithubScheduleWorkerId,
        config: GithubScheduleServiceConfig,
    ) -> Result<Self, GithubScheduleServiceConfigurationError>
    where
        R: GithubProviderManifestRepository + GithubScheduleRepository + 'static,
    {
        if source.provider_id().as_str() != GITHUB_PROVIDER {
            return Err(GithubScheduleServiceConfigurationError);
        }
        Ok(Self {
            objects,
            source,
            manifests: repository.clone(),
            schedules: repository,
            admission,
            private_sources,
            credentials,
            clock,
            worker_id,
            config,
        })
    }

    /// Runs bounded passes until local shutdown or a non-recoverable failure.
    ///
    /// Claims already started in a pass are never intentionally abandoned; a
    /// shutdown merely prevents the next pass from beginning. Explicit
    /// backend and source unavailability is retried after the bounded polling
    /// delay; invalid or contradictory evidence remains fatal.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository, source, blob, admission, or trusted-time
    /// failure from a scheduler pass.
    pub async fn run(
        self: Arc<Self>,
        shutdown: CancellationToken,
    ) -> Result<(), GithubScheduleServiceError> {
        let poll = Duration::from_millis(
            u64::try_from(self.config.poll_millis())
                .map_err(|_| GithubScheduleServiceError::Configuration)?,
        );
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }
            match Box::pin(self.run_once()).await {
                Ok(_) => {}
                Err(error) if retryable_schedule_error(&error) => {}
                Err(error) => return Err(error),
            }
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                () = sleep(poll) => {}
            }
        }
    }

    /// Performs one bounded manifest discovery scan and due-fire scan.
    ///
    /// # Errors
    ///
    /// Returns a sanitized repository, source, blob, admission, or trusted-time
    /// failure encountered during the pass.
    pub async fn run_once(&self) -> Result<GithubScheduleServicePass, GithubScheduleServiceError> {
        let mut pass = GithubScheduleServicePass::default();
        let manifests = self
            .manifests
            .list_current_github_provider_manifests(self.config.maximum_manifests())
            .await?;
        for record in manifests {
            if self.discover_manifest(record).await? {
                pass.discovered = pass.discovered.saturating_add(1);
            }
        }
        for _ in 0..self.config.maximum_fires_per_pass() {
            let Some(claimed) = self
                .schedules
                .claim_due_github_schedule_fire(
                    ClaimDueGithubScheduleFire::new(
                        self.worker_id,
                        self.config.fire_claim_millis(),
                    )
                    .map_err(|_| GithubScheduleServiceError::Configuration)?,
                )
                .await?
            else {
                break;
            };
            pass.due_fires = pass.due_fires.saturating_add(1);
            Box::pin(self.process_due_fire(claimed)).await?;
        }
        Ok(pass)
    }

    async fn discover_manifest(
        &self,
        record: GithubProviderManifestRecord,
    ) -> Result<bool, GithubScheduleServiceError> {
        if !record.is_current() {
            return Ok(false);
        }
        let manifest = record.manifest().clone();
        let Some(owner) = manifest.github_repository_owner_id() else {
            return Ok(false);
        };
        let source_authority = match manifest.repository_visibility() {
            ProviderRepositoryVisibility::Public => GithubScheduleSourceAuthority::PublicAnonymous,
            ProviderRepositoryVisibility::Private => {
                let Some(selector) = self.private_sources.selector(manifest.connection_id()) else {
                    return Ok(false);
                };
                if self.credentials.is_none() {
                    return Ok(false);
                }
                GithubScheduleSourceAuthority::Private(selector.clone())
            }
        };
        let registry_id = GithubScheduleRegistryId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubScheduleServiceError::Configuration)?;
        let claim = match self
            .schedules
            .claim_github_schedule_discovery(
                ClaimGithubScheduleDiscovery::new(
                    registry_id,
                    manifest.clone(),
                    owner,
                    source_authority.clone(),
                    self.worker_id,
                    self.config.discovery_claim_millis(),
                )
                .map_err(|_| GithubScheduleServiceError::Configuration)?,
            )
            .await
        {
            Ok(claim) => claim,
            Err(GithubScheduleStoreError::Conflict | GithubScheduleStoreError::ClaimRejected) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let discovered = match self
            .fetch_and_store_discovery_archive(&manifest, claim, &source_authority)
            .await
        {
            Ok(archive) => archive,
            Err(
                GithubScheduleServiceError::SourceUnavailable
                | GithubScheduleServiceError::SourceRejected
                | GithubScheduleServiceError::PrivateSourceUnavailable
                | GithubScheduleServiceError::PrivateSourceRejected,
            ) => return Ok(false),
            Err(error) => return Err(error),
        };
        let Ok(entries) = registry_entries(
            &manifest,
            claim,
            &discovered.revision,
            &discovered.bytes,
            discovered.digest,
        ) else {
            return Ok(false);
        };
        let archive =
            GithubScheduleArchive::new(discovered.digest, discovered.object_key, discovered.size)
                .map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        match self
            .schedules
            .register_github_schedule_registry(
                RegisterGithubScheduleRegistry::new(
                    claim,
                    manifest,
                    source_authority,
                    discovered.revision,
                    archive,
                    entries,
                )
                .map_err(|_| GithubScheduleServiceError::InvalidRegistry)?,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(GithubScheduleStoreError::Conflict | GithubScheduleStoreError::ClaimRejected) => {
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn fetch_and_store_discovery_archive(
        &self,
        manifest: &GithubProviderManifest,
        claim: GithubScheduleDiscoveryClaim,
        authority: &GithubScheduleSourceAuthority,
    ) -> Result<DiscoveryArchive, GithubScheduleServiceError> {
        let repository = ScmRepositoryId::new(manifest.github_repository_name().as_str())
            .map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        let revision = RevisionSpec::new(manifest.git_ref())
            .map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        let limits = ArchiveLimits::new(manifest.limits().archive_max_compressed_bytes())
            .map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        let snapshot = match authority {
            GithubScheduleSourceAuthority::PublicAnonymous => {
                self.fetch_snapshot(SnapshotRequest::public(&repository, &revision, limits))
                    .await?
            }
            GithubScheduleSourceAuthority::Private(selector) => {
                let credentials = self
                    .credentials
                    .as_ref()
                    .ok_or(GithubScheduleServiceError::PrivateSourceRejected)?;
                let observed_at = self.clock.now()?;
                let request = GithubScheduleSourceCredentialRequest::new(
                    claim,
                    manifest,
                    selector,
                    observed_at,
                )
                .map_err(|_| GithubScheduleServiceError::PrivateSourceRejected)?;
                let credential = credentials
                    .acquire(request)
                    .await
                    .map_err(map_private_credential_error)?;
                let request = GithubScheduleSourceCredentialRequest::new(
                    claim,
                    manifest,
                    selector,
                    observed_at,
                )
                .map_err(|_| GithubScheduleServiceError::PrivateSourceRejected)?;
                if !credential.matches(&request) {
                    credential.release().await;
                    return Err(GithubScheduleServiceError::PrivateSourceRejected);
                }
                let result = self
                    .fetch_snapshot(SnapshotRequest::authenticated(
                        &repository,
                        &revision,
                        credential.token(),
                        limits,
                    ))
                    .await;
                credential.release().await;
                result?
            }
        };
        if snapshot.provider().as_str() != GITHUB_PROVIDER
            || snapshot.repository() != &repository
            || snapshot.requested_revision() != &revision
            || snapshot.format() != ArchiveFormat::TarGzip
            || snapshot.size() > limits.maximum_bytes()
        {
            return Err(GithubScheduleServiceError::SourceRejected);
        }
        let revision = snapshot.resolved_revision().as_str().to_owned();
        if automata_ci_scm::ExactRevision::new(revision.clone()).is_err() {
            return Err(GithubScheduleServiceError::SourceRejected);
        }
        let bytes = snapshot.into_bytes();
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let key_text = format!("{ARCHIVE_KEY_PREFIX}/{digest}.tar.gz");
        let blob_key = BlobKey::new(key_text.clone())
            .map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        let media_type = MediaType::new(GITHUB_SCHEDULE_ARCHIVE_MEDIA_TYPE)
            .map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        let payload =
            automata_ci_blob::BlobPayload::from_bytes(blob_key, media_type, bytes.clone());
        if payload.descriptor().digest() != digest {
            return Err(GithubScheduleServiceError::InvalidArchive);
        }
        self.objects
            .put_if_absent(payload)
            .await
            .map_err(GithubScheduleServiceError::Blob)?;
        let size =
            u64::try_from(bytes.len()).map_err(|_| GithubScheduleServiceError::InvalidArchive)?;
        Ok(DiscoveryArchive {
            revision,
            digest,
            object_key: ObjectKey::new(key_text)
                .map_err(|_| GithubScheduleServiceError::InvalidArchive)?,
            size,
            bytes,
        })
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<automata_ci_scm::RepositorySnapshot, GithubScheduleServiceError> {
        timeout(
            Duration::from_millis(
                u64::try_from(MAX_PROVIDER_REQUEST_MILLIS)
                    .expect("fixed positive provider timeout"),
            ),
            self.source.fetch_snapshot(request),
        )
        .await
        .map_err(|_| GithubScheduleServiceError::SourceUnavailable)?
        .map_err(map_source_error)
    }

    async fn process_due_fire(
        &self,
        claimed: ClaimedGithubScheduleFire,
    ) -> Result<(), GithubScheduleServiceError> {
        let claim = claimed.claim();
        let now = self.clock.now()?;
        let Ok(cron) =
            automata_ci_schedule::CronExpression::parse(claimed.entry().cron_expression())
        else {
            return self.complete_invalid_registry(claim).await;
        };
        let lateness = now.get().saturating_sub(claimed.scheduled_at().get());
        if lateness > self.config.staleness_millis() {
            let next = cron
                .next_after(now, claimed.entry().timezone())
                .map_err(|_| GithubScheduleServiceError::InvalidRegistry)?;
            return self
                .complete(
                    claim,
                    GithubScheduleFireConclusion::Skipped("github.schedule.stale".to_owned()),
                    next,
                )
                .await;
        }
        let check_claim = match self
            .schedules
            .register_github_scheduled_check_subject(RegisterGithubScheduledCheckSubject::new(
                claim,
            ))
            .await
        {
            Ok(_) => claim,
            Err(GithubScheduleStoreError::ClaimRejected | GithubScheduleStoreError::Conflict) => {
                return Ok(());
            }
            Err(error) => {
                return self
                    .retry_or_return(claim, "github.schedule.check_unavailable", error)
                    .await;
            }
        };
        let claim = match self
            .schedules
            .renew_github_schedule_fire(check_claim, self.config.fire_claim_millis())
            .await
        {
            Ok(claim) => claim,
            Err(GithubScheduleStoreError::ClaimRejected | GithubScheduleStoreError::Conflict) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let conclusion = match Box::pin(self.admit_claimed_fire(&claimed, claim)).await {
            Ok(run_id) => GithubScheduleFireConclusion::Admitted(run_id),
            Err(FireFailure::Skipped(kind)) => {
                GithubScheduleFireConclusion::Skipped(kind.to_owned())
            }
            Err(FireFailure::Failed(kind)) => GithubScheduleFireConclusion::Failed(kind.to_owned()),
            Err(FireFailure::InvalidRegistry) => {
                return self.complete_invalid_registry(claim).await;
            }
            Err(FireFailure::Retry(kind)) => return self.retry(claim, kind).await,
            Err(FireFailure::Lost) => return Ok(()),
        };
        let next = cron
            .next_after(claimed.scheduled_at(), claimed.entry().timezone())
            .map_err(|_| GithubScheduleServiceError::InvalidRegistry)?;
        self.complete(claim, conclusion, next).await
    }

    async fn admit_claimed_fire(
        &self,
        claimed: &ClaimedGithubScheduleFire,
        claim: GithubScheduleFireClaim,
    ) -> Result<automata_ci_core::RunId, FireFailure> {
        let (source, available, repository_owner_id) =
            self.load_claimed_workflow_sources(claimed).await?;
        let plan = compile_claimed_workflow(claimed, &source)?;
        let evidence =
            GithubScheduleEvidence::new(claimed.entry().cron_expression(), claimed.scheduled_at())
                .map_err(|_| FireFailure::InvalidRegistry)?;
        let event = Bytes::from(
            evidence
                .encode()
                .map_err(|_| FireFailure::InvalidRegistry)?,
        );
        let base_context = JobRuntimeContext::new_base(
            ContextValue::empty_object(),
            ContextValue::empty_object(),
            BTreeMap::new(),
        )
        .map_err(|_| FireFailure::InvalidRegistry)?;
        let coordinates = AdmissionRepositoryCoordinates::new(
            GITHUB_PROVIDER,
            claimed.provider_repository_id(),
            claimed.repository_owner(),
            claimed.repository_name(),
        )
        .map_err(|_| FireFailure::InvalidRegistry)?;
        let workflow_name = plan.name().map_or_else(
            || claimed.entry().workflow_path().to_owned(),
            |name| name.value().clone(),
        );
        let repository =
            TrustRepositoryEvidence::new(claimed.provider_repository_id(), repository_owner_id)
                .map_err(|_| FireFailure::InvalidRegistry)?;
        let actor = TrustActorEvidence::new(
            GITHUB_SCHEDULE_SERVICE_ACTOR,
            TrustActorKind::System,
            TrustAutomationKind::None,
        )
        .map_err(|_| FireFailure::InvalidRegistry)?;
        let trust_snapshot = TrustPolicy::current()
            .evaluate(
                TrustEvidence::new(TrustOriginKind::Schedule, TrustEventKind::Schedule)
                    .with_original_actor(actor.clone())
                    .with_triggering_actor(actor)
                    .with_repositories(repository.clone(), repository)
                    .with_refs(
                        claimed.default_branch_ref(),
                        claimed.default_branch_ref(),
                        claimed.default_branch_ref(),
                    )
                    .with_revisions(
                        claimed.source_revision(),
                        claimed.source_revision(),
                        claimed.source_revision(),
                    )
                    .with_fork(false)
                    .with_token_recursion(TrustTokenRecursion::External),
            )
            .map_err(|_| FireFailure::InvalidRegistry)?;
        let request = WorkflowAdmissionRequest::builder(
            claimed.tenant().clone(),
            coordinates,
            claimed.entry().workflow_path(),
            source,
            event,
            plan,
            base_context,
            WorkflowAdmissionIdempotency::operation(OperationId::from_uuid(
                claim.fire_id().as_uuid(),
            )),
        )
        .trust_snapshot(trust_snapshot)
        .event_media_type(AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE)
        .commit_sha(claimed.source_revision())
        .git_ref(claimed.default_branch_ref())
        .workflow_name(workflow_name)
        .actor(GITHUB_SCHEDULE_SERVICE_ACTOR)
        .run_attempt(u32::from(claim.attempt()))
        .repository_workflow_sources(available)
        .build()
        .map_err(map_admission_request_error)?;
        Box::pin(
            self.admission
                .admit_scheduled_github_workflow(request, claim),
        )
        .await
        .map(|result| result.receipt().run_id())
        .map_err(|error| map_admission_error(&error))
    }

    async fn load_claimed_workflow_sources(
        &self,
        claimed: &ClaimedGithubScheduleFire,
    ) -> Result<(Bytes, Vec<RepositoryWorkflowSource>, String), FireFailure> {
        let manifest = self
            .manifests
            .load_github_provider_manifest_revision(
                claimed.tenant(),
                claimed.connection_id(),
                claimed.manifest_revision(),
            )
            .await
            .map_err(|_| FireFailure::Lost)?;
        let manifest = manifest.manifest();
        let repository_owner_id = manifest
            .github_repository_owner_id()
            .ok_or(FireFailure::Lost)?
            .get()
            .to_string();
        if manifest.digest() != claimed.manifest_digest()
            || manifest.repository_id() != claimed.repository_id()
            || manifest.git_ref() != claimed.default_branch_ref()
            || !manifest.selects_workflow_path(claimed.entry().workflow_path())
        {
            return Err(FireFailure::Lost);
        }
        let descriptor =
            archive_descriptor(claimed.archive()).map_err(|()| FireFailure::InvalidRegistry)?;
        let archive = self
            .objects
            .get_verified(&descriptor, claimed.archive().encoded_size())
            .await
            .map_err(|error| match error.kind() {
                automata_ci_blob::BlobStoreErrorKind::Unavailable
                | automata_ci_blob::BlobStoreErrorKind::Unauthorized => {
                    FireFailure::Retry("github.schedule.archive_unavailable")
                }
                _ => FireFailure::InvalidRegistry,
            })?
            .into_bytes();
        let workflows = discover_repository_workflows(
            &archive,
            discovery_limits(manifest).map_err(|()| FireFailure::InvalidRegistry)?,
            RepositoryWorkflowDiscoveryPolicy::GithubDelivery,
        )
        .map_err(|_| FireFailure::InvalidRegistry)?;
        let mut available = Vec::new();
        let mut selected = None;
        for workflow in workflows {
            let (path, source) = workflow.into_parts();
            let Ok(source) = source else {
                continue;
            };
            let bytes = Bytes::from(source);
            if path == claimed.entry().workflow_path() {
                selected = Some(bytes.clone());
            }
            available.push(RepositoryWorkflowSource::new(path, bytes));
        }
        let source = selected.ok_or(FireFailure::InvalidRegistry)?;
        if Sha256Digest::from_bytes(Sha256::digest(&source).into())
            != claimed.entry().workflow_source_digest()
        {
            return Err(FireFailure::InvalidRegistry);
        }
        Ok((source, available, repository_owner_id))
    }

    async fn complete_invalid_registry(
        &self,
        claim: GithubScheduleFireClaim,
    ) -> Result<(), GithubScheduleServiceError> {
        match self
            .schedules
            .complete_github_schedule_fire(CompleteGithubScheduleFire::invalid_registry(claim))
            .await
        {
            Ok(_)
            | Err(GithubScheduleStoreError::ClaimRejected | GithubScheduleStoreError::Conflict) => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn complete(
        &self,
        claim: GithubScheduleFireClaim,
        conclusion: GithubScheduleFireConclusion,
        next: UnixMillis,
    ) -> Result<(), GithubScheduleServiceError> {
        let request = CompleteGithubScheduleFire::new(claim, conclusion, next)
            .map_err(|_| GithubScheduleServiceError::InvalidRegistry)?;
        match self.schedules.complete_github_schedule_fire(request).await {
            Ok(_)
            | Err(GithubScheduleStoreError::ClaimRejected | GithubScheduleStoreError::Conflict) => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn retry(
        &self,
        claim: GithubScheduleFireClaim,
        kind: &'static str,
    ) -> Result<(), GithubScheduleServiceError> {
        let request = RetryGithubScheduleFire::new(claim, self.config.retry_millis(), kind)
            .map_err(|_| GithubScheduleServiceError::Configuration)?;
        match self.schedules.retry_github_schedule_fire(request).await {
            Ok(_)
            | Err(GithubScheduleStoreError::ClaimRejected | GithubScheduleStoreError::Conflict) => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn retry_or_return(
        &self,
        claim: GithubScheduleFireClaim,
        kind: &'static str,
        error: GithubScheduleStoreError,
    ) -> Result<(), GithubScheduleServiceError> {
        match error {
            GithubScheduleStoreError::Store(_) => self.retry(claim, kind).await,
            error => Err(error.into()),
        }
    }
}

fn compile_claimed_workflow(
    claimed: &ClaimedGithubScheduleFire,
    source: &Bytes,
) -> Result<WorkflowPlan, FireFailure> {
    let source_text = std::str::from_utf8(source)
        .map_err(|_| FireFailure::Failed("github.schedule.workflow_invalid_encoding"))?;
    let provenance = SourceProvenance::new(
        SourceId::new(claimed.entry().workflow_path()),
        SourceOrigin::Repository {
            repository: Arc::from(format!(
                "{}/{}",
                claimed.repository_owner(),
                claimed.repository_name()
            )),
            revision: Arc::from(claimed.source_revision()),
            path: Arc::from(claimed.entry().workflow_path()),
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source_text));
    if !parsed.is_accepted() {
        return Err(FireFailure::Failed(
            "github.schedule.workflow_frontend_rejected",
        ));
    }
    let Some(source_plan) = parsed.plan() else {
        return Err(FireFailure::InvalidRegistry);
    };
    let event = WorkflowEventProvenance::new(GITHUB_PROVIDER, "schedule")
        .with_commit_sha(claimed.source_revision())
        .with_git_ref(claimed.default_branch_ref());
    let report = GithubWorkflowCompiler::new().compile(
        CompileWorkflowRequest::new(source_plan, event).with_event_metadata(
            GithubEventMetadata::schedule(claimed.entry().cron_expression()),
        ),
    );
    match report.disposition() {
        CompilationDisposition::Accepted => {
            report.into_parts().0.ok_or(FireFailure::InvalidRegistry)
        }
        CompilationDisposition::NotSelected(_) => Err(FireFailure::Skipped(
            "github.schedule.workflow_not_selected",
        )),
        CompilationDisposition::Rejected => Err(FireFailure::Failed(
            "github.schedule.workflow_compilation_rejected",
        )),
        CompilationDisposition::RequiresChangedFiles => Err(FireFailure::Failed(
            "github.schedule.workflow_invalid_selection",
        )),
        _ => Err(FireFailure::Failed("github.schedule.workflow_unsupported")),
    }
}

impl fmt::Debug for GithubScheduleService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubScheduleService")
            .field("objects", &self.objects)
            .field("source", &self.source)
            .field("manifests", &"[provider manifest repository]")
            .field("schedules", &"[schedule repository]")
            .field("admission", &"[workflow admission service]")
            .field(
                "private_source_count",
                &self.private_sources.selectors.len(),
            )
            .field(
                "private_credentials",
                &self.credentials.as_ref().map(|_| "[configured]"),
            )
            .field("clock", &"[trusted clock]")
            .field("worker_id", &self.worker_id)
            .field("config", &self.config)
            .finish()
    }
}

struct DiscoveryArchive {
    revision: String,
    digest: Sha256Digest,
    object_key: ObjectKey,
    size: u64,
    bytes: Bytes,
}

#[derive(Clone, Copy)]
enum FireFailure {
    Skipped(&'static str),
    Failed(&'static str),
    Retry(&'static str),
    InvalidRegistry,
    Lost,
}

/// Sanitized scheduler failure.
#[derive(Debug, Error)]
pub enum GithubScheduleServiceError {
    /// Scheduler configuration or a fixed invariant was invalid.
    #[error("GitHub schedule service configuration is invalid")]
    Configuration,
    /// The product clock was unavailable, negative, or not representable.
    #[error("GitHub schedule service clock returned an invalid time")]
    InvalidTrustedTime,
    /// Immutable archive metadata was invalid.
    #[error("GitHub schedule archive evidence is invalid")]
    InvalidArchive,
    /// Immutable registry construction was invalid.
    #[error("GitHub schedule registry evidence is invalid")]
    InvalidRegistry,
    /// Anonymous source access is temporarily unavailable.
    #[error("GitHub schedule source is temporarily unavailable")]
    SourceUnavailable,
    /// Anonymous source response could not be proven exact.
    #[error("GitHub schedule source evidence is invalid")]
    SourceRejected,
    /// Private schedule source authority is temporarily unavailable.
    #[error("GitHub private schedule source authority is unavailable")]
    PrivateSourceUnavailable,
    /// Private schedule source authority rejected exact current evidence.
    #[error("GitHub private schedule source authority rejected the request")]
    PrivateSourceRejected,
    /// Immutable blob storage failed.
    #[error(transparent)]
    Blob(#[from] BlobStoreError),
    /// Manifest read boundary failed.
    #[error(transparent)]
    Manifest(#[from] GithubProviderManifestStoreError),
    /// Durable schedule boundary failed.
    #[error(transparent)]
    Store(#[from] GithubScheduleStoreError),
}

fn retryable_schedule_error(error: &GithubScheduleServiceError) -> bool {
    match error {
        GithubScheduleServiceError::SourceUnavailable
        | GithubScheduleServiceError::PrivateSourceUnavailable
        | GithubScheduleServiceError::Manifest(GithubProviderManifestStoreError::Operation(_))
        | GithubScheduleServiceError::Store(GithubScheduleStoreError::Store(_)) => true,
        GithubScheduleServiceError::Blob(error) => error.kind() == BlobStoreErrorKind::Unavailable,
        GithubScheduleServiceError::Configuration
        | GithubScheduleServiceError::InvalidTrustedTime
        | GithubScheduleServiceError::InvalidArchive
        | GithubScheduleServiceError::InvalidRegistry
        | GithubScheduleServiceError::SourceRejected
        | GithubScheduleServiceError::PrivateSourceRejected
        | GithubScheduleServiceError::Manifest(_)
        | GithubScheduleServiceError::Store(_) => false,
    }
}

fn registry_entries(
    manifest: &GithubProviderManifest,
    claim: GithubScheduleDiscoveryClaim,
    revision: &str,
    archive: &[u8],
    _archive_digest: Sha256Digest,
) -> Result<Vec<GithubScheduleRegistryEntry>, ()> {
    let workflows = discover_repository_workflows(
        archive,
        discovery_limits(manifest)?,
        RepositoryWorkflowDiscoveryPolicy::GithubDelivery,
    )
    .map_err(|_| ())?;
    let mut definitions = Vec::new();
    for workflow in workflows {
        let (path, source) = workflow.into_parts();
        if !manifest.selects_workflow_path(&path) {
            continue;
        }
        let source = source.map_err(|_| ())?;
        let source_text = std::str::from_utf8(&source).map_err(|_| ())?;
        let provenance = SourceProvenance::new(
            SourceId::new(path.clone()),
            SourceOrigin::Repository {
                repository: Arc::from(manifest.github_repository_name().as_str()),
                revision: Arc::from(revision),
                path: Arc::from(path.clone()),
            },
        );
        let parsed = GithubWorkflowFrontend::default()
            .parse(ParseWorkflowRequest::new(provenance, source_text));
        if !parsed.is_accepted() {
            return Err(());
        }
        let plan = parsed.plan().ok_or(())?;
        let schedules = extract_github_schedule_entries(plan).map_err(|_| ())?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&source).into());
        for schedule in schedules {
            definitions.push((path.clone(), digest, schedule));
        }
    }
    definitions.sort_by(|left, right| {
        (left.0.as_str(), left.2.ordinal()).cmp(&(right.0.as_str(), right.2.ordinal()))
    });
    definitions
        .into_iter()
        .enumerate()
        .map(|(ordinal, (path, digest, schedule))| {
            let next = schedule
                .expression()
                .next_after(claim.claimed_at(), schedule.timezone())
                .map_err(|_| ())?;
            GithubScheduleRegistryEntry::new(
                u16::try_from(ordinal).map_err(|_| ())?,
                automata_ci_store::GithubCheckSubjectKey::new(path).map_err(|_| ())?,
                digest,
                schedule.ordinal(),
                schedule.expression().exact(),
                schedule.timezone(),
                next,
            )
            .map_err(|_| ())
        })
        .collect()
}

fn discovery_limits(
    manifest: &GithubProviderManifest,
) -> Result<RepositoryWorkflowDiscoveryLimits, ()> {
    let limits = manifest.limits();
    RepositoryWorkflowDiscoveryLimits::new(
        limits.archive_max_compressed_bytes(),
        limits.archive_max_decompressed_bytes(),
        usize::try_from(limits.archive_max_entries()).map_err(|_| ())?,
        limits.archive_max_expanded_bytes(),
        usize::try_from(limits.archive_max_entry_path_bytes()).map_err(|_| ())?,
        usize::try_from(limits.archive_max_workflows()).map_err(|_| ())?,
        limits.workflow_max_bytes(),
    )
    .map_err(|_| ())
}

fn archive_descriptor(archive: &GithubScheduleArchive) -> Result<BlobDescriptor, ()> {
    Ok(BlobDescriptor::new(
        BlobKey::new(archive.object_key().as_str()).map_err(|_| ())?,
        archive.digest(),
        archive.encoded_size(),
        MediaType::new(archive.media_type()).map_err(|_| ())?,
    ))
}

const fn map_private_credential_error(
    error: GithubScheduleSourceCredentialProviderError,
) -> GithubScheduleServiceError {
    match error {
        GithubScheduleSourceCredentialProviderError::Unavailable => {
            GithubScheduleServiceError::PrivateSourceUnavailable
        }
        GithubScheduleSourceCredentialProviderError::Rejected
        | GithubScheduleSourceCredentialProviderError::InvariantViolation => {
            GithubScheduleServiceError::PrivateSourceRejected
        }
    }
}

const fn map_source_error(error: ScmError) -> GithubScheduleServiceError {
    match error.kind() {
        ScmErrorKind::Unauthorized
        | ScmErrorKind::Forbidden
        | ScmErrorKind::RateLimited
        | ScmErrorKind::Unavailable => GithubScheduleServiceError::SourceUnavailable,
        ScmErrorKind::NotFound
        | ScmErrorKind::TooLarge
        | ScmErrorKind::InvalidResponse
        | ScmErrorKind::Integrity => GithubScheduleServiceError::SourceRejected,
    }
}

const fn map_admission_request_error(error: WorkflowAdmissionRequestError) -> FireFailure {
    match error {
        WorkflowAdmissionRequestError::InvalidPlan
        | WorkflowAdmissionRequestError::ProvenanceMismatch
        | WorkflowAdmissionRequestError::DeliveryMismatch => FireFailure::InvalidRegistry,
        _ => FireFailure::Failed("github.schedule.admission_request_rejected"),
    }
}

fn map_admission_error(error: &WorkflowAdmissionError) -> FireFailure {
    match error {
        WorkflowAdmissionError::Store(
            automata_ci_store::LogicalWorkflowAdmissionStoreError::WorkflowDisabled,
        ) => FireFailure::Skipped("github.workflow.disabled"),
        WorkflowAdmissionError::Store(
            automata_ci_store::LogicalWorkflowAdmissionStoreError::RunNumberExhausted,
        ) => FireFailure::Failed("github.schedule.run_number_exhausted"),
        WorkflowAdmissionError::Blob(_) | WorkflowAdmissionError::Store(_) => {
            FireFailure::Retry("github.schedule.admission_unavailable")
        }
        _ => FireFailure::Failed("github.schedule.admission_rejected"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_policy_has_deterministic_defaults_and_rejects_open_catch_up() {
        let policy = GithubScheduleServiceConfig::default();
        assert_eq!(policy.poll_millis(), DEFAULT_POLL_MILLIS);
        assert_eq!(policy.staleness_millis(), DEFAULT_STALENESS_MILLIS);
        assert_eq!(policy.maximum_manifests(), DEFAULT_MAX_MANIFESTS);
        assert_eq!(policy.maximum_fires_per_pass(), DEFAULT_MAX_FIRES);
        assert_eq!(
            GithubScheduleServiceConfig::new(1, 1, 1, 1, MAX_STALENESS_MILLIS + 1, 1, 1,),
            Err(GithubScheduleServiceConfigurationError)
        );
        assert_eq!(
            GithubScheduleServiceConfig::new(1, 1, 1, 1, 1, 1, MAX_FIRES_PER_PASS + 1),
            Err(GithubScheduleServiceConfigurationError)
        );
    }

    #[test]
    fn canonical_schedule_event_evidence_is_never_a_webhook_delivery() {
        let evidence = GithubScheduleEvidence::new("0/5 * * * *", UnixMillis::new(42_000))
            .expect("canonical schedule evidence");
        let encoded = evidence.encode().expect("canonical evidence encoding");
        let text = std::str::from_utf8(&encoded).expect("UTF-8 JSON evidence");
        assert!(text.contains("automata_github_schedule"));
        assert!(!text.contains("delivery"));
        assert_eq!(
            AUTOMATA_GITHUB_SCHEDULE_EVIDENCE_V1_MEDIA_TYPE,
            "application/vnd.automata.github-schedule-evidence.v1+json"
        );
    }

    #[test]
    fn disabled_workflow_is_a_terminal_schedule_skip() {
        let error = WorkflowAdmissionError::Store(
            automata_ci_store::LogicalWorkflowAdmissionStoreError::WorkflowDisabled,
        );
        assert!(matches!(
            map_admission_error(&error),
            FireFailure::Skipped("github.workflow.disabled")
        ));
    }

    #[test]
    fn scheduler_retries_only_explicit_transient_boundaries() {
        let retryable = [
            GithubScheduleServiceError::SourceUnavailable,
            GithubScheduleServiceError::PrivateSourceUnavailable,
            GithubScheduleServiceError::Blob(BlobStoreError::new(BlobStoreErrorKind::Unavailable)),
            GithubScheduleServiceError::Manifest(GithubProviderManifestStoreError::operation(
                std::io::Error::other("temporary manifest backend failure"),
            )),
            GithubScheduleServiceError::Store(GithubScheduleStoreError::Store(
                automata_ci_store::StoreError::Operation(
                    automata_ci_store::RepositoryOperationError::from_source(
                        std::io::Error::other("temporary schedule backend failure"),
                    ),
                ),
            )),
        ];
        for error in &retryable {
            assert!(
                retryable_schedule_error(error),
                "expected retryable error: {error}"
            );
        }

        let fatal = [
            GithubScheduleServiceError::Configuration,
            GithubScheduleServiceError::InvalidTrustedTime,
            GithubScheduleServiceError::InvalidArchive,
            GithubScheduleServiceError::InvalidRegistry,
            GithubScheduleServiceError::SourceRejected,
            GithubScheduleServiceError::PrivateSourceRejected,
            GithubScheduleServiceError::Blob(BlobStoreError::new(BlobStoreErrorKind::Unauthorized)),
            GithubScheduleServiceError::Blob(BlobStoreError::new(BlobStoreErrorKind::Integrity)),
            GithubScheduleServiceError::Manifest(GithubProviderManifestStoreError::CorruptData),
            GithubScheduleServiceError::Store(GithubScheduleStoreError::Conflict),
        ];
        for error in &fatal {
            assert!(
                !retryable_schedule_error(error),
                "expected fatal error: {error}"
            );
        }
    }
}
