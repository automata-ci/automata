//! Production runtime for one exact GitHub provider registry.
//!
//! Construction converges immutable provider manifests and server-service
//! authorities before it transfers the webhook connection registry into live
//! ingress. The runtime then owns delivery, Checks, credential maintenance,
//! and exact handoff-release supervision as one shutdown unit.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::ImmutableBlobStore;
use automata_ci_control::runner_control::{
    ImmutableBlobJobIrReader, JobIrObjectReader, OptionalRuntimeAuthorityIssuer,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_credential_github::{
    GithubAppCredentialBroker, GithubAppCredentialConfig, GithubAppHttpLimits, GithubAppIssuer,
    GithubInstallationId, GithubRepositoryRuntimeAuthorityIssuer,
    GithubRuntimeAuthorityCommitSupervisor, GithubRuntimeAuthorityCoordinatorClock,
    GithubRuntimeAuthorityLifecycleBroker, GithubRuntimeAuthorityLifecycleBrokerRouter,
    GithubRuntimeAuthorityLifecycleCoordinator, GithubRuntimeAuthorityLifecycleError,
    GithubRuntimeAuthorityLifecycleSupervisor, GithubRuntimeAuthorityMintBroker,
    GithubRuntimeAuthorityMintCoordinator, GithubRuntimeAuthorityRequestResolver,
    GithubRuntimeAuthorityRevocationOutcome, GithubServerServiceCoordinationOutcome,
    GithubServerServiceCoordinatorClock, GithubServerServiceCoordinatorError,
    GithubServerServiceCredentialBroker, GithubServerServiceCredentialCoordinator,
    GithubServerServiceCredentialIssuer, GithubServerServiceCredentialRepository,
    GithubServerServiceCredentialRequestResolver, GithubServerServiceInstallationRouter,
    PendingGithubServerServiceMintCommit, PendingGithubServerServiceRevocationCommit,
    PinnedGithubRuntimeAuthorityMintBroker,
};
use automata_ci_github::{GithubHttpEndpoint, GithubHttpLimits, GithubWebhookVerifier};
use automata_ci_github_delivery::{
    GithubChecksCredentialProvider, GithubChecksPublisher, GithubChecksPublisherConfig,
    GithubChecksPublisherError, GithubChecksPublisherOutcome, GithubDeliveryClock,
    GithubDeliveryConfigurationError, GithubDeliveryConnection, GithubDeliveryIngress,
    GithubDeliveryRepositories, GithubDeliveryService, GithubDeliveryServiceConfig,
    GithubDeliveryServiceError, GithubDeliverySourceCredentialProvider, GithubDeliveryWorkerConfig,
    GithubDeliveryWorkerConfigurationError, GithubDeliveryWorkflowAdmissionProcessor,
    GithubDeliveryWorkflowProcessor, GithubPushChangedFilesProvider,
    GithubRestPushChangedFilesProvider, GithubScheduleClock,
    GithubSchedulePrivateSourceAuthorities, GithubScheduleService,
    GithubScheduleServiceConfigurationError, GithubScheduleServiceError,
    GithubScheduleSourceCredentialProvider,
};
use automata_ci_key_management::{EnvelopeCodec, KeyEncryptionProvider};
use automata_ci_protocol::RuntimeAuthorityEndpoint;
use automata_ci_provider::ProviderConnectionId;
use automata_ci_scm::ScmProvider;
use automata_ci_store::{
    GITHUB_PROVIDER_WEB_ORIGIN, GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId,
    GithubCheckStoreError, GithubJobRuntimeAuthorityRepository,
    GithubRepositoryDispatchEvidenceRepository, GithubRuntimeAuthorityRepository,
    GithubRuntimeAuthorityWorkerId, GithubScheduleWorkerId, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityRepository,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceIssuanceState, GithubServerServiceJwtIssuer, GithubServerServiceScope,
    GithubServerServiceWorkerId, GithubSubjectEvidenceRepository,
    GithubWorkflowPermissionDefaultsObservation,
    GithubWorkflowPermissionDefaultsObservationRepository, LogicalWorkflowAdmissionRepository,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, ProviderDeliveryClaimOwnerId,
    ProviderRepositoryVisibility, RetireGithubServerServiceAuthority, TenantScope,
};
use automata_ci_store_postgres::PostgresStore;
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, WorkflowAdmissionObserver, WorkflowAdmissionService,
};
use futures::{StreamExt as _, stream::FuturesUnordered};
use thiserror::Error;
use tokio::{
    runtime::Handle,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    GithubProviderBootstrapError, GithubProviderBootstrapPlan, GithubProviderConfig,
    GithubProviderCredentialAdapterConfigurationError, GithubProviderCredentialAdapters,
    GithubProviderCredentialReleaseSupervisor, GithubProviderRepositoryConfig,
    GithubProviderTransport, GithubWorkflowPermissionObservationError,
    MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES,
    github_job_runtime_authority::{
        GithubJobRuntimeAuthorityIssuer, GithubJobRuntimeAuthorityResolver,
    },
};

const GITHUB_HTTP_USER_AGENT: &str = concat!("automata-ci/", env!("CARGO_PKG_VERSION"));
const DEFAULT_IDLE_DELAY: Duration = Duration::from_secs(1);
const DEFAULT_RELEASE_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_IDLE_DELAY: Duration = Duration::from_mins(1);
const MAX_DRAIN_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY: usize = 32;
const MAX_SUPERVISED_JOB_AUTHORITY_COMMITS: usize = 1_024;
const MAX_SUPERVISED_SERVICE_CREDENTIAL_COMMITS: usize =
    MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY;
const WORKFLOW_PERMISSION_CREDENTIAL_STARTUP_DEADLINE: Duration = Duration::from_mins(10);
const WORKFLOW_PERMISSION_CREDENTIAL_RETRY_DELAY: Duration = Duration::from_millis(100);
const WORKFLOW_PERMISSION_REFRESH_SAFETY_MARGIN_MILLIS: i64 = 60_000;
const WORKFLOW_PERMISSION_REFRESH_RETRY_MIN: Duration = Duration::from_mins(1);
const WORKFLOW_PERMISSION_REFRESH_RETRY_MAX: Duration = Duration::from_secs(7 * 60 + 30);
const WORKFLOW_PERMISSION_INITIAL_RETRY_JITTER_MARGIN_MILLIS: i64 = 60_000 + 60_000 / 4;

#[derive(Clone, Debug, Eq, PartialEq)]
struct JobAuthorityBrokerPin {
    github_app_id: GithubServerServiceAppId,
    github_app_client_id: GithubServerServiceAppClientId,
    github_app_jwt_issuer_kind: GithubServerServiceJwtIssuer,
    app_key_spki_sha256: Sha256Digest,
    configuration_fingerprint: Sha256Digest,
}

type JobAuthorityBrokerPins = BTreeMap<u64, JobAuthorityBrokerPin>;

fn job_authority_broker_pins(
    plan: &GithubProviderBootstrapPlan,
) -> Result<JobAuthorityBrokerPins, GithubProviderRuntimeBuildError> {
    let mut pins = BTreeMap::new();
    for authority in plan
        .authorities()
        .iter()
        .filter(|authority| authority.scope() == GithubServerServiceScope::ChecksWrite)
    {
        let installation_id = authority.installation_id().get();
        let exact = JobAuthorityBrokerPin {
            github_app_id: authority.github_app_id(),
            github_app_client_id: authority.app_client_id().clone(),
            github_app_jwt_issuer_kind: authority.jwt_issuer(),
            app_key_spki_sha256: authority.app_key_spki_sha256(),
            configuration_fingerprint: authority.configuration_fingerprint(),
        };
        if pins
            .insert(installation_id, exact.clone())
            .is_some_and(|prior| prior != exact)
        {
            return Err(GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority);
        }
    }
    if pins.is_empty() {
        return Err(GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority);
    }
    Ok(pins)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GithubProviderFatalNotification;

/// Whether delivery needs only anonymous Public source access or exact Private access too.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubProviderSourceMode {
    /// Every configured source repository is Public and fetched anonymously.
    PublicOnly,
    /// At least one source repository is Private; Public fetches remain anonymous.
    PublicAndPrivate,
}

/// Non-secret topology of one built GitHub provider runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubProviderRuntimeShape {
    repositories: usize,
    installations: usize,
    tenants: usize,
    source_mode: GithubProviderSourceMode,
}

impl GithubProviderRuntimeShape {
    fn from_config(config: &GithubProviderConfig) -> Self {
        let installations = config
            .repositories()
            .iter()
            .map(GithubProviderRepositoryConfig::installation_id)
            .collect::<BTreeSet<_>>()
            .len();
        let tenants = config
            .repositories()
            .iter()
            .map(|repository| repository.tenant().clone())
            .collect::<BTreeSet<_>>()
            .len();
        let source_mode = if config
            .repositories()
            .iter()
            .any(|repository| repository.visibility() == ProviderRepositoryVisibility::Private)
        {
            GithubProviderSourceMode::PublicAndPrivate
        } else {
            GithubProviderSourceMode::PublicOnly
        };
        Self {
            repositories: config.repositories().len(),
            installations,
            tenants,
            source_mode,
        }
    }

    /// Returns the exact configured repository count.
    #[must_use]
    pub const fn repository_count(self) -> usize {
        self.repositories
    }

    /// Returns the number of distinct exact installation routes.
    #[must_use]
    pub const fn installation_count(self) -> usize {
        self.installations
    }

    /// Returns the number of distinct configured tenants.
    #[must_use]
    pub const fn tenant_count(self) -> usize {
        self.tenants
    }

    /// Returns the closed source-authority mode selected at construction.
    #[must_use]
    pub const fn source_mode(self) -> GithubProviderSourceMode {
        self.source_mode
    }
}

/// Bounded polling and exact-release policy for one provider runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubProviderRuntimePolicy {
    idle_delay: Duration,
    release_capacity: usize,
    release_retry_interval: Duration,
    drain_timeout: Duration,
}

impl GithubProviderRuntimePolicy {
    /// Constructs one bounded runtime policy.
    ///
    /// # Errors
    ///
    /// Rejects an idle delay outside `1ms..=60s`, a release capacity outside
    /// `1..=4096`, an exact-release retry interval outside `1ms..=60s`, or a
    /// whole-provider drain timeout outside `1ms..=10m`.
    pub fn new(
        idle_delay: Duration,
        release_capacity: usize,
        release_retry_interval: Duration,
        drain_timeout: Duration,
    ) -> Result<Self, GithubProviderRuntimePolicyError> {
        if idle_delay.is_zero()
            || idle_delay < Duration::from_millis(1)
            || idle_delay > MAX_IDLE_DELAY
        {
            return Err(GithubProviderRuntimePolicyError);
        }
        if release_capacity == 0 || release_capacity > MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES {
            return Err(GithubProviderRuntimePolicyError);
        }
        if release_retry_interval.is_zero()
            || release_retry_interval < Duration::from_millis(1)
            || release_retry_interval > Duration::from_mins(1)
        {
            return Err(GithubProviderRuntimePolicyError);
        }
        if drain_timeout.is_zero() || drain_timeout > MAX_DRAIN_TIMEOUT {
            return Err(GithubProviderRuntimePolicyError);
        }
        Ok(Self {
            idle_delay,
            release_capacity,
            release_retry_interval,
            drain_timeout,
        })
    }
}

impl Default for GithubProviderRuntimePolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_IDLE_DELAY,
            MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES,
            DEFAULT_RELEASE_RETRY_INTERVAL,
            DEFAULT_DRAIN_TIMEOUT,
        )
        .expect("the fixed GitHub provider runtime policy is bounded")
    }
}

/// Invalid bounded runtime polling or release policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the GitHub provider runtime policy is invalid")]
pub struct GithubProviderRuntimePolicyError;

#[derive(Clone)]
struct WorkflowPermissionObservationTarget {
    manifest: automata_ci_store::GithubProviderManifest,
    authority: automata_ci_store::GithubServerServiceAuthorityIdentity,
    bootstrap: automata_ci_store::BootstrapGithubProviderRepository,
}

struct WorkflowPermissionDefaultsRefresher {
    store: Arc<PostgresStore>,
    adapters: Arc<GithubProviderCredentialAdapters>,
    endpoint: GithubHttpEndpoint,
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    owner: GithubServerServiceWorkerId,
    targets: Arc<[WorkflowPermissionObservationTarget]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkflowPermissionRefreshOutcome {
    Ready,
    PolicyMismatch,
}

impl fmt::Debug for WorkflowPermissionDefaultsRefresher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowPermissionDefaultsRefresher")
            .field("store", &"[OBSERVATION STORE]")
            .field("adapters", &"[CREDENTIAL ADAPTERS]")
            .field("endpoint", &"[GITHUB ENDPOINT]")
            .field("clock", &"[COORDINATOR CLOCK]")
            .field("owner", &self.owner)
            .field("target_count", &self.targets.len())
            .finish()
    }
}

impl WorkflowPermissionDefaultsRefresher {
    async fn refresh_all(
        &self,
    ) -> Result<WorkflowPermissionRefreshOutcome, GithubProviderRuntimeBuildError> {
        let (round_budget, attempt_budget) =
            workflow_permission_refresh_budgets(self.targets.len())?;
        let round_deadline = Instant::now()
            .checked_add(round_budget)
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let mut attempts = FuturesUnordered::new();
        let mut targets = self.targets.iter();
        for target in targets
            .by_ref()
            .take(MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY)
        {
            let deadline = Instant::now()
                .checked_add(attempt_budget)
                .map(|deadline| deadline.min(round_deadline))
                .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
            attempts.push(self.refresh(target, deadline));
        }
        let mut first_error = None;
        let mut policy_mismatch = false;
        tokio::time::timeout_at(tokio::time::Instant::from_std(round_deadline), async {
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(WorkflowPermissionRefreshOutcome::PolicyMismatch) => {
                        policy_mismatch = true;
                    }
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Ok(WorkflowPermissionRefreshOutcome::Ready) | Err(_) => {}
                }
                if let Some(target) = targets.next() {
                    let deadline = Instant::now()
                        .checked_add(attempt_budget)
                        .map(|deadline| deadline.min(round_deadline))
                        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
                    attempts.push(self.refresh(target, deadline));
                }
            }
            Ok::<(), GithubProviderRuntimeBuildError>(())
        })
        .await
        .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)??;
        first_error.map_or_else(
            || {
                Ok(if policy_mismatch {
                    WorkflowPermissionRefreshOutcome::PolicyMismatch
                } else {
                    WorkflowPermissionRefreshOutcome::Ready
                })
            },
            Err,
        )
    }

    async fn refresh(
        &self,
        target: &WorkflowPermissionObservationTarget,
        operation_deadline: Instant,
    ) -> Result<WorkflowPermissionRefreshOutcome, GithubProviderRuntimeBuildError> {
        let request_started_at = self.clock.now();
        let observation_id =
            automata_ci_store::GithubServerServiceConsumerId::from_uuid(Uuid::new_v4())
                .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let candidate = automata_ci_store::GithubWorkflowPermissionObservationCandidate::new(
            &target.bootstrap,
            &target.authority,
            observation_id,
            self.owner,
            request_started_at,
        )
        .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let remaining_provider_millis = request_started_at
            .get()
            .checked_add(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
            .and_then(|deadline| deadline.checked_sub(self.clock.now().get()))
            .filter(|remaining| *remaining > 0)
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let candidate_deadline = Instant::now()
            .checked_add(Duration::from_millis(
                u64::try_from(remaining_provider_millis)
                    .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?,
            ))
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let deadline = candidate_deadline.min(operation_deadline);
        if deadline <= Instant::now() {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.store
                .claim_github_workflow_permission_observation(candidate.clone()),
        )
        .await
        .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?
        .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let observed = self
            .adapters
            .observe_workflow_permission_defaults(
                &self.endpoint,
                &target.manifest,
                &candidate,
                deadline,
            )
            .await
            .map_err(GithubProviderRuntimeBuildError::WorkflowPermissions)?;
        let defaults = observed.defaults();
        let release = observed.release_request().clone();
        let observation = GithubWorkflowPermissionDefaultsObservation::new(
            &target.bootstrap,
            candidate,
            &release,
            observed.handoff_generation(),
            defaults.default_workflow_permissions(),
            defaults.can_approve_pull_request_reviews(),
            observed.provider_observed_at(),
        );
        let Ok(observation) = observation else {
            self.adapters.retain_workflow_permission_attempt(observed);
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        };
        let finalization = automata_ci_store::FinalizeGithubWorkflowPermissionObservation::new(
            target.bootstrap.clone(),
            release,
            observation,
        );
        let Ok(finalization) = finalization else {
            self.adapters.retain_workflow_permission_attempt(observed);
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        };
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.store
                .finalize_github_workflow_permission_observation(finalization),
        )
        .await
        {
            Ok(Ok(true)) => {
                observed.confirm_finalized();
                Ok(WorkflowPermissionRefreshOutcome::Ready)
            }
            Ok(Ok(false)) => {
                observed.confirm_finalized();
                Ok(WorkflowPermissionRefreshOutcome::PolicyMismatch)
            }
            Ok(Err(_)) | Err(_) => {
                self.adapters.retain_workflow_permission_attempt(observed);
                Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)
            }
        }
    }
}

/// Builder that owns already-loaded provider secrets only until construction finishes.
pub struct GithubProviderRuntimeBuilder {
    config: GithubProviderConfig,
    app_private_key: SecretString,
    webhook_secret: Zeroizing<Vec<u8>>,
    key_encryption_provider: Arc<dyn KeyEncryptionProvider>,
    store: Arc<PostgresStore>,
    blobs: Arc<dyn ImmutableBlobStore>,
    admission_observer: Option<Arc<dyn WorkflowAdmissionObserver>>,
    policy: GithubProviderRuntimePolicy,
}

impl GithubProviderRuntimeBuilder {
    /// Captures validated configuration, once-loaded secrets, and product adapters.
    ///
    /// `key_encryption_provider` must be the mandatory control-plane wrapping
    /// provider shared with the `PostgresStore`, not the optional user-secret
    /// encryption provider.
    #[must_use]
    pub fn new(
        config: GithubProviderConfig,
        app_private_key: SecretString,
        webhook_secret: Zeroizing<Vec<u8>>,
        key_encryption_provider: Arc<dyn KeyEncryptionProvider>,
        store: Arc<PostgresStore>,
        blobs: Arc<dyn ImmutableBlobStore>,
    ) -> Self {
        Self {
            config,
            app_private_key,
            webhook_secret,
            key_encryption_provider,
            store,
            blobs,
            admission_observer: None,
            policy: GithubProviderRuntimePolicy::default(),
        }
    }

    /// Installs the product's admission observer without changing provider authority.
    #[must_use]
    pub fn with_admission_observer(mut self, observer: Arc<dyn WorkflowAdmissionObserver>) -> Self {
        self.admission_observer = Some(observer);
        self
    }

    /// Replaces the bounded idle and release policy.
    #[must_use]
    pub fn with_policy(mut self, policy: GithubProviderRuntimePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Converges bootstrap state and builds the live aggregate.
    ///
    /// The App PEM and webhook bytes are consumed by this builder and dropped
    /// after brokers and the verifier have derived their in-memory authority.
    /// No connection registry is transferred into ingress until every exact
    /// manifest and server-service authority has converged in Store.
    ///
    /// # Errors
    ///
    /// Returns a sanitized construction or bootstrap error. Secret material,
    /// provider response bodies, URLs, and database details are never included.
    #[allow(clippy::too_many_lines)]
    pub async fn build(self) -> Result<GithubProviderRuntime, GithubProviderRuntimeBuildError> {
        let Self {
            config,
            app_private_key,
            webhook_secret,
            key_encryption_provider,
            store,
            blobs,
            admission_observer,
            policy,
        } = self;
        let shape = GithubProviderRuntimeShape::from_config(&config);
        let clock = Arc::new(NonRegressingGithubProviderClock::default());
        let delivery_clock: Arc<dyn GithubDeliveryClock> = clock.clone();
        let credential_clock: Arc<dyn GithubServerServiceCoordinatorClock> = clock.clone();
        let observation_clock = credential_clock.clone();
        let schedule_clock: Arc<dyn GithubScheduleClock> = clock.clone();
        let runtime_authority_clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> = clock;
        let applied_at = credential_clock.now();

        let verifier = GithubWebhookVerifier::new(&webhook_secret)
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWebhookSecret)?;
        drop(webhook_secret);
        let issuer = github_app_issuer(&config)?;
        let mut brokers = Vec::with_capacity(shape.installation_count());
        for installation_id in config
            .repositories()
            .iter()
            .map(|repository| repository.installation_id().get())
            .collect::<BTreeSet<_>>()
        {
            let installation = GithubInstallationId::new(installation_id)
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidConfiguration)?;
            let broker_config =
                provider_credential_config(config.transport(), issuer.clone(), installation)?;
            let broker = Arc::new(
                GithubAppCredentialBroker::new(broker_config, &app_private_key)
                    .map_err(|_| GithubProviderRuntimeBuildError::InvalidAppKey)?,
            );
            brokers.push((installation_id, broker));
        }
        drop(app_private_key);
        let bootstrap_broker = brokers
            .first()
            .map(|(_, broker)| broker.as_ref())
            .ok_or(GithubProviderRuntimeBuildError::InvalidConfiguration)?;
        let plan = GithubProviderBootstrapPlan::new(&config, bootstrap_broker, &verifier)?;
        let job_authority_broker_pins = job_authority_broker_pins(&plan)?;
        let connection_ids: Arc<[ProviderConnectionId]> = plan
            .connections()
            .iter()
            .map(GithubDeliveryConnection::connection_id)
            .collect::<Vec<_>>()
            .into();
        let tenants: Arc<[TenantScope]> = plan
            .connections()
            .iter()
            .map(|connection| connection.tenant().clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .into();
        let mut maintenance_authorities = plan
            .authorities()
            .iter()
            .map(GithubServerServiceAuthoritySelector::from_identity)
            .collect::<Vec<_>>();
        let workflow_permission_targets: Arc<[WorkflowPermissionObservationTarget]> = plan
            .manifests()
            .iter()
            .enumerate()
            .map(|(index, manifest)| {
                let bootstrap = plan.repository_bootstrap_request(index, applied_at)?;
                if bootstrap.manifest().manifest() != manifest {
                    return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
                }
                let authority = plan
                    .authorities()
                    .iter()
                    .find(|authority| {
                        authority.scope() == GithubServerServiceScope::WorkflowPermissionsRead
                            && authority.tenant() == manifest.tenant()
                            && authority.repository_id() == manifest.repository_id()
                            && authority.connection_id() == manifest.connection_id()
                    })
                    .cloned()
                    .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
                Ok(WorkflowPermissionObservationTarget {
                    manifest: manifest.clone(),
                    authority,
                    bootstrap,
                })
            })
            .collect::<Result<Vec<_>, GithubProviderRuntimeBuildError>>()?
            .into();
        if connection_ids.is_empty()
            || tenants.is_empty()
            || maintenance_authorities.is_empty()
            || workflow_permission_targets.is_empty()
            || policy.release_capacity
                < workflow_permission_targets
                    .len()
                    .min(MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY)
        {
            return Err(GithubProviderRuntimeBuildError::InvalidConfiguration);
        }

        for policy in plan.runner_policies() {
            blobs
                .put_if_absent(policy.clone())
                .await
                .map_err(|_| GithubProviderRuntimeBuildError::RunnerPolicyUnavailable)?;
        }

        plan.prepare_workflow_permission_bootstrap(store.as_ref(), applied_at)
            .await?;
        let credential_request_resolver = plan.staged_credential_request_resolver();
        let credential_adapter_routes = credential_request_resolver.clone();
        let resolver: Arc<dyn GithubServerServiceCredentialRequestResolver> =
            Arc::new(credential_request_resolver.clone());
        let routed_brokers = brokers
            .iter()
            .map(|(installation_id, broker)| {
                let broker: Arc<dyn GithubServerServiceCredentialBroker> = broker.clone();
                (*installation_id, broker)
            })
            .collect::<Vec<_>>();
        let router = Arc::new(
            GithubServerServiceInstallationRouter::new(routed_brokers)
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidInstallationRouter)?,
        );
        let broker: Arc<dyn GithubServerServiceCredentialBroker> = router.clone();
        let credential_repository: Arc<dyn GithubServerServiceCredentialRepository> = store.clone();
        let credential_authority_repository: Arc<dyn GithubServerServiceAuthorityRepository> =
            store.clone();
        let envelopes = Arc::new(EnvelopeCodec::new(key_encryption_provider));
        let runtime_handle = Handle::try_current()
            .map_err(|_| GithubProviderRuntimeBuildError::RuntimeUnavailable)?;
        let credential_commit_supervisor = Arc::new(CredentialMaintenanceCommitSupervisor::new(
            runtime_handle.clone(),
            policy.release_retry_interval,
            MAX_SUPERVISED_SERVICE_CREDENTIAL_COMMITS,
        ));

        let job_authority_repository: Arc<dyn GithubRuntimeAuthorityRepository> = store.clone();
        let job_authority_evidence: Arc<dyn GithubJobRuntimeAuthorityRepository> = store.clone();
        let job_ir_objects: Arc<dyn JobIrObjectReader> =
            Arc::new(ImmutableBlobJobIrReader::new(blobs.clone()));
        let job_authority_resolver = Arc::new(GithubJobRuntimeAuthorityResolver::new(
            job_authority_evidence,
            job_ir_objects,
        ));
        let identity_resolver: Arc<
            dyn automata_ci_credential_github::GithubRuntimeAuthorityIdentityResolver,
        > = job_authority_resolver.clone();
        let request_resolver: Arc<dyn GithubRuntimeAuthorityRequestResolver> =
            job_authority_resolver;
        let mint_supervisor = Arc::new(
            GithubRuntimeAuthorityCommitSupervisor::new(
                job_authority_repository.clone(),
                runtime_handle.clone(),
                MAX_SUPERVISED_JOB_AUTHORITY_COMMITS,
                policy.release_retry_interval,
            )
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?,
        );
        let authority_endpoint = provider_runtime_authority_endpoint(config.transport())?;
        let mut job_authority_routes = Vec::with_capacity(brokers.len());
        for (installation_id, app_broker) in &brokers {
            let pin = job_authority_broker_pins
                .get(installation_id)
                .cloned()
                .ok_or(GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?;
            if app_broker.app_key_spki_sha256() != pin.app_key_spki_sha256 {
                return Err(GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority);
            }
            let mint_broker: Arc<dyn GithubRuntimeAuthorityMintBroker> = Arc::new(
                PinnedGithubRuntimeAuthorityMintBroker::new(
                    app_broker.clone(),
                    pin.github_app_id,
                    pin.github_app_client_id,
                    pin.github_app_jwt_issuer_kind,
                    pin.configuration_fingerprint,
                )
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?,
            );
            let worker = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
            let coordinator = Arc::new(GithubRuntimeAuthorityMintCoordinator::new(
                job_authority_repository.clone(),
                request_resolver.clone(),
                mint_broker,
                envelopes.clone(),
                runtime_authority_clock.clone(),
                worker,
                mint_supervisor.clone(),
            ));
            let issuer = Arc::new(
                match config.transport() {
                    GithubProviderTransport::GithubDotCom => {
                        GithubRepositoryRuntimeAuthorityIssuer::new(
                            identity_resolver.clone(),
                            coordinator,
                            job_authority_repository.clone(),
                            envelopes.clone(),
                            runtime_authority_clock.clone(),
                            authority_endpoint.clone(),
                        )
                    }
                    GithubProviderTransport::LoopbackEmulator { .. } => {
                        GithubRepositoryRuntimeAuthorityIssuer::new_for_mapped_emulator(
                            identity_resolver.clone(),
                            coordinator,
                            job_authority_repository.clone(),
                            envelopes.clone(),
                            runtime_authority_clock.clone(),
                            authority_endpoint.clone(),
                        )
                    }
                }
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?,
            );
            job_authority_routes.push((*installation_id, issuer));
        }
        let job_runtime_authority_issuer: Arc<dyn OptionalRuntimeAuthorityIssuer> = Arc::new(
            GithubJobRuntimeAuthorityIssuer::new(identity_resolver, job_authority_routes)
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?,
        );

        let lifecycle_supervisor = Arc::new(
            GithubRuntimeAuthorityLifecycleSupervisor::new(
                job_authority_repository.clone(),
                runtime_handle.clone(),
                MAX_SUPERVISED_JOB_AUTHORITY_COMMITS,
                policy.release_retry_interval,
            )
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?,
        );
        let lifecycle_worker = GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let lifecycle_routes = brokers
            .iter()
            .map(|(installation_id, app_broker)| {
                let pin = job_authority_broker_pins
                    .get(installation_id)
                    .cloned()
                    .ok_or(GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?;
                if app_broker.app_key_spki_sha256() != pin.app_key_spki_sha256 {
                    return Err(GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority);
                }
                Ok((
                    app_broker.clone(),
                    pin.github_app_id,
                    pin.github_app_client_id,
                    pin.github_app_jwt_issuer_kind,
                    pin.configuration_fingerprint,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let lifecycle_broker: Arc<dyn GithubRuntimeAuthorityLifecycleBroker> = Arc::new(
            GithubRuntimeAuthorityLifecycleBrokerRouter::new(lifecycle_routes)
                .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)?,
        );
        let job_authority_maintenance = Arc::new(GithubRuntimeAuthorityLifecycleCoordinator::new(
            job_authority_repository,
            lifecycle_broker,
            envelopes.clone(),
            runtime_authority_clock,
            lifecycle_worker,
            lifecycle_supervisor.clone(),
        ));
        let job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort> =
            Arc::new(JobRuntimeAuthorityDrain {
                mint: mint_supervisor,
                lifecycle: lifecycle_supervisor,
                service_credentials: credential_commit_supervisor.clone(),
            });

        let credential_worker = GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let coordinator = Arc::new(GithubServerServiceCredentialCoordinator::new(
            credential_repository.clone(),
            resolver,
            broker,
            envelopes.clone(),
            credential_clock.clone(),
            credential_worker,
        ));
        converge_workflow_permission_authorities(
            credential_repository.clone(),
            credential_authority_repository.clone(),
            coordinator.clone(),
            credential_clock.clone(),
            credential_commit_supervisor.clone(),
            plan.authorities(),
        )
        .await?;
        let credential_issuer = Arc::new(GithubServerServiceCredentialIssuer::new(
            credential_repository.clone(),
            envelopes,
            credential_clock.clone(),
        ));
        let releases = Arc::new(GithubProviderCredentialReleaseSupervisor::new(
            credential_clock.clone(),
            runtime_handle,
            policy.release_capacity,
            policy.release_retry_interval,
        )?);
        let adapters = Arc::new(GithubProviderCredentialAdapters::new(
            credential_issuer,
            credential_repository.clone(),
            credential_authority_repository.clone(),
            store.clone(),
            releases.clone(),
            plan.authorities(),
            credential_adapter_routes,
            credential_clock.clone(),
        )?);
        let schedule_private_authorities = GithubSchedulePrivateSourceAuthorities::new(
            plan.authorities()
                .iter()
                .filter(|authority| {
                    authority.scope() == GithubServerServiceScope::PrivateRepositorySourceRead
                })
                .map(|authority| {
                    (
                        authority.connection_id(),
                        automata_ci_store::GithubServerServiceAuthoritySelector::from_identity(
                            authority,
                        ),
                    )
                }),
        )
        .map_err(GithubProviderRuntimeBuildError::ScheduleWorker)?;

        let endpoint = provider_http_endpoint(config.transport())?;
        let workflow_dispatch_source: Arc<dyn ScmProvider> = Arc::new(endpoint.clone());
        let workflow_dispatch_credentials = match shape.source_mode() {
            GithubProviderSourceMode::PublicOnly => None,
            GithubProviderSourceMode::PublicAndPrivate => Some(adapters.clone()),
        };
        let workflow_dispatch_worker = GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let observation_owner = GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let permission_defaults = Arc::new(WorkflowPermissionDefaultsRefresher {
            store: store.clone(),
            adapters: adapters.clone(),
            endpoint: endpoint.clone(),
            clock: observation_clock,
            owner: observation_owner,
            targets: workflow_permission_targets,
        });
        if permission_defaults.refresh_all().await? != WorkflowPermissionRefreshOutcome::Ready {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
        let _ready = plan.bootstrap(store.as_ref(), applied_at).await?;
        let cleanup_authorities = retire_superseded_server_service_authorities(
            credential_authority_repository.as_ref(),
            plan.manifests(),
            plan.authorities(),
            credential_clock.as_ref(),
        )
        .await?;
        for selector in cleanup_authorities {
            if !maintenance_authorities.contains(&selector) {
                maintenance_authorities.push(selector);
            }
        }
        let maintenance_authorities: Arc<[GithubServerServiceAuthoritySelector]> =
            maintenance_authorities.into();
        let admission_repository: Arc<dyn LogicalWorkflowAdmissionRepository> = store.clone();
        let mut admission = WorkflowAdmissionService::with_system_ports(
            blobs.clone(),
            admission_repository,
            Arc::new(GithubWorkflowPlanVerifier::new()),
        );
        if let Some(observer) = admission_observer {
            admission = admission.with_observer(observer);
        }
        let schedule_admission = admission.clone();
        let schedule_worker = GithubScheduleWorkerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let schedule_source = Arc::new(endpoint.clone());
        let schedule = match shape.source_mode() {
            GithubProviderSourceMode::PublicOnly => GithubScheduleService::new_public_only(
                blobs.clone(),
                schedule_source,
                store.clone(),
                schedule_admission,
                schedule_clock,
                schedule_worker,
                config.schedule().service_config(),
            ),
            GithubProviderSourceMode::PublicAndPrivate => {
                let credentials: Arc<dyn GithubScheduleSourceCredentialProvider> = adapters.clone();
                GithubScheduleService::new_with_private_source_credentials(
                    blobs.clone(),
                    schedule_source,
                    store.clone(),
                    schedule_admission,
                    schedule_private_authorities,
                    Some(credentials),
                    schedule_clock,
                    schedule_worker,
                    config.schedule().service_config(),
                )
            }
        }
        .map_err(GithubProviderRuntimeBuildError::ScheduleWorker)?;
        let changed_files: Arc<dyn GithubPushChangedFilesProvider> =
            Arc::new(GithubRestPushChangedFilesProvider::new(endpoint.clone()));
        let workflow_processor: Arc<dyn GithubDeliveryWorkflowProcessor> = Arc::new(
            GithubDeliveryWorkflowAdmissionProcessor::new(admission)
                .with_changed_files_provider(changed_files),
        );
        let repository_source = Arc::new(endpoint.clone());
        let repository_dispatch_resolver = Arc::new(endpoint.clone());
        let repository_dispatch_evidence: Arc<dyn GithubRepositoryDispatchEvidenceRepository> =
            store.clone();
        let delivery_worker = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let delivery = match shape.source_mode() {
            GithubProviderSourceMode::PublicOnly => {
                GithubDeliveryService::new_public_only_with_repository_dispatch(
                    blobs.clone(),
                    repository_source,
                    repository_dispatch_resolver,
                    workflow_processor,
                    store.clone(),
                    repository_dispatch_evidence,
                    delivery_clock.clone(),
                    delivery_worker,
                    GithubDeliveryWorkerConfig::default(),
                    GithubDeliveryServiceConfig::default(),
                )
            }
            GithubProviderSourceMode::PublicAndPrivate => {
                let source_credentials: Arc<dyn GithubDeliverySourceCredentialProvider> =
                    adapters.clone();
                GithubDeliveryService::new_with_private_source_credentials_and_repository_dispatch(
                    blobs.clone(),
                    repository_source,
                    repository_dispatch_resolver,
                    workflow_processor,
                    store.clone(),
                    repository_dispatch_evidence,
                    source_credentials,
                    delivery_clock.clone(),
                    delivery_worker,
                    GithubDeliveryWorkerConfig::default(),
                    GithubDeliveryServiceConfig::default(),
                )
            }
        }
        .map_err(GithubProviderRuntimeBuildError::DeliveryWorker)?;

        let checks_credentials: Arc<dyn GithubChecksCredentialProvider> = adapters.clone();
        let checks_outbox: Arc<dyn GithubCheckProjectionOutbox> = store.clone();
        let checks = Arc::new(
            GithubChecksPublisher::new(
                endpoint,
                checks_outbox,
                blobs.clone(),
                checks_credentials,
                delivery_clock.clone(),
                config.dashboard_url().clone(),
                GithubChecksPublisherConfig::default(),
            )
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidConfiguration)?,
        );
        let checks_worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4())
            .map_err(|_| GithubProviderRuntimeBuildError::InvalidWorkerIdentity)?;
        let subject_evidence: Arc<dyn GithubSubjectEvidenceRepository> = store.clone();
        let repository_dispatches: Arc<dyn GithubRepositoryDispatchEvidenceRepository> =
            store.clone();
        let check_reruns: Arc<dyn automata_ci_store::GithubCheckRerunRepository> = store;
        let ingress = Arc::new(
            GithubDeliveryIngress::new(
                verifier,
                config.webhook().verifier_revision(),
                plan.into_connections(),
                blobs,
                GithubDeliveryRepositories::new(subject_evidence)
                    .with_repository_dispatches(repository_dispatches)
                    .with_check_reruns(check_reruns),
                delivery_clock,
            )
            .map_err(GithubProviderRuntimeBuildError::Ingress)?,
        );
        let maintenance: Arc<dyn CredentialMaintenancePort> =
            Arc::new(ServerServiceCredentialMaintenance {
                coordinator,
                repository: credential_repository,
            });
        let release_drain: Arc<dyn ReleaseDrainPort> = releases;

        Ok(GithubProviderRuntime {
            ingress,
            delivery: Arc::new(delivery),
            schedule: Arc::new(schedule),
            checks,
            maintenance,
            permission_defaults,
            credential_commit_supervisor,
            job_authority_maintenance,
            job_authority_drain,
            job_runtime_authority_issuer,
            workflow_dispatch_source,
            workflow_dispatch_credentials,
            workflow_dispatch_worker,
            release_drain,
            connection_ids,
            maintenance_authorities,
            checks_worker,
            idle_delay: policy.idle_delay,
            drain_timeout: policy.drain_timeout,
            shape,
        })
    }
}

fn provider_credential_config(
    transport: &GithubProviderTransport,
    issuer: GithubAppIssuer,
    installation: GithubInstallationId,
) -> Result<GithubAppCredentialConfig, GithubProviderRuntimeBuildError> {
    match transport {
        GithubProviderTransport::GithubDotCom => {
            GithubAppCredentialConfig::github_dot_com(issuer, installation, GITHUB_HTTP_USER_AGENT)
        }
        GithubProviderTransport::LoopbackEmulator { api_base, .. } => {
            GithubAppCredentialConfig::new_for_loopback_emulator(
                api_base.clone(),
                issuer,
                installation,
                GITHUB_HTTP_USER_AGENT,
                GithubAppHttpLimits::default(),
            )
        }
    }
    .map_err(|_| GithubProviderRuntimeBuildError::InvalidProviderClient)
}

pub(crate) fn provider_http_endpoint(
    transport: &GithubProviderTransport,
) -> Result<GithubHttpEndpoint, GithubProviderRuntimeBuildError> {
    match transport {
        GithubProviderTransport::GithubDotCom => {
            GithubHttpEndpoint::github_dot_com(GITHUB_HTTP_USER_AGENT)
        }
        GithubProviderTransport::LoopbackEmulator { api_base, .. } => {
            let mut server_origin = api_base.clone();
            server_origin.set_path("/");
            server_origin.set_query(None);
            server_origin.set_fragment(None);
            GithubHttpEndpoint::new_for_loopback_emulator(
                server_origin,
                api_base.clone(),
                GITHUB_HTTP_USER_AGENT,
                GithubHttpLimits::default(),
            )
        }
    }
    .map_err(|_| GithubProviderRuntimeBuildError::InvalidProviderClient)
}

fn provider_runtime_authority_endpoint(
    transport: &GithubProviderTransport,
) -> Result<RuntimeAuthorityEndpoint, GithubProviderRuntimeBuildError> {
    match transport {
        GithubProviderTransport::GithubDotCom => {
            RuntimeAuthorityEndpoint::new(GITHUB_PROVIDER_WEB_ORIGIN)
        }
        GithubProviderTransport::LoopbackEmulator {
            job_runtime_origin, ..
        } => RuntimeAuthorityEndpoint::trusted_private_development(job_runtime_origin.as_str()),
    }
    .map_err(|_| GithubProviderRuntimeBuildError::InvalidJobRuntimeAuthority)
}

impl fmt::Debug for GithubProviderRuntimeBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderRuntimeBuilder")
            .field("config", &self.config)
            .field("app_private_key", &"[REDACTED]")
            .field("webhook_secret", &"[REDACTED]")
            .field("key_encryption_provider", &"[KEY ENCRYPTION PROVIDER]")
            .field("store", &"[POSTGRES STORE]")
            .field("blobs", &"[IMMUTABLE BLOB STORE]")
            .field("admission_observer", &self.admission_observer.is_some())
            .field("policy", &self.policy)
            .finish()
    }
}

/// Fully built provider ingress and background runtime.
pub struct GithubProviderRuntime {
    ingress: Arc<GithubDeliveryIngress>,
    delivery: Arc<GithubDeliveryService>,
    schedule: Arc<GithubScheduleService>,
    checks: Arc<GithubChecksPublisher>,
    maintenance: Arc<dyn CredentialMaintenancePort>,
    permission_defaults: Arc<WorkflowPermissionDefaultsRefresher>,
    credential_commit_supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    job_authority_maintenance: Arc<GithubRuntimeAuthorityLifecycleCoordinator>,
    job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort>,
    job_runtime_authority_issuer: Arc<dyn OptionalRuntimeAuthorityIssuer>,
    workflow_dispatch_source: Arc<dyn ScmProvider>,
    workflow_dispatch_credentials: Option<Arc<GithubProviderCredentialAdapters>>,
    workflow_dispatch_worker: GithubServerServiceWorkerId,
    release_drain: Arc<dyn ReleaseDrainPort>,
    connection_ids: Arc<[ProviderConnectionId]>,
    maintenance_authorities: Arc<[GithubServerServiceAuthoritySelector]>,
    checks_worker: GithubCheckProjectionWorkerId,
    idle_delay: Duration,
    drain_timeout: Duration,
    shape: GithubProviderRuntimeShape,
}

impl GithubProviderRuntime {
    /// Returns the authenticated webhook ingress for HTTP route composition.
    #[must_use]
    pub fn ingress(&self) -> Arc<GithubDeliveryIngress> {
        self.ingress.clone()
    }

    /// Returns the non-secret exact runtime topology.
    #[must_use]
    pub const fn shape(&self) -> GithubProviderRuntimeShape {
        self.shape
    }

    /// Returns the exact optional GitHub repository-authority issuer.
    ///
    /// Clone this accessor before consuming the aggregate with [`Self::run`].
    /// It declines only foreign-provider jobs or exact historical
    /// `CredentialFree` evidence; a GitHub `Standard` mismatch fails closed.
    #[must_use]
    pub fn job_runtime_authority_issuer(&self) -> Arc<dyn OptionalRuntimeAuthorityIssuer> {
        self.job_runtime_authority_issuer.clone()
    }

    pub(super) fn workflow_dispatch_source(&self) -> Arc<dyn ScmProvider> {
        self.workflow_dispatch_source.clone()
    }

    pub(super) fn workflow_dispatch_credentials(
        &self,
    ) -> Option<Arc<GithubProviderCredentialAdapters>> {
        self.workflow_dispatch_credentials.clone()
    }

    pub(super) const fn workflow_dispatch_worker(&self) -> GithubServerServiceWorkerId {
        self.workflow_dispatch_worker
    }

    /// Consumes the aggregate and runs its single background service instance.
    ///
    /// Checks and credential provider futures are never cancelled mid-call.
    /// On shutdown or the first fatal loop error, new consumer work stops; all
    /// loops finish their bounded current operation, any exact pending mint or
    /// revocation result is replayed, and only then are supervised handoff
    /// releases drained. Exact pending Store commits keep retrying through
    /// transient failure until the policy's whole-provider drain deadline.
    /// Reaching that deadline is returned as an explicit sanitized error; it
    /// never masquerades as a successful shutdown.
    ///
    /// # Errors
    ///
    /// Returns the first sanitized fatal loop error after ordered drain.
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), GithubProviderRuntimeError> {
        self.run_inner(shutdown, None).await
    }

    pub(super) async fn run_with_fatal_notification(
        self,
        shutdown: CancellationToken,
        fatal_notification: oneshot::Sender<GithubProviderFatalNotification>,
    ) -> Result<(), GithubProviderRuntimeError> {
        self.run_inner(shutdown, Some(fatal_notification)).await
    }

    async fn run_inner(
        self,
        shutdown: CancellationToken,
        fatal_notification: Option<oneshot::Sender<GithubProviderFatalNotification>>,
    ) -> Result<(), GithubProviderRuntimeError> {
        let Self {
            ingress: _,
            delivery,
            schedule,
            checks,
            maintenance,
            permission_defaults,
            credential_commit_supervisor,
            job_authority_maintenance,
            job_authority_drain,
            job_runtime_authority_issuer: _,
            workflow_dispatch_source: _,
            workflow_dispatch_credentials: _,
            workflow_dispatch_worker: _,
            release_drain,
            connection_ids,
            maintenance_authorities,
            checks_worker,
            idle_delay,
            drain_timeout,
            shape: _,
        } = self;
        let stop = CancellationToken::new();
        let loops = FuturesUnordered::new();
        let delivery_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::Delivery(delivery.run(delivery_stop).await)
        }));
        let schedule_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::Schedules(schedule.run(schedule_stop).await)
        }));
        let checks_connections = connection_ids;
        let checks_delay = idle_delay;
        let checks_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::Checks(
                run_checks_loop(
                    checks,
                    checks_connections,
                    checks_worker,
                    checks_delay,
                    checks_stop,
                )
                .await,
            )
        }));
        let maintenance_selectors = maintenance_authorities;
        let maintenance_delay = idle_delay;
        let maintenance_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::Credentials(
                run_credential_maintenance_loop(
                    maintenance,
                    credential_commit_supervisor,
                    maintenance_selectors,
                    maintenance_delay,
                    maintenance_stop,
                )
                .await,
            )
        }));
        let permission_defaults_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::PermissionDefaults(
                run_workflow_permission_refresh_loop(permission_defaults, permission_defaults_stop)
                    .await,
            )
        }));
        let job_authority_delay = idle_delay;
        let job_authority_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::JobAuthority(
                run_job_authority_maintenance_loop(
                    job_authority_maintenance,
                    job_authority_delay,
                    job_authority_stop,
                )
                .await,
            )
        }));
        supervise_runtime_loops(
            loops,
            shutdown,
            stop,
            job_authority_drain,
            release_drain,
            drain_timeout,
            fatal_notification,
        )
        .await
    }
}

impl fmt::Debug for GithubProviderRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubProviderRuntime")
            .field("shape", &self.shape)
            .field("connection_count", &self.connection_ids.len())
            .field("tenant_count", &self.shape.tenant_count())
            .field(
                "maintenance_authority_count",
                &self.maintenance_authorities.len(),
            )
            .field("checks_worker", &self.checks_worker)
            .field(
                "job_runtime_authority_issuer",
                &"[OPTIONAL RUNTIME AUTHORITY ISSUER]",
            )
            .field("idle_delay", &self.idle_delay)
            .field("drain_timeout", &self.drain_timeout)
            .finish_non_exhaustive()
    }
}

/// Sanitized provider-runtime construction failure.
#[derive(Debug, Error)]
pub enum GithubProviderRuntimeBuildError {
    /// Validated configuration could not be represented at an adjacent boundary.
    #[error("the GitHub provider runtime configuration is inconsistent")]
    InvalidConfiguration,
    /// The loaded webhook HMAC secret was invalid.
    #[error("the GitHub provider webhook secret is invalid")]
    InvalidWebhookSecret,
    /// The loaded App private key could not construct an exact broker.
    #[error("the GitHub provider App key is invalid")]
    InvalidAppKey,
    /// The hardened GitHub client could not be constructed.
    #[error("the GitHub provider client configuration is invalid")]
    InvalidProviderClient,
    /// The distinct installation registry could not construct a no-default router.
    #[error("the GitHub provider installation registry is invalid")]
    InvalidInstallationRouter,
    /// Exact job-scoped repository authority could not be constructed safely.
    #[error("the GitHub job runtime-authority configuration is invalid")]
    InvalidJobRuntimeAuthority,
    /// A process-lifetime worker identity could not be represented.
    #[error("the GitHub provider worker identity is invalid")]
    InvalidWorkerIdentity,
    /// Construction was polled outside a Tokio runtime.
    #[error("the GitHub provider runtime is unavailable")]
    RuntimeUnavailable,
    /// The mandatory historical runner-policy blob could not be published.
    #[error("the GitHub provider runner policy is unavailable")]
    RunnerPolicyUnavailable,
    /// Immutable manifest or authority convergence failed.
    #[error(transparent)]
    Bootstrap(#[from] GithubProviderBootstrapError),
    /// Credential adapter or release supervision configuration failed.
    #[error(transparent)]
    Credentials(#[from] GithubProviderCredentialAdapterConfigurationError),
    /// Effective repository defaults could not be observed with least authority.
    #[error(transparent)]
    WorkflowPermissions(GithubWorkflowPermissionObservationError),
    /// Observed workflow-permission provenance did not match immutable configuration.
    #[error("the GitHub workflow-permission observation is invalid")]
    WorkflowPermissionObservation,
    /// Delivery worker configuration was incompatible with runtime policy.
    #[error(transparent)]
    DeliveryWorker(GithubDeliveryWorkerConfigurationError),
    /// Schedule worker configuration was incompatible with runtime policy.
    #[error(transparent)]
    ScheduleWorker(GithubScheduleServiceConfigurationError),
    /// The post-bootstrap ingress registry was inconsistent.
    #[error(transparent)]
    Ingress(GithubDeliveryConfigurationError),
}

/// Sanitized fatal background-service failure after ordered drain.
#[derive(Debug, Error)]
pub enum GithubProviderRuntimeError {
    /// Durable delivery supervision failed.
    #[error(transparent)]
    Delivery(#[from] GithubDeliveryServiceError),
    /// Durable schedule discovery or due-fire supervision failed.
    #[error(transparent)]
    Schedules(#[from] GithubScheduleServiceError),
    /// Fenced GitHub Checks publication failed.
    #[error(transparent)]
    Checks(#[from] GithubChecksPublisherError),
    /// Server-service credential maintenance failed.
    #[error(transparent)]
    Credentials(#[from] GithubServerServiceCoordinatorError),
    /// Effective repository permission-default evidence could not be refreshed.
    #[error("GitHub workflow-permission default refresh failed")]
    PermissionDefaults,
    /// Job-scoped repository authority lifecycle evidence was inconsistent.
    #[error(transparent)]
    JobAuthority(#[from] GithubRuntimeAuthorityLifecycleError),
    /// A background loop returned successfully before shutdown was requested.
    #[error("a GitHub provider runtime loop stopped unexpectedly")]
    UnexpectedStop,
    /// Current work or exact commit/release custody exceeded the bounded drain.
    #[error("the GitHub provider runtime did not drain before its shutdown deadline")]
    DrainTimeout,
}

#[derive(Debug, Default)]
struct NonRegressingGithubProviderClock {
    last: AtomicI64,
}

impl NonRegressingGithubProviderClock {
    fn observe(&self, observed: i64) -> UnixMillis {
        let observed = observed.max(0);
        let previous = self.last.fetch_max(observed, Ordering::AcqRel);
        UnixMillis::new(previous.max(observed))
    }

    fn system_now(&self) -> UnixMillis {
        let observed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
            });
        self.observe(observed)
    }
}

impl GithubDeliveryClock for NonRegressingGithubProviderClock {
    fn now(&self) -> UnixMillis {
        self.system_now()
    }
}

impl GithubServerServiceCoordinatorClock for NonRegressingGithubProviderClock {
    fn now(&self) -> UnixMillis {
        self.system_now()
    }
}

impl GithubRuntimeAuthorityCoordinatorClock for NonRegressingGithubProviderClock {
    fn now(&self) -> UnixMillis {
        self.system_now()
    }
}

impl GithubScheduleClock for NonRegressingGithubProviderClock {
    fn now(&self) -> Result<UnixMillis, GithubScheduleServiceError> {
        Ok(self.system_now())
    }
}

fn github_app_issuer(
    config: &GithubProviderConfig,
) -> Result<GithubAppIssuer, GithubProviderRuntimeBuildError> {
    let value = match config.app().jwt_issuer() {
        GithubServerServiceJwtIssuer::AppClientId => config.app().client_id().as_str().to_owned(),
        GithubServerServiceJwtIssuer::AppId => config.app().app_id().get().to_string(),
    };
    GithubAppIssuer::new(value).map_err(|_| GithubProviderRuntimeBuildError::InvalidConfiguration)
}

struct FairSweep<T> {
    items: Arc<[T]>,
    next: usize,
    consecutive_idle: usize,
}

impl<T: Clone> FairSweep<T> {
    fn new(items: Arc<[T]>) -> Self {
        debug_assert!(!items.is_empty());
        Self {
            items,
            next: 0,
            consecutive_idle: 0,
        }
    }

    fn next(&mut self) -> T {
        let item = self.items[self.next].clone();
        self.next = (self.next + 1) % self.items.len();
        item
    }

    fn observe(&mut self, idle: bool) -> bool {
        if idle {
            self.consecutive_idle += 1;
            if self.consecutive_idle == self.items.len() {
                self.consecutive_idle = 0;
                return true;
            }
        } else {
            self.consecutive_idle = 0;
        }
        false
    }
}

async fn run_checks_loop(
    checks: Arc<GithubChecksPublisher>,
    connections: Arc<[ProviderConnectionId]>,
    worker: GithubCheckProjectionWorkerId,
    idle_delay: Duration,
    stop: CancellationToken,
) -> Result<(), GithubChecksPublisherError> {
    let mut sweep = FairSweep::new(connections);
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let connection = sweep.next();
        match checks.run_once(connection, worker).await {
            Ok(GithubChecksPublisherOutcome::Idle) => {
                if sweep.observe(true) && sleep_or_stop(idle_delay, &stop).await {
                    return Ok(());
                }
            }
            Ok(GithubChecksPublisherOutcome::Advanced(_)) => {
                tracing::debug!(?connection, "GitHub Check projection advanced");
                let _ = sweep.observe(false);
            }
            Ok(GithubChecksPublisherOutcome::RetryScheduled(_)) => {
                tracing::warn!(
                    ?connection,
                    "GitHub Check projection scheduled a durable retry"
                );
                let _ = sweep.observe(false);
            }
            Ok(GithubChecksPublisherOutcome::ReconciliationRequired(_)) => {
                tracing::warn!(?connection, "GitHub Check creation requires reconciliation");
                let _ = sweep.observe(false);
            }
            Ok(GithubChecksPublisherOutcome::Blocked(_)) => {
                tracing::error!(
                    ?connection,
                    "GitHub Check projection blocked on provider mismatch"
                );
                let _ = sweep.observe(false);
            }
            Err(GithubChecksPublisherError::Store(GithubCheckStoreError::Operation(_))) => {
                tracing::warn!(?connection, "GitHub Check projection store is unavailable");
                let _ = sweep.observe(false);
                if sleep_or_stop(idle_delay, &stop).await {
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[async_trait]
trait PendingCredentialCommit: fmt::Debug + Send + Sync {
    async fn replay(&self) -> bool;
}

enum CredentialMaintenanceOutcome {
    Idle,
    Worked,
    Pending(oneshot::Receiver<()>),
}

#[async_trait]
trait CredentialMaintenancePort: fmt::Debug + Send + Sync {
    async fn coordinate_authority(
        &self,
        selector: GithubServerServiceAuthoritySelector,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError>;
}

struct ServerServiceCredentialMaintenance {
    coordinator: Arc<GithubServerServiceCredentialCoordinator>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
}

#[async_trait]
impl CredentialMaintenancePort for ServerServiceCredentialMaintenance {
    async fn coordinate_authority(
        &self,
        selector: GithubServerServiceAuthoritySelector,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError> {
        let outcome = self.coordinator.coordinate_authority(selector).await?;
        Ok(supervise_credential_coordination(
            outcome,
            custody,
            self.repository.clone(),
        ))
    }
}

fn supervise_credential_coordination(
    outcome: GithubServerServiceCoordinationOutcome,
    custody: CredentialMaintenanceCustody,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
) -> CredentialMaintenanceOutcome {
    match outcome {
        GithubServerServiceCoordinationOutcome::Idle => CredentialMaintenanceOutcome::Idle,
        GithubServerServiceCoordinationOutcome::MintCommitPending(pending) => {
            CredentialMaintenanceOutcome::Pending(custody.supervise(Box::new(PendingMintCommit {
                pending: Box::new(CorePendingMintCommit {
                    pending,
                    repository,
                }),
            })))
        }
        GithubServerServiceCoordinationOutcome::RevocationCommitPending(pending) => {
            CredentialMaintenanceOutcome::Pending(custody.supervise(Box::new(
                PendingRevocationCommit {
                    pending: Box::new(CorePendingRevocationCommit {
                        pending,
                        repository,
                    }),
                },
            )))
        }
        GithubServerServiceCoordinationOutcome::Reduced { .. }
        | GithubServerServiceCoordinationOutcome::MintAlreadyStarted(_)
        | GithubServerServiceCoordinationOutcome::MintStartedWindowExhausted(_) => {
            CredentialMaintenanceOutcome::Worked
        }
    }
}

impl fmt::Debug for ServerServiceCredentialMaintenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerServiceCredentialMaintenance")
            .field("coordinator", &self.coordinator)
            .field("repository", &"[CREDENTIAL REPOSITORY]")
            .finish()
    }
}

struct PendingMintCommit {
    pending: Box<dyn PendingCredentialCommit>,
}

#[async_trait]
impl PendingCredentialCommit for PendingMintCommit {
    async fn replay(&self) -> bool {
        self.pending.replay().await
    }
}

impl fmt::Debug for PendingMintCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingMintCommit")
            .field("pending", &self.pending)
            .finish()
    }
}

struct CorePendingMintCommit {
    pending: Box<PendingGithubServerServiceMintCommit>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
}

#[async_trait]
impl PendingCredentialCommit for CorePendingMintCommit {
    async fn replay(&self) -> bool {
        self.pending.replay(self.repository.as_ref()).await.is_ok()
    }
}

impl fmt::Debug for CorePendingMintCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorePendingMintCommit")
            .field("pending", &self.pending)
            .field("repository", &"[CREDENTIAL REPOSITORY]")
            .finish()
    }
}

struct PendingRevocationCommit {
    pending: Box<dyn PendingCredentialCommit>,
}

#[async_trait]
impl PendingCredentialCommit for PendingRevocationCommit {
    async fn replay(&self) -> bool {
        self.pending.replay().await
    }
}

impl fmt::Debug for PendingRevocationCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRevocationCommit")
            .field("pending", &self.pending)
            .finish()
    }
}

struct CorePendingRevocationCommit {
    pending: Box<PendingGithubServerServiceRevocationCommit>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
}

#[async_trait]
impl PendingCredentialCommit for CorePendingRevocationCommit {
    async fn replay(&self) -> bool {
        self.pending.replay(self.repository.as_ref()).await.is_ok()
    }
}

impl fmt::Debug for CorePendingRevocationCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorePendingRevocationCommit")
            .field("pending", &self.pending)
            .field("repository", &"[CREDENTIAL REPOSITORY]")
            .finish()
    }
}

/// Independent bounded custody for irreversible service-credential commits.
struct CredentialMaintenanceCommitSupervisor {
    runtime: Handle,
    retry_interval: Duration,
    permits: Arc<Semaphore>,
    outstanding: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
    custody: Arc<Mutex<Vec<Arc<SupervisedCredentialCommit>>>>,
}

impl CredentialMaintenanceCommitSupervisor {
    fn new(runtime: Handle, retry_interval: Duration, capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "service-credential custody capacity is positive"
        );
        Self {
            runtime,
            retry_interval,
            permits: Arc::new(Semaphore::new(capacity)),
            outstanding: Arc::new(AtomicUsize::new(0)),
            drained: Arc::new(tokio::sync::Notify::new()),
            custody: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        }
    }

    fn try_reserve(&self) -> Option<CredentialMaintenanceCommitReservation> {
        self.redrive_retained();
        self.outstanding.fetch_add(1, Ordering::AcqRel);
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            self.drained.notify_waiters();
            return None;
        };
        Some(CredentialMaintenanceCommitReservation {
            _permit: permit,
            outstanding: Arc::clone(&self.outstanding),
            drained: Arc::clone(&self.drained),
        })
    }

    async fn reserve_until(
        &self,
        deadline: Instant,
    ) -> Option<CredentialMaintenanceCommitReservation> {
        self.redrive_retained();
        let pending = PendingCredentialMaintenanceReservation::new(
            Arc::clone(&self.outstanding),
            Arc::clone(&self.drained),
        );
        let remaining = deadline.checked_duration_since(Instant::now());
        let permit = match remaining {
            Some(remaining) => {
                tokio::time::timeout(remaining, Arc::clone(&self.permits).acquire_owned())
                    .await
                    .ok()
                    .and_then(Result::ok)
            }
            None => None,
        };
        let permit = permit?;
        Some(pending.commit(permit))
    }

    fn supervise(
        &self,
        reservation: CredentialMaintenanceCommitReservation,
        pending: Box<dyn PendingCredentialCommit>,
    ) -> oneshot::Receiver<()> {
        let custody = Arc::new(SupervisedCredentialCommit {
            _reservation: reservation,
            pending: Arc::from(pending),
            task_abort: Mutex::new(None),
            driver_active: Arc::new(AtomicBool::new(false)),
            removed: AtomicBool::new(false),
        });
        {
            let mut retained = self
                .custody
                .lock()
                .expect("service-credential custody lock");
            retained.push(Arc::clone(&custody));
        }

        let (result_sender, result_receiver) = oneshot::channel();
        let started = self.start_driver(&custody, Some(result_sender));
        assert!(started, "new service-credential custody starts one driver");
        result_receiver
    }

    fn start_driver(
        &self,
        custody: &Arc<SupervisedCredentialCommit>,
        result_sender: Option<oneshot::Sender<()>>,
    ) -> bool {
        if custody.removed.load(Ordering::Acquire) {
            return false;
        }
        if custody
            .driver_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if custody.removed.load(Ordering::Acquire) {
            custody.driver_active.store(false, Ordering::Release);
            self.drained.notify_waiters();
            return false;
        }
        let retained = Arc::clone(&self.custody);
        let task_custody = Arc::clone(custody);
        let retry_interval = self.retry_interval;
        let driver_active = CredentialCommitDriverObservation {
            active: Arc::clone(&custody.driver_active),
            drained: Arc::clone(&self.drained),
        };
        let task = self.runtime.spawn(async move {
            let _driver_active = driver_active;
            loop {
                if task_custody.pending.replay().await {
                    break;
                }
                tokio::time::sleep(retry_interval).await;
            }
            task_custody.removed.store(true, Ordering::Release);
            let removed = {
                let mut retained = retained.lock().expect("service-credential custody lock");
                retained
                    .iter()
                    .position(|entry| Arc::ptr_eq(entry, &task_custody))
                    .map(|index| retained.swap_remove(index))
            };
            drop(removed);
            drop(task_custody);
            if let Some(result_sender) = result_sender {
                let _ = result_sender.send(());
            }
        });
        *custody
            .task_abort
            .lock()
            .expect("service-credential task lock") = Some(task.abort_handle());
        true
    }

    fn redrive_retained(&self) {
        let custody = self
            .custody
            .lock()
            .expect("service-credential custody lock")
            .clone();
        for custody in custody {
            let _ = self.start_driver(&custody, None);
        }
    }

    #[cfg(test)]
    fn abort_pending_task(&self) -> bool {
        let custody = self
            .custody
            .lock()
            .expect("service-credential custody lock")
            .first()
            .cloned();
        let Some(custody) = custody else {
            return false;
        };
        let task = custody
            .task_abort
            .lock()
            .expect("service-credential task lock")
            .clone();
        task.is_some_and(|task| {
            task.abort();
            true
        })
    }

    fn close(&self) {
        self.permits.close();
    }

    async fn wait_for_idle(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.redrive_retained();
            if self.outstanding.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    async fn drain(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.wait_for_idle())
            .await
            .is_ok()
    }
}

impl fmt::Debug for CredentialMaintenanceCommitSupervisor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialMaintenanceCommitSupervisor")
            .field("retry_interval", &self.retry_interval)
            .field("outstanding", &self.outstanding.load(Ordering::Acquire))
            .field("available_capacity", &self.permits.available_permits())
            .field(
                "retained_custody_count",
                &self
                    .custody
                    .lock()
                    .expect("service-credential custody lock")
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

struct SupervisedCredentialCommit {
    _reservation: CredentialMaintenanceCommitReservation,
    pending: Arc<dyn PendingCredentialCommit>,
    task_abort: Mutex<Option<tokio::task::AbortHandle>>,
    driver_active: Arc<AtomicBool>,
    removed: AtomicBool,
}

struct CredentialCommitDriverObservation {
    active: Arc<AtomicBool>,
    drained: Arc<tokio::sync::Notify>,
}

impl Drop for CredentialCommitDriverObservation {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        self.drained.notify_waiters();
    }
}

struct CredentialMaintenanceCommitReservation {
    _permit: OwnedSemaphorePermit,
    outstanding: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
}

struct PendingCredentialMaintenanceReservation {
    outstanding: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
    armed: bool,
}

impl PendingCredentialMaintenanceReservation {
    fn new(outstanding: Arc<AtomicUsize>, drained: Arc<tokio::sync::Notify>) -> Self {
        outstanding.fetch_add(1, Ordering::AcqRel);
        Self {
            outstanding,
            drained,
            armed: true,
        }
    }

    fn commit(mut self, permit: OwnedSemaphorePermit) -> CredentialMaintenanceCommitReservation {
        self.armed = false;
        CredentialMaintenanceCommitReservation {
            _permit: permit,
            outstanding: Arc::clone(&self.outstanding),
            drained: Arc::clone(&self.drained),
        }
    }
}

impl Drop for PendingCredentialMaintenanceReservation {
    fn drop(&mut self) {
        if self.armed {
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            self.drained.notify_waiters();
        }
    }
}

struct CredentialMaintenanceCustody {
    supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    reservation: CredentialMaintenanceCommitReservation,
}

impl CredentialMaintenanceCustody {
    fn supervise(self, pending: Box<dyn PendingCredentialCommit>) -> oneshot::Receiver<()> {
        self.supervisor.supervise(self.reservation, pending)
    }
}

impl Drop for CredentialMaintenanceCommitReservation {
    fn drop(&mut self) {
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
        self.drained.notify_waiters();
    }
}

async fn retire_superseded_server_service_authorities(
    repository: &dyn GithubServerServiceAuthorityRepository,
    manifests: &[automata_ci_store::GithubProviderManifest],
    desired: &[automata_ci_store::GithubServerServiceAuthorityIdentity],
    clock: &dyn GithubServerServiceCoordinatorClock,
) -> Result<Vec<GithubServerServiceAuthoritySelector>, GithubProviderRuntimeBuildError> {
    let mut cleanup = Vec::new();
    let mut retirement_plan = Vec::new();
    for manifest in manifests {
        let desired_for_repository = desired
            .iter()
            .filter(|identity| {
                identity.tenant() == manifest.tenant()
                    && identity.repository_id() == manifest.repository_id()
                    && identity.connection_id() == manifest.connection_id()
            })
            .collect::<Vec<_>>();
        let revision_watermark = desired_for_repository
            .first()
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        if desired_for_repository.iter().any(|identity| {
            identity.app_configuration_revision() != revision_watermark.app_configuration_revision()
                || identity.policy_revision() != revision_watermark.policy_revision()
        }) {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
        let existing = repository
            .list_github_server_service_authorities_for_repository(
                manifest.tenant(),
                manifest.repository_id(),
                manifest.connection_id(),
            )
            .await
            .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        for descriptor in existing {
            if desired_for_repository
                .iter()
                .any(|identity| identity.authority_id() == descriptor.identity().authority_id())
            {
                if descriptor.state() != GithubServerServiceAuthorityState::Active {
                    return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
                }
                continue;
            }
            let existing_app_revision = descriptor.identity().app_configuration_revision();
            let existing_policy_revision = descriptor.identity().policy_revision();
            let desired_app_revision = revision_watermark.app_configuration_revision();
            let desired_policy_revision = revision_watermark.policy_revision();
            let is_strictly_older = existing_app_revision <= desired_app_revision
                && existing_policy_revision <= desired_policy_revision
                && (existing_app_revision < desired_app_revision
                    || existing_policy_revision < desired_policy_revision);
            if !is_strictly_older {
                return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
            }
            let selector =
                GithubServerServiceAuthoritySelector::from_identity(descriptor.identity());
            let desired_route = desired_for_repository
                .iter()
                .find(|identity| identity.scope() == descriptor.identity().scope())
                .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
            if !shares_server_service_revocation_route(descriptor.identity(), desired_route) {
                // Installation replacement and App-identity replacement require
                // a retained historical broker route. Schema 4 does not yet
                // authenticate or retain that route, so fail before mutating any
                // superseded authority in this complete validation pass.
                return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
            }
            retirement_plan.push((descriptor, selector));
        }
    }
    for (descriptor, selector) in retirement_plan {
        if descriptor.state() == GithubServerServiceAuthorityState::Active {
            let request = RetireGithubServerServiceAuthority::new(selector.clone(), clock.now())
                .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
            let retired = repository
                .retire_github_server_service_authority(request)
                .await
                .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
            if !matches!(
                retired.state(),
                GithubServerServiceAuthorityState::Retiring
                    | GithubServerServiceAuthorityState::Retired
            ) {
                return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
            }
            if retired.state() == GithubServerServiceAuthorityState::Retired {
                continue;
            }
        } else if descriptor.state() != GithubServerServiceAuthorityState::Retiring {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
        cleanup.push(selector);
    }
    Ok(cleanup)
}

fn shares_server_service_revocation_route(
    existing: &automata_ci_store::GithubServerServiceAuthorityIdentity,
    desired: &automata_ci_store::GithubServerServiceAuthorityIdentity,
) -> bool {
    existing.installation_id() == desired.installation_id()
        && existing.github_app_id() == desired.github_app_id()
        && existing.app_client_id() == desired.app_client_id()
        && existing.jwt_issuer() == desired.jwt_issuer()
        && existing.configuration_fingerprint() == desired.configuration_fingerprint()
}

async fn converge_workflow_permission_authorities(
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    authority_repository: Arc<dyn GithubServerServiceAuthorityRepository>,
    coordinator: Arc<GithubServerServiceCredentialCoordinator>,
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    commit_supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    authorities: &[automata_ci_store::GithubServerServiceAuthorityIdentity],
) -> Result<(), GithubProviderRuntimeBuildError> {
    let targets = authorities
        .iter()
        .filter(|authority| authority.scope() == GithubServerServiceScope::WorkflowPermissionsRead)
        .cloned()
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
    }
    let deadline = Instant::now()
        .checked_add(WORKFLOW_PERMISSION_CREDENTIAL_STARTUP_DEADLINE)
        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    let mut convergence = futures::stream::iter(targets.iter().cloned().map(|authority| {
        converge_workflow_permission_authority(
            repository.clone(),
            authority_repository.clone(),
            coordinator.clone(),
            clock.clone(),
            commit_supervisor.clone(),
            authority,
            deadline,
        )
    }))
    .buffer_unordered(MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY);
    while let Some(result) = convergence.next().await {
        result?;
    }

    // One final bounded snapshot closes a race where a credential became
    // non-current or too close to expiry while another target converged.
    let required_use_through = required_workflow_permission_use_horizon(clock.as_ref())?;
    let mut validation = futures::stream::iter(targets.iter().map(|authority| {
        inspect_workflow_permission_authority_readiness(
            authority_repository.as_ref(),
            authority,
            required_use_through,
            deadline,
        )
    }))
    .buffer_unordered(MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY);
    while let Some(result) = validation.next().await {
        if !result?.ready {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
    }
    Ok(())
}

fn required_workflow_permission_use_horizon(
    clock: &dyn GithubServerServiceCoordinatorClock,
) -> Result<UnixMillis, GithubProviderRuntimeBuildError> {
    let refresh_budget_millis =
        i64::try_from(workflow_permission_refresh_round_budget()?.as_millis())
            .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    clock
        .now()
        .get()
        .checked_add(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
        .and_then(|horizon| horizon.checked_add(refresh_budget_millis))
        .map(UnixMillis::new)
        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)
}

fn workflow_permission_refresh_round_budget() -> Result<Duration, GithubProviderRuntimeBuildError> {
    let half_freshness = automata_ci_store::GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS / 2;
    half_freshness
        .checked_sub(WORKFLOW_PERMISSION_INITIAL_RETRY_JITTER_MARGIN_MILLIS)
        .and_then(|millis| millis.checked_sub(WORKFLOW_PERMISSION_REFRESH_SAFETY_MARGIN_MILLIS))
        // A target can finish at the beginning of one successful round, then
        // move to the tail of both the next failed round and its retry as
        // dynamic concurrency slots refill. Reserve two complete round tails.
        .and_then(|millis| millis.checked_div(2))
        .filter(|millis| *millis > 0)
        .and_then(|millis| u64::try_from(millis).ok())
        .map(Duration::from_millis)
        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)
}

fn workflow_permission_refresh_budgets(
    target_count: usize,
) -> Result<(Duration, Duration), GithubProviderRuntimeBuildError> {
    if target_count == 0 {
        return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
    }
    let round_budget = workflow_permission_refresh_round_budget()?;
    let wave_count = target_count.div_ceil(MAX_WORKFLOW_PERMISSION_OBSERVATION_CONCURRENCY);
    let wave_count = u32::try_from(wave_count)
        .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    let attempt_budget = round_budget
        .checked_div(wave_count)
        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    Ok((round_budget, attempt_budget))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkflowPermissionAuthorityReadiness {
    ready: bool,
    failed_generations: u16,
}

impl WorkflowPermissionAuthorityReadiness {
    const fn observed_new_failure_since(self, previous: Self) -> bool {
        self.failed_generations > previous.failed_generations
    }
}

async fn inspect_workflow_permission_authority_readiness(
    repository: &dyn GithubServerServiceAuthorityRepository,
    authority: &automata_ci_store::GithubServerServiceAuthorityIdentity,
    required_use_through: UnixMillis,
    deadline: Instant,
) -> Result<WorkflowPermissionAuthorityReadiness, GithubProviderRuntimeBuildError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    tokio::time::timeout(remaining, async {
        let descriptor = repository
            .inspect_github_server_service_authority(authority.tenant(), authority.authority_id())
            .await
            .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        if descriptor.identity() != authority
            || descriptor.state() != GithubServerServiceAuthorityState::Active
        {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
        let issuance = repository
            .inspect_current_github_server_service_issuance(
                authority.tenant(),
                authority.authority_id(),
            )
            .await
            .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let ready = descriptor.current_generation().is_some_and(|generation| {
            issuance.is_some_and(|receipt| {
                receipt.key().authority_id() == authority.authority_id()
                    && receipt.key().generation() == generation
                    && receipt.state() == GithubServerServiceIssuanceState::Ready
                    && receipt
                        .usable_until()
                        .is_some_and(|usable_until| usable_until >= required_use_through)
            })
        });
        Ok(WorkflowPermissionAuthorityReadiness {
            ready,
            failed_generations: descriptor.consecutive_generation_failures(),
        })
    })
    .await
    .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?
}

#[allow(clippy::too_many_arguments)]
async fn converge_workflow_permission_authority(
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
    authority_repository: Arc<dyn GithubServerServiceAuthorityRepository>,
    coordinator: Arc<GithubServerServiceCredentialCoordinator>,
    clock: Arc<dyn GithubServerServiceCoordinatorClock>,
    commit_supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    authority: automata_ci_store::GithubServerServiceAuthorityIdentity,
    deadline: Instant,
) -> Result<(), GithubProviderRuntimeBuildError> {
    let selector = GithubServerServiceAuthoritySelector::from_identity(&authority);
    loop {
        let required_use_through = required_workflow_permission_use_horizon(clock.as_ref())?;
        let readiness_before = inspect_workflow_permission_authority_readiness(
            authority_repository.as_ref(),
            &authority,
            required_use_through,
            deadline,
        )
        .await?;
        if readiness_before.ready {
            return Ok(());
        }
        let reservation = commit_supervisor
            .reserve_until(deadline)
            .await
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let custody = CredentialMaintenanceCustody {
            supervisor: commit_supervisor.clone(),
            reservation,
        };
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        let outcome = tokio::time::timeout(
            remaining,
            coordinator.coordinate_authority(selector.clone()),
        )
        .await
        .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?
        .map(|outcome| supervise_credential_coordination(outcome, custody, repository.clone()));
        match outcome {
            Ok(CredentialMaintenanceOutcome::Pending(completion)) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
                tokio::time::timeout(remaining, completion)
                    .await
                    .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?
                    .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
            }
            Ok(CredentialMaintenanceOutcome::Worked | CredentialMaintenanceOutcome::Idle)
            | Err(
                GithubServerServiceCoordinatorError::Repository
                | GithubServerServiceCoordinatorError::EnvelopePreparation,
            ) => {}
            Err(_) => {
                return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
            }
        }
        let readiness_after = inspect_workflow_permission_authority_readiness(
            authority_repository.as_ref(),
            &authority,
            required_workflow_permission_use_horizon(clock.as_ref())?,
            deadline,
        )
        .await?;
        if readiness_after.ready {
            return Ok(());
        }
        if readiness_after.observed_new_failure_since(readiness_before) {
            return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
        }
        sleep_workflow_permission_convergence_retry(deadline).await?;
    }
}

async fn sleep_workflow_permission_convergence_retry(
    deadline: Instant,
) -> Result<(), GithubProviderRuntimeBuildError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    tokio::time::sleep(remaining.min(WORKFLOW_PERMISSION_CREDENTIAL_RETRY_DELAY)).await;
    Ok(())
}

async fn run_credential_maintenance_loop(
    maintenance: Arc<dyn CredentialMaintenancePort>,
    commit_supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    authorities: Arc<[GithubServerServiceAuthoritySelector]>,
    idle_delay: Duration,
    stop: CancellationToken,
) -> Result<(), GithubServerServiceCoordinatorError> {
    let mut sweep = FairSweep::new(authorities);
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let Some(reservation) = commit_supervisor.try_reserve() else {
            if stop.is_cancelled() {
                return Ok(());
            }
            return Err(GithubServerServiceCoordinatorError::Inconsistent);
        };
        let custody = CredentialMaintenanceCustody {
            supervisor: commit_supervisor.clone(),
            reservation,
        };
        let selector = sweep.next();
        match maintenance.coordinate_authority(selector, custody).await {
            Ok(CredentialMaintenanceOutcome::Idle) => {
                if sweep.observe(true) && sleep_or_stop(idle_delay, &stop).await {
                    return Ok(());
                }
            }
            Ok(CredentialMaintenanceOutcome::Worked) => {
                let _ = sweep.observe(false);
            }
            Ok(CredentialMaintenanceOutcome::Pending(completion)) => {
                let _ = sweep.observe(false);
                tokio::select! {
                    biased;
                    result = completion => {
                        result.map_err(|_| GithubServerServiceCoordinatorError::Repository)?;
                    }
                    () = stop.cancelled() => return Ok(()),
                }
            }
            Err(
                GithubServerServiceCoordinatorError::Repository
                | GithubServerServiceCoordinatorError::EnvelopePreparation,
            ) => {
                let _ = sweep.observe(false);
                if sleep_or_stop(idle_delay, &stop).await {
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

async fn run_workflow_permission_refresh_loop(
    refresher: Arc<WorkflowPermissionDefaultsRefresher>,
    stop: CancellationToken,
) -> Result<(), GithubProviderRuntimeBuildError> {
    if refresher.targets.is_empty() {
        return Err(GithubProviderRuntimeBuildError::WorkflowPermissionObservation);
    }
    let owner = refresher.owner;
    drive_workflow_permission_refresh_loop(
        move || {
            let refresher = Arc::clone(&refresher);
            async move { refresher.refresh_all().await }
        },
        owner,
        stop,
    )
    .await
}

fn jittered_workflow_permission_retry_delay(
    base: Duration,
    owner: GithubServerServiceWorkerId,
    attempt: u64,
    maximum: Duration,
) -> Duration {
    let mut seed = attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for byte in owner.as_uuid().as_bytes() {
        seed ^= u64::from(*byte);
        seed = seed.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let maximum_jitter_millis = u64::try_from(base.as_millis() / 4).unwrap_or(u64::MAX - 1);
    let jitter_millis = seed % maximum_jitter_millis.saturating_add(1);
    base.checked_add(Duration::from_millis(jitter_millis))
        .unwrap_or(maximum)
        .min(maximum)
}

async fn drive_workflow_permission_refresh_loop<Refresh, RefreshFuture>(
    mut refresh_all: Refresh,
    owner: GithubServerServiceWorkerId,
    stop: CancellationToken,
) -> Result<(), GithubProviderRuntimeBuildError>
where
    Refresh: FnMut() -> RefreshFuture,
    RefreshFuture:
        Future<Output = Result<WorkflowPermissionRefreshOutcome, GithubProviderRuntimeBuildError>>,
{
    let half_freshness =
        u64::try_from(automata_ci_store::GITHUB_WORKFLOW_PERMISSION_DEFAULT_FRESHNESS_MILLIS / 2)
            .map_err(|_| GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
    let cadence = Duration::from_millis(half_freshness.max(1));
    let mut retry_delay = WORKFLOW_PERMISSION_REFRESH_RETRY_MIN;
    let mut retry_attempt = 0_u64;
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let next_round = tokio::time::Instant::now()
            .checked_add(cadence)
            .ok_or(GithubProviderRuntimeBuildError::WorkflowPermissionObservation)?;
        // Start the first live round immediately, then schedule each successor
        // from the preceding round's start. At most 32 provider calls run at
        // once, leaving headroom below GitHub's shared 100-request concurrency
        // limit while keeping all 256 configured repositories inside half of
        // the durable freshness window. Drain every started attempt so its
        // exact credential release remains under custody.
        let outcome = tokio::select! {
            biased;
            () = stop.cancelled() => return Ok(()),
            outcome = refresh_all() => outcome,
        };
        match outcome {
            Ok(WorkflowPermissionRefreshOutcome::PolicyMismatch) => {
                // A stable configuration mismatch invalidates the durable head.
                // Re-observe on the normal cadence instead of hammering the
                // provider with retries that cannot repair operator policy.
                // Preserve start-to-start cadence so other repositories that
                // were Ready in this mixed round cannot age past their head TTL.
                retry_delay = WORKFLOW_PERMISSION_REFRESH_RETRY_MIN;
                retry_attempt = 0;
                let delay = next_round.saturating_duration_since(tokio::time::Instant::now());
                if sleep_or_stop(delay, &stop).await {
                    return Ok(());
                }
                continue;
            }
            Err(_) => {
                // Admission is independently fail-closed by the durable freshness
                // head. A transient provider or Store outage must not terminate the
                // only process capable of refreshing that head. Exponential,
                // worker-jittered retries stay below the normal half-life cadence
                // and avoid a cross-replica provider request storm.
                let delay = jittered_workflow_permission_retry_delay(
                    retry_delay,
                    owner,
                    retry_attempt,
                    cadence,
                );
                if sleep_or_stop(delay, &stop).await {
                    return Ok(());
                }
                retry_delay = retry_delay
                    .checked_mul(2)
                    .unwrap_or(WORKFLOW_PERMISSION_REFRESH_RETRY_MAX)
                    .min(WORKFLOW_PERMISSION_REFRESH_RETRY_MAX);
                retry_attempt = retry_attempt.saturating_add(1);
                continue;
            }
            Ok(WorkflowPermissionRefreshOutcome::Ready) => {}
        }
        retry_delay = WORKFLOW_PERMISSION_REFRESH_RETRY_MIN;
        retry_attempt = 0;
        let delay = next_round.saturating_duration_since(tokio::time::Instant::now());
        if sleep_or_stop(delay, &stop).await {
            return Ok(());
        }
    }
}

async fn run_job_authority_maintenance_loop(
    coordinator: Arc<GithubRuntimeAuthorityLifecycleCoordinator>,
    idle_delay: Duration,
    stop: CancellationToken,
) -> Result<(), GithubRuntimeAuthorityLifecycleError> {
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        match coordinator.coordinate_once_until_stopped(&stop).await {
            Ok(None) => return Ok(()),
            Ok(Some(outcome)) => {
                let idle = outcome.reconciliation().total() == 0
                    && outcome.revocation() == GithubRuntimeAuthorityRevocationOutcome::Idle;
                if idle && sleep_or_stop(idle_delay, &stop).await {
                    return Ok(());
                }
            }
            Err(
                GithubRuntimeAuthorityLifecycleError::Repository
                | GithubRuntimeAuthorityLifecycleError::SupervisionCapacity,
            ) => {
                if sleep_or_stop(idle_delay, &stop).await {
                    return Ok(());
                }
            }
            Err(error @ GithubRuntimeAuthorityLifecycleError::Inconsistent) => return Err(error),
        }
    }
}

async fn sleep_or_stop(delay: Duration, stop: &CancellationToken) -> bool {
    tokio::select! {
        () = stop.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

#[async_trait]
trait ReleaseDrainPort: fmt::Debug + Send + Sync {
    async fn drain(&self, timeout: Duration) -> bool;
}

#[async_trait]
trait JobRuntimeAuthorityDrainPort: fmt::Debug + Send + Sync {
    fn close(&self);
    async fn drain(&self, timeout: Duration) -> bool;
}

struct JobRuntimeAuthorityDrain {
    mint: Arc<GithubRuntimeAuthorityCommitSupervisor>,
    lifecycle: Arc<GithubRuntimeAuthorityLifecycleSupervisor>,
    service_credentials: Arc<CredentialMaintenanceCommitSupervisor>,
}

#[async_trait]
impl JobRuntimeAuthorityDrainPort for JobRuntimeAuthorityDrain {
    fn close(&self) {
        self.mint.close();
        self.lifecycle.close();
        self.service_credentials.close();
    }

    async fn drain(&self, timeout: Duration) -> bool {
        let (mint, lifecycle, service_credentials) = tokio::join!(
            self.mint.drain(timeout),
            self.lifecycle.drain(timeout),
            self.service_credentials.drain(timeout),
        );
        mint && lifecycle && service_credentials
    }
}

impl fmt::Debug for JobRuntimeAuthorityDrain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobRuntimeAuthorityDrain")
            .field("mint", &self.mint)
            .field("lifecycle", &self.lifecycle)
            .field("service_credentials", &self.service_credentials)
            .finish()
    }
}

#[async_trait]
impl ReleaseDrainPort for GithubProviderCredentialReleaseSupervisor {
    async fn drain(&self, timeout: Duration) -> bool {
        Self::drain(self, timeout).await
    }
}

enum RuntimeLoopExit {
    Delivery(Result<(), GithubDeliveryServiceError>),
    Schedules(Result<(), GithubScheduleServiceError>),
    Checks(Result<(), GithubChecksPublisherError>),
    Credentials(Result<(), GithubServerServiceCoordinatorError>),
    PermissionDefaults(Result<(), GithubProviderRuntimeBuildError>),
    JobAuthority(Result<(), GithubRuntimeAuthorityLifecycleError>),
}

type RuntimeLoopFuture<'a> = Pin<Box<dyn Future<Output = RuntimeLoopExit> + Send + 'a>>;

fn runtime_loop<'a>(
    future: impl Future<Output = RuntimeLoopExit> + Send + 'a,
) -> RuntimeLoopFuture<'a> {
    Box::pin(future)
}

async fn supervise_runtime_loops(
    mut loops: FuturesUnordered<RuntimeLoopFuture<'_>>,
    shutdown: CancellationToken,
    stop: CancellationToken,
    job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort>,
    release_drain: Arc<dyn ReleaseDrainPort>,
    drain_timeout: Duration,
    mut fatal_notification: Option<oneshot::Sender<GithubProviderFatalNotification>>,
) -> Result<(), GithubProviderRuntimeError> {
    let mut first_error = None;
    let mut stopping = shutdown.is_cancelled();
    let mut loop_drain_timed_out = false;
    let mut drain_deadline = stopping.then(|| tokio::time::Instant::now() + drain_timeout);
    if stopping {
        job_authority_drain.close();
        stop.cancel();
    }
    while !loops.is_empty() {
        let exit = if stopping {
            let deadline =
                drain_deadline.expect("a stopping provider runtime always has a drain deadline");
            if let Ok(exit) = tokio::time::timeout_at(deadline, loops.next()).await {
                exit
            } else {
                loop_drain_timed_out = true;
                break;
            }
        } else {
            tokio::select! {
                () = shutdown.cancelled() => {
                    stopping = true;
                    drain_deadline = Some(tokio::time::Instant::now() + drain_timeout);
                    job_authority_drain.close();
                    stop.cancel();
                    continue;
                }
                exit = loops.next() => exit,
            }
        };
        let Some(exit) = exit else {
            break;
        };
        let error = match exit {
            RuntimeLoopExit::Delivery(Ok(()))
            | RuntimeLoopExit::Schedules(Ok(()))
            | RuntimeLoopExit::Checks(Ok(()))
            | RuntimeLoopExit::Credentials(Ok(()))
            | RuntimeLoopExit::PermissionDefaults(Ok(()))
            | RuntimeLoopExit::JobAuthority(Ok(())) => None,
            RuntimeLoopExit::Delivery(Err(error)) => Some(error.into()),
            RuntimeLoopExit::Schedules(Err(error)) => Some(error.into()),
            RuntimeLoopExit::Checks(Err(error)) => Some(error.into()),
            RuntimeLoopExit::Credentials(Err(error)) => Some(error.into()),
            RuntimeLoopExit::PermissionDefaults(Err(_)) => {
                Some(GithubProviderRuntimeError::PermissionDefaults)
            }
            RuntimeLoopExit::JobAuthority(Err(error)) => Some(error.into()),
        };
        let pre_shutdown_exit = !stopping && !shutdown.is_cancelled();
        let mut notify_fatal = false;
        if first_error.is_none() {
            first_error = error.or_else(|| {
                pre_shutdown_exit.then_some(GithubProviderRuntimeError::UnexpectedStop)
            });
            notify_fatal = pre_shutdown_exit && first_error.is_some();
        }
        if !stopping {
            stopping = true;
            drain_deadline = Some(tokio::time::Instant::now() + drain_timeout);
            job_authority_drain.close();
            stop.cancel();
        }
        if notify_fatal && let Some(notification) = fatal_notification.take() {
            let _ = notification.send(GithubProviderFatalNotification);
        }
    }
    job_authority_drain.close();
    let deadline = drain_deadline.unwrap_or_else(|| tokio::time::Instant::now() + drain_timeout);
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if loop_drain_timed_out || remaining.is_zero() || !job_authority_drain.drain(remaining).await {
        return Err(GithubProviderRuntimeError::DrainTimeout);
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() || !release_drain.drain(remaining).await {
        return Err(GithubProviderRuntimeError::DrainTimeout);
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
#[path = "github_provider_runtime_tests.rs"]
mod tests;
