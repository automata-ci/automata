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
    time::{Duration, SystemTime, UNIX_EPOCH},
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
use automata_ci_store::{
    GITHUB_PROVIDER_WEB_ORIGIN, GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId,
    GithubCheckStoreError, GithubJobRuntimeAuthorityRepository,
    GithubRepositoryDispatchEvidenceRepository, GithubRuntimeAuthorityRepository,
    GithubRuntimeAuthorityWorkerId, GithubScheduleWorkerId, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityRepository, GithubServerServiceJwtIssuer,
    GithubServerServiceScope, GithubServerServiceWorkerId, GithubSubjectEvidenceRepository,
    LogicalWorkflowAdmissionRepository, ProviderConnectionId, ProviderDeliveryClaimOwnerId,
    ProviderRepositoryVisibility, TenantScope,
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
    GithubProviderTransport, MAX_GITHUB_PROVIDER_SUPERVISED_RELEASES,
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
const MAX_SUPERVISED_JOB_AUTHORITY_COMMITS: usize = 1_024;
const MAX_SUPERVISED_SERVICE_CREDENTIAL_COMMITS: usize = 1;

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

    /// Returns the number of distinct tenants in the fair maintenance sweep.
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
        if connection_ids.is_empty() || tenants.is_empty() {
            return Err(GithubProviderRuntimeBuildError::InvalidConfiguration);
        }

        for policy in plan.runner_policies() {
            blobs
                .put_if_absent(policy.clone())
                .await
                .map_err(|_| GithubProviderRuntimeBuildError::RunnerPolicyUnavailable)?;
        }

        let ready = plan.bootstrap(store.as_ref(), applied_at).await?;
        let credential_request_resolver = ready.credential_request_resolver();
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
        let credential_issuer = Arc::new(GithubServerServiceCredentialIssuer::new(
            credential_repository.clone(),
            envelopes,
            credential_clock.clone(),
        ));
        let releases = Arc::new(GithubProviderCredentialReleaseSupervisor::new(
            credential_clock,
            runtime_handle,
            policy.release_capacity,
            policy.release_retry_interval,
        )?);
        let adapters = Arc::new(GithubProviderCredentialAdapters::new(
            credential_issuer,
            credential_repository.clone(),
            credential_authority_repository,
            releases.clone(),
            plan.authorities(),
            credential_adapter_routes,
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

        let checks_credentials: Arc<dyn GithubChecksCredentialProvider> = adapters;
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
            credential_commit_supervisor,
            job_authority_maintenance,
            job_authority_drain,
            job_runtime_authority_issuer,
            release_drain,
            connection_ids,
            tenants,
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

fn provider_http_endpoint(
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
    credential_commit_supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    job_authority_maintenance: Arc<GithubRuntimeAuthorityLifecycleCoordinator>,
    job_authority_drain: Arc<dyn JobRuntimeAuthorityDrainPort>,
    job_runtime_authority_issuer: Arc<dyn OptionalRuntimeAuthorityIssuer>,
    release_drain: Arc<dyn ReleaseDrainPort>,
    connection_ids: Arc<[ProviderConnectionId]>,
    tenants: Arc<[TenantScope]>,
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
            credential_commit_supervisor,
            job_authority_maintenance,
            job_authority_drain,
            job_runtime_authority_issuer: _,
            release_drain,
            connection_ids,
            tenants,
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
        let maintenance_tenants = tenants;
        let maintenance_delay = idle_delay;
        let maintenance_stop = stop.clone();
        loops.push(runtime_loop(async move {
            RuntimeLoopExit::Credentials(
                run_credential_maintenance_loop(
                    maintenance,
                    credential_commit_supervisor,
                    maintenance_tenants,
                    maintenance_delay,
                    maintenance_stop,
                )
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
            .field("tenant_count", &self.tenants.len())
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
    async fn coordinate_next(
        &self,
        tenant: TenantScope,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError>;
}

struct ServerServiceCredentialMaintenance {
    coordinator: Arc<GithubServerServiceCredentialCoordinator>,
    repository: Arc<dyn GithubServerServiceCredentialRepository>,
}

#[async_trait]
impl CredentialMaintenancePort for ServerServiceCredentialMaintenance {
    async fn coordinate_next(
        &self,
        tenant: TenantScope,
        custody: CredentialMaintenanceCustody,
    ) -> Result<CredentialMaintenanceOutcome, GithubServerServiceCoordinatorError> {
        let outcome = self.coordinator.coordinate_next(tenant).await?;
        Ok(match outcome {
            GithubServerServiceCoordinationOutcome::Idle => CredentialMaintenanceOutcome::Idle,
            GithubServerServiceCoordinationOutcome::MintCommitPending(pending) => {
                CredentialMaintenanceOutcome::Pending(custody.supervise(Box::new(
                    PendingMintCommit {
                        pending: Box::new(CorePendingMintCommit {
                            pending,
                            repository: self.repository.clone(),
                        }),
                    },
                )))
            }
            GithubServerServiceCoordinationOutcome::RevocationCommitPending(pending) => {
                CredentialMaintenanceOutcome::Pending(custody.supervise(Box::new(
                    PendingRevocationCommit {
                        pending: Box::new(CorePendingRevocationCommit {
                            pending,
                            repository: self.repository.clone(),
                        }),
                    },
                )))
            }
            GithubServerServiceCoordinationOutcome::Reduced { .. }
            | GithubServerServiceCoordinationOutcome::MintAlreadyStarted(_)
            | GithubServerServiceCoordinationOutcome::MintStartedWindowExhausted(_) => {
                CredentialMaintenanceOutcome::Worked
            }
        })
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

/// Independent bounded custody for the one serialized service-credential commit.
struct CredentialMaintenanceCommitSupervisor {
    runtime: Handle,
    retry_interval: Duration,
    permits: Arc<Semaphore>,
    outstanding: Arc<AtomicUsize>,
    drained: Arc<tokio::sync::Notify>,
    custody: Arc<Mutex<Option<Arc<SupervisedCredentialCommit>>>>,
}

impl CredentialMaintenanceCommitSupervisor {
    fn new(runtime: Handle, retry_interval: Duration) -> Self {
        Self {
            runtime,
            retry_interval,
            permits: Arc::new(Semaphore::new(MAX_SUPERVISED_SERVICE_CREDENTIAL_COMMITS)),
            outstanding: Arc::new(AtomicUsize::new(0)),
            drained: Arc::new(tokio::sync::Notify::new()),
            custody: Arc::new(Mutex::new(None)),
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
            assert!(
                retained.is_none(),
                "a bounded service-credential permit admits only one exact request"
            );
            *retained = Some(Arc::clone(&custody));
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
                if retained
                    .as_ref()
                    .is_some_and(|entry| Arc::ptr_eq(entry, &task_custody))
                {
                    retained.take()
                } else {
                    None
                }
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
        if let Some(custody) = custody {
            let _ = self.start_driver(&custody, None);
        }
    }

    #[cfg(test)]
    fn abort_pending_task(&self) -> bool {
        let custody = self
            .custody
            .lock()
            .expect("service-credential custody lock")
            .clone();
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
                "retained_custody",
                &self
                    .custody
                    .lock()
                    .expect("service-credential custody lock")
                    .is_some(),
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

async fn run_credential_maintenance_loop(
    maintenance: Arc<dyn CredentialMaintenancePort>,
    commit_supervisor: Arc<CredentialMaintenanceCommitSupervisor>,
    tenants: Arc<[TenantScope]>,
    idle_delay: Duration,
    stop: CancellationToken,
) -> Result<(), GithubServerServiceCoordinatorError> {
    let mut sweep = FairSweep::new(tenants);
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
        let tenant = sweep.next();
        match maintenance.coordinate_next(tenant, custody).await {
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
            | RuntimeLoopExit::JobAuthority(Ok(())) => None,
            RuntimeLoopExit::Delivery(Err(error)) => Some(error.into()),
            RuntimeLoopExit::Schedules(Err(error)) => Some(error.into()),
            RuntimeLoopExit::Checks(Err(error)) => Some(error.into()),
            RuntimeLoopExit::Credentials(Err(error)) => Some(error.into()),
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
