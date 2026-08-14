use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use automata_ci_auth::{
    authorization::AuthorizationContext,
    github::GithubEndpoints,
    human::{ProviderSubject, TenantId},
    installation::{InstallationRepository, InstallationRepositoryError, InstallationState},
    login::LoginReturnPath,
    machine::MachineIdentityVerifier,
    secret::SecretString,
    session::SessionKind,
    time::{Clock, SystemClock},
};
use automata_ci_auth_postgres::{
    PostgresDelegatedActorResolver, PostgresHumanRbacManagementRepository,
};
use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType};
use automata_ci_blob_s3::{
    S3BlobStore, S3BlobStoreConfig, S3BlobStoreConfigError, StaticS3Credentials,
};
use automata_ci_control::{
    LeaseClock, LeaseIdGenerator, LeasePollConfig, RandomLeaseIdGenerator, SystemLeaseClock,
};
use automata_ci_control_plane::{DeterministicScheduler, SchedulerPolicy};
use automata_ci_core::RunId;
use automata_ci_github::MAX_GITHUB_WEBHOOK_SECRET_BYTES;
use automata_ci_key_management::KeyEncryptionProvider;
use automata_ci_protocol::ProtocolLimits;
use automata_ci_provisioning::{ProvisioningWorkloadAuthenticator, WorkspaceProvisioner};
use automata_ci_provisioning_grpc::{ManagementGrpcServer, ManagementServerTlsConfig};
use automata_ci_provisioning_postgres::PostgresWorkspaceProvisioner;
use automata_ci_results_github::{
    ArtifactRepository, ArtifactService, CacheLimits, CacheRepository, CacheService,
    GithubCacheApi, GithubCacheHttpLimits, GithubResultsApi, GithubResultsHttpLimits,
    GithubResultsRuntimeAuthorityIssuer, HmacResultsAuthority, HmacResultsAuthorityConfig,
    ObservedResultsArtifactRepository, ObservedResultsBlobStore, PostgresArtifactRepository,
    PostgresCacheRepository, ResultsClock, ResultsIdGenerator, ResultsLimits, ResultsObserver,
    SystemResultsClock, SystemResultsIdGenerator,
};
use automata_ci_runner_auth::{DurableRunnerMachineAuthenticator, RunnerMachineAuthLimits};
use automata_ci_runner_auth_postgres::PostgresRunnerMachineDirectory;
use automata_ci_runner_control::{
    ControlIdGenerator, DurableRunnerControlHandler, ImmutableBlobJobIrReader, JobIrObjectReader,
    LeaseOfferCommandPublisher, LeasePollAdapter, LeasePoller, ManagedSecretBindingIssuer,
    RandomControlIdGenerator, RunnerControlConfig, RunnerControlPorts, RunnerDurabilityPorts,
    RunnerIdentityPorts, RunnerLeasePorts, RunnerRegistrationAuthorizer,
    RunnerSessionFenceResolver, StoreLeaseOfferCommandPublisher, StoreRunnerSessionFenceResolver,
};
use automata_ci_runner_transport::{
    ConfigurationError as TransportConfigurationError, RunnerControlHandler, RunnerControlServer,
    ServerTlsConfig, TransportLimits,
};
use automata_ci_secret::{SecretProvider, SecretProviderRegistry};
use automata_ci_secret_postgres::PostgresSecretProvider;
use automata_ci_store::{
    BuiltinSecretCleanupRepository, ConformanceReadRepository, ControlPlaneMaintenanceRepository,
    ControlPlaneStateRepository, CurrentRunnerSessionRepository, HumanWorkflowReadRepository,
    LogicalActivationPreparationStore, LogicalActivationRepository, LogicalActivationWorkerId,
    LogicalInstanceResultRepository, LogicalInstanceResultWorkerId, LogicalJobResultRepository,
    LogicalJobResultWorkerId, LogicalMaterializationRepository, LogicalMaterializationWorkerId,
    LogicalRunFinalizationRepository, LogicalRunFinalizationWorkerId,
    LogicalWorkSelectionRepository, LogicalWorkflowAdmissionRepository,
    ManagedSecretAuthorityRepository, PostgresSecretCustodyRepository,
    PostgresSecretManagementRepository, PostgresStore, PostgresStoreError,
    ProtectedEnvironmentRepository, RepositoryPublicationRepository,
    RepositorySecretManagementReadRepository, RepositorySecretManagementRepository,
    ReusableWorkflowRuntimeRepository, RunnerCapabilityAdmissionRepository as _,
    RunnerCapabilityReadiness, RunnerCommandOutbox, RunnerControlTransactionRepository,
    RunnerLeaseOfferRepository, RunnerLeaseRequestRepository, RunnerOperationReceiptRepository,
    RunnerSessionRepository, SecretCleanupWorkerId, SecretCustodyKeySet, SecretCustodyRepository,
    SecretMutationRecoveryRepository, TenantScope, WorkflowRerunRepository,
};
use automata_ci_workflow_service::{
    AdmissionClock, AutonomousWorkflowPhaseExecutor, AutonomousWorkflowService,
    GithubAutonomousWorkflowPhaseExecutor, GithubWorkflowDispatchService,
    GithubWorkflowPlanVerifier, LogicalResultProjectionService, LogicalRunFinalizationService,
    ReusableWorkflowRuntimeService, SystemAdmissionClock, WorkflowAdmissionObserver,
    WorkflowAdmissionService, WorkflowRerunService,
};
use axum::Router;
use bytes::Bytes;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use thiserror::Error;
use tokio::net::TcpListener;

use super::github_job_runtime_authority::unavailable_github_job_runtime_authority_issuer;
use super::github_oidc::{
    GithubOidcProductError, build_github_oidc_product, compose_runtime_authority_issuer,
};
use super::state_metrics::ControlPlaneStateSampler;
use super::{
    ControlPlaneMaintenanceLoop, ControlPlaneMetrics, GithubProviderRuntime,
    GithubProviderRuntimeBuildError, GithubProviderRuntimeBuilder, MaintenanceClock,
    MaintenanceLoopConfigError, Readiness, ReadinessMonitor, ReadinessMonitorError, ReadinessProbe,
    ReadinessProbeError, SecretEncryptionLoadError, SecretLoadError, ServerConfig,
    SystemMaintenanceClock,
};
use crate::app::{
    conformance_api::{conformance_api_router, deployment_conformance_api_router},
    delegated_actor_api::{
        DelegatedActorVerifier, DelegatedActorVerifierConfig, router as delegated_actor_api_router,
    },
    github_auth::{
        GithubAuthHttpState, GithubProviderOrigin, GithubSetupHttpState,
        OperationalGithubAuthBackend, router as github_auth_router,
        setup_router as github_setup_router,
    },
    human_auth_middleware::HumanRequestAuthentication,
    management_api::management_api_router,
    protected_environment_review_api::{
        ProtectedEnvironmentReviewApiBackend, protected_environment_review_api_router,
    },
    publication_settings::publication_settings_router,
    repository_secrets::{
        OperationalRepositorySecretWebData, RepositorySecretWebData,
        repository_secret_browser_router,
    },
    runner_enrollment_api::{RunnerCertificateIssuer, runner_enrollment_api_router},
    secret_api::{RepositorySecretApiBackend, repository_secret_api_router},
    web::{
        LiveWebData, ManagementRbacWebData, RbacWebData, RequestContext, SetupPageAvailability,
        SetupPageAvailabilityError, SetupPageAvailabilityState, WebData,
    },
    workflow_dispatch_api::{WorkflowDispatchApiBackend, workflow_dispatch_api_router},
    workflow_rerun_api::{WorkflowRerunApiBackend, workflow_rerun_api_router},
};

use super::human_auth::HumanAuthRuntime;
use super::installation_setup::InstallationSetupService;
use super::managed_secret_delivery::{
    LeasedManagedSecretBindingIssuer, ManagedSecretRunnerHandler,
};
use super::protected_environment_gate::ProtectedEnvironmentLeaseGate;
use super::protected_environment_review::OperationalProtectedEnvironmentReviewBackend;
use super::provisioning_workload_auth::PinnedProvisioningWorkloadAuthenticator;
use super::secret_cleanup::{
    BuiltinSecretCleanupLoop, BuiltinSecretCleanupPorts, SecretCleanupClock,
    SystemSecretCleanupClock,
};
use super::secret_custody::SecretCustodyVerifier;
use super::secret_management::OperationalRepositorySecretBackend;
use super::secret_mutation_recovery::{SecretMutationRecoveryLoop, SecretMutationRecoveryPorts};
use super::workflow_dispatch::OperationalWorkflowDispatchBackend;
use super::workflow_rerun::OperationalWorkflowRerunBackend;

const MAX_TLS_CERTIFICATES: usize = 32;
const MAX_TLS_CERTIFICATE_DER_BYTES: usize = 1024 * 1024;
const MAX_TLS_CHAIN_DER_BYTES: usize = 4 * 1024 * 1024;
const READINESS_OBJECT_KEY: &str = "system/readiness/v1";
const READINESS_MEDIA_TYPE: &str = "application/vnd.automata.readiness+plain";
const READINESS_BYTES: &[u8] = b"automata-immutable-readiness-v1\n";
const RESULTS_ISSUER: &str = "automata";
const RESULTS_AUDIENCE: &str = "github-actions-results";
const RESULTS_RUNTIME_TOKEN_VALIDITY_SECONDS: u64 = 6 * 60 * 60;
const RESULTS_UPLOAD_CAPABILITY_VALIDITY_SECONDS: u64 = 15 * 60;
const RESULTS_ALLOWED_CLOCK_SKEW_SECONDS: u64 = 60;
const SECRET_CLEANUP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const SECRET_CLEANUP_STALE_AFTER: Duration = Duration::from_mins(15);
const MAX_GITHUB_APP_PRIVATE_KEY_PEM_BYTES: usize = 32 * 1_024;

pub(crate) struct ProductionComponents {
    pub(crate) runner_server: RunnerControlServer,
    pub(crate) management_server: Option<ManagementGrpcServer>,
    pub(crate) readiness_monitor: ReadinessMonitor,
    pub(crate) maintenance_loop: ControlPlaneMaintenanceLoop,
    pub(crate) logical_run_finalization: LogicalRunFinalizationService,
    pub(crate) logical_result_projection: LogicalResultProjectionService,
    pub(crate) autonomous_workflow: AutonomousWorkflowService,
    pub(crate) reusable_workflow_runtime: ReusableWorkflowRuntimeService,
    pub(crate) secret_cleanup_loop: Option<BuiltinSecretCleanupLoop>,
    pub(crate) secret_mutation_recovery_loop: Option<SecretMutationRecoveryLoop>,
    pub(crate) state_sampler: ControlPlaneStateSampler,
    pub(crate) human_api: Router,
    pub(crate) delegated_actor_api: Option<Router>,
    pub(crate) human_request_authentication: Option<HumanRequestAuthentication>,
    pub(crate) rbac_web_data: Option<Arc<dyn RbacWebData>>,
    pub(crate) setup_page_availability: Option<Arc<dyn SetupPageAvailability>>,
    pub(crate) github_provider: Option<GithubProviderRuntime>,
    pub(crate) results_api: Router,
    pub(crate) web_data: Arc<dyn WebData>,
    pub(crate) web_fallback_context: RequestContext,
}

impl fmt::Debug for ProductionComponents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionComponents")
            .field("runner_server", &self.runner_server)
            .field("management_server", &self.management_server)
            .field("readiness_monitor", &self.readiness_monitor)
            .field("maintenance_loop", &self.maintenance_loop)
            .field("logical_run_finalization", &self.logical_run_finalization)
            .field("logical_result_projection", &self.logical_result_projection)
            .field("autonomous_workflow", &"[CONFIGURED]")
            .field("reusable_workflow_runtime", &self.reusable_workflow_runtime)
            .field("secret_cleanup_loop", &self.secret_cleanup_loop)
            .field(
                "secret_mutation_recovery_loop",
                &self.secret_mutation_recovery_loop,
            )
            .field("state_sampler", &self.state_sampler)
            .field("human_api", &self.human_api)
            .field("delegated_actor_api", &self.delegated_actor_api)
            .field(
                "human_request_authentication",
                &self.human_request_authentication,
            )
            .field("rbac_web_data", &self.rbac_web_data)
            .field("setup_page_availability", &self.setup_page_availability)
            .field(
                "github_provider",
                &self
                    .github_provider
                    .as_ref()
                    .map(GithubProviderRuntime::shape),
            )
            .field("results_api", &self.results_api)
            .field("web_data", &self.web_data)
            .field("web_fallback_context", &self.web_fallback_context)
            .finish()
    }
}

impl ProductionComponents {
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn initialize(
        config: &ServerConfig,
        runner_listener: TcpListener,
        management_listener: Option<TcpListener>,
        readiness: &Readiness,
        metrics: &ControlPlaneMetrics,
    ) -> Result<Self, ServerCompositionError> {
        let tls = load_server_tls(config)?;
        let blob_store = build_blob_store(config)?;
        let DatabaseBuild {
            store,
            control_plane_key_provider,
        } = connect_database(config).await?;
        let store = Arc::new(store);
        // Schema changes are a startup transition, not a liveness probe. Running
        // the migrator on every readiness tick repeatedly acquires migration
        // locks and emits expected duplicate-table diagnostics under SQLx.
        store.migrate().await?;
        let delegated_actor_api = config
            .management()
            .map(|management| -> Result<Router, ServerCompositionError> {
                let verifier = DelegatedActorVerifier::new(DelegatedActorVerifierConfig {
                    issuer: management
                        .authority()
                        .delegated_actor_issuer()
                        .as_str()
                        .to_owned(),
                    audience: management.authority().shard_id().as_str().to_owned(),
                    jwks_url: management.delegated_actor_jwks_url().clone(),
                })
                .map_err(|_| ServerCompositionError::InvalidManagementConfiguration)?;
                let resolver: Arc<dyn automata_ci_auth::delegated_actor::DelegatedActorResolver> =
                    Arc::new(PostgresDelegatedActorResolver::new(
                        store.postgres_pool().clone(),
                    ));
                Ok(delegated_actor_api_router(Arc::new(verifier), resolver))
            })
            .transpose()?;
        let management_server =
            build_management_server(config, management_listener, store.as_ref())?;
        let workflow_clock: Arc<dyn AdmissionClock> = Arc::new(SystemAdmissionClock);
        let logical_run_finalization_repository: Arc<dyn LogicalRunFinalizationRepository> =
            store.clone();
        let logical_run_finalization_worker =
            LogicalRunFinalizationWorkerId::from_uuid(RunId::new().as_uuid())
                .map_err(|_| ServerCompositionError::InvalidLogicalRunFinalizationWorker)?;
        let logical_run_finalization = LogicalRunFinalizationService::new(
            logical_run_finalization_repository,
            Arc::clone(&workflow_clock),
            logical_run_finalization_worker,
        );
        let logical_instance_results: Arc<dyn LogicalInstanceResultRepository> = store.clone();
        let logical_job_results: Arc<dyn LogicalJobResultRepository> = store.clone();
        let logical_instance_result_worker =
            LogicalInstanceResultWorkerId::from_uuid(RunId::new().as_uuid())
                .map_err(|_| ServerCompositionError::InvalidLogicalResultProjectionWorker)?;
        let logical_job_result_worker = LogicalJobResultWorkerId::from_uuid(RunId::new().as_uuid())
            .map_err(|_| ServerCompositionError::InvalidLogicalResultProjectionWorker)?;
        let logical_result_projection = LogicalResultProjectionService::new(
            Arc::clone(&blob_store),
            logical_instance_results,
            logical_job_results,
            Arc::clone(&workflow_clock),
            logical_instance_result_worker,
            logical_job_result_worker,
            ProtocolLimits::default(),
        );
        let workflow_selections: Arc<dyn LogicalWorkSelectionRepository> = store.clone();
        let workflow_preparations: Arc<dyn LogicalActivationPreparationStore> = store.clone();
        let workflow_activations: Arc<dyn LogicalActivationRepository> = store.clone();
        let workflow_materializations: Arc<dyn LogicalMaterializationRepository> = store.clone();
        let workflow_executor: Arc<dyn AutonomousWorkflowPhaseExecutor> =
            Arc::new(GithubAutonomousWorkflowPhaseExecutor::with_limits(
                Arc::clone(&blob_store),
                Arc::clone(&workflow_preparations),
                Arc::clone(&workflow_activations),
                Arc::clone(&workflow_materializations),
                Arc::clone(&workflow_clock),
                ProtocolLimits::default(),
            ));
        let logical_activation_worker =
            LogicalActivationWorkerId::from_uuid(RunId::new().as_uuid())
                .map_err(|_| ServerCompositionError::InvalidAutonomousWorkflowWorker)?;
        let logical_materialization_worker =
            LogicalMaterializationWorkerId::from_uuid(RunId::new().as_uuid())
                .map_err(|_| ServerCompositionError::InvalidAutonomousWorkflowWorker)?;
        let autonomous_workflow = AutonomousWorkflowService::new(
            workflow_selections,
            workflow_preparations,
            workflow_activations,
            workflow_materializations,
            workflow_executor,
            Arc::clone(&workflow_clock),
            logical_activation_worker,
            logical_materialization_worker,
        );
        let reusable_workflow_repository: Arc<dyn ReusableWorkflowRuntimeRepository> =
            store.clone();
        let reusable_workflow_runtime = ReusableWorkflowRuntimeService::with_limits(
            reusable_workflow_repository,
            Arc::clone(&blob_store),
            ProtocolLimits::default(),
        );
        let github_oidc = build_github_oidc_product(config.github_oidc(), store.as_ref()).await?;
        let capability_readiness = if github_oidc.operationally_ready() {
            RunnerCapabilityReadiness::unavailable().with_github_oidc()
        } else {
            RunnerCapabilityReadiness::unavailable()
        };
        verify_runner_capability_readiness(store.as_ref(), capability_readiness).await?;
        let state_repository: Arc<dyn ControlPlaneStateRepository> = store.clone();
        let state_sampler = metrics.state_sampler(state_repository);

        // Retain the human-read and immutable-object ports before the concrete
        // adapters are moved into runner-control composition below.
        let human_reads: Arc<dyn HumanWorkflowReadRepository> = store.clone();
        let fallback_tenant = TenantId::new(config.fallback_tenant_id.clone())
            .map_err(|_| ServerCompositionError::InvalidFallbackTenant)?;
        let web_fallback_context = RequestContext::new(
            fallback_tenant.clone(),
            AuthorizationContext::anonymous(),
            None,
            None,
        )
        .map_err(|_| ServerCompositionError::InvalidFallbackTenant)?;

        let secret_build = build_secret_management(config, store.as_ref()).await?;
        let secret_management = secret_build.runtime;
        let repository_secret_web: Option<Arc<dyn RepositorySecretWebData>> =
            secret_management.as_ref().map(|management| {
                let data: Arc<dyn RepositorySecretWebData> =
                    Arc::new(OperationalRepositorySecretWebData::new(
                        Arc::clone(&management.backend),
                        Arc::clone(&management.read_repository),
                        Arc::clone(&human_reads),
                        Arc::clone(&management.clock),
                    ));
                data
            });
        let mut human = build_human_api(
            config,
            store.clone(),
            blob_store.clone(),
            metrics,
            secret_management.as_ref(),
            repository_secret_web.clone(),
            fallback_tenant,
            capability_readiness,
        )
        .await?;
        let github_provider_config = validate_effective_ui_tenant(config, &human.effective_tenant)?;
        let managed_secret_tenant =
            TenantScope::from_authenticated_tenant_id(human.effective_tenant.as_str().to_owned())
                .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
        let github_provider = build_github_provider_runtime(
            github_provider_config,
            Arc::clone(&store),
            Arc::clone(&blob_store),
            control_plane_key_provider,
            metrics,
        )
        .await?;
        if github_provider.is_some() {
            let admission_repository: Arc<dyn LogicalWorkflowAdmissionRepository> = store.clone();
            let admission = WorkflowAdmissionService::with_system_ports(
                Arc::clone(&blob_store),
                admission_repository,
                Arc::new(GithubWorkflowPlanVerifier::new()),
            )
            .with_observer(Arc::new(metrics.clone()));
            let dispatch_backend: Arc<dyn WorkflowDispatchApiBackend> =
                Arc::new(OperationalWorkflowDispatchBackend::new(
                    GithubWorkflowDispatchService::new(admission),
                ));
            let dispatch_clock: Arc<dyn Clock> = Arc::new(SystemClock);
            human.router = human.router.merge(workflow_dispatch_api_router(
                dispatch_backend,
                dispatch_clock,
            ));
        }
        let github_job_runtime_authority_issuer = github_provider.as_ref().map_or_else(
            unavailable_github_job_runtime_authority_issuer,
            GithubProviderRuntime::job_runtime_authority_issuer,
        );
        let readiness_monitor = build_readiness_monitor(
            config,
            Arc::clone(&store),
            &blob_store,
            Arc::clone(&secret_build.custody),
            readiness,
            metrics,
        )
        .await?;

        let live_web_data = LiveWebData::new(Arc::clone(&human_reads), Arc::clone(&blob_store));
        let live_web_data = if let Some(secrets) = repository_secret_web.as_ref() {
            live_web_data.with_repository_secrets(Arc::clone(secrets))
        } else {
            live_web_data
        };
        let web_data: Arc<dyn WebData> = Arc::new(live_web_data);
        let maintenance_loop = build_maintenance_loop(config, store.clone(), metrics)?;
        let (results_api, results_runtime_authority_issuer) =
            build_results(config, store.as_ref(), blob_store.clone(), metrics)?;
        let runtime_authority_issuer = compose_runtime_authority_issuer(
            results_runtime_authority_issuer,
            github_oidc.authority_issuer,
            github_job_runtime_authority_issuer,
        )
        .map_err(|_| ServerCompositionError::InvalidResultsConfiguration)?;
        let results_api = results_api.merge(github_oidc.router);

        let directory = Arc::new(PostgresRunnerMachineDirectory::new(
            store.postgres_pool().clone(),
        ));
        let auth_clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let authenticator = Arc::new(DurableRunnerMachineAuthenticator::new(
            directory,
            auth_clock,
            RunnerMachineAuthLimits::default(),
        ));

        let lease_clock: Arc<dyn LeaseClock> = Arc::new(SystemLeaseClock);
        let lease_ids: Arc<dyn LeaseIdGenerator> = Arc::new(RandomLeaseIdGenerator);
        let control_ids: Arc<dyn ControlIdGenerator> = Arc::new(RandomControlIdGenerator);
        let scheduler: Arc<dyn SchedulerPolicy> = Arc::new(DeterministicScheduler);

        let protected_environment_repository: Arc<dyn ProtectedEnvironmentRepository> =
            store.clone();
        let protected_environment_gate = Arc::new(ProtectedEnvironmentLeaseGate::new(
            Arc::clone(&protected_environment_repository),
            managed_secret_tenant.clone(),
        ));
        let lease_repository: Arc<dyn automata_ci_control::LeasePollRepository> = store.clone();
        let lease_poller: Arc<dyn LeasePoller> = Arc::new(
            LeasePollAdapter::new(
                lease_repository,
                scheduler,
                Arc::clone(&lease_clock),
                lease_ids,
                LeasePollConfig::default(),
            )
            .with_attempt_gate(protected_environment_gate)
            .with_observer(Arc::new(metrics.clone())),
        );
        let sessions: Arc<dyn RunnerSessionRepository> = store.clone();
        let current_sessions: Arc<dyn CurrentRunnerSessionRepository> = store.clone();
        let fence_resolver: Arc<dyn RunnerSessionFenceResolver> =
            Arc::new(StoreRunnerSessionFenceResolver::new(current_sessions));
        let lease_offer_repository: Arc<dyn RunnerLeaseOfferRepository> = store.clone();
        let lease_offers: Arc<dyn LeaseOfferCommandPublisher> = Arc::new(
            StoreLeaseOfferCommandPublisher::new(lease_offer_repository, Arc::clone(&control_ids)),
        );
        let job_ir_objects: Arc<dyn JobIrObjectReader> =
            Arc::new(ImmutableBlobJobIrReader::new(blob_store.clone()));
        let ingress_objects: Arc<dyn ImmutableBlobStore> = blob_store;
        let transactions: Arc<dyn RunnerControlTransactionRepository> = store.clone();
        let receipts: Arc<dyn RunnerOperationReceiptRepository> = store.clone();
        let lease_requests: Arc<dyn RunnerLeaseRequestRepository> = store.clone();
        let command_outbox: Arc<dyn RunnerCommandOutbox> = store.clone();
        let authorizer: Arc<dyn RunnerRegistrationAuthorizer> = authenticator.clone();
        let managed_secret_binding_issuer: Option<Arc<dyn ManagedSecretBindingIssuer>> =
            if secret_build.delivery_provider.is_some() {
                Some(Arc::new(LeasedManagedSecretBindingIssuer::new(
                    protected_environment_repository,
                    managed_secret_tenant,
                )))
            } else {
                None
            };

        let control_config = RunnerControlConfig::default();
        let ports = RunnerControlPorts::new(
            RunnerIdentityPorts::new(authorizer, fence_resolver, sessions),
            RunnerLeasePorts::new(lease_poller, job_ir_objects, lease_offers),
            RunnerDurabilityPorts::new(
                ingress_objects,
                transactions,
                receipts,
                lease_requests,
                command_outbox,
            ),
            lease_clock,
            control_ids,
        )
        .with_runtime_authority_issuer(runtime_authority_issuer);
        let ports = if let Some(issuer) = managed_secret_binding_issuer {
            ports.with_managed_secret_binding_issuer(issuer)
        } else {
            ports
        };
        let handler: Arc<dyn RunnerControlHandler> = Arc::new(
            DurableRunnerControlHandler::new(ports, control_config)
                .with_observer(Arc::new(metrics.clone())),
        );
        let verifier: Arc<dyn MachineIdentityVerifier> = authenticator;
        let runner_server = RunnerControlServer::new(
            runner_listener,
            &tls,
            verifier,
            handler,
            ProtocolLimits::default(),
            TransportLimits::default(),
        )?
        .with_observer(Arc::new(metrics.clone()));
        let runner_server = if let Some(provider) = secret_build.delivery_provider {
            let repository: Arc<dyn ManagedSecretAuthorityRepository> = store.clone();
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let handler = ManagedSecretRunnerHandler::new(
                repository,
                provider,
                Arc::clone(&secret_build.custody),
                clock,
            )
            .ok_or(ServerCompositionError::InvalidSecretManagement)?;
            runner_server.with_ephemeral_handler(
                config
                    .runner_public_authority
                    .clone()
                    .ok_or(ServerCompositionError::InvalidSecretManagement)?,
                Arc::new(handler),
            )
        } else {
            runner_server
        };

        let (secret_cleanup_loop, secret_mutation_recovery_loop) = secret_management
            .map_or((None, None), |runtime| {
                (Some(runtime.cleanup_loop), Some(runtime.recovery_loop))
            });
        Ok(Self {
            runner_server,
            management_server,
            readiness_monitor,
            maintenance_loop,
            logical_run_finalization,
            logical_result_projection,
            autonomous_workflow,
            reusable_workflow_runtime,
            secret_cleanup_loop,
            secret_mutation_recovery_loop,
            state_sampler,
            human_api: human.router,
            delegated_actor_api,
            human_request_authentication: human.request_authentication,
            rbac_web_data: human.rbac_web_data,
            setup_page_availability: human.setup_page_availability,
            github_provider,
            results_api,
            web_data,
            web_fallback_context,
        })
    }
}

fn build_management_server(
    config: &ServerConfig,
    listener: Option<TcpListener>,
    store: &PostgresStore,
) -> Result<Option<ManagementGrpcServer>, ServerCompositionError> {
    let (config, listener) = match (config.management(), listener) {
        (None, None) => return Ok(None),
        (Some(config), Some(listener)) => (config, listener),
        (None, Some(_)) | (Some(_), None) => {
            return Err(ServerCompositionError::InvalidManagementConfiguration);
        }
    };

    let mut client_ca = config.load_client_ca_certificate_pem()?;
    let mut server_certificate = config.load_server_certificate_pem()?;
    let tls = ManagementServerTlsConfig::new(
        std::mem::take(&mut *client_ca),
        std::mem::take(&mut *server_certificate),
        config.load_server_private_key_pem()?,
    )
    .map_err(|_| ServerCompositionError::InvalidManagementConfiguration)?;
    let authenticator: Arc<dyn ProvisioningWorkloadAuthenticator> =
        Arc::new(PinnedProvisioningWorkloadAuthenticator::new(
            config.authority().clone(),
            config.client_certificate_sha256().to_vec(),
        ));
    let provisioner: Arc<dyn WorkspaceProvisioner> = Arc::new(PostgresWorkspaceProvisioner::new(
        store.postgres_pool().clone(),
    ));
    Ok(Some(ManagementGrpcServer::new(
        listener,
        tls,
        authenticator,
        provisioner,
    )))
}

async fn verify_runner_capability_readiness(
    store: &PostgresStore,
    readiness: RunnerCapabilityReadiness,
) -> Result<(), ServerCompositionError> {
    // Durable capability inventory is admitted only against products whose
    // full operational readiness this replica has already proved.
    store
        .verify_runner_capability_readiness(readiness)
        .await
        .map_err(|_| ServerCompositionError::RunnerCapabilityAdmission)?;
    Ok(())
}

async fn build_readiness_monitor(
    config: &ServerConfig,
    store: Arc<PostgresStore>,
    blob_store: &Arc<dyn ImmutableBlobStore>,
    custody: Arc<SecretCustodyVerifier>,
    readiness: &Readiness,
    metrics: &ControlPlaneMetrics,
) -> Result<ReadinessMonitor, ServerCompositionError> {
    let database_probe: Arc<dyn ReadinessProbe> =
        Arc::new(PostgresConnectionProbe::new(store, custody));
    let object_store_probe: Arc<dyn ReadinessProbe> =
        Arc::new(ImmutableBlobReadinessProbe::new(Arc::clone(blob_store))?);
    let readiness_monitor = ReadinessMonitor::new(
        database_probe,
        object_store_probe,
        config.readiness_probe_interval,
    )?
    .with_metrics(metrics.clone());
    let snapshot = readiness_monitor.check_once(readiness).await;
    if !snapshot.database() || !snapshot.object_store() {
        return Err(ServerCompositionError::DependencyProbe {
            database: snapshot.database(),
            object_store: snapshot.object_store(),
        });
    }
    Ok(readiness_monitor)
}

struct DatabaseBuild {
    store: PostgresStore,
    control_plane_key_provider: Arc<dyn KeyEncryptionProvider>,
}

async fn connect_database(config: &ServerConfig) -> Result<DatabaseBuild, ServerCompositionError> {
    let database_url = config.load_database_url()?;
    let payload_keyring = config.control_plane_encryption().load_local_keyring()?;
    let control_plane_key_provider: Arc<dyn KeyEncryptionProvider> = Arc::new(payload_keyring);
    let store = PostgresStore::connect(
        &database_url,
        config.database_max_connections,
        config.database_transport_security,
    )
    .await
    .map_err(ServerCompositionError::from)?;
    Ok(DatabaseBuild {
        store: store.with_runner_payload_encryption(Arc::clone(&control_plane_key_provider)),
        control_plane_key_provider,
    })
}

#[derive(Debug)]
struct TenantAlignedGithubProviderConfig(Option<super::GithubProviderConfig>);

fn validate_effective_ui_tenant(
    config: &ServerConfig,
    effective_tenant: &TenantId,
) -> Result<TenantAlignedGithubProviderConfig, ServerCompositionError> {
    let provider_repository_tenants = config
        .github_provider()
        .into_iter()
        .flat_map(super::GithubProviderConfig::repositories)
        .map(|repository| repository.tenant().as_str());
    validate_tenant_alignment(effective_tenant.as_str(), provider_repository_tenants)?;
    Ok(TenantAlignedGithubProviderConfig(
        config.github_provider().cloned(),
    ))
}

fn validate_tenant_alignment<'a>(
    effective_tenant: &str,
    provider_repository_tenants: impl IntoIterator<Item = &'a str>,
) -> Result<(), ServerCompositionError> {
    if provider_repository_tenants
        .into_iter()
        .any(|tenant| tenant != effective_tenant)
    {
        return Err(ServerCompositionError::InconsistentEffectiveUiTenant);
    }
    Ok(())
}

#[cfg(test)]
mod effective_ui_tenant_tests {
    use std::{fs, path::PathBuf};

    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command};

    const EFFECTIVE_TENANT: &str = "effective-tenant-sentinel";
    const FOREIGN_PROVIDER_TENANT: &str = "foreign-provider-tenant-sentinel";

    fn provider_server_config() -> ServerConfig {
        let directory = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(std::env::temp_dir, PathBuf::from)
            .join("effective-ui-tenant-composition");
        fs::create_dir_all(&directory).expect("target-local configuration directory");
        let path = directory.join(format!("github-provider-{}.json", std::process::id()));
        fs::write(
            &path,
            include_bytes!("../../config/github-provider.example.json"),
        )
        .expect("provider configuration fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("provider configuration fixture must be owner-only");
        }
        let source = format!("file:{}", path.display());
        let cli_arguments = vec![
            "automata",
            "server",
            "--results-public-url",
            "https://results.example.test/",
            "--github-provider-config-source",
            source.as_str(),
        ];
        let cli = Cli::try_parse_from(cli_arguments).expect("tenant-alignment server syntax");
        let Command::Server(server_args) = cli.command else {
            panic!("server command expected");
        };
        ServerConfig::from_args(&server_args).expect("tenant-alignment server configuration")
    }

    #[test]
    fn exact_single_tenant_topology_allows_every_enabled_surface() {
        validate_tenant_alignment(EFFECTIVE_TENANT, [EFFECTIVE_TENANT, EFFECTIVE_TENANT])
            .expect("one exact tenant must reach provider composition");
    }

    #[test]
    fn no_provider_preserves_the_resolved_effective_tenant() {
        validate_tenant_alignment(EFFECTIVE_TENANT, std::iter::empty::<&'static str>())
            .expect("the resolved tenant remains valid without a configured provider");
    }

    #[test]
    fn server_configuration_is_gated_without_loading_provider_secret_sources() {
        let effective_tenant = TenantId::new("automata-main").expect("effective tenant");
        let aligned = provider_server_config();
        assert!(
            validate_effective_ui_tenant(&aligned, &effective_tenant)
                .expect("matching provider")
                .0
                .is_some()
        );
    }

    #[test]
    fn any_mismatch_fails_the_pre_side_effect_gate_without_reflecting_tenants() {
        let cases: [&[&str]; 2] = [
            &[FOREIGN_PROVIDER_TENANT],
            &[EFFECTIVE_TENANT, FOREIGN_PROVIDER_TENANT],
        ];
        for provider_tenants in cases {
            let error =
                validate_tenant_alignment(EFFECTIVE_TENANT, provider_tenants.iter().copied())
                    .expect_err("tenant mismatch must stop before provider runtime composition");
            assert!(matches!(
                error,
                ServerCompositionError::InconsistentEffectiveUiTenant
            ));
            let rendered = error.to_string();
            assert_eq!(
                rendered,
                "human UI and GitHub provider tenant configuration is inconsistent"
            );
            for tenant in [EFFECTIVE_TENANT, FOREIGN_PROVIDER_TENANT] {
                assert!(!rendered.contains(tenant));
            }
        }
    }
}

async fn build_github_provider_runtime(
    provider: TenantAlignedGithubProviderConfig,
    store: Arc<PostgresStore>,
    blobs: Arc<dyn ImmutableBlobStore>,
    control_plane_key_provider: Arc<dyn KeyEncryptionProvider>,
    metrics: &ControlPlaneMetrics,
) -> Result<Option<GithubProviderRuntime>, ServerCompositionError> {
    let TenantAlignedGithubProviderConfig(provider) = provider;
    let Some(provider) = provider else {
        return Ok(None);
    };
    let app_key = {
        let bytes = provider
            .app()
            .private_key_source()
            .load_bytes(MAX_GITHUB_APP_PRIVATE_KEY_PEM_BYTES)?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| ServerCompositionError::InvalidGithubProviderConfiguration)?;
        SecretString::new(value.to_owned())
            .map_err(|_| ServerCompositionError::InvalidGithubProviderConfiguration)?
    };
    let webhook_secret = provider
        .webhook()
        .hmac_secret_source()
        .load_bytes(MAX_GITHUB_WEBHOOK_SECRET_BYTES)?;
    let observer: Arc<dyn WorkflowAdmissionObserver> = Arc::new(metrics.clone());
    let runtime = GithubProviderRuntimeBuilder::new(
        provider,
        app_key,
        webhook_secret,
        control_plane_key_provider,
        store,
        blobs,
    )
    .with_admission_observer(observer)
    .build()
    .await?;
    Ok(Some(runtime))
}

fn build_results(
    config: &ServerConfig,
    store: &PostgresStore,
    blob_store: Arc<dyn ImmutableBlobStore>,
    metrics: &ControlPlaneMetrics,
) -> Result<
    (
        Router,
        Arc<dyn automata_ci_runner_control::RuntimeAuthorityIssuer>,
    ),
    ServerCompositionError,
> {
    let clock: Arc<dyn ResultsClock> = Arc::new(SystemResultsClock);
    let authority_config = HmacResultsAuthorityConfig::new(
        RESULTS_ISSUER,
        RESULTS_AUDIENCE,
        config.results_key_id.clone(),
        config.results_public_endpoint.clone(),
        RESULTS_RUNTIME_TOKEN_VALIDITY_SECONDS,
        RESULTS_UPLOAD_CAPABILITY_VALIDITY_SECONDS,
        RESULTS_ALLOWED_CLOCK_SKEW_SECONDS,
    )
    .map_err(|_| ServerCompositionError::InvalidResultsConfiguration)?;
    let signing_key = config.load_results_signing_key()?;
    let authority = Arc::new(
        HmacResultsAuthority::new(&signing_key, authority_config, Arc::clone(&clock))
            .map_err(|_| ServerCompositionError::InvalidResultsConfiguration)?,
    );
    let cache_repositories = config
        .github_provider()
        .into_iter()
        .flat_map(super::GithubProviderConfig::repositories)
        .map(|repository| repository.cache_repository().clone());
    let runtime_authority_issuer: Arc<dyn automata_ci_runner_control::RuntimeAuthorityIssuer> =
        Arc::new(
            GithubResultsRuntimeAuthorityIssuer::new(
                Arc::clone(&authority),
                RESULTS_RUNTIME_TOKEN_VALIDITY_SECONDS,
                cache_repositories,
            )
            .map_err(|_| ServerCompositionError::InvalidResultsConfiguration)?,
        );
    let observer: Arc<dyn ResultsObserver> = Arc::new(metrics.clone());
    let repository: Arc<dyn ArtifactRepository> = Arc::new(PostgresArtifactRepository::new(
        store.postgres_pool().clone(),
    ));
    let repository: Arc<dyn ArtifactRepository> = Arc::new(ObservedResultsArtifactRepository::new(
        repository,
        Arc::clone(&observer),
    ));
    let blob_store: Arc<dyn ImmutableBlobStore> = Arc::new(ObservedResultsBlobStore::new(
        blob_store,
        Arc::clone(&observer),
    ));
    let ids: Arc<dyn ResultsIdGenerator> = Arc::new(SystemResultsIdGenerator);
    let cache_repository: Arc<dyn CacheRepository> =
        Arc::new(PostgresCacheRepository::new(store.postgres_pool().clone()));
    let cache_service = Arc::new(CacheService::new(
        cache_repository,
        Arc::clone(&blob_store),
        Arc::clone(&clock),
        Arc::clone(&ids),
        CacheLimits::default(),
    ));
    let service = Arc::new(
        ArtifactService::new(repository, blob_store, clock, ids, ResultsLimits::default())
            .with_observer(Arc::clone(&observer)),
    );
    let runtime_tokens = authority.clone();
    let upload_capabilities = authority.clone();
    let download_capabilities = authority.clone();
    let cache_runtime_tokens = authority.clone();
    let cache_capabilities = authority;
    let router = GithubResultsApi::new(
        service,
        runtime_tokens,
        upload_capabilities,
        download_capabilities,
        GithubResultsHttpLimits::default(),
    )
    .with_observer(Arc::clone(&observer))
    .router()
    .merge(
        GithubCacheApi::new(
            cache_service,
            cache_runtime_tokens,
            cache_capabilities,
            GithubCacheHttpLimits::default(),
        )
        .with_observer(observer)
        .router(),
    );
    Ok((router, runtime_authority_issuer))
}

fn build_maintenance_loop(
    config: &ServerConfig,
    store: Arc<PostgresStore>,
    metrics: &ControlPlaneMetrics,
) -> Result<ControlPlaneMaintenanceLoop, MaintenanceLoopConfigError> {
    let repository: Arc<dyn ControlPlaneMaintenanceRepository> = store;
    let clock: Arc<dyn MaintenanceClock> = Arc::new(SystemMaintenanceClock::default());
    ControlPlaneMaintenanceLoop::new(
        repository,
        clock,
        config.maintenance_interval,
        config.maximum_lease_failures,
        config.maintenance_batch_size,
        config.stale_runner_session_timeout,
    )
    .map(|maintenance| maintenance.with_metrics(metrics.clone()))
}

struct SecretManagementComposition {
    backend: Arc<dyn RepositorySecretApiBackend>,
    read_repository: Arc<dyn RepositorySecretManagementReadRepository>,
    clock: Arc<dyn Clock>,
    cleanup_loop: BuiltinSecretCleanupLoop,
    recovery_loop: SecretMutationRecoveryLoop,
}

struct SecretManagementBuild {
    runtime: Option<SecretManagementComposition>,
    custody: Arc<SecretCustodyVerifier>,
    delivery_provider: Option<Arc<dyn SecretProvider>>,
}

fn build_builtin_secret_registry(
    provider: Arc<dyn SecretProvider>,
) -> Result<Arc<SecretProviderRegistry>, ServerCompositionError> {
    SecretProviderRegistry::new(provider.provider_id().clone(), [provider])
        .map(Arc::new)
        .map_err(|_| ServerCompositionError::InvalidSecretManagement)
}

async fn build_secret_management(
    config: &ServerConfig,
    store: &PostgresStore,
) -> Result<SecretManagementBuild, ServerCompositionError> {
    let poll_interval = config.maintenance_interval;
    let Some(secret_config) = config.secret_encryption() else {
        let repository: Arc<dyn SecretCustodyRepository> = Arc::new(
            PostgresSecretCustodyRepository::new(store.postgres_pool().clone()),
        );
        let custody = Arc::new(SecretCustodyVerifier::new(repository, None));
        custody
            .verify_within(config.readiness_probe_interval)
            .await
            .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
        return Ok(SecretManagementBuild {
            runtime: None,
            custody,
            delivery_provider: None,
        });
    };
    let configured_keys = SecretCustodyKeySet::new(
        secret_config.active_key_id().clone(),
        secret_config.decrypt_only_key_ids().cloned().collect(),
    )
    .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
    let key_provider: Arc<dyn KeyEncryptionProvider> =
        Arc::new(secret_config.load_local_keyring()?);
    let custody_repository: Arc<dyn SecretCustodyRepository> = Arc::new(
        PostgresSecretCustodyRepository::new(store.postgres_pool().clone())
            .with_key_encryption_provider(Arc::clone(&key_provider)),
    );
    let custody = Arc::new(SecretCustodyVerifier::new(
        custody_repository,
        Some(configured_keys),
    ));
    custody
        .verify_within(config.readiness_probe_interval)
        .await
        .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
    let repository = Arc::new(PostgresSecretManagementRepository::new(
        store.postgres_pool().clone(),
    ));
    let provider: Arc<dyn SecretProvider> = Arc::new(PostgresSecretProvider::new(
        store.postgres_pool().clone(),
        key_provider,
    ));
    let delivery_provider = Arc::clone(&provider);
    let providers = build_builtin_secret_registry(provider)?;
    let management_repository: Arc<dyn RepositorySecretManagementRepository> = repository.clone();
    let read_repository: Arc<dyn RepositorySecretManagementReadRepository> = repository.clone();
    let cleanup_repository: Arc<dyn BuiltinSecretCleanupRepository> = repository.clone();
    let recovery_repository: Arc<dyn SecretMutationRecoveryRepository> = repository;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let backend: Arc<dyn RepositorySecretApiBackend> = Arc::new(
        OperationalRepositorySecretBackend::new(
            management_repository,
            Arc::clone(&providers),
            Arc::clone(&custody),
            Arc::clone(&clock),
        )
        .map_err(|_| ServerCompositionError::InvalidSecretManagement)?,
    );
    let cleanup_clock: Arc<dyn SecretCleanupClock> = Arc::new(SystemSecretCleanupClock::default());
    let cleanup_worker_id = SecretCleanupWorkerId::new(format!("secret-cleanup-{}", RunId::new()))
        .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
    let cleanup_loop = BuiltinSecretCleanupLoop::new(
        BuiltinSecretCleanupPorts::new(
            cleanup_repository,
            Arc::clone(&providers),
            Arc::clone(&custody),
        ),
        Arc::clone(&cleanup_clock),
        cleanup_worker_id,
        poll_interval,
        SECRET_CLEANUP_OPERATION_TIMEOUT,
        SECRET_CLEANUP_STALE_AFTER,
    )
    .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
    let recovery_worker_id =
        SecretCleanupWorkerId::new(format!("secret-recovery-{}", RunId::new()))
            .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
    let recovery_loop = SecretMutationRecoveryLoop::new(
        SecretMutationRecoveryPorts::new(recovery_repository, providers, Arc::clone(&custody)),
        cleanup_clock,
        recovery_worker_id,
        poll_interval,
        SECRET_CLEANUP_OPERATION_TIMEOUT,
        SECRET_CLEANUP_STALE_AFTER,
    )
    .map_err(|_| ServerCompositionError::InvalidSecretManagement)?;
    Ok(SecretManagementBuild {
        runtime: Some(SecretManagementComposition {
            backend,
            read_repository,
            clock,
            cleanup_loop,
            recovery_loop,
        }),
        custody,
        delivery_provider: Some(delivery_provider),
    })
}

struct HumanApiComposition {
    router: Router,
    request_authentication: Option<HumanRequestAuthentication>,
    rbac_web_data: Option<Arc<dyn RbacWebData>>,
    setup_page_availability: Option<Arc<dyn SetupPageAvailability>>,
    effective_tenant: TenantId,
}

struct InstallationSetupPageAvailability {
    installations: Arc<dyn InstallationRepository>,
}

impl InstallationSetupPageAvailability {
    fn new(installations: Arc<dyn InstallationRepository>) -> Self {
        Self { installations }
    }
}

impl fmt::Debug for InstallationSetupPageAvailability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationSetupPageAvailability")
            .field("installations", &"[REDACTED]")
            .finish()
    }
}

#[async_trait]
impl SetupPageAvailability for InstallationSetupPageAvailability {
    async fn current(&self) -> Result<SetupPageAvailabilityState, SetupPageAvailabilityError> {
        match self.installations.load().await {
            Ok(InstallationState::Armed { .. }) => Ok(SetupPageAvailabilityState::Armed),
            Ok(
                InstallationState::Unconfigured { .. }
                | InstallationState::LoginBound { .. }
                | InstallationState::Configured { .. },
            ) => Ok(SetupPageAvailabilityState::Absent),
            Err(InstallationRepositoryError::Unavailable) => {
                Err(SetupPageAvailabilityError::Unavailable)
            }
            Err(
                InstallationRepositoryError::InvalidRequest
                | InstallationRepositoryError::NotArmed
                | InstallationRepositoryError::ProofRejected
                | InstallationRepositoryError::Expired
                | InstallationRepositoryError::AlreadyBound
                | InstallationRepositoryError::AlreadyConfigured
                | InstallationRepositoryError::VersionConflict
                | InstallationRepositoryError::IdentityConflict
                | InstallationRepositoryError::CredentialCustody
                | InstallationRepositoryError::CorruptData,
            ) => Err(SetupPageAvailabilityError::Corrupt),
        }
    }
}

#[cfg(test)]
mod setup_page_composition_tests {
    use std::sync::Mutex;

    use automata_ci_auth::{
        human::PrincipalId,
        installation::{
            ArmInstallationSetup, BindInstallationLogin, CompleteInstallationOutcome,
            CompleteInstallationSetup, InstallationRepositoryFuture, InstallationRevision,
        },
        login::LoginTransactionId,
        time::UnixTimestamp,
    };
    use automata_ci_ui_renderer::{RenderError, RenderedPage, Renderer};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::app::{
        http::{
            HttpPolicy, router_with_readiness_web_data, router_with_renderer_readiness_web_data,
        },
        web::{EmptyWebData, RequestContext},
    };

    const RENDERED_SETUP: &str = "<!doctype html><html><body>setup page</body></html>";
    const SECRET_SENTINEL: &str = "bootstrap-token-sentinel-0123456789abcdef";

    struct MutableInstallationRepository {
        state: Mutex<MutableInstallationState>,
    }

    struct MutableInstallationState {
        outcome: Result<InstallationState, InstallationRepositoryError>,
        loads: usize,
    }

    impl MutableInstallationRepository {
        fn new(outcome: Result<InstallationState, InstallationRepositoryError>) -> Self {
            Self {
                state: Mutex::new(MutableInstallationState { outcome, loads: 0 }),
            }
        }

        fn set(&self, outcome: Result<InstallationState, InstallationRepositoryError>) {
            self.state
                .lock()
                .expect("installation test state must remain available")
                .outcome = outcome;
        }

        fn loads(&self) -> usize {
            self.state
                .lock()
                .expect("installation test state must remain available")
                .loads
        }
    }

    impl fmt::Debug for MutableInstallationRepository {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MutableInstallationRepository([REDACTED])")
        }
    }

    impl InstallationRepository for MutableInstallationRepository {
        fn load(&self) -> InstallationRepositoryFuture<'_, InstallationState> {
            Box::pin(async move {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| InstallationRepositoryError::Unavailable)?;
                state.loads = state.loads.saturating_add(1);
                state.outcome.clone()
            })
        }

        fn arm(
            &self,
            _request: ArmInstallationSetup,
        ) -> InstallationRepositoryFuture<'_, InstallationState> {
            Box::pin(async { panic!("setup-page availability must never arm installation") })
        }

        fn bind_login(
            &self,
            _request: BindInstallationLogin,
        ) -> InstallationRepositoryFuture<'_, InstallationState> {
            Box::pin(async { panic!("setup-page availability must never bind installation") })
        }

        fn complete(
            &self,
            _request: CompleteInstallationSetup,
        ) -> InstallationRepositoryFuture<'_, CompleteInstallationOutcome> {
            Box::pin(async { panic!("setup-page availability must never complete installation") })
        }
    }

    #[derive(Debug, Default)]
    struct RecordingRenderer {
        requests: Mutex<Vec<String>>,
    }

    impl RecordingRenderer {
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("renderer test state must remain available")
                .clone()
        }
    }

    impl Renderer for RecordingRenderer {
        fn render(&self, request_json: &str) -> Result<RenderedPage, RenderError> {
            self.requests
                .lock()
                .expect("renderer test state must remain available")
                .push(request_json.to_owned());
            Ok(RenderedPage::from_complete_html(RENDERED_SETUP.to_owned()))
        }
    }

    fn installation_state(disposition: &str) -> InstallationState {
        let revision = InstallationRevision::new(1).expect("installation revision");
        let tenant_id = TenantId::new("setup-composition-test").expect("tenant ID");
        let provider_id = automata_ci_auth::human::ProviderId::new("github").expect("provider ID");
        let expected_provider_subject =
            ProviderSubject::new(SECRET_SENTINEL).expect("provider subject");
        let login_transaction_id = LoginTransactionId::new("11111111-1111-4111-8111-111111111111")
            .expect("login transaction ID");
        match disposition {
            "unconfigured" => InstallationState::Unconfigured { revision },
            "armed" => InstallationState::Armed {
                revision,
                tenant_id,
                provider_id,
                expected_provider_subject,
                expires_at: UnixTimestamp::from_seconds(1_000),
            },
            "login_bound" => InstallationState::LoginBound {
                revision,
                tenant_id,
                provider_id,
                expected_provider_subject,
                login_transaction_id,
                expires_at: UnixTimestamp::from_seconds(1_000),
            },
            "configured" => InstallationState::Configured {
                revision,
                tenant_id,
                principal_id: PrincipalId::new("initial-administrator").expect("principal ID"),
                provider_id,
                provider_subject: expected_provider_subject,
                login_transaction_id,
                configured_at: UnixTimestamp::from_seconds(900),
            },
            _ => panic!("unknown installation test disposition"),
        }
    }

    fn setup_router(
        repository: Option<Arc<MutableInstallationRepository>>,
    ) -> (Router, Arc<RecordingRenderer>) {
        let renderer = Arc::new(RecordingRenderer::default());
        let renderer_port: Arc<dyn Renderer> = renderer.clone();
        let availability = repository.map(setup_availability);
        let tenant = TenantId::new("setup-composition-test").expect("tenant ID");
        let router = router_with_renderer_readiness_web_data(
            renderer_port,
            HttpPolicy::default(),
            Readiness::all_ready(),
            Arc::new(EmptyWebData),
            None,
            availability,
            RequestContext::anonymous(tenant),
        );
        (router, renderer)
    }

    fn setup_availability(
        repository: Arc<MutableInstallationRepository>,
    ) -> Arc<dyn SetupPageAvailability> {
        let installations: Arc<dyn InstallationRepository> = repository;
        Arc::new(InstallationSetupPageAvailability::new(installations))
    }

    async fn get(router: &Router, uri: &str) -> axum::response::Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("setup GET request"),
            )
            .await
            .expect("setup response")
    }

    #[tokio::test]
    async fn disabled_and_every_non_armed_installation_state_keep_setup_absent() {
        let (disabled, renderer) = setup_router(None);
        assert_eq!(
            get(&disabled, "/setup").await.status(),
            StatusCode::NOT_FOUND
        );
        assert!(renderer.requests().is_empty());

        for disposition in ["unconfigured", "login_bound", "configured"] {
            let repository = Arc::new(MutableInstallationRepository::new(Ok(installation_state(
                disposition,
            ))));
            let (router, renderer) = setup_router(Some(repository.clone()));
            assert_eq!(
                get(&router, "/setup").await.status(),
                StatusCode::NOT_FOUND,
                "state {disposition}"
            );
            assert_eq!(repository.loads(), 1, "state {disposition}");
            assert!(renderer.requests().is_empty(), "state {disposition}");
        }
    }

    #[tokio::test]
    async fn armed_state_renders_value_free_setup_and_rejects_every_query() {
        let repository = Arc::new(MutableInstallationRepository::new(Ok(installation_state(
            "armed",
        ))));
        let (router, renderer) = setup_router(Some(repository.clone()));

        let rejected = get(&router, &format!("/setup?probe={SECRET_SENTINEL}")).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let rejected_body = to_bytes(rejected.into_body(), 64 * 1_024)
            .await
            .expect("bounded setup query-rejection body");
        assert!(
            !rejected_body
                .windows(SECRET_SENTINEL.len())
                .any(|window| window == SECRET_SENTINEL.as_bytes())
        );
        assert_eq!(repository.loads(), 0);
        assert!(renderer.requests().is_empty());

        let setup_response = get(&router, "/setup").await;
        assert_eq!(setup_response.status(), StatusCode::OK);
        let setup_body = to_bytes(setup_response.into_body(), RENDERED_SETUP.len())
            .await
            .expect("bounded rendered setup body");
        assert_eq!(setup_body.as_ref(), RENDERED_SETUP.as_bytes());
        assert!(
            !setup_body
                .windows(SECRET_SENTINEL.len())
                .any(|window| window == SECRET_SENTINEL.as_bytes())
        );
        assert_eq!(repository.loads(), 1);
        let requests = renderer.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("\"kind\":\"setup\""));
        assert!(!requests[0].contains(SECRET_SENTINEL));
        assert!(!requests[0].contains("bootstrap_token"));
        assert!(!format!("{repository:?}").contains(SECRET_SENTINEL));
    }

    #[tokio::test]
    async fn production_renderer_emits_one_valueless_native_setup_form() {
        let repository = Arc::new(MutableInstallationRepository::new(Ok(installation_state(
            "armed",
        ))));
        let tenant = TenantId::new("setup-composition-test").expect("tenant ID");
        let router = router_with_readiness_web_data(
            Readiness::all_ready(),
            Arc::new(EmptyWebData),
            None,
            Some(setup_availability(repository.clone())),
            RequestContext::anonymous(tenant),
        )
        .expect("production embedded renderer");

        let response = get(&router, "/setup").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 512 * 1_024)
            .await
            .expect("bounded production setup body");
        let html = std::str::from_utf8(&body).expect("setup HTML must be UTF-8");
        assert_eq!(html.matches("<form").count(), 1);
        assert!(html.contains("action=\"/setup/auth/github\""));
        assert!(html.contains("method=\"post\""));
        let return_marker = html
            .find("name=\"return_path\"")
            .expect("fixed local return-path field");
        let return_start = html[..return_marker]
            .rfind("<input")
            .expect("return-path input start");
        let return_end = html[return_marker..]
            .find('>')
            .map(|offset| return_marker + offset)
            .expect("return-path input end");
        let return_input = &html[return_start..=return_end];
        assert!(return_input.contains("type=\"hidden\""));
        assert!(return_input.contains("value=\"/\""));
        let password_marker = html
            .find("name=\"bootstrap_token\"")
            .expect("native bootstrap password field");
        let input_start = html[..password_marker]
            .rfind("<input")
            .expect("bootstrap input start");
        let input_end = html[password_marker..]
            .find('>')
            .map(|offset| password_marker + offset)
            .expect("bootstrap input end");
        let password_input = &html[input_start..=input_end];
        assert!(password_input.contains("type=\"password\""));
        assert!(!password_input.contains("value="));
        assert!(!html.contains(SECRET_SENTINEL));
        assert_eq!(repository.loads(), 1);
    }

    #[tokio::test]
    async fn one_running_router_withdraws_setup_across_login_and_completion() {
        let repository = Arc::new(MutableInstallationRepository::new(Ok(installation_state(
            "armed",
        ))));
        let (router, renderer) = setup_router(Some(repository.clone()));

        assert_eq!(get(&router, "/setup").await.status(), StatusCode::OK);
        repository.set(Ok(installation_state("login_bound")));
        assert_eq!(get(&router, "/setup").await.status(), StatusCode::NOT_FOUND);
        repository.set(Ok(installation_state("configured")));
        assert_eq!(get(&router, "/setup").await.status(), StatusCode::NOT_FOUND);

        assert_eq!(repository.loads(), 3);
        assert_eq!(renderer.requests().len(), 1);
    }

    #[tokio::test]
    async fn unavailable_and_corrupt_reads_reach_distinct_closed_http_failures() {
        for (error, status) in [
            (
                InstallationRepositoryError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                InstallationRepositoryError::CorruptData,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                InstallationRepositoryError::InvalidRequest,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let repository = Arc::new(MutableInstallationRepository::new(Err(error)));
            let (router, renderer) = setup_router(Some(repository.clone()));
            assert_eq!(get(&router, "/setup").await.status(), status);
            assert_eq!(repository.loads(), 1);
            assert!(renderer.requests().is_empty());
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "human API composition keeps each independently owned product boundary explicit"
)]
async fn build_human_api(
    config: &ServerConfig,
    store: Arc<PostgresStore>,
    blob_store: Arc<dyn ImmutableBlobStore>,
    _metrics: &ControlPlaneMetrics,
    secret_management: Option<&SecretManagementComposition>,
    repository_secret_web: Option<Arc<dyn RepositorySecretWebData>>,
    fallback_tenant: TenantId,
    capability_readiness: RunnerCapabilityReadiness,
) -> Result<HumanApiComposition, ServerCompositionError> {
    let deployment_token = config.load_conformance_export_token()?;
    let mut router = match deployment_token.as_deref() {
        Some(token) => {
            let tenant =
                TenantScope::from_authenticated_tenant_id(fallback_tenant.as_str().to_owned())
                    .map_err(|_| ServerCompositionError::InvalidFallbackTenant)?;
            let reads: Arc<dyn HumanWorkflowReadRepository> = store.clone();
            let deliveries: Arc<dyn ConformanceReadRepository> = store.clone();
            deployment_conformance_api_router(
                reads,
                deliveries,
                Arc::clone(&blob_store),
                tenant,
                token,
            )
        }
        None => Router::new(),
    };

    let enrollment_issuer = if config.human_auth().is_some() {
        let client_ca = config.load_client_ca_pem()?;
        let client_ca_key = config.load_client_ca_private_key_pem()?;
        let server_ca = config.load_runner_server_ca_pem()?;
        let server_certificate = config.load_server_certificate_pem()?;
        let authority = config
            .runner_public_authority
            .as_ref()
            .ok_or(ServerCompositionError::InvalidRunnerEnrollment)?;
        Some(Arc::new(
            RunnerCertificateIssuer::from_pem(
                &client_ca,
                &client_ca_key,
                &server_ca,
                &server_certificate,
                format!("https://{authority}/"),
            )
            .map_err(|_| ServerCompositionError::InvalidRunnerEnrollment)?,
        ))
    } else {
        None
    };
    let Some(config) = config.human_auth() else {
        return Ok(HumanApiComposition {
            router,
            request_authentication: None,
            rbac_web_data: None,
            setup_page_availability: None,
            effective_tenant: fallback_tenant,
        });
    };
    let runtime = HumanAuthRuntime::build(config, store.as_ref())
        .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?;
    let installation = runtime
        .installation_repository()
        .load()
        .await
        .map_err(|_| ServerCompositionError::HumanAuthenticationState)?;
    let (tenant_id, setup_service) = match installation {
        InstallationState::Configured {
            tenant_id,
            provider_id,
            ..
        } if provider_id.as_str() == "github" => (tenant_id, None),
        InstallationState::Configured { .. } => {
            return Err(ServerCompositionError::HumanAuthenticationState);
        }
        InstallationState::Unconfigured { .. }
        | InstallationState::Armed { .. }
        | InstallationState::LoginBound { .. } => {
            let bootstrap = config
                .bootstrap()
                .ok_or(ServerCompositionError::HumanAuthenticationNotConfigured)?;
            let expected_subject = ProviderSubject::new(bootstrap.github_user_id().to_string())
                .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?;
            let service = Arc::new(
                InstallationSetupService::new(
                    Arc::clone(runtime.login_service()),
                    Arc::clone(runtime.installation_repository()),
                    Arc::clone(runtime.session_service()),
                    Arc::clone(runtime.installation_proofs()),
                    bootstrap.tenant().clone(),
                    expected_subject,
                    Arc::clone(runtime.clock()),
                    runtime.lifetimes(),
                )
                .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?,
            );
            let token = bootstrap.load_token()?;
            let state = service
                .ensure_armed(token.as_str())
                .await
                .map_err(|_| ServerCompositionError::HumanAuthenticationSetup)?;
            drop(token);
            match state {
                InstallationState::Configured {
                    tenant_id,
                    provider_id,
                    ..
                } if provider_id.as_str() == "github" => (tenant_id, None),
                InstallationState::Configured { .. } => {
                    return Err(ServerCompositionError::HumanAuthenticationState);
                }
                InstallationState::Armed { tenant_id, .. }
                | InstallationState::LoginBound { tenant_id, .. } => (tenant_id, Some(service)),
                InstallationState::Unconfigured { .. } => {
                    return Err(ServerCompositionError::HumanAuthenticationSetup);
                }
            }
        }
    };

    let github_endpoints = GithubEndpoints::github_dot_com()
        .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?;
    let provider_origin = GithubProviderOrigin::new(github_endpoints.authorization())
        .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?;
    let default_return_path = LoginReturnPath::new("/")
        .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?;
    let github_backend = Arc::new(OperationalGithubAuthBackend::new(
        Arc::clone(runtime.login_service()),
        Arc::clone(runtime.session_service()),
        setup_service.clone(),
    ));
    let github_state = GithubAuthHttpState::new(
        github_backend,
        tenant_id.clone(),
        runtime.origin().clone(),
        provider_origin.clone(),
        default_return_path.clone(),
        Arc::clone(runtime.clock()),
    );
    router = router.merge(github_auth_router(github_state));

    let setup_page_availability = setup_service.as_ref().map(|_| {
        let availability: Arc<dyn SetupPageAvailability> = Arc::new(
            InstallationSetupPageAvailability::new(Arc::clone(runtime.installation_repository())),
        );
        availability
    });

    if let Some(service) = setup_service {
        let setup_state = GithubSetupHttpState::new(
            service,
            runtime.origin().clone(),
            provider_origin,
            default_return_path,
            Arc::clone(runtime.clock()),
        );
        router = router.merge(github_setup_router(setup_state));
    }

    let management = Arc::new(PostgresHumanRbacManagementRepository::new(
        store.postgres_pool().clone(),
    ));
    router = router.merge(runner_enrollment_api_router(
        Arc::clone(&management),
        enrollment_issuer.ok_or(ServerCompositionError::InvalidRunnerEnrollment)?,
        Arc::clone(runtime.clock()),
        capability_readiness,
    ));
    let management_api_repository: Arc<
        dyn automata_ci_auth::management::HumanRbacManagementRepository,
    > = management.clone();
    router = router.merge(management_api_router(
        management_api_repository,
        Arc::clone(runtime.clock()),
    ));
    let repository: Arc<dyn automata_ci_auth::management::HumanRbacManagementRepository> =
        management;
    let rbac_web_data: Arc<dyn RbacWebData> = Arc::new(ManagementRbacWebData::new(
        repository,
        Arc::clone(runtime.clock()),
    ));
    let publication_reads: Arc<dyn HumanWorkflowReadRepository> = store.clone();
    let publications: Arc<dyn RepositoryPublicationRepository> = store.clone();
    router = router.merge(publication_settings_router(
        publication_reads,
        publications,
        Arc::clone(runtime.clock()),
    ));
    let conformance_reads: Arc<dyn HumanWorkflowReadRepository> = store.clone();
    let conformance_deliveries: Arc<dyn ConformanceReadRepository> = store.clone();
    router = router.merge(conformance_api_router(
        conformance_reads,
        conformance_deliveries,
        blob_store,
    ));
    let environment_reviews: Arc<dyn ProtectedEnvironmentRepository> = store.clone();
    let environment_review_backend: Arc<dyn ProtectedEnvironmentReviewApiBackend> = Arc::new(
        OperationalProtectedEnvironmentReviewBackend::new(environment_reviews),
    );
    router = router.merge(protected_environment_review_api_router(
        environment_review_backend,
        Arc::clone(runtime.clock()),
    ));
    let rerun_repository: Arc<dyn WorkflowRerunRepository> = store.clone();
    let rerun_backend: Arc<dyn WorkflowRerunApiBackend> = Arc::new(
        OperationalWorkflowRerunBackend::new(WorkflowRerunService::new(rerun_repository)),
    );
    router = router.merge(workflow_rerun_api_router(
        rerun_backend,
        Arc::clone(runtime.clock()),
    ));
    if let Some(secret_management) = secret_management {
        router = router.merge(repository_secret_api_router(
            Arc::clone(&secret_management.backend),
            Arc::clone(&secret_management.read_repository),
            Arc::clone(&secret_management.clock),
        ));
    }
    if let Some(repository_secret_web) = repository_secret_web {
        router = router.merge(repository_secret_browser_router(repository_secret_web));
    }

    let lifetimes = runtime.lifetimes();
    let effective_tenant = tenant_id.clone();
    let request_authentication = HumanRequestAuthentication::new(
        Arc::clone(runtime.session_service()),
        Arc::clone(runtime.request_resolver()),
        Arc::clone(runtime.clock()),
        runtime.origin().clone(),
        tenant_id,
        lifetimes.idle(SessionKind::Browser),
        lifetimes.idle(SessionKind::Cli),
    )
    .map_err(|_| ServerCompositionError::InvalidHumanAuthentication)?;
    Ok(HumanApiComposition {
        router,
        request_authentication: Some(request_authentication),
        rbac_web_data: Some(rbac_web_data),
        setup_page_availability,
        effective_tenant,
    })
}

#[derive(Debug)]
struct PostgresConnectionProbe {
    store: Arc<PostgresStore>,
    custody: Arc<SecretCustodyVerifier>,
}

impl PostgresConnectionProbe {
    const fn new(store: Arc<PostgresStore>, custody: Arc<SecretCustodyVerifier>) -> Self {
        Self { store, custody }
    }
}

#[async_trait]
impl ReadinessProbe for PostgresConnectionProbe {
    async fn probe(&self) -> Result<(), ReadinessProbeError> {
        let connection = self
            .store
            .postgres_pool()
            .acquire()
            .await
            .map_err(|_| ReadinessProbeError)?;
        drop(connection);
        self.custody.verify().await.map_err(|_| ReadinessProbeError)
    }
}

#[derive(Debug)]
struct ImmutableBlobReadinessProbe {
    store: Arc<dyn ImmutableBlobStore>,
    payload: BlobPayload,
}

impl ImmutableBlobReadinessProbe {
    fn new(store: Arc<dyn ImmutableBlobStore>) -> Result<Self, ServerCompositionError> {
        let key = BlobKey::new(READINESS_OBJECT_KEY)
            .map_err(|_| ServerCompositionError::InternalReadinessObject)?;
        let media_type = MediaType::new(READINESS_MEDIA_TYPE)
            .map_err(|_| ServerCompositionError::InternalReadinessObject)?;
        let payload = BlobPayload::from_bytes(key, media_type, Bytes::from_static(READINESS_BYTES));
        Ok(Self { store, payload })
    }
}

#[async_trait]
impl ReadinessProbe for ImmutableBlobReadinessProbe {
    async fn probe(&self) -> Result<(), ReadinessProbeError> {
        self.store
            .put_if_absent(self.payload.clone())
            .await
            .map_err(|_| ReadinessProbeError)?;
        let descriptor = self.payload.descriptor();
        self.store
            .get_verified(descriptor, descriptor.size())
            .await
            .map_err(|_| ReadinessProbeError)?;
        Ok(())
    }
}

fn build_blob_store(
    config: &ServerConfig,
) -> Result<Arc<dyn ImmutableBlobStore>, ServerCompositionError> {
    let blob_config = if config.s3_endpoint.scheme() == "http" {
        if !config.s3_allow_loopback_http {
            return Err(ServerCompositionError::InsecureS3Endpoint);
        }
        S3BlobStoreConfig::loopback_development(
            config.s3_endpoint.clone(),
            config.s3_region.clone(),
            config.s3_bucket.clone(),
            config.s3_prefix.clone(),
            config.s3_operation_timeout,
        )?
    } else {
        S3BlobStoreConfig::new(
            config.s3_endpoint.clone(),
            config.s3_region.clone(),
            config.s3_bucket.clone(),
            config.s3_prefix.clone(),
            config.s3_force_path_style,
            config.s3_operation_timeout,
        )?
    };
    let blob_config = blob_config.with_at_rest_encryption(config.s3_at_rest_encryption.clone());
    let access_key = config.load_s3_access_key()?;
    let secret_key = config.load_s3_secret_key()?;
    let session_token = config.load_s3_session_token()?;
    let credentials = StaticS3Credentials::new(
        access_key.as_str(),
        secret_key.as_str(),
        session_token
            .as_ref()
            .map(|value| value.as_str().to_owned()),
    )?;
    let client = blob_config.client(credentials);
    Ok(Arc::new(S3BlobStore::new(client, &blob_config)))
}

fn load_server_tls(config: &ServerConfig) -> Result<ServerTlsConfig, ServerCompositionError> {
    let ca_pem = config.load_client_ca_pem()?;
    let certificate_pem = config.load_server_certificate_pem()?;
    let private_key_pem = config.load_server_private_key_pem()?;

    let roots = parse_root_store(&ca_pem)?;
    let certificate_chain = parse_certificate_chain(&certificate_pem)?;
    let private_key = parse_private_key(&private_key_pem)?;
    ServerTlsConfig::new(roots, certificate_chain, private_key)
        .map_err(ServerCompositionError::Transport)
}

fn parse_root_store(pem: &[u8]) -> Result<RootCertStore, ServerCompositionError> {
    let certificates = parse_certificate_chain(pem)?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| ServerCompositionError::InvalidTlsPem)?;
    }
    if roots.is_empty() {
        return Err(ServerCompositionError::InvalidTlsPem);
    }
    Ok(roots)
}

fn parse_certificate_chain(
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, ServerCompositionError> {
    validate_pem_begin_lines(pem, &[b"-----BEGIN CERTIFICATE-----"])?;
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ServerCompositionError::InvalidTlsPem)?;
    if certificates.is_empty() || certificates.len() > MAX_TLS_CERTIFICATES {
        return Err(ServerCompositionError::InvalidTlsPem);
    }
    let mut aggregate = 0_usize;
    for certificate in &certificates {
        if certificate.is_empty() || certificate.len() > MAX_TLS_CERTIFICATE_DER_BYTES {
            return Err(ServerCompositionError::InvalidTlsPem);
        }
        aggregate = aggregate
            .checked_add(certificate.len())
            .filter(|value| *value <= MAX_TLS_CHAIN_DER_BYTES)
            .ok_or(ServerCompositionError::InvalidTlsPem)?;
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, ServerCompositionError> {
    validate_pem_begin_lines(
        pem,
        &[
            b"-----BEGIN PRIVATE KEY-----",
            b"-----BEGIN RSA PRIVATE KEY-----",
            b"-----BEGIN EC PRIVATE KEY-----",
        ],
    )?;
    let mut keys = PrivateKeyDer::pem_slice_iter(pem);
    let key = keys
        .next()
        .ok_or(ServerCompositionError::InvalidTlsPem)?
        .map_err(|_| ServerCompositionError::InvalidTlsPem)?;
    if keys.next().is_some() {
        return Err(ServerCompositionError::InvalidTlsPem);
    }
    Ok(key)
}

fn validate_pem_begin_lines(pem: &[u8], allowed: &[&[u8]]) -> Result<(), ServerCompositionError> {
    let mut sections = 0_usize;
    for line in pem.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"-----BEGIN ") {
            sections = sections.saturating_add(1);
            if !allowed.contains(&line) {
                return Err(ServerCompositionError::InvalidTlsPem);
            }
        }
    }
    if sections == 0 {
        return Err(ServerCompositionError::InvalidTlsPem);
    }
    Ok(())
}

/// Sanitized failure while composing concrete production adapters.
#[derive(Debug, Error)]
pub enum ServerCompositionError {
    /// A bounded environment or file reference could not be loaded.
    #[error(transparent)]
    Secret(#[from] SecretLoadError),
    /// A mandatory local envelope-key source or rotation set was invalid.
    #[error(transparent)]
    Encryption(#[from] SecretEncryptionLoadError),
    /// `PostgreSQL` could not connect or apply embedded migrations.
    #[error(transparent)]
    Postgres(#[from] PostgresStoreError),
    /// S3 namespace or credential configuration was invalid.
    #[error(transparent)]
    S3(#[from] S3BlobStoreConfigError),
    /// The unauthenticated UI fallback tenant is invalid.
    #[error("fallback tenant identity is invalid")]
    InvalidFallbackTenant,
    /// Enabled UI and provider surfaces disagree on tenant scope.
    #[error("human UI and GitHub provider tenant configuration is inconsistent")]
    InconsistentEffectiveUiTenant,
    /// The configured human-authentication adapters or policies are invalid.
    #[error("human authentication configuration is invalid")]
    InvalidHumanAuthentication,
    /// Runner enrollment CA material or public endpoint was invalid.
    #[error("runner enrollment configuration is invalid")]
    InvalidRunnerEnrollment,
    /// The configured built-in provider violates the encrypted secret contract.
    #[error("secret management configuration is invalid")]
    InvalidSecretManagement,
    /// Durable installation state could not be read safely.
    #[error("human authentication installation state is unavailable")]
    HumanAuthenticationState,
    /// Human authentication was enabled before installation setup completed.
    #[error("human authentication installation setup is not complete")]
    HumanAuthenticationNotConfigured,
    /// Installation setup could not be armed from the exact operator configuration.
    #[error("human authentication installation setup could not be armed")]
    HumanAuthenticationSetup,
    /// Durable runner capabilities do not match products ready on this replica.
    #[error("runner capability admission failed")]
    RunnerCapabilityAdmission,
    /// A fresh process-local run-finalization worker identity was invalid.
    #[error("logical run-finalization worker identity is invalid")]
    InvalidLogicalRunFinalizationWorker,
    /// A fresh process-local result-projection worker identity was invalid.
    #[error("logical result-projection worker identity is invalid")]
    InvalidLogicalResultProjectionWorker,
    /// A fresh process-local autonomous workflow worker identity was invalid.
    #[error("autonomous workflow worker identity is invalid")]
    InvalidAutonomousWorkflowWorker,
    /// Plain HTTP was not explicitly permitted for a loopback S3 endpoint.
    #[error("plain HTTP S3 requires the explicit loopback-development option")]
    InsecureS3Endpoint,
    /// A PEM source was malformed, empty, excessive, or contained multiple keys.
    #[error("runner TLS PEM material is invalid")]
    InvalidTlsPem,
    /// The private management listener's TLS identity or product wiring was invalid.
    #[error("management listener configuration is invalid")]
    InvalidManagementConfiguration,
    /// The reviewed TLS/transport policy rejected the supplied configuration.
    #[error(transparent)]
    Transport(#[from] TransportConfigurationError),
    /// The product's fixed readiness descriptor violated its own invariant.
    #[error("internal immutable readiness object is invalid")]
    InternalReadinessObject,
    /// The readiness-monitor interval was invalid.
    #[error(transparent)]
    ReadinessMonitor(#[from] ReadinessMonitorError),
    /// The bounded replica maintenance policy was invalid.
    #[error(transparent)]
    MaintenanceLoop(#[from] MaintenanceLoopConfigError),
    /// Results endpoint, signing policy, or runtime authority composition was invalid.
    #[error("GitHub Results authority configuration is invalid")]
    InvalidResultsConfiguration,
    /// Optional GitHub-compatible OIDC composition or durable readiness was invalid.
    #[error(transparent)]
    GithubOidc(#[from] GithubOidcProductError),
    /// The optional GitHub provider configuration or its secret encoding was invalid.
    #[error("GitHub provider configuration is invalid")]
    InvalidGithubProviderConfiguration,
    /// The exact GitHub provider runtime could not be built or converged.
    #[error(transparent)]
    GithubProvider(#[from] GithubProviderRuntimeBuildError),
    /// At least one mandatory dependency failed its startup probe.
    #[error(
        "mandatory dependency probe failed (database_ready={database}, object_store_ready={object_store})"
    )]
    DependencyProbe {
        /// Whether database connection and embedded migrations succeeded.
        database: bool,
        /// Whether immutable object creation and verified read succeeded.
        object_store: bool,
    },
}
