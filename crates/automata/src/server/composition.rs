use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_auth::{
    machine::MachineIdentityVerifier,
    time::{Clock, SystemClock},
};
use automata_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType};
use automata_blob_s3::{
    S3BlobStore, S3BlobStoreConfig, S3BlobStoreConfigError, StaticS3Credentials,
};
use automata_control::{
    LeaseClock, LeaseIdGenerator, LeasePollConfig, RandomLeaseIdGenerator, SystemLeaseClock,
};
use automata_control_plane::{DeterministicScheduler, SchedulerPolicy};
use automata_protocol::ProtocolLimits;
use automata_results_github::{
    ArtifactRepository, ArtifactService, GithubResultsApi, GithubResultsHttpLimits,
    GithubResultsRuntimeAuthorityIssuer, HmacResultsAuthority, HmacResultsAuthorityConfig,
    PostgresArtifactRepository, ResultsClock, ResultsIdGenerator, ResultsLimits,
    SystemResultsClock, SystemResultsIdGenerator,
};
use automata_runner_auth::{DurableRunnerMachineAuthenticator, RunnerMachineAuthLimits};
use automata_runner_auth_postgres::PostgresRunnerMachineDirectory;
use automata_runner_control::{
    ControlIdGenerator, DurableRunnerControlHandler, ImmutableBlobJobIrReader, JobIrObjectReader,
    LeaseOfferCommandPublisher, LeasePollAdapter, LeasePoller, RandomControlIdGenerator,
    RunnerControlConfig, RunnerControlPorts, RunnerDurabilityPorts, RunnerIdentityPorts,
    RunnerLeasePorts, RunnerRegistrationAuthorizer, RunnerSessionFenceResolver,
    StoreLeaseOfferCommandPublisher, StoreRunnerSessionFenceResolver,
};
use automata_runner_transport::{
    ConfigurationError as TransportConfigurationError, RunnerControlHandler, RunnerControlServer,
    ServerTlsConfig, TlsVersionPolicy, TransportLimits,
};
use automata_store::{
    ControlPlaneMaintenanceRepository, CurrentRunnerSessionRepository, PostgresStore,
    PostgresStoreError, RunnerCommandOutbox, RunnerControlTransactionRepository,
    RunnerLeaseOfferRepository, RunnerLeaseRequestRepository, RunnerOperationReceiptRepository,
    RunnerSessionRepository, TenantScope,
};
use automata_workflow_service::{
    GithubWorkflowMaterializer, WorkflowAdmissionService, github_hosted_ubuntu_24_04_catalog,
};
use axum::Router;
use bytes::Bytes;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use thiserror::Error;
use tokio::net::TcpListener;

use super::{
    ControlPlaneMaintenanceLoop, MaintenanceClock, MaintenanceLoopConfigError, Readiness,
    ReadinessMonitor, ReadinessMonitorError, ReadinessProbe, ReadinessProbeError, SecretLoadError,
    ServerConfig, SystemMaintenanceClock,
};
use crate::app::workflow_api::{
    GithubLocalWorkflowAdmission, LocalAdmissionToken, local_workflow_admission_router,
};

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

pub(crate) struct ProductionComponents {
    pub(crate) runner_server: RunnerControlServer,
    pub(crate) readiness_monitor: ReadinessMonitor,
    pub(crate) maintenance_loop: ControlPlaneMaintenanceLoop,
    pub(crate) human_api: Router,
    pub(crate) results_api: Router,
}

impl fmt::Debug for ProductionComponents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionComponents")
            .field("runner_server", &self.runner_server)
            .field("readiness_monitor", &self.readiness_monitor)
            .field("maintenance_loop", &self.maintenance_loop)
            .field("human_api", &self.human_api)
            .field("results_api", &self.results_api)
            .finish()
    }
}

impl ProductionComponents {
    pub(crate) async fn initialize(
        config: &ServerConfig,
        runner_listener: TcpListener,
        readiness: &Readiness,
    ) -> Result<Self, ServerCompositionError> {
        let tls = load_server_tls(config)?;
        let blob_store = build_blob_store(config)?;
        let database_url = config.load_database_url()?;
        let store =
            Arc::new(PostgresStore::connect(&database_url, config.database_max_connections).await?);
        // Schema changes are a startup transition, not a liveness probe. Running
        // the migrator on every readiness tick repeatedly acquires migration
        // locks and emits expected duplicate-table diagnostics under SQLx.
        store.migrate().await?;

        let database_probe: Arc<dyn ReadinessProbe> =
            Arc::new(PostgresConnectionProbe::new(Arc::clone(&store)));
        let object_store_probe: Arc<dyn ReadinessProbe> =
            Arc::new(ImmutableBlobReadinessProbe::new(Arc::clone(&blob_store))?);
        let readiness_monitor = ReadinessMonitor::new(
            database_probe,
            object_store_probe,
            config.readiness_probe_interval,
        )?;
        let snapshot = readiness_monitor.check_once(readiness).await;
        if !snapshot.is_ready() {
            return Err(ServerCompositionError::DependencyProbe {
                database: snapshot.database(),
                object_store: snapshot.object_store(),
            });
        }

        let human_api = build_human_api(config, store.clone(), blob_store.clone())?;
        let maintenance_loop = build_maintenance_loop(config, store.clone())?;
        let (results_api, runtime_authority_issuer) =
            build_results(config, store.as_ref(), blob_store.clone())?;

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

        let lease_repository: Arc<dyn automata_control::LeasePollRepository> = store.clone();
        let lease_poller: Arc<dyn LeasePoller> = Arc::new(LeasePollAdapter::new(
            lease_repository,
            scheduler,
            Arc::clone(&lease_clock),
            lease_ids,
            LeasePollConfig::default(),
        ));
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
        let command_outbox: Arc<dyn RunnerCommandOutbox> = store;
        let authorizer: Arc<dyn RunnerRegistrationAuthorizer> = authenticator.clone();

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
        let handler: Arc<dyn RunnerControlHandler> =
            Arc::new(DurableRunnerControlHandler::new(ports, control_config));
        let verifier: Arc<dyn MachineIdentityVerifier> = authenticator;
        let runner_server = RunnerControlServer::new(
            runner_listener,
            &tls,
            verifier,
            handler,
            ProtocolLimits::default(),
            TransportLimits::default(),
        )?;

        Ok(Self {
            runner_server,
            readiness_monitor,
            maintenance_loop,
            human_api,
            results_api,
        })
    }
}

fn build_results(
    config: &ServerConfig,
    store: &PostgresStore,
    blob_store: Arc<dyn ImmutableBlobStore>,
) -> Result<
    (
        Router,
        Arc<dyn automata_runner_control::RuntimeAuthorityIssuer>,
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
    let runtime_authority_issuer: Arc<dyn automata_runner_control::RuntimeAuthorityIssuer> =
        Arc::new(
            GithubResultsRuntimeAuthorityIssuer::new(
                Arc::clone(&authority),
                RESULTS_RUNTIME_TOKEN_VALIDITY_SECONDS,
            )
            .map_err(|_| ServerCompositionError::InvalidResultsConfiguration)?,
        );
    let repository: Arc<dyn ArtifactRepository> = Arc::new(PostgresArtifactRepository::new(
        store.postgres_pool().clone(),
    ));
    let ids: Arc<dyn ResultsIdGenerator> = Arc::new(SystemResultsIdGenerator);
    let service = Arc::new(ArtifactService::new(
        repository,
        blob_store,
        clock,
        ids,
        ResultsLimits::default(),
    ));
    let runtime_tokens = authority.clone();
    let upload_capabilities = authority;
    let router = GithubResultsApi::new(
        service,
        runtime_tokens,
        upload_capabilities,
        GithubResultsHttpLimits::default(),
    )
    .router();
    Ok((router, runtime_authority_issuer))
}

fn build_maintenance_loop(
    config: &ServerConfig,
    store: Arc<PostgresStore>,
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
}

fn build_human_api(
    config: &ServerConfig,
    store: Arc<PostgresStore>,
    blob_store: Arc<dyn ImmutableBlobStore>,
) -> Result<Router, ServerCompositionError> {
    let Some(token) = config.load_local_admission_token()? else {
        return Ok(Router::new());
    };
    let token = Arc::new(
        LocalAdmissionToken::new(token.as_str())
            .map_err(|_| ServerCompositionError::InvalidLocalAdmission)?,
    );
    let tenant = TenantScope::from_authenticated_tenant_id(&config.local_admission_tenant)
        .map_err(|_| ServerCompositionError::InvalidLocalAdmission)?;
    let profiles = github_hosted_ubuntu_24_04_catalog()
        .map_err(|_| ServerCompositionError::InvalidLocalAdmission)?;
    let materializer = Arc::new(GithubWorkflowMaterializer::new(profiles));
    let repository: Arc<dyn automata_store::WorkflowAdmissionRepository> = store;
    let service = WorkflowAdmissionService::with_system_ports(blob_store, repository, materializer);
    let admission = Arc::new(GithubLocalWorkflowAdmission::new(tenant, service));
    Ok(local_workflow_admission_router(admission, token))
}

#[derive(Debug)]
struct PostgresConnectionProbe {
    store: Arc<PostgresStore>,
}

impl PostgresConnectionProbe {
    const fn new(store: Arc<PostgresStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ReadinessProbe for PostgresConnectionProbe {
    async fn probe(&self) -> Result<(), ReadinessProbeError> {
        self.store
            .postgres_pool()
            .acquire()
            .await
            .map(|_| ())
            .map_err(|_| ReadinessProbeError)
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
    ServerTlsConfig::new(
        roots,
        certificate_chain,
        private_key,
        TlsVersionPolicy::Tls13Only,
    )
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
    /// `PostgreSQL` could not connect or apply embedded migrations.
    #[error(transparent)]
    Postgres(#[from] PostgresStoreError),
    /// S3 namespace or credential configuration was invalid.
    #[error(transparent)]
    S3(#[from] S3BlobStoreConfigError),
    /// Local bootstrap admission configuration is invalid.
    #[error("local workflow admission configuration is invalid")]
    InvalidLocalAdmission,
    /// Plain HTTP was not explicitly permitted for a loopback S3 endpoint.
    #[error("plain HTTP S3 requires the explicit loopback-development option")]
    InsecureS3Endpoint,
    /// A PEM source was malformed, empty, excessive, or contained multiple keys.
    #[error("runner TLS PEM material is invalid")]
    InvalidTlsPem,
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
