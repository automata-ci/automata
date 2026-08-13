use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_ci::app::{
    conformance_control::{ProductConformanceAdapters, ProductFaultOperation},
    conformance_fault_ports::{
        ConformanceArtifactRepository, ConformanceBlobStore,
        ConformanceGithubChecksCredentialProvider, ConformanceRepositoryCredentialBroker,
        ConformanceRepositorySource, ConformanceRunnerControlClient,
    },
};
use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType, MemoryBlobStore};
use automata_ci_conformance::{
    DurableTransition, FaultMode, FaultPlan, FixtureControlError, ProductService,
    ServiceObservation, ServiceRestartProbe, ServiceState, ShardPlan,
};
use automata_ci_core::{
    Architecture, AttemptId, FencingToken, JobId, JobIrVersionRange, OperatingSystem, OperationId,
    RunId, RunnerCapabilities, RunnerId, RunnerPlatform, UnixMillis,
};
use automata_ci_credential::{
    CredentialError, CredentialErrorKind, IssuedRepositoryCredential, MinimumValidity,
    PermissionLevel, PermissionName, PermissionSet, ProviderResourceId, RepositoryCredentialBroker,
    RepositoryCredentialRequest, RepositoryScope, WorkloadIdentity,
};
use automata_ci_github_delivery::GithubChecksCredentialProvider;
use automata_ci_protocol::{ProtocolLimits, RunnerHello, SUPPORTED_PROTOCOL_RANGE};
use automata_ci_results_github::{
    ArtifactBlockReservation, ArtifactFinalizationReservation, ArtifactFinalizationWork,
    ArtifactId, ArtifactName, ArtifactRepository, ArtifactRepositoryError,
    ArtifactRepositoryErrorKind, BeginArtifactFinalization, CommitArtifactBlocks,
    CommittedArtifact, CompleteArtifactBlock, CompleteArtifactFinalization, CreateArtifact,
    CreateArtifactOutcome, ExecutionAuthority, FinalizeArtifactOutcome, ListArtifacts,
    LoadArtifactFinalization, PublishedArtifactMetadata, RecordArtifactVerification,
    RenewArtifactFinalization, ReserveArtifactBlock, ResolveArtifactDownload, UploadId,
};
use automata_ci_runner_runtime::{
    RunnerRuntimeControlClient, RuntimeControlError, RuntimeControlErrorKind, RuntimeControlFuture,
    RuntimeControlRetry,
};
use automata_ci_runner_transport::PreparedRequest;
use automata_ci_scm::{
    ArchiveLimits, ExactRevision, RepositoryId, RepositorySource, RepositorySourcePort,
    RepositorySourceRequest, ScmError, ScmErrorKind, ScmProviderId,
};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug)]
struct Probe(Mutex<(ServiceState, u64)>);

impl Probe {
    fn new() -> Self {
        Self(Mutex::new((ServiceState::Running, 1)))
    }
}

impl ServiceRestartProbe for Probe {
    fn observe(&self, _service: ProductService) -> Result<ServiceObservation, FixtureControlError> {
        let state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        ServiceObservation::new(state.0, state.1, format!("process-{}", state.1))
    }

    fn stop(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        self.0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?
            .0 = ServiceState::Stopped;
        Ok(())
    }

    fn start(&self, _service: ProductService) -> Result<(), FixtureControlError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| FixtureControlError::ProbeFailed)?;
        state.1 += 1;
        state.0 = ServiceState::Running;
        Ok(())
    }
}

fn advance(adapters: &ProductConformanceAdapters, next: DurableTransition) {
    let [service] = adapters
        .control()
        .current_transition()
        .required_restart_services()
    else {
        panic!("nonterminal transition has one scheduled service");
    };
    adapters
        .control()
        .restart_with(*service, &Probe::new())
        .expect("scheduled restart");
    adapters.control().transition(next).expect("transition");
}

fn adapters(
    name: &str,
    faults: impl IntoIterator<Item = (ProductFaultOperation, DurableTransition, FaultMode)>,
) -> ProductConformanceAdapters {
    let plan = ShardPlan::derive(name, 1).expect("shard plan");
    ProductConformanceAdapters::for_shard(
        0,
        Arc::new(FaultPlan::new(faults).expect("fault plan")),
        &plan,
        0,
    )
    .expect("adapters")
}

#[derive(Debug)]
struct FailingSource {
    provider: ScmProviderId,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl RepositorySourcePort for FailingSource {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_repository_source(
        &self,
        _request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySource, ScmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ScmError::new(ScmErrorKind::NotFound))
    }
}

#[derive(Debug)]
struct FailingCredentialBroker {
    provider: ScmProviderId,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl RepositoryCredentialBroker for FailingCredentialBroker {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn issue(
        &self,
        _request: &RepositoryCredentialRequest,
    ) -> Result<IssuedRepositoryCredential, CredentialError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(CredentialError::new(CredentialErrorKind::NotFound))
    }
}

#[derive(Debug)]
struct FailingArtifacts {
    calls: Arc<AtomicUsize>,
    create_succeeds: bool,
}

impl FailingArtifacts {
    fn fail<T>(&self) -> Result<T, ArtifactRepositoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ArtifactRepositoryError::new(
            ArtifactRepositoryErrorKind::NotFound,
        ))
    }
}

#[async_trait]
impl ArtifactRepository for FailingArtifacts {
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        if self.create_succeeds {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(CreateArtifactOutcome {
                artifact_id: ArtifactId::new(1).expect("artifact ID"),
                upload_id: request.upload_id,
            })
        } else {
            self.fail()
        }
    }
    async fn reserve_block(
        &self,
        _request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        self.fail()
    }
    async fn complete_block(
        &self,
        _request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        self.fail()
    }
    async fn commit_blocks(
        &self,
        _request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        self.fail()
    }
    async fn begin_finalization(
        &self,
        _request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        self.fail()
    }
    async fn load_finalization(
        &self,
        _request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        self.fail()
    }
    async fn renew_finalization(
        &self,
        _request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        self.fail()
    }
    async fn record_verification(
        &self,
        _request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        self.fail()
    }
    async fn complete_finalization(
        &self,
        _request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        self.fail()
    }
    async fn list(
        &self,
        _request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        self.fail()
    }
    async fn resolve_download(
        &self,
        _request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        self.fail()
    }
}

#[derive(Debug)]
struct FailingRunner(Arc<AtomicUsize>);

impl RunnerRuntimeControlClient for FailingRunner {
    fn exchange<'a>(
        &'a self,
        _request: &'a PreparedRequest,
        _cancellation: CancellationToken,
    ) -> RuntimeControlFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(RuntimeControlError::new(
                RuntimeControlErrorKind::InvalidResponse,
                RuntimeControlRetry::Never,
            ))
        })
    }
}

fn create_artifact() -> CreateArtifact {
    CreateArtifact {
        authority: ExecutionAuthority::new(
            RunId::new(),
            JobId::new(),
            AttemptId::new(),
            FencingToken::new(1).expect("fence"),
        ),
        upload_id: UploadId::from_uuid(Uuid::new_v4()),
        name: ArtifactName::new("dist", 255).expect("name"),
        version: 1,
        mime_type: "application/zip".to_owned(),
        expires_at_seconds: None,
        observed_at_seconds: 1,
        maximum_artifacts_per_run: 1,
    }
}

fn hello_request() -> PreparedRequest {
    PreparedRequest::handshake(
        RunnerHello::new(
            OperationId::new(),
            SUPPORTED_PROTOCOL_RANGE,
            JobIrVersionRange::current(),
            RunnerCapabilities::new(
                RunnerId::new(),
                RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
            ),
            UnixMillis::new(1),
        ),
        &ProtocolLimits::default(),
    )
    .expect("hello")
}

fn assert_checks_provider<T: GithubChecksCredentialProvider>() {}

#[tokio::test]
async fn empty_plan_delegates_source_and_token_ports_and_leaves_checks_unarmed() {
    let adapters = adapters("empty-port-faults", []);
    let source_calls = Arc::new(AtomicUsize::new(0));
    let source = ConformanceRepositorySource::new(
        Arc::new(FailingSource {
            provider: ScmProviderId::new("github").expect("provider"),
            calls: Arc::clone(&source_calls),
        }),
        Arc::clone(adapters.faults()),
    );
    let repository = RepositoryId::new("automata-ci/automata").expect("repository");
    let revision = ExactRevision::new("a".repeat(40)).expect("revision");
    assert_eq!(
        source
            .fetch_repository_source(RepositorySourceRequest::public(
                &repository,
                &revision,
                ArchiveLimits::default(),
            ))
            .await
            .expect_err("delegate error")
            .kind(),
        ScmErrorKind::NotFound
    );
    assert_eq!(source_calls.load(Ordering::SeqCst), 1);

    let broker_calls = Arc::new(AtomicUsize::new(0));
    let broker = ConformanceRepositoryCredentialBroker::new(
        Arc::new(FailingCredentialBroker {
            provider: ScmProviderId::new("github").expect("provider"),
            calls: Arc::clone(&broker_calls),
        }),
        Arc::clone(adapters.faults()),
    );
    let credential_request = RepositoryCredentialRequest::new(
        WorkloadIdentity::new("tenant/run/job/attempt").expect("workload"),
        RepositoryScope::new(
            ScmProviderId::new("github").expect("provider"),
            RepositoryId::new("automata-ci/automata").expect("repository"),
            ProviderResourceId::new("42").expect("resource"),
        ),
        PermissionSet::new([(
            PermissionName::new("contents").expect("permission"),
            PermissionLevel::Read,
        )])
        .expect("permissions"),
        MinimumValidity::from_seconds(60).expect("validity"),
    );
    assert_eq!(
        broker
            .issue(&credential_request)
            .await
            .expect_err("delegate error")
            .kind(),
        CredentialErrorKind::NotFound
    );
    assert_eq!(broker_calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        adapters
            .faults()
            .take_due(ProductFaultOperation::ChecksCredential),
        Ok(None)
    );
    assert_checks_provider::<ConformanceGithubChecksCredentialProvider>();
}

#[tokio::test]
async fn object_results_and_runner_faults_are_operation_specific_then_delegate_when_exhausted() {
    let cases = [
        ProductFaultOperation::ObjectWrite,
        ProductFaultOperation::ResultsMutation,
        ProductFaultOperation::RunnerHandshake,
    ];
    let adapters = adapters(
        "typed-port-faults",
        cases.into_iter().map(|operation| {
            (
                operation,
                DurableTransition::Provisioned,
                FaultMode::Unavailable,
            )
        }),
    );

    let objects = ConformanceBlobStore::new(
        Arc::new(MemoryBlobStore::default()),
        Arc::clone(adapters.faults()),
    );
    let payload = || {
        BlobPayload::from_bytes(
            BlobKey::new("conformance/object").expect("key"),
            MediaType::new("application/octet-stream").expect("media type"),
            Bytes::from_static(b"payload"),
        )
    };
    assert_eq!(
        objects
            .put_if_absent(payload())
            .await
            .expect_err("fault")
            .kind(),
        automata_ci_blob::BlobStoreErrorKind::Unavailable
    );

    let artifact_calls = Arc::new(AtomicUsize::new(0));
    let results = ConformanceArtifactRepository::new(
        Arc::new(FailingArtifacts {
            calls: Arc::clone(&artifact_calls),
            create_succeeds: false,
        }),
        Arc::clone(adapters.faults()),
    );
    assert_eq!(
        results
            .create(create_artifact())
            .await
            .expect_err("fault")
            .kind(),
        ArtifactRepositoryErrorKind::Unavailable
    );
    assert_eq!(artifact_calls.load(Ordering::SeqCst), 0);

    let runner_calls = Arc::new(AtomicUsize::new(0));
    let runner = ConformanceRunnerControlClient::new(
        Arc::new(FailingRunner(Arc::clone(&runner_calls))),
        Arc::clone(adapters.faults()),
    );
    let hello = hello_request();
    assert_eq!(
        runner
            .exchange(&hello, CancellationToken::new())
            .await
            .expect_err("fault")
            .kind(),
        RuntimeControlErrorKind::Unavailable
    );
    assert_eq!(runner_calls.load(Ordering::SeqCst), 0);
    assert_eq!(adapters.control().faults().remaining(), 0);

    advance(&adapters, DurableTransition::WebhookAccepted);
    objects
        .put_if_absent(payload())
        .await
        .expect("exhausted object fault delegates");
    assert_eq!(
        results
            .create(create_artifact())
            .await
            .expect_err("delegate")
            .kind(),
        ArtifactRepositoryErrorKind::NotFound
    );
    assert_eq!(artifact_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        runner
            .exchange(&hello, CancellationToken::new())
            .await
            .expect_err("delegate")
            .kind(),
        RuntimeControlErrorKind::InvalidResponse
    );
    assert_eq!(runner_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn indeterminate_mutation_delegates_before_returning_an_unavailable_result() {
    let adapters = adapters(
        "indeterminate-mutation-faults",
        [
            (
                ProductFaultOperation::ObjectWrite,
                DurableTransition::Provisioned,
                FaultMode::IndeterminateMutation,
            ),
            (
                ProductFaultOperation::ResultsMutation,
                DurableTransition::Provisioned,
                FaultMode::IndeterminateMutation,
            ),
        ],
    );
    let backing = MemoryBlobStore::default();
    let objects =
        ConformanceBlobStore::new(Arc::new(backing.clone()), Arc::clone(adapters.faults()));
    let payload = BlobPayload::from_bytes(
        BlobKey::new("conformance/indeterminate").expect("key"),
        MediaType::new("application/octet-stream").expect("media type"),
        Bytes::from_static(b"committed"),
    );
    let descriptor = payload.descriptor().clone();
    assert_eq!(
        objects
            .put_if_absent(payload)
            .await
            .expect_err("post-commit injected error")
            .kind(),
        automata_ci_blob::BlobStoreErrorKind::Unavailable
    );
    assert_eq!(
        backing
            .get_verified(&descriptor, descriptor.size())
            .await
            .expect("underlying write committed")
            .bytes()
            .as_ref(),
        b"committed"
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let results = ConformanceArtifactRepository::new(
        Arc::new(FailingArtifacts {
            calls: Arc::clone(&calls),
            create_succeeds: true,
        }),
        Arc::clone(adapters.faults()),
    );
    assert_eq!(
        results
            .create(create_artifact())
            .await
            .expect_err("post-commit injected error")
            .kind(),
        ArtifactRepositoryErrorKind::Unavailable
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    results
        .create(create_artifact())
        .await
        .expect("one-shot fault is exhausted");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(adapters.control().faults().remaining(), 0);
}
