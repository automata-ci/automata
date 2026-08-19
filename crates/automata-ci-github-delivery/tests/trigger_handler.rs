use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::MemoryBlobStore;
use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_github_delivery::{
    GithubTriggerCredential, GithubTriggerCredentialOperation, GithubTriggerCredentialProvider,
    GithubTriggerCredentialProviderError, GithubTriggerCredentialRelease,
    GithubTriggerCredentialRequest, GithubTriggerHandler, GithubWorkflowTriggerHandler,
};
use automata_ci_provider::{
    BindProviderProcessingSource, ClaimProviderProcessing, ClaimedProviderProcessing,
    ClaimedProviderResult, CompleteProviderProcessing, CompleteProviderResult, ExternalDeliveryId,
    ExternalDeliveryIdentity, ExternalRepositoryId, ExternalRepositoryIdentity, ExternalSubjectId,
    FailProviderProcessing, FailProviderResult, NormalizedTrigger, ProviderArchiveLimits,
    ProviderCapabilities, ProviderConfigurationRevision, ProviderConnectionConfiguration,
    ProviderConnectionId, ProviderConnectionManifest, ProviderConnectionRevision,
    ProviderDefaultBranch, ProviderDeliveryEvidence, ProviderDeliveryId,
    ProviderDeliveryObservations, ProviderEventName, ProviderGitRef, ProviderGitRefKind,
    ProviderInstanceId, ProviderInstanceManifest, ProviderInstanceRecord, ProviderLifecycleState,
    ProviderManifestRepository, ProviderOrigins, ProviderProcessingClaimFence,
    ProviderProcessingFuture, ProviderProcessingInput, ProviderProcessingInvocationId,
    ProviderProcessingReceipt, ProviderProcessingRepository, ProviderProcessingRepositoryError,
    ProviderProcessingState, ProviderProcessingWorkerId, ProviderRepository,
    ProviderRepositoryError, ProviderRepositoryFuture, ProviderRepositoryPath,
    ProviderResultClaimFence, ProviderResultFuture, ProviderResultRepository,
    ProviderResultRepositoryError, ProviderResultSaveOutcome, ProviderResultSubject,
    ProviderRunnerPolicyBinding, ProviderSaveOutcome, ProviderSchemaVersion,
    ProviderSecretBindings, ProviderSecretSet, ProviderTypeId, ProviderWebhookEndpointId,
    ProviderWebhookEndpointRevision, ProviderWebhookSecretReference,
    ProviderWebhookSignatureEvidence, ProviderWorkflowSource, PushCommitEvidence, PushTrigger,
    RenewProviderProcessing, RenewProviderResult, RepositoryVisibility, RetryProviderProcessing,
    RetryProviderResult, SaveDesiredProviderResult, VerifiedProviderControlDelivery,
    VerifiedProviderTriggerDelivery, provider_capability_digest, provider_raw_webhook_descriptor,
};
use automata_ci_provider_delivery::{
    ProviderControlHandlingError, ProviderDeliveryClock, ProviderDeliveryClockError,
    ProviderProcessingDispatcher, ProviderProcessingLease, ProviderProcessingProcessor,
    ProviderProcessingWorker, ProviderProcessingWorkerConfig, ProviderProcessingWorkerOutcome,
    ProviderRuntimeAdapter, ProviderRuntimeAdapterRegistry, ProviderRuntimeContext,
    ProviderTriggerOutcome,
};
use automata_ci_provider_github::{
    GithubConnectionPolicy, GithubHttpLimits, GithubInstanceConfiguration, GithubJwtIssuer,
    GithubProviderFactory,
};
use automata_ci_scm::RepositoryId;
use automata_ci_store::{
    AdmitLogicalWorkflowRun, AuthenticatedProviderDeliveryClaim, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, ProviderWorkflowApplicationService, ProviderWorkflowResultService,
    WorkflowAdmissionService,
};
use axum::http::StatusCode;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::support::{AFTER, BEFORE, HttpResponse, HttpServer, archive};

const WORKFLOW_PATH: &str = ".ci/workflows/ci.yml";
const FILTERED_WORKFLOW: &[u8] = br"name: Filtered
on:
  push:
    paths:
      - src/**
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - run: echo filtered
";

#[tokio::test]
async fn common_worker_drives_exact_github_source_diff_admission_and_result_contracts() {
    let server = HttpServer::spawn().await;
    enqueue_filtered_source(&server);
    let contract = contract(&server.origin());

    assert_eq!(
        contract.worker.run_once().await.expect("processing pass"),
        ProviderProcessingWorkerOutcome::Completed
    );
    assert_eq!(contract.processing.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        contract
            .admissions
            .commands
            .lock()
            .expect("admission lock")
            .len(),
        1
    );
    let desired = contract.results.desired.lock().expect("result lock");
    assert_eq!(desired.len(), 1);
    assert_eq!(
        desired[0].projection().phase(),
        automata_ci_provider::ProviderResultPhase::Queued
    );
    drop(desired);
    assert_eq!(
        contract
            .credentials
            .operations
            .lock()
            .expect("credential lock")
            .as_slice(),
        &[
            GithubTriggerCredentialOperation::ReadSource,
            GithubTriggerCredentialOperation::ReadPushChangedFiles,
        ]
    );
    assert_eq!(contract.releases.load(Ordering::SeqCst), 2);

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[0].uri,
        format!("/api/v3/repos/owner/repository/tarball/{AFTER}")
    );
    assert_eq!(requests[1].uri, "/archive/source.tar.gz");
    assert_eq!(
        requests[2].uri,
        format!("/api/v3/repos/owner/repository/compare/{BEFORE}...{AFTER}?per_page=100&page=1")
    );
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[2].method, "GET");
    assert_eq!(requests[0].headers["authorization"], "Bearer trigger-token");
    assert_eq!(requests[2].headers["authorization"], "Bearer trigger-token");
    assert!(!requests[1].headers.contains_key("authorization"));
    assert!(requests.iter().all(|request| request.body.is_empty()));
}

fn enqueue_filtered_source(server: &HttpServer) {
    let source = archive(BTreeMap::from([(WORKFLOW_PATH, FILTERED_WORKFLOW)]));
    server.enqueue(
        HttpResponse::status(StatusCode::FOUND)
            .header("location", server.url("archive/source.tar.gz").as_str()),
    );
    server.enqueue(HttpResponse::binary(
        StatusCode::OK,
        "application/gzip",
        source.to_vec(),
    ));
    server.enqueue(HttpResponse::json(
        StatusCode::OK,
        serde_json::to_vec(&json!({
            "status": "ahead",
            "ahead_by": 1,
            "behind_by": 0,
            "total_commits": 1,
            "base_commit": {"sha": BEFORE},
            "merge_base_commit": {"sha": BEFORE},
            "commits": [{"sha": AFTER}],
            "files": [{"filename": "src/lib.rs", "status": "modified"}]
        }))
        .expect("compare response"),
    ));
}

struct Contract {
    worker: ProviderProcessingWorker,
    processing: Arc<ProcessingRepository>,
    admissions: Arc<Admissions>,
    results: Arc<Results>,
    credentials: Arc<Credentials>,
    releases: Arc<AtomicUsize>,
}

fn contract(origin: &Url) -> Contract {
    let (provider, connection) = manifests(origin);
    let worker_id = ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(5)).expect("worker");
    let invocation = invocation(&provider, &connection, worker_id);
    let processing = Arc::new(ProcessingRepository::new(invocation));
    let manifests = Arc::new(Manifests {
        provider,
        connection,
    });
    let admissions = Arc::new(Admissions::default());
    let results = Arc::new(Results::default());
    let result_service = ProviderWorkflowResultService::new(
        results.clone(),
        Url::parse("https://ci.automata.example/").expect("dashboard origin"),
    )
    .expect("result service");
    let application = ProviderWorkflowApplicationService::new(
        WorkflowAdmissionService::with_system_ports(
            Arc::new(MemoryBlobStore::default()),
            admissions.clone(),
            Arc::new(GithubWorkflowPlanVerifier::new()),
        ),
        result_service,
    );
    let releases = Arc::new(AtomicUsize::new(0));
    let credentials = Arc::new(Credentials {
        operations: Mutex::new(Vec::new()),
        releases: releases.clone(),
    });
    let trigger_handler = Arc::new(
        GithubWorkflowTriggerHandler::new(
            application,
            credentials.clone(),
            Arc::new(FixedClock),
            "automata-trigger-contract/1",
            GithubHttpLimits::default(),
        )
        .expect("trigger handler"),
    );
    let runtime = Arc::new(TriggerRuntime {
        provider_type: ProviderTypeId::new("github").expect("provider type"),
        handler: trigger_handler,
    });
    let dispatcher = Arc::new(ProviderProcessingDispatcher::new(
        ProviderRuntimeAdapterRegistry::new([runtime as Arc<dyn ProviderRuntimeAdapter>])
            .expect("runtime registry"),
        manifests,
    ));
    let worker = ProviderProcessingWorker::new(
        worker_id,
        processing.clone(),
        dispatcher as Arc<dyn ProviderProcessingProcessor>,
        Arc::new(FixedClock),
        ProviderProcessingWorkerConfig::new(60_000, 1_000).expect("worker config"),
    );
    Contract {
        worker,
        processing,
        admissions,
        results,
        credentials,
        releases,
    }
}

#[derive(Debug)]
struct TriggerRuntime {
    provider_type: ProviderTypeId,
    handler: Arc<dyn GithubTriggerHandler>,
}

#[async_trait]
impl ProviderRuntimeAdapter for TriggerRuntime {
    fn provider_type(&self) -> &ProviderTypeId {
        &self.provider_type
    }

    async fn process_trigger(
        &self,
        context: &ProviderRuntimeContext,
        trigger: &VerifiedProviderTriggerDelivery,
        invocation: &ClaimedProviderProcessing,
        lease: &ProviderProcessingLease,
    ) -> ProviderTriggerOutcome {
        self.handler
            .process_trigger(context, trigger, invocation, lease)
            .await
    }

    async fn handle_control(
        &self,
        _context: &ProviderRuntimeContext,
        _control: &VerifiedProviderControlDelivery,
        _invocation: &ClaimedProviderProcessing,
        _lease: &ProviderProcessingLease,
    ) -> Result<Option<ProviderDeliveryId>, ProviderControlHandlingError> {
        Err(ProviderControlHandlingError::InvalidEvidence)
    }
}

#[derive(Debug)]
struct Credentials {
    operations: Mutex<Vec<GithubTriggerCredentialOperation>>,
    releases: Arc<AtomicUsize>,
}

#[async_trait]
impl GithubTriggerCredentialProvider for Credentials {
    async fn acquire(
        &self,
        request: GithubTriggerCredentialRequest<'_>,
    ) -> Result<GithubTriggerCredential, GithubTriggerCredentialProviderError> {
        self.operations
            .lock()
            .expect("credential lock")
            .push(request.operation());
        let usable_until = UnixMillis::new(
            request
                .required_through()
                .get()
                .checked_add(60_000)
                .expect("credential lifetime"),
        );
        GithubTriggerCredential::new(
            request.context().connection().revision(),
            request
                .context()
                .connection()
                .configuration()
                .repository()
                .external_id()
                .clone(),
            request.fence(),
            request.operation(),
            request.app_id(),
            request.installation_id(),
            request.repository().clone(),
            SecretString::new("trigger-token").expect("credential"),
            request.required_through(),
            usable_until,
            Box::new(Release(self.releases.clone())),
        )
        .map_err(|_| GithubTriggerCredentialProviderError::InvariantViolation)
    }
}

#[derive(Debug)]
struct Release(Arc<AtomicUsize>);

#[async_trait]
impl GithubTriggerCredentialRelease for Release {
    async fn release(self: Box<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct FixedClock;

impl ProviderDeliveryClock for FixedClock {
    fn now(&self) -> Result<UnixMillis, ProviderDeliveryClockError> {
        Ok(UnixMillis::new(1_000))
    }
}

#[derive(Debug)]
struct ProcessingRepository {
    claim: Mutex<Option<ClaimedProviderProcessing>>,
    receipt: ProviderProcessingReceipt,
    completed: AtomicUsize,
}

impl ProcessingRepository {
    fn new(claim: ClaimedProviderProcessing) -> Self {
        Self {
            receipt: claim.receipt(),
            claim: Mutex::new(Some(claim)),
            completed: AtomicUsize::new(0),
        }
    }
}

impl ProviderProcessingRepository for ProcessingRepository {
    fn claim_processing(
        &self,
        _request: ClaimProviderProcessing,
    ) -> ProviderProcessingFuture<'_, Option<ClaimedProviderProcessing>> {
        Box::pin(async move { Ok(self.claim.lock().expect("claim lock").take()) })
    }

    fn bind_processing_source(
        &self,
        _request: BindProviderProcessingSource,
    ) -> ProviderProcessingFuture<'_, ClaimedProviderProcessing> {
        Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
    }

    fn renew_processing(
        &self,
        _request: RenewProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingClaimFence> {
        Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
    }

    fn complete_processing(
        &self,
        _request: CompleteProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
        Box::pin(async move {
            self.completed.fetch_add(1, Ordering::SeqCst);
            ProviderProcessingReceipt::new(
                self.receipt.invocation_id(),
                self.receipt.cause_delivery_id(),
                self.receipt.source_delivery_id(),
                ProviderProcessingState::Completed,
                self.receipt.attempts(),
                self.receipt.created_at(),
            )
            .map_err(|_| ProviderProcessingRepositoryError::Corrupt)
        })
    }

    fn retry_processing(
        &self,
        _request: RetryProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
        Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
    }

    fn fail_processing(
        &self,
        _request: FailProviderProcessing,
    ) -> ProviderProcessingFuture<'_, ProviderProcessingReceipt> {
        Box::pin(async { Err(ProviderProcessingRepositoryError::Corrupt) })
    }
}

#[derive(Debug)]
struct Manifests {
    provider: ProviderInstanceManifest,
    connection: ProviderConnectionManifest,
}

impl ProviderManifestRepository for Manifests {
    fn save_instance(
        &self,
        _record: ProviderInstanceRecord,
    ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
        Box::pin(async { Err(ProviderRepositoryError::Unavailable) })
    }

    fn load_instance(
        &self,
        instance_id: ProviderInstanceId,
        revision: ProviderConfigurationRevision,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
        Box::pin(async move {
            if self.provider.instance_id() != instance_id || self.provider.revision() != revision {
                return Ok(None);
            }
            let secrets = ProviderSecretSet::new(self.provider.secrets(), [])
                .map_err(|_| ProviderRepositoryError::Corrupt)?;
            ProviderInstanceRecord::new(self.provider.clone(), secrets).map(Some)
        })
    }

    fn current_instance(
        &self,
        instance_id: ProviderInstanceId,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderInstanceRecord>> {
        Box::pin(async move {
            if self.provider.instance_id() != instance_id {
                return Ok(None);
            }
            let secrets = ProviderSecretSet::new(self.provider.secrets(), [])
                .map_err(|_| ProviderRepositoryError::Corrupt)?;
            ProviderInstanceRecord::new(self.provider.clone(), secrets).map(Some)
        })
    }

    fn latest_secret_generation(
        &self,
        _instance_id: ProviderInstanceId,
        _name: automata_ci_provider::ProviderSecretName,
    ) -> ProviderRepositoryFuture<'_, Option<automata_ci_provider::ProviderSecretGeneration>> {
        Box::pin(async { Ok(None) })
    }

    fn save_connection(
        &self,
        _manifest: ProviderConnectionManifest,
    ) -> ProviderRepositoryFuture<'_, ProviderSaveOutcome> {
        Box::pin(async { Err(ProviderRepositoryError::Unavailable) })
    }

    fn load_connection(
        &self,
        connection_id: ProviderConnectionId,
        revision: ProviderConnectionRevision,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
        Box::pin(async move {
            Ok((self.connection.connection_id() == connection_id
                && self.connection.revision() == revision)
                .then(|| self.connection.clone()))
        })
    }

    fn current_connection(
        &self,
        connection_id: ProviderConnectionId,
    ) -> ProviderRepositoryFuture<'_, Option<ProviderConnectionManifest>> {
        Box::pin(async move {
            Ok((self.connection.connection_id() == connection_id).then(|| self.connection.clone()))
        })
    }

    fn current_connections(
        &self,
        instance_id: ProviderInstanceId,
    ) -> ProviderRepositoryFuture<'_, Vec<ProviderConnectionManifest>> {
        Box::pin(async move {
            Ok(
                (self.connection.configuration().repository().instance_id() == instance_id)
                    .then(|| self.connection.clone())
                    .into_iter()
                    .collect(),
            )
        })
    }
}

#[derive(Debug, Default)]
struct Admissions {
    commands: Mutex<Vec<AdmitLogicalWorkflowRun>>,
}

#[async_trait]
impl LogicalWorkflowAdmissionRepository for Admissions {
    async fn admit_logical_workflow(
        &self,
        _command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    async fn admit_authenticated_provider_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        _current_claim: AuthenticatedProviderDeliveryClaim,
        _observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            false,
        );
        self.commands.lock().expect("admission lock").push(command);
        Ok(receipt)
    }
}

#[derive(Debug, Default)]
struct Results {
    desired: Mutex<Vec<SaveDesiredProviderResult>>,
}

impl ProviderResultRepository for Results {
    fn load_workflow_subject(
        &self,
        _run_id: automata_ci_core::RunId,
    ) -> ProviderResultFuture<'_, Option<ProviderResultSubject>> {
        Box::pin(async { Ok(None) })
    }

    fn save_desired(
        &self,
        request: SaveDesiredProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultSaveOutcome> {
        Box::pin(async move {
            self.desired.lock().expect("result lock").push(request);
            Ok(ProviderResultSaveOutcome::Inserted)
        })
    }

    fn claim_result(
        &self,
        _request: automata_ci_provider::ClaimProviderResult,
    ) -> ProviderResultFuture<'_, Option<ClaimedProviderResult>> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn complete_result(&self, _request: CompleteProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn renew_result(
        &self,
        _request: RenewProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultClaimFence> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn retry_result(&self, _request: RetryProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }

    fn fail_result(&self, _request: FailProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
    }
}

fn manifests(origin: &Url) -> (ProviderInstanceManifest, ProviderConnectionManifest) {
    let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(1)).expect("instance");
    let provider_revision = ProviderConfigurationRevision::new(1).expect("provider revision");
    let api = origin.join("api/v3/").expect("API origin");
    let capabilities: ProviderCapabilities =
        GithubProviderFactory::capabilities().expect("GitHub capabilities");
    let provider = ProviderInstanceManifest::new(
        instance_id,
        ProviderTypeId::new("github").expect("provider type"),
        provider_revision,
        ProviderLifecycleState::Active,
        ProviderOrigins::new(origin.as_str(), api.as_str()).expect("provider origins"),
        GithubInstanceConfiguration::new(
            501,
            "Iv1.automata",
            GithubJwtIssuer::AppClientId,
            origin.clone(),
        )
        .expect("GitHub configuration")
        .document()
        .expect("configuration document"),
        ProviderSecretBindings::empty(),
        provider_capability_digest(&capabilities).expect("capability digest"),
        UnixMillis::new(100),
        Some(UnixMillis::new(100)),
        None,
    )
    .expect("provider manifest");
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("workspace"),
        ExternalRepositoryIdentity::new(
            instance_id,
            ExternalRepositoryId::new("42").expect("repository ID"),
        ),
        provider_revision,
        provider.configuration().digest(),
        provider.capability_digest(),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".ci/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner schema"),
            Sha256Digest::from_bytes([5; 32]),
        ),
        ProviderArchiveLimits::new(
            1_024 * 1_024,
            8 * 1_024 * 1_024,
            1_000,
            1_024,
            100,
            1_024 * 1_024,
        )
        .expect("archive limits"),
        GithubConnectionPolicy::new(
            71,
            RepositoryId::new("owner/repository").expect("repository route"),
        )
        .expect("GitHub policy")
        .document()
        .expect("policy document"),
    );
    let connection = ProviderConnectionManifest::new(
        ProviderConnectionId::from_uuid(Uuid::from_u128(2)).expect("connection"),
        ProviderConnectionRevision::new(1).expect("connection revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(100),
        Some(UnixMillis::new(100)),
        None,
    )
    .expect("connection manifest");
    (provider, connection)
}

fn invocation(
    provider: &ProviderInstanceManifest,
    connection: &ProviderConnectionManifest,
    worker_id: ProviderProcessingWorkerId,
) -> ClaimedProviderProcessing {
    let repository = ProviderRepository::new(
        connection.configuration().repository().clone(),
        ExternalSubjectId::new("7").expect("owner ID"),
        ProviderRepositoryPath::new("owner/repository").expect("repository path"),
        RepositoryVisibility::Private,
    );
    let push = PushTrigger::new(
        repository,
        ProviderGitRef::new("refs/heads/main", ProviderGitRefKind::Branch).expect("branch ref"),
        Some(object(BEFORE)),
        Some(object(AFTER)),
        PushCommitEvidence::complete([object(AFTER)]).expect("commit evidence"),
        false,
        None,
    )
    .expect("push trigger");
    let sealed = NormalizedTrigger::Push(push)
        .seal()
        .expect("sealed trigger");
    let raw = provider_raw_webhook_descriptor(Sha256Digest::from_bytes([7; 32]), 1)
        .expect("raw descriptor");
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(3)).expect("delivery");
    let evidence = ProviderDeliveryEvidence::rehydrate(
        delivery_id,
        ProviderWebhookEndpointId::from_uuid(Uuid::from_u128(4)).expect("endpoint"),
        ProviderWebhookEndpointRevision::new(1).expect("endpoint revision"),
        provider.provider_type().clone(),
        provider.instance_id(),
        provider.revision(),
        connection.connection_id(),
        connection.revision(),
        ExternalDeliveryIdentity::new(
            provider.instance_id(),
            ExternalDeliveryId::new("delivery-1").expect("delivery identity"),
        ),
        ProviderEventName::new("push").expect("event name"),
        UnixMillis::new(900),
        raw,
        UnixMillis::new(1_000),
        ProviderWebhookSignatureEvidence::new(
            "github-hmac-sha256",
            ProviderWebhookSecretReference::new(
                provider.revision(),
                automata_ci_provider::ProviderSecretName::new("webhook-secret")
                    .expect("secret name"),
                automata_ci_provider::ProviderSecretGeneration::new(1).expect("secret generation"),
            ),
        )
        .expect("signature evidence"),
        ProviderDeliveryObservations::new(Vec::new()).expect("observations"),
    )
    .expect("delivery evidence");
    let delivery =
        VerifiedProviderTriggerDelivery::rehydrate(evidence, sealed).expect("verified delivery");
    let receipt = ProviderProcessingReceipt::new(
        ProviderProcessingInvocationId::from_uuid(Uuid::from_u128(6)).expect("invocation"),
        delivery_id,
        Some(delivery_id),
        ProviderProcessingState::Claimed,
        1,
        UnixMillis::new(1_000),
    )
    .expect("processing receipt");
    let fence = ProviderProcessingClaimFence::new(
        receipt.invocation_id(),
        worker_id,
        1,
        UnixMillis::new(1_000),
        UnixMillis::new(61_000),
    )
    .expect("processing fence");
    ClaimedProviderProcessing::new(
        receipt,
        ProviderProcessingInput::Trigger(Box::new(delivery)),
        fence,
    )
    .expect("claimed processing")
}

fn object(value: &str) -> automata_ci_core::GitObjectId {
    automata_ci_core::GitObjectId::from_provider_hex(value).expect("object ID")
}
