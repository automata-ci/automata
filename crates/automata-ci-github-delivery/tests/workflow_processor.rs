mod subject_evidence;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, ImmutableBlobStore as _, MediaType, MemoryBlobStore,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github_delivery::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubDeliveryClock, GithubDeliverySourceAuthority,
    GithubDeliveryWorker, GithubDeliveryWorkerConfig, GithubDeliveryWorkerError,
    GithubDeliveryWorkerOutcome, GithubDeliveryWorkerPrerequisite,
    GithubDeliveryWorkflowAdmissionProcessor,
};
use automata_ci_scm::{
    ArchiveFormat, ExactRevision, RepositoryId as ScmRepositoryId, RepositorySource,
    RepositorySourcePort, RepositorySourceRequest, ScmError, ScmProviderId,
};
use automata_ci_store::{
    AcceptProviderDelivery, AdmissionObject, AdmitLogicalWorkflowRun,
    AuthenticatedGithubDeliveryClaim, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, GithubAuthenticatedEvent, GithubAuthenticatedEventKind,
    GithubSubjectEvidenceRepository, GithubSubjectEvidenceStoreError,
    GithubWorkflowRunSubjectEvidence, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    ManifestPinnedGithubDeliveryEvidence, ManifestPinnedGithubDeliveryReceipt, ObjectKey,
    ProviderConnectionId, ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryId, ProviderDeliveryIdentity, ProviderDeliveryReceipt,
    ProviderDeliveryRepository, ProviderDeliveryState, ProviderDeliveryStoreError,
    ProviderDeliveryWorkflowConclusion, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RejectProviderDelivery, RepositoryId as StoreRepositoryId, RetryProviderDelivery, TenantScope,
    WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_service::{GithubWorkflowPlanVerifier, WorkflowAdmissionService};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType, Header};
use uuid::Uuid;

use subject_evidence::fixture_subject_evidence;

const BEFORE: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
const OWNER: &str = "octo-private";
const REPOSITORY: &str = "private-repository";
const REPOSITORY_ID: u64 = 9_001;
const REPOSITORY_OWNER_ID: u64 = 8_001;
const INSTALLATION_ID: u64 = 4_242;
const DELIVERY: &str = "delivery-workflow-processor-1";
const WORKFLOW_PATH: &str = ".ci/workflows/ci.yml";
const CREDENTIAL: &str = "installation-token-private-marker";
const ACCEPTED_WORKFLOW: &[u8] = b"name: Exact CI\non: push\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo exact\n";
const PATH_WORKFLOW: &[u8] = b"name: Paths CI\non:\n  push:\n    paths: ['src/**']\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo paths\n";
const PULL_REQUEST_WORKFLOW: &[u8] = b"name: Pull Request CI\non: pull_request\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo pull-request\n";

#[derive(Debug)]
struct FixedClock;

impl GithubDeliveryClock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(500)
    }
}

#[derive(Debug)]
struct FixedSource {
    source: RepositorySource,
    visibility: ProviderRepositoryVisibility,
}

#[async_trait]
impl RepositorySourcePort for FixedSource {
    fn provider_id(&self) -> &ScmProviderId {
        self.source.provider()
    }

    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySource, ScmError> {
        assert_eq!(request.repository(), self.source.repository());
        assert_eq!(request.revision(), self.source.revision());
        assert_eq!(
            request.credential().is_some(),
            self.visibility == ProviderRepositoryVisibility::Private
        );
        Ok(self.source.clone())
    }
}

#[derive(Debug, Default)]
struct LogicalAdmissions {
    commands: Mutex<Vec<AdmitLogicalWorkflowRun>>,
    delivery_ids: Mutex<Vec<ProviderDeliveryId>>,
    ordinary_calls: AtomicUsize,
}

impl LogicalAdmissions {
    fn commands(&self) -> Vec<AdmitLogicalWorkflowRun> {
        self.commands.lock().expect("commands lock").clone()
    }

    fn delivery_ids(&self) -> Vec<ProviderDeliveryId> {
        self.delivery_ids.lock().expect("delivery IDs lock").clone()
    }

    fn record(&self, command: AdmitLogicalWorkflowRun) -> LogicalWorkflowAdmissionReceipt {
        let replayed = !self.commands.lock().expect("commands lock").is_empty();
        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            replayed,
        );
        self.commands.lock().expect("commands lock").push(command);
        receipt
    }
}

#[async_trait]
impl LogicalWorkflowAdmissionRepository for LogicalAdmissions {
    async fn admit_logical_workflow(
        &self,
        command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        self.ordinary_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.record(command))
    }

    async fn admit_authenticated_github_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        assert_eq!(command.admitted_at(), observed_at);
        self.delivery_ids
            .lock()
            .expect("delivery IDs lock")
            .push(current_claim.claim().delivery_id());
        Ok(self.record(command))
    }
}

#[derive(Debug, Default)]
struct DeliveryOutcomes {
    completions: Mutex<Vec<CompleteProviderDelivery>>,
    retries: Mutex<Vec<RetryProviderDelivery>>,
}

impl DeliveryOutcomes {
    fn completions(&self) -> Vec<CompleteProviderDelivery> {
        self.completions.lock().expect("completions lock").clone()
    }
}

#[async_trait]
impl ProviderDeliveryRepository for DeliveryOutcomes {
    async fn accept_provider_delivery(
        &self,
        _request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        panic!("acceptance is outside the processor test")
    }

    async fn claim_provider_delivery(
        &self,
        _request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError> {
        panic!("claiming is outside the processor test")
    }

    async fn complete_provider_delivery(
        &self,
        request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        let receipt = transition_receipt(request.claim(), ProviderDeliveryState::Completed);
        self.completions
            .lock()
            .expect("completions lock")
            .push(request);
        Ok(receipt)
    }

    async fn retry_provider_delivery(
        &self,
        request: RetryProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        let receipt = transition_receipt(request.claim(), ProviderDeliveryState::RetryPending);
        self.retries.lock().expect("retries lock").push(request);
        Ok(receipt)
    }

    async fn reject_provider_delivery(
        &self,
        request: RejectProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        Ok(transition_receipt(
            request.claim(),
            ProviderDeliveryState::Rejected,
        ))
    }
}

#[derive(Clone)]
struct FixtureSubjectEvidence(ManifestPinnedGithubDeliveryEvidence);

impl FixtureSubjectEvidence {
    fn from_claimed(claimed: &ClaimedProviderDelivery) -> Self {
        Self(fixture_subject_evidence(
            claimed.receipt().id(),
            claimed.identity(),
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
            claimed.receipt().accepted_at(),
            0x7101,
        ))
    }

    fn authenticated_event(
        claimed: &ClaimedProviderDelivery,
        kind: GithubAuthenticatedEventKind,
        git_ref: &str,
    ) -> Self {
        let legacy = Self::from_claimed(claimed).0;
        let event = GithubAuthenticatedEvent::new(kind, git_ref).expect("event coordinates");
        Self(
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
                legacy.delivery_id(),
                legacy.repository_owner_id(),
                legacy.manifest().clone(),
                legacy.authenticated_webhook_verifier_fingerprint(),
                legacy.authenticated_webhook_verifier_revision(),
                legacy.checks_authority().clone(),
                legacy.private_source_authority().cloned(),
                legacy.check_subject_id(),
                legacy.check_head_sha(),
                event,
                legacy.accepted_at(),
            )
            .expect("authenticated event evidence"),
        )
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for FixtureSubjectEvidence {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        _request: automata_ci_store::AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        panic!("acceptance is outside the processor test")
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        if self.0.tenant() != tenant || self.0.delivery_id() != delivery_id {
            return Err(GithubSubjectEvidenceStoreError::NotFound);
        }
        Ok(self.0.clone())
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        _tenant: &TenantScope,
        _repository_id: StoreRepositoryId,
        _run_id: automata_ci_core::RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        panic!("run evidence is outside the processor test")
    }
}

fn transition_receipt(
    claim: ProviderDeliveryClaimFence,
    state: ProviderDeliveryState,
) -> ProviderDeliveryReceipt {
    ProviderDeliveryReceipt::from_durable_parts(claim.delivery_id(), state, 1, UnixMillis::new(50))
        .expect("transition receipt")
}

struct Harness {
    worker: GithubDeliveryWorker,
    claimed: ClaimedProviderDelivery,
    blobs: Arc<MemoryBlobStore>,
    logical: Arc<LogicalAdmissions>,
    deliveries: Arc<DeliveryOutcomes>,
}

async fn harness(files: BTreeMap<&str, &[u8]>, commit_count: usize) -> Harness {
    let visibility = ProviderRepositoryVisibility::Private;
    let blobs = Arc::new(MemoryBlobStore::default());
    let body = push_body(commit_count, visibility);
    let raw_key = "provider-deliveries/github/event/fixture.json";
    let raw_payload = BlobPayload::from_bytes(
        BlobKey::new(raw_key).expect("raw key"),
        MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE).expect("raw media type"),
        body.clone(),
    );
    let raw_descriptor = raw_payload.descriptor().clone();
    blobs
        .put_if_absent(raw_payload)
        .await
        .expect("publish raw event");
    let raw_event = AdmissionObject::new_event(
        raw_descriptor.digest(),
        ObjectKey::new(raw_key).expect("raw object key"),
        raw_descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let claimed = claimed(raw_event, visibility);
    let logical = Arc::new(LogicalAdmissions::default());
    let admission = WorkflowAdmissionService::with_system_ports(
        blobs.clone(),
        logical.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let processor = GithubDeliveryWorkflowAdmissionProcessor::new(admission);
    let source = RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        ExactRevision::new(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive(files),
    );
    let deliveries = Arc::new(DeliveryOutcomes::default());
    let subject_evidence = Arc::new(FixtureSubjectEvidence::from_claimed(&claimed));
    let worker = GithubDeliveryWorker::new(
        blobs.clone(),
        Arc::new(FixedSource { source, visibility }),
        Arc::new(processor),
        deliveries.clone(),
        subject_evidence,
        Arc::new(FixedClock),
        GithubDeliveryWorkerConfig::default(),
    )
    .expect("worker");
    Harness {
        worker,
        claimed,
        blobs,
        logical,
        deliveries,
    }
}

async fn pull_request_harness(files: BTreeMap<&str, &[u8]>) -> Harness {
    let blobs = Arc::new(MemoryBlobStore::default());
    let body = pull_request_body();
    let raw_key = "provider-deliveries/github/event/pull-request-fixture.json";
    let raw_payload = BlobPayload::from_bytes(
        BlobKey::new(raw_key).expect("raw key"),
        MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE).expect("raw media type"),
        body,
    );
    let raw_descriptor = raw_payload.descriptor().clone();
    blobs
        .put_if_absent(raw_payload)
        .await
        .expect("publish raw event");
    let raw_event = AdmissionObject::new_event(
        raw_descriptor.digest(),
        ObjectKey::new(raw_key).expect("raw object key"),
        raw_descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let claimed = claimed(raw_event, ProviderRepositoryVisibility::Private);
    let logical = Arc::new(LogicalAdmissions::default());
    let admission = WorkflowAdmissionService::with_system_ports(
        blobs.clone(),
        logical.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let source = RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        ExactRevision::new(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive(files),
    );
    let deliveries = Arc::new(DeliveryOutcomes::default());
    let subject_evidence = Arc::new(FixtureSubjectEvidence::authenticated_event(
        &claimed,
        GithubAuthenticatedEventKind::PullRequest,
        "refs/pull/7/merge",
    ));
    let worker = GithubDeliveryWorker::new(
        blobs.clone(),
        Arc::new(FixedSource {
            source,
            visibility: ProviderRepositoryVisibility::Private,
        }),
        Arc::new(GithubDeliveryWorkflowAdmissionProcessor::new(admission)),
        deliveries.clone(),
        subject_evidence,
        Arc::new(FixedClock),
        GithubDeliveryWorkerConfig::default(),
    )
    .expect("worker");
    Harness {
        worker,
        claimed,
        blobs,
        logical,
        deliveries,
    }
}

fn claimed(
    raw_event: AdmissionObject,
    visibility: ProviderRepositoryVisibility,
) -> ClaimedProviderDelivery {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(1)).expect("delivery id");
    let receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Claimed,
        1,
        UnixMillis::new(50),
    )
    .expect("receipt");
    let claim = ProviderDeliveryClaimFence::from_durable_parts(
        delivery_id,
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("owner"),
        7,
    )
    .expect("claim");
    let repository = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
        visibility,
        format!("{OWNER}/{REPOSITORY}"),
    )
    .expect("repository coordinates");
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-private").expect("tenant"),
        "github",
        ProviderConnectionId::from_uuid(Uuid::from_u128(3)).expect("connection"),
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        repository,
        DELIVERY,
    )
    .expect("identity");
    ClaimedProviderDelivery::from_durable_parts(
        receipt,
        identity,
        Sha256Digest::from_bytes([0x42; 32]),
        raw_event,
        claim,
        UnixMillis::new(100),
        UnixMillis::new(10_000),
    )
    .expect("claimed delivery")
}

fn push_body(commit_count: usize, visibility: ProviderRepositoryVisibility) -> Bytes {
    let commits = (1..=commit_count)
        .map(|value| format!(r#"{{"id":"{value:040x}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let (private, visibility) = match visibility {
        ProviderRepositoryVisibility::Public => (false, "public"),
        ProviderRepositoryVisibility::Private => (true, "private"),
    };
    Bytes::from(format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE}","after":"{AFTER}","created":false,"deleted":false,"forced":false,"repository":{{"id":{REPOSITORY_ID},"private":{private},"visibility":"{visibility}","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"commits":[{commits}]}}"#,
    ))
}

fn pull_request_body() -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"opened","number":7,"pull_request":{{"number":7,"merged":false,"merge_commit_sha":"{AFTER}","head":{{"ref":"feature/topic","sha":"{AFTER}","repo":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}}}},"base":{{"ref":"main","sha":"{BEFORE}","repo":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}}}}}},"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ))
}

fn archive(files: BTreeMap<&str, &[u8]>) -> Bytes {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
    for (path, bytes) in files {
        append_entry(
            &mut builder,
            &format!("repository-root/{path}"),
            EntryType::Regular,
            bytes,
        );
    }
    let encoder = builder.into_inner().expect("finish tar");
    Bytes::from(encoder.finish().expect("finish gzip"))
}

fn append_entry(
    builder: &mut Builder<GzEncoder<Vec<u8>>>,
    path: &str,
    entry_type: EntryType,
    bytes: &[u8],
) {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(if entry_type.is_dir() { 0o755 } else { 0o644 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(bytes.len()).expect("entry size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .expect("append archive entry");
}

async fn process(
    harness: &Harness,
) -> Result<GithubDeliveryWorkerOutcome, GithubDeliveryWorkerError> {
    let archive_credential = SecretString::new(CREDENTIAL).expect("credential");
    let authority = match harness.claimed.identity().repository_visibility() {
        ProviderRepositoryVisibility::Public => GithubDeliverySourceAuthority::PublicAnonymous,
        ProviderRepositoryVisibility::Private => {
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &archive_credential,
            }
        }
    };
    harness
        .worker
        .process_claimed(harness.claimed.clone(), authority)
        .await
}

fn outcome_kind(conclusion: &ProviderDeliveryWorkflowConclusion) -> (&'static str, Option<&str>) {
    match conclusion {
        ProviderDeliveryWorkflowConclusion::Admitted { .. } => ("admitted", None),
        ProviderDeliveryWorkflowConclusion::Skipped { reason } => {
            ("skipped", Some(reason.as_str()))
        }
        ProviderDeliveryWorkflowConclusion::Failed { failure_kind } => {
            ("failed", Some(failure_kind.as_str()))
        }
    }
}

#[tokio::test]
async fn accepted_path_admits_exact_evidence_and_replays_the_same_run() {
    let harness = harness(BTreeMap::from([(WORKFLOW_PATH, ACCEPTED_WORKFLOW)]), 0).await;

    assert!(matches!(
        process(&harness).await.expect("first processing"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));
    assert!(matches!(
        process(&harness).await.expect("exact replay"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));

    let commands = harness.logical.commands();
    assert_eq!(commands.len(), 2);
    assert_eq!(harness.logical.ordinary_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness.logical.delivery_ids(),
        vec![harness.claimed.receipt().id(); 2]
    );
    let first = &commands[0];
    assert_eq!(first.tenant().as_str(), "tenant-private");
    assert_eq!(first.repository().provider(), "github");
    assert_eq!(first.repository().provider_repository_id(), "9001");
    assert_eq!(first.repository().owner(), OWNER);
    assert_eq!(first.repository().name(), REPOSITORY);
    assert_eq!(first.workflow_path(), WORKFLOW_PATH);
    assert_eq!(first.workflow_name(), "Exact CI");
    assert_eq!(first.git_ref(), "refs/heads/main");
    assert_eq!(first.event_name(), "push");
    assert_eq!(
        first.head_sha(),
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        ]
    );
    let WorkflowAdmissionIdempotency::ProviderDelivery(idempotency) = first.idempotency() else {
        panic!("delivery processing must use provider idempotency");
    };
    assert!(idempotency.starts_with("provider-delivery-v2:"));
    assert_eq!(commands[0].idempotency(), commands[1].idempotency());
    assert_eq!(commands[0].request_digest(), commands[1].request_digest());
    assert_eq!(commands[0].run_id(), commands[1].run_id());
    assert_eq!(commands[0].source(), commands[1].source());
    assert_eq!(commands[0].event(), commands[1].event());

    let source = read_admission_object(&harness.blobs, first.source()).await;
    assert_eq!(source.as_ref(), ACCEPTED_WORKFLOW);
    let event = read_admission_object(&harness.blobs, first.event()).await;
    assert_eq!(event, push_body(0, ProviderRepositoryVisibility::Private));

    let completions = harness.deliveries.completions();
    assert_eq!(completions.len(), 2);
    let first_conclusion = completions[0].outcomes()[0].conclusion();
    let second_conclusion = completions[1].outcomes()[0].conclusion();
    assert_eq!(first_conclusion, second_conclusion);
    assert_eq!(
        first_conclusion,
        &ProviderDeliveryWorkflowConclusion::Admitted {
            run_id: first.run_id()
        }
    );
}

#[tokio::test]
async fn pull_request_metadata_and_raw_event_reach_logical_admission_exactly() {
    let harness =
        pull_request_harness(BTreeMap::from([(WORKFLOW_PATH, PULL_REQUEST_WORKFLOW)])).await;

    assert!(matches!(
        process(&harness).await.expect("pull-request processing"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));
    let commands = harness.logical.commands();
    assert_eq!(commands.len(), 1);
    let command = &commands[0];
    assert_eq!(command.event_name(), "pull_request");
    assert_eq!(command.git_ref(), "refs/pull/7/merge");
    assert_eq!(command.workflow_name(), "Pull Request CI");
    assert_eq!(
        command.head_sha(),
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        ]
    );
    assert_eq!(
        read_admission_object(&harness.blobs, command.event()).await,
        pull_request_body()
    );
    assert_eq!(
        outcome_kind(harness.deliveries.completions()[0].outcomes()[0].conclusion()),
        ("admitted", None)
    );
}

async fn read_admission_object(blobs: &MemoryBlobStore, object: &AdmissionObject) -> Bytes {
    let descriptor = BlobDescriptor::new(
        BlobKey::new(object.object_key().as_str()).expect("blob key"),
        object.digest(),
        object.encoded_size(),
        MediaType::new(object.media_type()).expect("media type"),
    );
    blobs
        .get_verified(&descriptor, object.encoded_size())
        .await
        .expect("verified object")
        .into_bytes()
}

#[tokio::test]
async fn path_filter_without_provider_evidence_is_a_non_mutating_prerequisite() {
    let harness = harness(BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]), 0).await;

    assert_eq!(
        process(&harness).await,
        Err(GithubDeliveryWorkerError::Prerequisite(
            GithubDeliveryWorkerPrerequisite::ProviderChangedFiles
        ))
    );
    assert!(harness.logical.commands().is_empty());
    assert!(harness.deliveries.completions().is_empty());
}

#[tokio::test]
async fn authenticated_commit_ceiling_bypasses_diff_without_a_provider_call() {
    let harness = harness(BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]), 1_001).await;

    process(&harness).await.expect("provider bypass processing");
    assert_eq!(harness.logical.commands().len(), 1);
    assert_eq!(
        outcome_kind(harness.deliveries.completions()[0].outcomes()[0].conclusion()),
        ("admitted", None)
    );
}

#[tokio::test]
async fn invalid_source_and_valid_non_selection_are_deterministic_path_outcomes() {
    let dispatch = b"name: Manual\non: workflow_dispatch\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo manual\n";
    let invalid = harness(
        BTreeMap::from([(WORKFLOW_PATH, b"not: [valid".as_slice())]),
        0,
    )
    .await;
    process(&invalid).await.expect("invalid pinned workflow");
    assert!(invalid.logical.commands().is_empty());
    let completions = invalid.deliveries.completions();
    let outcomes = completions[0].outcomes();
    assert_eq!(
        outcome_kind(outcomes[0].conclusion()),
        ("failed", Some("github.workflow.frontend_rejected"))
    );

    let not_selected = harness(BTreeMap::from([(WORKFLOW_PATH, dispatch.as_slice())]), 0).await;
    process(&not_selected)
        .await
        .expect("non-selected pinned workflow");
    assert!(not_selected.logical.commands().is_empty());
    let completions = not_selected.deliveries.completions();
    let outcomes = completions[0].outcomes();
    assert_eq!(
        outcome_kind(outcomes[0].conclusion()),
        ("skipped", Some("github.workflow.event_not_configured"))
    );
}
