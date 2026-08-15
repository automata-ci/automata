use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, ImmutableBlobStore as _, MediaType, MemoryBlobStore,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github::{
    GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE, GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX,
    GithubRepositoryVisibility as GithubRepositoryVisibilityFact, GithubSealedEventEnvelopeV1,
    GithubWebhookBodyDigest, StoredAuthenticatedGithubWebhook,
    rehydrate_stored_authenticated_github_webhook,
};
use automata_ci_github_delivery::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubDeliveryClock,
    GithubDeliveryPrivateRepositoryAction, GithubDeliverySourceAuthority,
    GithubDeliverySourceCredential, GithubDeliverySourceCredentialBinding,
    GithubDeliverySourceCredentialProvider, GithubDeliverySourceCredentialProviderError,
    GithubDeliverySourceCredentialRequest, GithubDeliveryWorker, GithubDeliveryWorkerConfig,
    GithubDeliveryWorkerError, GithubDeliveryWorkerOutcome, GithubDeliveryWorkerPrerequisite,
    GithubDeliveryWorkflowAdmissionProcessor, GithubPullRequestChangedFilesRequest,
    GithubPushChangedFilesAuthority, GithubPushChangedFilesError, GithubPushChangedFilesProvider,
    GithubPushChangedFilesRequest, GithubServerServiceCredentialRelease,
};
use automata_ci_scm::{
    ArchiveFormat, ExactRevision, RepositoryId as ScmRepositoryId, RepositorySource,
    RepositorySourcePort, RepositorySourceRequest, ScmError, ScmProviderId,
};
use automata_ci_store::{
    AcceptProviderDelivery, AdmissionObject, AdmitLogicalWorkflowRun,
    AuthenticatedGithubDeliveryClaim, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, GithubAuthenticatedEvent, GithubAuthenticatedEventKind,
    GithubServerServiceAction, GithubServerServiceAuthorityId,
    GithubServerServiceAuthoritySelector, GithubServerServiceConsumerClaim,
    GithubServerServiceHandoffId, GithubSubjectEvidenceRepository, GithubSubjectEvidenceStoreError,
    GithubWorkflowRunSubjectEvidence, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, ManifestPinnedGithubDeliveryEvidence,
    ManifestPinnedGithubDeliveryReceipt, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryEventEnvelope,
    ProviderDeliveryFailureKind, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderDeliveryReceipt, ProviderDeliveryRepository, ProviderDeliveryState,
    ProviderDeliveryStoreError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryReceipt,
    ProviderDeliveryWorkflowOutcome, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RecordProviderDeliveryWorkflowProgress, RegisterProviderDeliveryWorkflowInventory,
    RejectProviderDelivery, RepositoryId as StoreRepositoryId, RetryProviderDelivery, TenantScope,
    WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_github::GithubChangedFiles;
use automata_ci_workflow_service::{GithubWorkflowPlanVerifier, WorkflowAdmissionService};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest as _, Sha256};
use tar::{Builder, EntryType, Header};
use uuid::Uuid;

use super::subject_evidence::fixture_subject_evidence;

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
const DIFF_CREDENTIAL: &str = "installation-token-private-diff-marker";
const ACCEPTED_WORKFLOW: &[u8] = b"name: Exact CI\non: push\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo exact\n";
const PATH_WORKFLOW: &[u8] = b"name: Paths CI\non:\n  push:\n    paths: ['src/**']\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo paths\n";
const PULL_REQUEST_WORKFLOW: &[u8] = b"name: Pull Request CI\non: pull_request\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo pull-request\n";
const PULL_REQUEST_PATH_WORKFLOW: &[u8] = b"name: Pull Request Paths CI\non:\n  pull_request:\n    paths: ['src/**']\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo pull-request-paths\n";

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
    workflow_disabled: AtomicBool,
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

    fn disable_workflow(&self) {
        self.workflow_disabled.store(true, Ordering::SeqCst);
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
        if self.workflow_disabled.load(Ordering::SeqCst) {
            return Err(LogicalWorkflowAdmissionStoreError::WorkflowDisabled);
        }
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
    inventory: Mutex<Option<ProviderDeliveryWorkflowInventory>>,
    progress: Mutex<Vec<ProviderDeliveryWorkflowOutcome>>,
}

impl DeliveryOutcomes {
    fn completions(&self) -> Vec<CompleteProviderDelivery> {
        self.completions.lock().expect("completions lock").clone()
    }

    fn retry_count(&self) -> usize {
        self.retries.lock().expect("retries lock").len()
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

    async fn register_provider_delivery_workflow_inventory(
        &self,
        request: RegisterProviderDeliveryWorkflowInventory,
    ) -> Result<ProviderDeliveryWorkflowInventoryReceipt, ProviderDeliveryStoreError> {
        let mut inventory = self.inventory.lock().expect("inventory lock");
        match inventory.as_ref() {
            Some(existing) if existing != request.inventory() => {
                return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
            }
            Some(_) => {}
            None => *inventory = Some(request.inventory().clone()),
        }
        ProviderDeliveryWorkflowInventoryReceipt::new(
            inventory.as_ref().expect("inventory initialized").clone(),
            self.progress.lock().expect("progress lock").clone(),
        )
        .map_err(|_| ProviderDeliveryStoreError::WorkflowProgressRejected)
    }

    async fn record_provider_delivery_workflow_progress(
        &self,
        request: RecordProviderDeliveryWorkflowProgress,
    ) -> Result<ProviderDeliveryWorkflowOutcome, ProviderDeliveryStoreError> {
        let inventory = self.inventory.lock().expect("inventory lock");
        let Some(inventory) = inventory.as_ref() else {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        };
        if inventory.digest() != request.inventory_digest()
            || !inventory
                .entries()
                .iter()
                .any(|entry| entry.workflow_path() == request.outcome().workflow_path())
        {
            return Err(ProviderDeliveryStoreError::WorkflowProgressRejected);
        }
        let mut progress = self.progress.lock().expect("progress lock");
        if let Some(existing) = progress
            .iter()
            .find(|existing| existing.workflow_path() == request.outcome().workflow_path())
        {
            return if existing == request.outcome() {
                Ok(existing.clone())
            } else {
                Err(ProviderDeliveryStoreError::WorkflowProgressRejected)
            };
        }
        progress.push(request.outcome().clone());
        Ok(request.outcome().clone())
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
        let base = Self::from_claimed(claimed).0;
        let event = GithubAuthenticatedEvent::new(kind, git_ref).expect("event coordinates");
        Self(
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
                base.delivery_id(),
                base.repository_owner_id(),
                base.manifest().clone(),
                base.authenticated_webhook_verifier_fingerprint(),
                base.authenticated_webhook_verifier_revision(),
                base.checks_authority().clone(),
                base.private_source_authority().cloned(),
                base.check_subject_id(),
                base.check_head_sha(),
                event,
                base.accepted_at(),
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct CredentialObservation {
    repository_owner_id: ProviderRepositoryOwnerId,
    claim: ProviderDeliveryClaimFence,
    attempt: u16,
    action: GithubDeliveryPrivateRepositoryAction,
    authority_selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DiffCredentialBehavior {
    #[default]
    Exact,
    WrongSelector,
    WrongAction,
}

#[derive(Debug, Default)]
struct DiffCredentials {
    calls: AtomicUsize,
    releases: Arc<AtomicUsize>,
    observations: Mutex<Vec<CredentialObservation>>,
    behavior: Mutex<DiffCredentialBehavior>,
}

impl DiffCredentials {
    fn set_behavior(&self, behavior: DiffCredentialBehavior) {
        *self.behavior.lock().expect("credential behavior lock") = behavior;
    }
}

#[derive(Debug)]
struct ReleaseProbe(Arc<AtomicUsize>);

#[async_trait]
impl GithubServerServiceCredentialRelease for ReleaseProbe {
    async fn release(self: Box<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl GithubDeliverySourceCredentialProvider for DiffCredentials {
    async fn acquire(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observations
            .lock()
            .expect("credential observations lock")
            .push(CredentialObservation {
                repository_owner_id: request.repository_owner_id(),
                claim: request.snapshot().claim(),
                attempt: request.snapshot().attempt(),
                action: request.action(),
                authority_selector: request.authority_selector().clone(),
                consumer: request.consumer_claim().expect("valid consumer claim"),
                observed_at: request.observed_at(),
                required_through: request.required_through(),
            });
        let behavior = *self.behavior.lock().expect("credential behavior lock");
        let authority_selector = if behavior == DiffCredentialBehavior::WrongSelector {
            GithubServerServiceAuthoritySelector::from_durable_parts(
                request.authority_selector().tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x7fff))
                    .expect("wrong authority ID"),
                request.authority_selector().identity_digest(),
                request.authority_selector().app_configuration_revision(),
                request.authority_selector().policy_revision(),
            )
        } else {
            request.authority_selector().clone()
        };
        let requested_consumer = request
            .consumer_claim()
            .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        let consumer = GithubServerServiceConsumerClaim::new(
            requested_consumer.consumer_id(),
            requested_consumer.owner(),
            requested_consumer.fence(),
            if behavior == DiffCredentialBehavior::WrongAction {
                GithubServerServiceAction::FetchPrivateRepositoryRevision
            } else {
                requested_consumer.action()
            },
            requested_consumer.revision(),
        );
        let binding = GithubDeliverySourceCredentialBinding::new(
            request.identity().clone(),
            request.repository_owner_id(),
            ScmRepositoryId::new(request.identity().repository_identity())
                .expect("credential repository"),
            authority_selector,
            GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x7300)).expect("handoff ID"),
            consumer,
            request.required_through(),
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        GithubDeliverySourceCredential::new(
            binding,
            request.observed_at(),
            SecretString::new(DIFF_CREDENTIAL).expect("diff credential"),
            request.required_through(),
            Box::new(ReleaseProbe(Arc::clone(&self.releases))),
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChangedFilesObservation {
    repository: String,
    request_digest: Sha256Digest,
    before: String,
    after: String,
    claim: ProviderDeliveryClaimFence,
    attempt: u16,
    observed_at: UnixMillis,
    required_through: UnixMillis,
    private_action: Option<GithubDeliveryPrivateRepositoryAction>,
    credential_present: bool,
    credential_matches: bool,
}

#[derive(Debug)]
struct ChangedFiles {
    result: Result<GithubChangedFiles, GithubPushChangedFilesError>,
    calls: AtomicUsize,
    observations: Mutex<Vec<ChangedFilesObservation>>,
}

impl ChangedFiles {
    fn new(result: Result<GithubChangedFiles, GithubPushChangedFilesError>) -> Self {
        Self {
            result,
            calls: AtomicUsize::new(0),
            observations: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl GithubPushChangedFilesProvider for ChangedFiles {
    async fn changed_files(
        &self,
        request: GithubPushChangedFilesRequest<'_>,
    ) -> Result<GithubChangedFiles, GithubPushChangedFilesError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (credential_present, credential_matches) = match request.authority() {
            GithubPushChangedFilesAuthority::PublicAnonymous => (false, false),
            GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(credential) => {
                (true, credential.expose_secret() == DIFF_CREDENTIAL)
            }
        };
        self.observations
            .lock()
            .expect("observations lock")
            .push(ChangedFilesObservation {
                repository: request.identity().repository_identity().to_owned(),
                request_digest: request.request_digest(),
                before: request.push().before_commit_sha().to_owned(),
                after: request.push().after_commit_sha().to_owned(),
                claim: request.snapshot().claim(),
                attempt: request.snapshot().attempt(),
                observed_at: request.observed_at(),
                required_through: request.required_through(),
                private_action: request.private_action(),
                credential_present,
                credential_matches,
            });
        self.result.clone()
    }

    async fn pull_request_changed_files(
        &self,
        request: GithubPullRequestChangedFilesRequest<'_>,
    ) -> Result<GithubChangedFiles, GithubPushChangedFilesError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.pull_request().base_revision().as_str(), BEFORE);
        assert_eq!(request.pull_request().head_revision().as_str(), AFTER);
        assert_eq!(
            request.private_action(),
            Some(GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles)
        );
        self.result.clone()
    }
}

struct Harness {
    worker: GithubDeliveryWorker,
    claimed: ClaimedProviderDelivery,
    blobs: Arc<MemoryBlobStore>,
    logical: Arc<LogicalAdmissions>,
    deliveries: Arc<DeliveryOutcomes>,
    credentials: Arc<DiffCredentials>,
}

async fn harness(
    files: BTreeMap<&str, &[u8]>,
    changed_files: Option<Arc<ChangedFiles>>,
    commit_count: usize,
) -> Harness {
    harness_with_visibility(
        files,
        changed_files,
        commit_count,
        ProviderRepositoryVisibility::Private,
    )
    .await
}

async fn harness_with_visibility(
    files: BTreeMap<&str, &[u8]>,
    changed_files: Option<Arc<ChangedFiles>>,
    commit_count: usize,
    visibility: ProviderRepositoryVisibility,
) -> Harness {
    let blobs = Arc::new(MemoryBlobStore::default());
    let body = push_body(commit_count, visibility);
    let digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let raw_key = format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{digest}.json");
    let raw_payload = BlobPayload::from_bytes(
        BlobKey::new(raw_key.clone()).expect("raw key"),
        MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE).expect("raw media type"),
        body.clone(),
    );
    let raw_descriptor = raw_payload.descriptor().clone();
    blobs
        .put_if_absent(raw_payload)
        .await
        .expect("publish raw event");
    let raw_event = AdmissionObject::new(
        raw_descriptor.digest(),
        ObjectKey::new(raw_key).expect("raw object key"),
        raw_descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let event_envelope = provider_event_envelope(&body, &raw_descriptor, "push", visibility);
    let claimed = claimed(raw_event, event_envelope, visibility);
    let logical = Arc::new(LogicalAdmissions::default());
    let admission = WorkflowAdmissionService::with_system_ports(
        blobs.clone(),
        logical.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let mut processor = GithubDeliveryWorkflowAdmissionProcessor::new(admission);
    if let Some(changed_files) = changed_files {
        processor = processor.with_changed_files_provider(changed_files);
    }
    let source = RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        ExactRevision::new(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive(files),
    );
    let deliveries = Arc::new(DeliveryOutcomes::default());
    let credentials = Arc::new(DiffCredentials::default());
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
        credentials,
    }
}

async fn pull_request_harness(
    files: BTreeMap<&str, &[u8]>,
    changed_files: Option<Arc<ChangedFiles>>,
) -> Harness {
    let blobs = Arc::new(MemoryBlobStore::default());
    let body = pull_request_body();
    let digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let raw_key = format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{digest}.json");
    let raw_payload = BlobPayload::from_bytes(
        BlobKey::new(raw_key.clone()).expect("raw key"),
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
    let event_envelope = provider_event_envelope(
        &body,
        &raw_descriptor,
        "pull_request",
        ProviderRepositoryVisibility::Private,
    );
    let claimed = claimed(
        raw_event,
        event_envelope,
        ProviderRepositoryVisibility::Private,
    );
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
    let credentials = Arc::new(DiffCredentials::default());
    let subject_evidence = Arc::new(FixtureSubjectEvidence::authenticated_event(
        &claimed,
        GithubAuthenticatedEventKind::PullRequest,
        "refs/pull/7/merge",
    ));
    let mut processor = GithubDeliveryWorkflowAdmissionProcessor::new(admission);
    if let Some(changed_files) = changed_files {
        processor = processor.with_changed_files_provider(changed_files);
    }
    let worker = GithubDeliveryWorker::new(
        blobs.clone(),
        Arc::new(FixedSource {
            source,
            visibility: ProviderRepositoryVisibility::Private,
        }),
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
        credentials,
    }
}

fn provider_event_envelope(
    body: &Bytes,
    descriptor: &BlobDescriptor,
    event_name: &str,
    visibility: ProviderRepositoryVisibility,
) -> ProviderDeliveryEventEnvelope {
    let visibility = match visibility {
        ProviderRepositoryVisibility::Public => GithubRepositoryVisibilityFact::Public,
        ProviderRepositoryVisibility::Private => GithubRepositoryVisibilityFact::Private,
    };
    let stored = StoredAuthenticatedGithubWebhook::from_durable_coordinates(
        body.clone(),
        GithubWebhookBodyDigest::from_bytes(*descriptor.digest().as_bytes()),
        descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
        event_name,
        DELIVERY,
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER_ID,
        visibility,
        OWNER,
        REPOSITORY,
    );
    let event =
        rehydrate_stored_authenticated_github_webhook(stored).expect("verified webhook fixture");
    let sealed = GithubSealedEventEnvelopeV1::seal(&event, descriptor.clone())
        .expect("sealed event envelope fixture");
    ProviderDeliveryEventEnvelope::new(
        sealed.schema(),
        sealed.registry_schema(),
        sealed.digest(),
        sealed.canonical_bytes().to_vec(),
        GITHUB_EVENT_ENVELOPE_V1_MEDIA_TYPE,
    )
    .expect("durable event envelope fixture")
}

fn claimed(
    raw_event: AdmissionObject,
    event_envelope: ProviderDeliveryEventEnvelope,
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
        event_envelope,
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
                changed_files_credentials: Some(harness.credentials.as_ref()),
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
async fn accepted_path_replays_durable_progress_without_readmission() {
    let harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, ACCEPTED_WORKFLOW)]),
        None,
        0,
    )
    .await;

    assert!(matches!(
        process(&harness).await.expect("first processing"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));
    assert!(matches!(
        process(&harness).await.expect("exact replay"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));

    let commands = harness.logical.commands();
    assert_eq!(commands.len(), 1);
    assert_eq!(harness.logical.ordinary_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness.logical.delivery_ids(),
        vec![harness.claimed.receipt().id()]
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
    assert!(idempotency.starts_with("provider-delivery:"));

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
async fn durably_disabled_workflow_is_skipped_without_admission() {
    let harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, ACCEPTED_WORKFLOW)]),
        None,
        0,
    )
    .await;
    harness.logical.disable_workflow();

    assert!(matches!(
        process(&harness).await.expect("disabled processing"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));
    assert!(harness.logical.commands().is_empty());
    let completions = harness.deliveries.completions();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].outcomes().len(), 1);
    assert_eq!(
        completions[0].outcomes()[0].conclusion(),
        &ProviderDeliveryWorkflowConclusion::Skipped {
            reason: ProviderDeliveryFailureKind::new("github.workflow.disabled")
                .expect("closed disabled reason"),
        }
    );
}

#[tokio::test]
async fn pull_request_metadata_and_raw_event_reach_logical_admission_exactly() {
    let harness = pull_request_harness(
        BTreeMap::from([(WORKFLOW_PATH, PULL_REQUEST_WORKFLOW)]),
        None,
    )
    .await;

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

#[tokio::test]
async fn pull_request_path_filters_resolve_changed_files_and_admit_without_a_prerequisite() {
    let changed = Arc::new(ChangedFiles::new(Ok(GithubChangedFiles::complete([
        "src/lib.rs",
    ]))));
    let harness = pull_request_harness(
        BTreeMap::from([(WORKFLOW_PATH, PULL_REQUEST_PATH_WORKFLOW)]),
        Some(changed.clone()),
    )
    .await;

    assert!(matches!(
        process(&harness)
            .await
            .expect("pull-request path processing"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));
    assert_eq!(changed.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
    assert_eq!(harness.logical.commands().len(), 1);
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
async fn changed_files_are_requested_only_after_typed_compiler_demand() {
    let changed = Arc::new(ChangedFiles::new(Ok(GithubChangedFiles::complete([
        "src/lib.rs",
    ]))));
    let harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
        Some(changed.clone()),
        0,
    )
    .await;

    process(&harness).await.expect("processing");
    assert_eq!(changed.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
    assert_eq!(harness.logical.commands().len(), 1);
    let observations = changed.observations.lock().expect("observations lock");
    assert_eq!(
        observations.as_slice(),
        [ChangedFilesObservation {
            repository: format!("{OWNER}/{REPOSITORY}"),
            request_digest: Sha256Digest::from_bytes([0x42; 32]),
            before: BEFORE.to_owned(),
            after: AFTER.to_owned(),
            claim: harness.claimed.claim(),
            attempt: 1,
            observed_at: UnixMillis::new(500),
            required_through: UnixMillis::new(10_000 + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS),
            private_action: Some(
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles
            ),
            credential_present: true,
            credential_matches: true,
        }]
    );
    let credential_observations = harness
        .credentials
        .observations
        .lock()
        .expect("credential observations lock");
    assert_eq!(credential_observations.len(), 1);
    assert_eq!(
        credential_observations[0].repository_owner_id,
        ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID")
    );
    assert_eq!(credential_observations[0].claim, harness.claimed.claim());
    assert_eq!(credential_observations[0].attempt, 1);
    assert_eq!(credential_observations[0].observed_at, UnixMillis::new(500));
    let pinned_evidence = fixture_subject_evidence(
        harness.claimed.receipt().id(),
        harness.claimed.identity(),
        ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
        harness.claimed.receipt().accepted_at(),
        0x7101,
    );
    assert_eq!(
        &credential_observations[0].authority_selector,
        pinned_evidence
            .private_source_authority()
            .expect("private delivery pins source authority")
    );
    assert_eq!(
        credential_observations[0].consumer.action(),
        GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
    );
    assert_eq!(credential_observations[0].consumer.fence().get(), 7);
    assert_eq!(credential_observations[0].consumer.revision().get(), 1);
    assert_eq!(
        credential_observations[0].action,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles
    );
    assert_ne!(
        credential_observations[0].action,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision
    );
    let completions = harness.deliveries.completions();
    let outcomes = completions[0].outcomes();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcome_kind(outcomes[0].conclusion()), ("admitted", None));
}

#[tokio::test]
async fn public_changed_files_are_anonymous_and_never_request_private_authority() {
    let changed = Arc::new(ChangedFiles::new(Ok(GithubChangedFiles::complete([
        "src/lib.rs",
    ]))));
    let harness = harness_with_visibility(
        BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
        Some(changed.clone()),
        0,
        ProviderRepositoryVisibility::Public,
    )
    .await;

    process(&harness).await.expect("public diff processing");
    assert_eq!(changed.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
    assert!(
        harness
            .credentials
            .observations
            .lock()
            .expect("credential observations lock")
            .is_empty()
    );
    let observations = changed.observations.lock().expect("observations lock");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].claim, harness.claimed.claim());
    assert_eq!(observations[0].attempt, 1);
    assert_eq!(observations[0].private_action, None);
    assert!(!observations[0].credential_present);
    assert!(!observations[0].credential_matches);
}

#[tokio::test]
async fn private_changed_files_reject_wrong_selector_or_action_before_provider_io() {
    for behavior in [
        DiffCredentialBehavior::WrongSelector,
        DiffCredentialBehavior::WrongAction,
    ] {
        let changed = Arc::new(ChangedFiles::new(Ok(GithubChangedFiles::complete([
            "src/lib.rs",
        ]))));
        let harness = harness(
            BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
            Some(changed.clone()),
            0,
        )
        .await;
        harness.credentials.set_behavior(behavior);

        assert!(matches!(
            process(&harness)
                .await
                .expect("invalid credential is durably rejected"),
            GithubDeliveryWorkerOutcome::Rejected(_)
        ));
        assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
        assert_eq!(changed.calls.load(Ordering::SeqCst), 0);
        assert!(harness.logical.commands().is_empty());
    }
}

#[tokio::test]
async fn path_filter_without_provider_evidence_is_a_non_mutating_prerequisite() {
    let harness = harness(BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]), None, 0).await;

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
    let harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
        None,
        1_001,
    )
    .await;

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
        None,
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

    let not_selected = harness(
        BTreeMap::from([(WORKFLOW_PATH, dispatch.as_slice())]),
        None,
        0,
    )
    .await;
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

#[tokio::test]
async fn changed_file_provider_failures_remain_closed_and_sanitized() {
    let oversized = Arc::new(ChangedFiles::new(Ok(GithubChangedFiles::complete(
        (0..=3_000).map(|index| format!("src/{index}.rs")),
    ))));
    let oversized_harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
        Some(oversized),
        0,
    )
    .await;
    process(&oversized_harness)
        .await
        .expect("manifest changed-file limit outcome");
    assert_eq!(
        oversized_harness
            .credentials
            .releases
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        outcome_kind(oversized_harness.deliveries.completions()[0].outcomes()[0].conclusion(),),
        ("failed", Some("github.workflow.changed_files_invalid"))
    );
    assert!(oversized_harness.logical.commands().is_empty());

    let invalid = Arc::new(ChangedFiles::new(Err(
        GithubPushChangedFilesError::InvalidEvidence,
    )));
    let invalid_harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
        Some(invalid),
        0,
    )
    .await;
    process(&invalid_harness)
        .await
        .expect("invalid evidence outcome");
    assert_eq!(
        invalid_harness.credentials.releases.load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        outcome_kind(invalid_harness.deliveries.completions()[0].outcomes()[0].conclusion(),),
        ("failed", Some("github.workflow.changed_files_invalid"))
    );

    let unavailable = Arc::new(ChangedFiles::new(Err(
        GithubPushChangedFilesError::Unavailable,
    )));
    let harness = harness(
        BTreeMap::from([(WORKFLOW_PATH, PATH_WORKFLOW)]),
        Some(unavailable),
        0,
    )
    .await;
    assert!(matches!(
        process(&harness).await.expect("durable retry"),
        GithubDeliveryWorkerOutcome::RetryScheduled(_)
    ));
    assert_eq!(harness.deliveries.retry_count(), 1);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
    assert!(harness.logical.commands().is_empty());
}
