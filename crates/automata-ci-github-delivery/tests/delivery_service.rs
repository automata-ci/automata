use std::{
    collections::BTreeMap,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    MediaType, PutBlobOutcome, VerifiedBlob,
};
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github_delivery::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubDeliveryClock,
    GithubDeliveryPrivateRepositoryAction, GithubDeliveryService, GithubDeliveryServiceConfig,
    GithubDeliveryServiceConfigurationError, GithubDeliveryServiceError,
    GithubDeliveryServiceOutcome, GithubDeliverySourceCredential,
    GithubDeliverySourceCredentialBinding, GithubDeliverySourceCredentialProvider,
    GithubDeliverySourceCredentialProviderError, GithubDeliverySourceCredentialRequest,
    GithubDeliveryWorkerConfig, GithubDeliveryWorkerOutcome,
    GithubDeliveryWorkflowAdmissionProcessor, GithubDeliveryWorkflowProcessor,
    GithubDeliveryWorkflowProcessorCompletion, GithubDeliveryWorkflowProcessorError,
    GithubDeliveryWorkflowRequest, GithubPushChangedFilesAuthority, GithubPushChangedFilesError,
    GithubPushChangedFilesProvider, GithubPushChangedFilesRequest,
    GithubServerServiceCredentialRelease,
};
use automata_ci_scm::{
    ArchiveFormat, ExactRevision, RepositoryId as ScmRepositoryId, RepositorySource,
    RepositorySourcePort, RepositorySourceRequest, ScmError, ScmProviderId,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim, ClaimProviderDelivery,
    ClaimedProviderDelivery, CompleteProviderDelivery, GithubCheckHeadSha,
    GithubServerServiceAction, GithubServerServiceAuthorityId,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceHandoffId, GithubServerServiceRevision,
    GithubSubjectEvidenceRepository, GithubSubjectEvidenceStoreError,
    GithubWorkflowRunSubjectEvidence, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, MAX_PROVIDER_DELIVERY_CLAIM_MILLIS,
    MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, ManifestPinnedGithubDeliveryEvidence,
    ManifestPinnedGithubDeliveryReceipt, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryClaimRenewalRepository, ProviderDeliveryFailureKind, ProviderDeliveryId,
    ProviderDeliveryIdentity, ProviderDeliveryReceipt, ProviderDeliveryRepository,
    ProviderDeliveryState, ProviderDeliveryStoreError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryReceipt,
    ProviderDeliveryWorkflowOutcome, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RecordProviderDeliveryWorkflowProgress, RegisterProviderDeliveryWorkflowInventory,
    RejectProviderDelivery, RenewProviderDeliveryClaim, RenewedProviderDeliveryClaim,
    RepositoryId as StoreRepositoryId, RetryProviderDelivery, TenantScope,
};
use automata_ci_workflow_github::GithubChangedFiles;
use automata_ci_workflow_service::{GithubWorkflowPlanVerifier, WorkflowAdmissionService};
use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest as _, Sha256};
use tar::{Builder, EntryType, Header};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::subject_evidence::{
    fixture_check_head_sha, fixture_subject_evidence, fixture_subject_evidence_with_head,
};

const BEFORE: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AFTER: &str = "0123456789abcdef0123456789abcdef01234567";
const ZERO: &str = "0000000000000000000000000000000000000000";
const OWNER: &str = "octo-private";
const REPOSITORY: &str = "private-repository";
const REPOSITORY_ID: u64 = 9_001;
const REPOSITORY_OWNER_ID: u64 = 8_001;
const INSTALLATION_ID: u64 = 4_242;
const TOKEN_MARKER: &str = "delivery-service-token-marker";
const INITIAL_NOW: i64 = 100;
const CLAIM_MILLIS: i64 = 50;
const RENEWED_NOW: i64 = 120;
const AFTER_INITIAL_EXPIRY: i64 = 155;
const PATH_FILTER_WORKFLOW: &[u8] = b"name: Paths CI\non:\n  push:\n    paths: ['src/**']\njobs:\n  verify:\n    runs-on: linux\n    steps:\n      - run: echo paths\n";

#[derive(Debug)]
struct ManualClock(AtomicI64);

impl ManualClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl GithubDeliveryClock for ManualClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Debug)]
struct BlockingClock {
    now: AtomicI64,
    block_call: usize,
    calls: AtomicUsize,
    observations: Mutex<Vec<tokio::time::Instant>>,
    blocked: AtomicBool,
    blocked_notify: Notify,
    released: Mutex<bool>,
    release: Condvar,
}

impl BlockingClock {
    fn new(now: i64, block_call: usize) -> Self {
        Self {
            now: AtomicI64::new(now),
            block_call,
            calls: AtomicUsize::new(0),
            observations: Mutex::new(Vec::new()),
            blocked: AtomicBool::new(false),
            blocked_notify: Notify::new(),
            released: Mutex::new(false),
            release: Condvar::new(),
        }
    }

    fn set(&self, now: i64) {
        self.now.store(now, Ordering::SeqCst);
    }

    async fn wait_until_blocked(&self) {
        loop {
            let notified = self.blocked_notify.notified();
            if self.blocked.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    fn release(&self) {
        *self.released.lock().expect("blocking clock release lock") = true;
        self.release.notify_all();
    }

    fn observation(&self, call: usize) -> tokio::time::Instant {
        self.observations
            .lock()
            .expect("blocking clock observations lock")[call]
    }
}

impl GithubDeliveryClock for BlockingClock {
    fn now(&self) -> UnixMillis {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.observations
            .lock()
            .expect("blocking clock observations lock")
            .push(tokio::time::Instant::now());
        if call == self.block_call {
            self.blocked.store(true, Ordering::SeqCst);
            self.blocked_notify.notify_waiters();
            let mut released = self.released.lock().expect("blocking clock release lock");
            while !*released {
                released = self
                    .release
                    .wait(released)
                    .expect("blocking clock release wait");
            }
        }
        UnixMillis::new(self.now.load(Ordering::SeqCst))
    }
}

#[derive(Debug)]
struct FixtureBlobStore {
    descriptor: BlobDescriptor,
    bytes: Bytes,
    reads: AtomicUsize,
}

#[async_trait]
impl ImmutableBlobStore for FixtureBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        panic!("the delivery service never writes its authenticated raw object")
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if descriptor != &self.descriptor || descriptor.size() > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        let payload = BlobPayload::verify(descriptor.clone(), self.bytes.clone())
            .map_err(|_| BlobStoreError::new(BlobStoreErrorKind::Integrity))?;
        Ok(VerifiedBlob::from_payload(payload))
    }
}

#[derive(Debug)]
struct SourceGate {
    entered: Notify,
    release: CancellationToken,
    future_dropped: AtomicBool,
}

impl SourceGate {
    fn new() -> Self {
        Self {
            entered: Notify::new(),
            release: CancellationToken::new(),
            future_dropped: AtomicBool::new(false),
        }
    }

    async fn wait_until_entered(&self) {
        tokio::time::timeout(Duration::from_secs(2), self.entered.notified())
            .await
            .expect("source request reached the blocking seam");
    }
}

struct SourceFutureGuard<'a>(&'a AtomicBool);

impl Drop for SourceFutureGuard<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct RecordingSourcePort {
    source: RepositorySource,
    gate: Option<Arc<SourceGate>>,
    calls: AtomicUsize,
    credential_present: AtomicBool,
    credential_matched: AtomicBool,
}

impl RecordingSourcePort {
    fn new(source: RepositorySource, gate: Option<Arc<SourceGate>>) -> Self {
        Self {
            source,
            gate,
            calls: AtomicUsize::new(0),
            credential_present: AtomicBool::new(false),
            credential_matched: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl RepositorySourcePort for RecordingSourcePort {
    fn provider_id(&self) -> &ScmProviderId {
        self.source.provider()
    }

    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySource, ScmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.credential_present
            .store(request.credential().is_some(), Ordering::SeqCst);
        self.credential_matched.store(
            request
                .credential()
                .is_some_and(|credential| credential.expose_secret() == TOKEN_MARKER),
            Ordering::SeqCst,
        );
        if let Some(gate) = &self.gate {
            let _guard = SourceFutureGuard(&gate.future_dropped);
            gate.entered.notify_one();
            gate.release.cancelled().await;
        }
        Ok(self.source.clone())
    }
}

#[derive(Debug)]
struct StaticProcessor;

#[async_trait]
impl GithubDeliveryWorkflowProcessor for StaticProcessor {
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        request
            .finish(Ok(ProviderDeliveryWorkflowConclusion::Skipped {
                reason: ProviderDeliveryFailureKind::new("github.workflow.not_selected")
                    .expect("fixed reason"),
            }))
            .await
    }
}

#[derive(Debug)]
struct UnreachableLogicalAdmissions;

#[async_trait]
impl LogicalWorkflowAdmissionRepository for UnreachableLogicalAdmissions {
    async fn admit_logical_workflow(
        &self,
        _command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        panic!("the path-filter miss must not reach ordinary logical admission")
    }

    async fn admit_authenticated_github_delivery(
        &self,
        _command: AdmitLogicalWorkflowRun,
        _claim: AuthenticatedGithubDeliveryClaim,
        _observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        panic!("the path-filter miss must not reach GitHub logical admission")
    }
}

#[derive(Debug)]
struct CountingWorkflowProcessor {
    inner: GithubDeliveryWorkflowAdmissionProcessor,
    calls: AtomicUsize,
}

impl CountingWorkflowProcessor {
    fn new(inner: GithubDeliveryWorkflowAdmissionProcessor) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl GithubDeliveryWorkflowProcessor for CountingWorkflowProcessor {
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.process_workflow(request).await
    }
}

#[derive(Debug)]
struct SnapshotGateProcessor {
    calls: AtomicUsize,
    snapshots: Mutex<Vec<automata_ci_github_delivery::GithubDeliveryClaimSnapshot>>,
    first_entered: Notify,
    first_release: CancellationToken,
    first_future_dropped: AtomicBool,
    fail_after_committed_renewal: Option<Arc<RenewalApplyGate>>,
}

impl SnapshotGateProcessor {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            snapshots: Mutex::new(Vec::new()),
            first_entered: Notify::new(),
            first_release: CancellationToken::new(),
            first_future_dropped: AtomicBool::new(false),
            fail_after_committed_renewal: None,
        }
    }

    fn failing_after_committed_renewal(renewal_apply_gate: Arc<RenewalApplyGate>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            snapshots: Mutex::new(Vec::new()),
            first_entered: Notify::new(),
            first_release: CancellationToken::new(),
            first_future_dropped: AtomicBool::new(false),
            fail_after_committed_renewal: Some(renewal_apply_gate),
        }
    }
}

#[async_trait]
impl GithubDeliveryWorkflowProcessor for SnapshotGateProcessor {
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        self.snapshots
            .lock()
            .expect("snapshot observations lock")
            .push(request.claim_snapshot());
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_entered.notify_one();
            if let Some(renewal_apply_gate) = &self.fail_after_committed_renewal {
                renewal_apply_gate.wait_committed().await;
                return request
                    .finish(Err(
                        GithubDeliveryWorkflowProcessorError::InvariantViolation,
                    ))
                    .await;
            }
            let _guard = SourceFutureGuard(&self.first_future_dropped);
            self.first_release.cancelled().await;
        }
        request
            .finish(Ok(ProviderDeliveryWorkflowConclusion::Skipped {
                reason: ProviderDeliveryFailureKind::new("github.workflow.not_selected")
                    .expect("fixed reason"),
            }))
            .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialBehavior {
    Exact,
    Error(GithubDeliverySourceCredentialProviderError),
    WrongTenant,
    WrongConnection,
    WrongInstallation,
    WrongRepository,
    WrongOwner,
    WrongOwnerChangedFilesDuringRenewalApply,
    WrongRoute,
    WrongFence,
    WrongAttempt,
    WrongAction,
    WrongSelector,
    WrongHorizon,
    Expired,
    RenewDuringAcquire,
    RejectDuringRenewalApply,
    ReleaseDuringRenewalApply,
    ReleaseChangedFilesDuringRenewalApply,
}

#[derive(Debug)]
struct CredentialAcquireGate {
    entered: Notify,
    release: CancellationToken,
}

#[derive(Debug)]
struct RenewalApplyGate {
    entered: Notify,
    entered_state: AtomicBool,
    committed: Notify,
    committed_state: AtomicBool,
    downstream_result_ready: Notify,
    downstream_result_ready_state: AtomicBool,
    durable_fence: AtomicI64,
    future_dropped: AtomicBool,
    release: CancellationToken,
}

impl RenewalApplyGate {
    fn new() -> Self {
        Self {
            entered: Notify::new(),
            entered_state: AtomicBool::new(false),
            committed: Notify::new(),
            committed_state: AtomicBool::new(false),
            downstream_result_ready: Notify::new(),
            downstream_result_ready_state: AtomicBool::new(false),
            durable_fence: AtomicI64::new(7),
            future_dropped: AtomicBool::new(false),
            release: CancellationToken::new(),
        }
    }

    async fn wait_entered(&self) {
        loop {
            let notified = self.entered.notified();
            if self.entered_state.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    async fn wait_committed(&self) {
        loop {
            let notified = self.committed.notified();
            if self.committed_state.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    fn mark_downstream_result_ready(&self) {
        self.downstream_result_ready_state
            .store(true, Ordering::SeqCst);
        self.downstream_result_ready.notify_waiters();
    }

    async fn wait_downstream_result_ready(&self) {
        loop {
            let notified = self.downstream_result_ready.notified();
            if self.downstream_result_ready_state.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RacingChangedFilesObservation {
    claim: ProviderDeliveryClaimFence,
    private_authority: bool,
}

#[derive(Debug)]
struct RenewalRacingChangedFiles {
    first_error: Option<GithubPushChangedFilesError>,
    calls: AtomicUsize,
    observations: Mutex<Vec<RacingChangedFilesObservation>>,
    renewal_apply_gate: Arc<RenewalApplyGate>,
}

impl RenewalRacingChangedFiles {
    fn new(
        first_error: GithubPushChangedFilesError,
        renewal_apply_gate: Arc<RenewalApplyGate>,
    ) -> Self {
        Self {
            first_error: Some(first_error),
            calls: AtomicUsize::new(0),
            observations: Mutex::new(Vec::new()),
            renewal_apply_gate,
        }
    }

    fn path_miss(renewal_apply_gate: Arc<RenewalApplyGate>) -> Self {
        Self {
            first_error: None,
            calls: AtomicUsize::new(0),
            observations: Mutex::new(Vec::new()),
            renewal_apply_gate,
        }
    }
}

#[async_trait]
impl GithubPushChangedFilesProvider for RenewalRacingChangedFiles {
    async fn changed_files(
        &self,
        request: GithubPushChangedFilesRequest<'_>,
    ) -> Result<GithubChangedFiles, GithubPushChangedFilesError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.observations
            .lock()
            .expect("changed-files observations lock")
            .push(RacingChangedFilesObservation {
                claim: request.snapshot().claim(),
                private_authority: matches!(
                    request.authority(),
                    GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(_)
                ),
            });
        if call == 0
            && let Some(first_error) = self.first_error
        {
            self.renewal_apply_gate.wait_committed().await;
            self.renewal_apply_gate.mark_downstream_result_ready();
            return Err(first_error);
        }
        Ok(GithubChangedFiles::complete(["README.md"]))
    }
}

struct RenewalFutureGuard<'a> {
    dropped: &'a AtomicBool,
    completed: bool,
}

impl RenewalFutureGuard<'_> {
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for RenewalFutureGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
}

impl CredentialAcquireGate {
    fn new() -> Self {
        Self {
            entered: Notify::new(),
            release: CancellationToken::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CredentialObservation {
    repository_owner_id: ProviderRepositoryOwnerId,
    connection_id: ProviderConnectionId,
    installation_id: ProviderInstallationId,
    repository_id: ProviderRepositoryId,
    claim: ProviderDeliveryClaimFence,
    attempt: u16,
    action: GithubDeliveryPrivateRepositoryAction,
    authority_selector: GithubServerServiceAuthoritySelector,
    consumer: GithubServerServiceConsumerClaim,
    observed_at: UnixMillis,
    required_through: UnixMillis,
}

#[derive(Debug)]
struct RecordingCredentialProvider {
    behavior: CredentialBehavior,
    observations: Mutex<Vec<CredentialObservation>>,
    calls: AtomicUsize,
    releases: Arc<AtomicUsize>,
    gate: Option<Arc<CredentialAcquireGate>>,
    renewal_apply_gate: Arc<RenewalApplyGate>,
}

impl RecordingCredentialProvider {
    fn new(behavior: CredentialBehavior, renewal_apply_gate: Arc<RenewalApplyGate>) -> Self {
        Self {
            behavior,
            observations: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            releases: Arc::new(AtomicUsize::new(0)),
            gate: (behavior == CredentialBehavior::RenewDuringAcquire)
                .then(|| Arc::new(CredentialAcquireGate::new())),
            renewal_apply_gate,
        }
    }

    fn credential_identity(
        &self,
        request: &GithubDeliverySourceCredentialRequest<'_>,
    ) -> (ProviderDeliveryIdentity, ScmRepositoryId) {
        let identity = request.identity();
        let tenant = if self.behavior == CredentialBehavior::WrongTenant {
            TenantScope::from_authenticated_tenant_id("wrong-tenant").expect("wrong tenant")
        } else {
            identity.tenant().clone()
        };
        let connection_id = if self.behavior == CredentialBehavior::WrongConnection {
            ProviderConnectionId::from_uuid(Uuid::from_u128(99)).expect("wrong connection")
        } else {
            identity.connection_id()
        };
        let installation_id = if self.behavior == CredentialBehavior::WrongInstallation {
            ProviderInstallationId::new(INSTALLATION_ID + 1).expect("wrong installation")
        } else {
            identity.installation_id()
        };
        let repository_id = if self.behavior == CredentialBehavior::WrongRepository {
            ProviderRepositoryId::new(REPOSITORY_ID + 1).expect("wrong repository")
        } else {
            identity.repository_id()
        };
        let route = if self.behavior == CredentialBehavior::WrongRoute {
            format!("{OWNER}/wrong-repository")
        } else {
            identity.repository_identity().to_owned()
        };
        let coordinates = ProviderRepositoryCoordinates::new(
            repository_id,
            ProviderRepositoryVisibility::Private,
            route.clone(),
        )
        .expect("credential repository coordinates");
        let credential_identity = ProviderDeliveryIdentity::new(
            tenant,
            "github",
            connection_id,
            installation_id,
            coordinates,
            identity.delivery_id(),
        )
        .expect("credential identity");
        let repository = ScmRepositoryId::new(route).expect("repository route");
        (credential_identity, repository)
    }

    fn repository_owner_id(
        &self,
        request: &GithubDeliverySourceCredentialRequest<'_>,
    ) -> ProviderRepositoryOwnerId {
        let wrong_during_predecessor_changed_files = self.behavior
            == CredentialBehavior::WrongOwnerChangedFilesDuringRenewalApply
            && request.action()
                == GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles
            && request.snapshot().claim().fence() == 7;
        if self.behavior == CredentialBehavior::WrongOwner || wrong_during_predecessor_changed_files
        {
            ProviderRepositoryOwnerId::new(request.repository_owner_id().get() + 1)
                .expect("wrong owner remains structurally valid")
        } else {
            request.repository_owner_id()
        }
    }

    fn consumer(
        &self,
        request: &GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubServerServiceConsumerClaim, GithubDeliverySourceCredentialProviderError> {
        let requested = request
            .consumer_claim()
            .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        let fence = if self.behavior == CredentialBehavior::WrongFence {
            GithubServerServiceClaimFence::new(requested.fence().get() + 1)
                .expect("wrong fence remains structurally valid")
        } else {
            requested.fence()
        };
        let action = if self.behavior == CredentialBehavior::WrongAction {
            match request.action() {
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision => {
                    GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
                }
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles => {
                    GithubServerServiceAction::FetchPrivateRepositoryRevision
                }
            }
        } else {
            requested.action()
        };
        let revision = if self.behavior == CredentialBehavior::WrongAttempt {
            GithubServerServiceRevision::new(requested.revision().get() + 1)
                .expect("wrong revision remains structurally valid")
        } else {
            requested.revision()
        };
        Ok(GithubServerServiceConsumerClaim::new(
            requested.consumer_id(),
            requested.owner(),
            fence,
            action,
            revision,
        ))
    }

    fn authority_selector(
        &self,
        request: &GithubDeliverySourceCredentialRequest<'_>,
    ) -> GithubServerServiceAuthoritySelector {
        if self.behavior == CredentialBehavior::WrongSelector {
            GithubServerServiceAuthoritySelector::from_durable_parts(
                request.authority_selector().tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x7fff))
                    .expect("wrong selector ID"),
                request.authority_selector().identity_digest(),
                request.authority_selector().app_configuration_revision(),
                request.authority_selector().policy_revision(),
            )
        } else {
            request.authority_selector().clone()
        }
    }

    fn credential_for(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let (credential_identity, repository) = self.credential_identity(&request);
        let repository_owner_id = self.repository_owner_id(&request);
        let consumer = self.consumer(&request)?;
        let authority_selector = self.authority_selector(&request);
        let required_through = if self.behavior == CredentialBehavior::WrongHorizon {
            UnixMillis::new(request.required_through().get() + 1)
        } else {
            request.required_through()
        };
        let conservative_expires_at = match self.behavior {
            CredentialBehavior::Expired => UnixMillis::new(request.required_through().get() - 1),
            _ => UnixMillis::new(required_through.get() + 1),
        };
        let binding = GithubDeliverySourceCredentialBinding::new(
            credential_identity,
            repository_owner_id,
            repository,
            authority_selector,
            GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x7400)).expect("handoff ID"),
            consumer,
            required_through,
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)?;
        GithubDeliverySourceCredential::new(
            binding,
            request.observed_at(),
            SecretString::new(TOKEN_MARKER).expect("source credential"),
            conservative_expires_at,
            Box::new(ReleaseProbe {
                calls: Arc::clone(&self.releases),
                renewal_apply_gate: match (self.behavior, request.action()) {
                    (
                        CredentialBehavior::ReleaseDuringRenewalApply,
                        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
                    )
                    | (
                        CredentialBehavior::ReleaseChangedFilesDuringRenewalApply,
                        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
                    ) => Some(Arc::clone(&self.renewal_apply_gate)),
                    _ => None,
                },
            }),
        )
        .map_err(|_| GithubDeliverySourceCredentialProviderError::InvariantViolation)
    }
}

#[derive(Debug)]
struct ReleaseProbe {
    calls: Arc<AtomicUsize>,
    renewal_apply_gate: Option<Arc<RenewalApplyGate>>,
}

#[async_trait]
impl GithubServerServiceCredentialRelease for ReleaseProbe {
    async fn release(self: Box<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.renewal_apply_gate {
            gate.mark_downstream_result_ready();
            gate.wait_committed().await;
        }
    }
}

#[async_trait]
impl GithubDeliverySourceCredentialProvider for RecordingCredentialProvider {
    async fn acquire(
        &self,
        request: GithubDeliverySourceCredentialRequest<'_>,
    ) -> Result<GithubDeliverySourceCredential, GithubDeliverySourceCredentialProviderError> {
        let identity = request.identity();
        self.observations
            .lock()
            .expect("credential observations lock")
            .push(CredentialObservation {
                repository_owner_id: request.repository_owner_id(),
                connection_id: identity.connection_id(),
                installation_id: identity.installation_id(),
                repository_id: identity.repository_id(),
                claim: request.snapshot().claim(),
                attempt: request.snapshot().attempt(),
                action: request.action(),
                authority_selector: request.authority_selector().clone(),
                consumer: request.consumer_claim().expect("valid consumer claim"),
                observed_at: request.observed_at(),
                required_through: request.required_through(),
            });
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 && self.behavior == CredentialBehavior::RejectDuringRenewalApply {
            self.renewal_apply_gate.wait_committed().await;
            assert_eq!(request.snapshot().claim().fence(), 7);
            assert_eq!(
                self.renewal_apply_gate.durable_fence.load(Ordering::SeqCst),
                8
            );
            return Err(GithubDeliverySourceCredentialProviderError::Rejected);
        }
        if self.behavior == CredentialBehavior::WrongOwnerChangedFilesDuringRenewalApply
            && request.action()
                == GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles
            && request.snapshot().claim().fence() == 7
        {
            self.renewal_apply_gate.wait_committed().await;
            let credential = self.credential_for(request);
            self.renewal_apply_gate.mark_downstream_result_ready();
            return credential;
        }
        if call == 0
            && let Some(gate) = &self.gate
        {
            gate.entered.notify_one();
            gate.release.cancelled().await;
        }
        if let CredentialBehavior::Error(error) = self.behavior {
            return Err(error);
        }
        self.credential_for(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenewalBehavior {
    Succeed,
    DatabaseIssuedTimes,
    DatabaseIssuedFutureTimes,
    ClaimLost,
    AmbiguousOnce,
    Unavailable,
    SameFence,
    WrongAttempt,
    BlockCommittedThenSucceed,
    BlockBeforeCommitThenSucceed,
    NeverReturns,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalBehavior {
    Succeed,
    ClaimLost,
    BlockThenSucceed,
}

#[derive(Debug)]
struct DeliveryTemplate {
    delivery_id: ProviderDeliveryId,
    identity: ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
    check_head_sha: GithubCheckHeadSha,
}

#[derive(Debug)]
struct RecordingRepository {
    template: DeliveryTemplate,
    renewal_behavior: RenewalBehavior,
    terminal_behavior: TerminalBehavior,
    claim_calls: Mutex<Vec<ClaimProviderDelivery>>,
    claim_count: AtomicUsize,
    reclaim_enabled: AtomicBool,
    claimed_at: Mutex<Option<UnixMillis>>,
    renewals: Mutex<Vec<RenewProviderDeliveryClaim>>,
    renewal_called: Notify,
    completions: Mutex<Vec<CompleteProviderDelivery>>,
    retries: Mutex<Vec<RetryProviderDelivery>>,
    rejections: Mutex<Vec<RejectProviderDelivery>>,
    inventory: Mutex<Option<ProviderDeliveryWorkflowInventory>>,
    progress: Mutex<Vec<ProviderDeliveryWorkflowOutcome>>,
    terminal_entered: Notify,
    terminal_release: CancellationToken,
    renewal_apply_gate: Arc<RenewalApplyGate>,
}

impl RecordingRepository {
    fn receipt(&self, state: ProviderDeliveryState) -> ProviderDeliveryReceipt {
        ProviderDeliveryReceipt::from_durable_parts(
            self.template.delivery_id,
            state,
            1,
            UnixMillis::new(50),
        )
        .expect("transition receipt")
    }

    fn transition_count(&self) -> usize {
        self.completions.lock().expect("completions lock").len()
            + self.retries.lock().expect("retries lock").len()
            + self.rejections.lock().expect("rejections lock").len()
    }
}

#[async_trait]
impl ProviderDeliveryRepository for RecordingRepository {
    async fn accept_provider_delivery(
        &self,
        _request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        panic!("delivery acceptance is outside the supervision service")
    }

    async fn claim_provider_delivery(
        &self,
        request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError> {
        self.claim_calls
            .lock()
            .expect("claim calls lock")
            .push(request);
        if self.claim_count.fetch_add(1, Ordering::SeqCst) != 0 {
            if !self.reclaim_enabled.swap(false, Ordering::SeqCst) {
                return Ok(None);
            }
            let fence = u64::try_from(self.renewal_apply_gate.durable_fence.load(Ordering::SeqCst))
                .map_err(|_| ProviderDeliveryStoreError::CorruptData)?
                .checked_add(1)
                .ok_or(ProviderDeliveryStoreError::FenceExhausted)?;
            self.renewal_apply_gate.durable_fence.store(
                i64::try_from(fence).map_err(|_| ProviderDeliveryStoreError::FenceExhausted)?,
                Ordering::SeqCst,
            );
            let claim = ProviderDeliveryClaimFence::from_durable_parts(
                self.template.delivery_id,
                request.owner(),
                fence,
            )
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?;
            let receipt = self.receipt(ProviderDeliveryState::Claimed);
            let requested_duration = request.expires_at().get() - request.observed_at().get();
            let claimed_at = database_issued_at(self.renewal_behavior, request.observed_at());
            return ClaimedProviderDelivery::from_durable_parts(
                receipt,
                self.template.identity.clone(),
                self.template.request_digest,
                self.template.raw_event.clone(),
                claim,
                claimed_at,
                UnixMillis::new(claimed_at.get() + requested_duration),
            )
            .map(Some)
            .map_err(|_| ProviderDeliveryStoreError::CorruptData);
        }
        let requested_duration = request.expires_at().get() - request.observed_at().get();
        let claimed_at = database_issued_at(self.renewal_behavior, request.observed_at());
        *self.claimed_at.lock().expect("claimed-at lock") = Some(claimed_at);
        let claim = ProviderDeliveryClaimFence::from_durable_parts(
            self.template.delivery_id,
            request.owner(),
            7,
        )
        .expect("claim fence");
        ClaimedProviderDelivery::from_durable_parts(
            self.receipt(ProviderDeliveryState::Claimed),
            self.template.identity.clone(),
            self.template.request_digest,
            self.template.raw_event.clone(),
            claim,
            claimed_at,
            UnixMillis::new(claimed_at.get() + requested_duration),
        )
        .map(Some)
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)
    }

    async fn complete_provider_delivery(
        &self,
        request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        self.completions
            .lock()
            .expect("completions lock")
            .push(request);
        if self.terminal_behavior == TerminalBehavior::BlockThenSucceed {
            self.terminal_entered.notify_one();
            self.terminal_release.cancelled().await;
        }
        if self.terminal_behavior == TerminalBehavior::ClaimLost {
            return Err(ProviderDeliveryStoreError::ClaimRejected);
        }
        Ok(self.receipt(ProviderDeliveryState::Completed))
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
        self.retries.lock().expect("retries lock").push(request);
        Ok(self.receipt(ProviderDeliveryState::RetryPending))
    }

    async fn reject_provider_delivery(
        &self,
        request: RejectProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        self.rejections
            .lock()
            .expect("rejections lock")
            .push(request);
        if self.terminal_behavior == TerminalBehavior::BlockThenSucceed {
            self.terminal_entered.notify_one();
            self.terminal_release.cancelled().await;
        }
        if self.terminal_behavior == TerminalBehavior::ClaimLost {
            return Err(ProviderDeliveryStoreError::ClaimRejected);
        }
        Ok(self.receipt(ProviderDeliveryState::Rejected))
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for RecordingRepository {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        _request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        panic!("delivery acceptance is outside the supervision service")
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        let identity = &self.template.identity;
        if identity.tenant() != tenant || self.template.delivery_id != delivery_id {
            return Err(GithubSubjectEvidenceStoreError::NotFound);
        }
        let repository_owner_id =
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID");
        let evidence = if self.template.check_head_sha == fixture_check_head_sha(AFTER) {
            fixture_subject_evidence(
                delivery_id,
                identity,
                repository_owner_id,
                UnixMillis::new(50),
                0x7200,
            )
        } else {
            fixture_subject_evidence_with_head(
                delivery_id,
                identity,
                repository_owner_id,
                UnixMillis::new(50),
                0x7200,
                self.template.check_head_sha,
            )
        };
        Ok(evidence)
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        _tenant: &TenantScope,
        _repository_id: StoreRepositoryId,
        _run_id: automata_ci_core::RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        panic!("run evidence is outside the supervision service")
    }
}

#[async_trait]
impl ProviderDeliveryClaimRenewalRepository for RecordingRepository {
    async fn renew_provider_delivery_claim(
        &self,
        request: RenewProviderDeliveryClaim,
    ) -> Result<RenewedProviderDeliveryClaim, ProviderDeliveryStoreError> {
        let call = {
            let mut renewals = self.renewals.lock().expect("renewals lock");
            renewals.push(request);
            renewals.len()
        };
        self.renewal_called.notify_one();
        if self.renewal_behavior == RenewalBehavior::ClaimLost {
            return Err(ProviderDeliveryStoreError::ClaimRejected);
        }
        if self.renewal_behavior == RenewalBehavior::Unavailable
            || (self.renewal_behavior == RenewalBehavior::AmbiguousOnce && call == 1)
        {
            return Err(ProviderDeliveryStoreError::operation(
                std::io::Error::other("synthetic renewal response loss"),
            ));
        }
        if self.renewal_behavior == RenewalBehavior::NeverReturns {
            return std::future::pending().await;
        }
        let claimed_at = self
            .claimed_at
            .lock()
            .expect("claimed-at lock")
            .expect("claim precedes renewal");
        let renewed_claim = if self.renewal_behavior == RenewalBehavior::SameFence {
            request.claim()
        } else {
            ProviderDeliveryClaimFence::from_durable_parts(
                request.claim().delivery_id(),
                request.claim().owner(),
                request
                    .claim()
                    .fence()
                    .checked_add(1)
                    .ok_or(ProviderDeliveryStoreError::FenceExhausted)?,
            )
            .map_err(|_| ProviderDeliveryStoreError::CorruptData)?
        };
        if self.renewal_behavior == RenewalBehavior::BlockBeforeCommitThenSucceed {
            let mut guard = RenewalFutureGuard {
                dropped: &self.renewal_apply_gate.future_dropped,
                completed: false,
            };
            self.renewal_apply_gate
                .entered_state
                .store(true, Ordering::SeqCst);
            self.renewal_apply_gate.entered.notify_waiters();
            self.renewal_apply_gate.release.cancelled().await;
            guard.complete();
        }
        self.renewal_apply_gate.durable_fence.store(
            i64::try_from(renewed_claim.fence()).expect("fixture fence fits i64"),
            Ordering::SeqCst,
        );
        if self.renewal_behavior == RenewalBehavior::BlockCommittedThenSucceed {
            self.renewal_apply_gate
                .committed_state
                .store(true, Ordering::SeqCst);
            self.renewal_apply_gate.committed.notify_waiters();
            self.renewal_apply_gate.release.cancelled().await;
        }
        let requested_duration = request.expires_at().get() - request.observed_at().get();
        let renewed_at = database_issued_at(self.renewal_behavior, request.observed_at());
        RenewedProviderDeliveryClaim::from_durable_parts(
            renewed_claim,
            if self.renewal_behavior == RenewalBehavior::WrongAttempt {
                2
            } else {
                1
            },
            claimed_at,
            renewed_at,
            UnixMillis::new(renewed_at.get() + requested_duration),
        )
        .map_err(|_| ProviderDeliveryStoreError::CorruptData)
    }
}

fn database_issued_at(behavior: RenewalBehavior, requested_at: UnixMillis) -> UnixMillis {
    match behavior {
        RenewalBehavior::DatabaseIssuedTimes => UnixMillis::new(requested_at.get() - 5),
        RenewalBehavior::DatabaseIssuedFutureTimes => UnixMillis::new(requested_at.get() + 5),
        _ => requested_at,
    }
}

struct Harness {
    service: Arc<GithubDeliveryService>,
    objects: Arc<FixtureBlobStore>,
    repository: Arc<RecordingRepository>,
    credentials: Arc<RecordingCredentialProvider>,
    source: Arc<RecordingSourcePort>,
    clock: Arc<ManualClock>,
    worker_id: ProviderDeliveryClaimOwnerId,
    renewal_apply_gate: Arc<RenewalApplyGate>,
}

struct BlockingClockHarness {
    service: Arc<GithubDeliveryService>,
    repository: Arc<RecordingRepository>,
    source_gate: Arc<SourceGate>,
}

fn blocking_clock_harness(
    clock: Arc<BlockingClock>,
    service_config: GithubDeliveryServiceConfig,
) -> BlockingClockHarness {
    let (template, descriptor, body) = delivery_template(
        ProviderRepositoryVisibility::Public,
        ProviderRepositoryVisibility::Public,
        false,
    );
    let renewal_apply_gate = Arc::new(RenewalApplyGate::new());
    let repository = Arc::new(RecordingRepository {
        template,
        renewal_behavior: RenewalBehavior::NeverReturns,
        terminal_behavior: TerminalBehavior::Succeed,
        claim_calls: Mutex::new(Vec::new()),
        claim_count: AtomicUsize::new(0),
        reclaim_enabled: AtomicBool::new(false),
        claimed_at: Mutex::new(None),
        renewals: Mutex::new(Vec::new()),
        renewal_called: Notify::new(),
        completions: Mutex::new(Vec::new()),
        retries: Mutex::new(Vec::new()),
        rejections: Mutex::new(Vec::new()),
        inventory: Mutex::new(None),
        progress: Mutex::new(Vec::new()),
        terminal_entered: Notify::new(),
        terminal_release: CancellationToken::new(),
        renewal_apply_gate,
    });
    let source_gate = Arc::new(SourceGate::new());
    let source = Arc::new(RecordingSourcePort::new(
        repository_source(),
        Some(source_gate.clone()),
    ));
    let worker_id =
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("worker identity");
    let objects = Arc::new(FixtureBlobStore {
        descriptor,
        bytes: body,
        reads: AtomicUsize::new(0),
    });
    let service = GithubDeliveryService::new_public_only(
        objects,
        source,
        Arc::new(StaticProcessor),
        repository.clone(),
        clock,
        worker_id,
        GithubDeliveryWorkerConfig::default(),
        service_config,
    )
    .expect("delivery service");
    BlockingClockHarness {
        service: Arc::new(service),
        repository,
        source_gate,
    }
}

fn harness(
    credential_behavior: CredentialBehavior,
    renewal_behavior: RenewalBehavior,
    terminal_behavior: TerminalBehavior,
    gate: Option<Arc<SourceGate>>,
    service_config: GithubDeliveryServiceConfig,
) -> Harness {
    harness_with_visibility(
        credential_behavior,
        renewal_behavior,
        terminal_behavior,
        gate,
        service_config,
        ProviderRepositoryVisibility::Private,
    )
}

fn harness_with_visibility(
    credential_behavior: CredentialBehavior,
    renewal_behavior: RenewalBehavior,
    terminal_behavior: TerminalBehavior,
    gate: Option<Arc<SourceGate>>,
    service_config: GithubDeliveryServiceConfig,
    visibility: ProviderRepositoryVisibility,
) -> Harness {
    let private_source_enabled = visibility == ProviderRepositoryVisibility::Private;
    harness_with_source_policy(
        credential_behavior,
        renewal_behavior,
        terminal_behavior,
        gate,
        service_config,
        visibility,
        private_source_enabled,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn harness_with_source_policy(
    credential_behavior: CredentialBehavior,
    renewal_behavior: RenewalBehavior,
    terminal_behavior: TerminalBehavior,
    gate: Option<Arc<SourceGate>>,
    service_config: GithubDeliveryServiceConfig,
    visibility: ProviderRepositoryVisibility,
    private_source_enabled: bool,
    deleted: bool,
) -> Harness {
    harness_with_stored_visibility(
        credential_behavior,
        renewal_behavior,
        terminal_behavior,
        gate,
        service_config,
        visibility,
        visibility,
        private_source_enabled,
        deleted,
    )
}

#[allow(clippy::too_many_arguments)]
fn harness_with_stored_visibility(
    credential_behavior: CredentialBehavior,
    renewal_behavior: RenewalBehavior,
    terminal_behavior: TerminalBehavior,
    gate: Option<Arc<SourceGate>>,
    service_config: GithubDeliveryServiceConfig,
    identity_visibility: ProviderRepositoryVisibility,
    stored_visibility: ProviderRepositoryVisibility,
    private_source_enabled: bool,
    deleted: bool,
) -> Harness {
    let (template, descriptor, body) =
        delivery_template(identity_visibility, stored_visibility, deleted);
    let renewal_apply_gate = Arc::new(RenewalApplyGate::new());
    let repository = Arc::new(RecordingRepository {
        template,
        renewal_behavior,
        terminal_behavior,
        claim_calls: Mutex::new(Vec::new()),
        claim_count: AtomicUsize::new(0),
        reclaim_enabled: AtomicBool::new(false),
        claimed_at: Mutex::new(None),
        renewals: Mutex::new(Vec::new()),
        renewal_called: Notify::new(),
        completions: Mutex::new(Vec::new()),
        retries: Mutex::new(Vec::new()),
        rejections: Mutex::new(Vec::new()),
        inventory: Mutex::new(None),
        progress: Mutex::new(Vec::new()),
        terminal_entered: Notify::new(),
        terminal_release: CancellationToken::new(),
        renewal_apply_gate: renewal_apply_gate.clone(),
    });
    let credentials = Arc::new(RecordingCredentialProvider::new(
        credential_behavior,
        renewal_apply_gate.clone(),
    ));
    let source = Arc::new(RecordingSourcePort::new(repository_source(), gate));
    let clock = Arc::new(ManualClock::new(INITIAL_NOW));
    let worker_id =
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("worker identity");
    let objects = Arc::new(FixtureBlobStore {
        descriptor,
        bytes: body,
        reads: AtomicUsize::new(0),
    });
    let service = if private_source_enabled {
        GithubDeliveryService::new_with_private_source_credentials(
            objects.clone(),
            source.clone(),
            Arc::new(StaticProcessor),
            repository.clone(),
            credentials.clone(),
            clock.clone(),
            worker_id,
            GithubDeliveryWorkerConfig::default(),
            service_config,
        )
    } else {
        GithubDeliveryService::new_public_only(
            objects.clone(),
            source.clone(),
            Arc::new(StaticProcessor),
            repository.clone(),
            clock.clone(),
            worker_id,
            GithubDeliveryWorkerConfig::default(),
            service_config,
        )
    }
    .expect("delivery service");
    Harness {
        service: Arc::new(service),
        objects,
        repository,
        credentials,
        source,
        clock,
        worker_id,
        renewal_apply_gate,
    }
}

fn snapshot_refresh_harness() -> (Harness, Arc<SnapshotGateProcessor>) {
    snapshot_processor_harness(RenewalBehavior::Succeed, false)
}

fn snapshot_processor_harness(
    renewal_behavior: RenewalBehavior,
    fail_after_committed_renewal: bool,
) -> (Harness, Arc<SnapshotGateProcessor>) {
    snapshot_processor_harness_with_config(
        renewal_behavior,
        fail_after_committed_renewal,
        service_config(),
    )
}

fn snapshot_processor_harness_with_config(
    renewal_behavior: RenewalBehavior,
    fail_after_committed_renewal: bool,
    delivery_service_config: GithubDeliveryServiceConfig,
) -> (Harness, Arc<SnapshotGateProcessor>) {
    let (template, descriptor, body) = delivery_template(
        ProviderRepositoryVisibility::Private,
        ProviderRepositoryVisibility::Private,
        false,
    );
    let renewal_apply_gate = Arc::new(RenewalApplyGate::new());
    let repository = Arc::new(RecordingRepository {
        template,
        renewal_behavior,
        terminal_behavior: TerminalBehavior::Succeed,
        claim_calls: Mutex::new(Vec::new()),
        claim_count: AtomicUsize::new(0),
        reclaim_enabled: AtomicBool::new(false),
        claimed_at: Mutex::new(None),
        renewals: Mutex::new(Vec::new()),
        renewal_called: Notify::new(),
        completions: Mutex::new(Vec::new()),
        retries: Mutex::new(Vec::new()),
        rejections: Mutex::new(Vec::new()),
        inventory: Mutex::new(None),
        progress: Mutex::new(Vec::new()),
        terminal_entered: Notify::new(),
        terminal_release: CancellationToken::new(),
        renewal_apply_gate: renewal_apply_gate.clone(),
    });
    let credentials = Arc::new(RecordingCredentialProvider::new(
        CredentialBehavior::Exact,
        renewal_apply_gate.clone(),
    ));
    let source = RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        ExactRevision::new(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive(BTreeMap::from([(
            ".ci/workflows/ci.yml",
            b"on: push\n".to_vec(),
        )])),
    );
    let source = Arc::new(RecordingSourcePort::new(source, None));
    let processor = Arc::new(if fail_after_committed_renewal {
        SnapshotGateProcessor::failing_after_committed_renewal(renewal_apply_gate.clone())
    } else {
        SnapshotGateProcessor::new()
    });
    let clock = Arc::new(ManualClock::new(INITIAL_NOW));
    let worker_id =
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("worker identity");
    let objects = Arc::new(FixtureBlobStore {
        descriptor,
        bytes: body,
        reads: AtomicUsize::new(0),
    });
    let service = GithubDeliveryService::new_with_private_source_credentials(
        objects.clone(),
        source.clone(),
        processor.clone(),
        repository.clone(),
        credentials.clone(),
        clock.clone(),
        worker_id,
        GithubDeliveryWorkerConfig::default(),
        delivery_service_config,
    )
    .expect("delivery service");
    (
        Harness {
            service: Arc::new(service),
            objects,
            repository,
            credentials,
            source,
            clock,
            worker_id,
            renewal_apply_gate,
        },
        processor,
    )
}

fn changed_files_renewal_harness(
    visibility: ProviderRepositoryVisibility,
    credential_behavior: CredentialBehavior,
    first_error: Option<GithubPushChangedFilesError>,
) -> (
    Harness,
    Arc<CountingWorkflowProcessor>,
    Arc<RenewalRacingChangedFiles>,
) {
    let (template, descriptor, body) = delivery_template(visibility, visibility, false);
    let renewal_apply_gate = Arc::new(RenewalApplyGate::new());
    let repository = Arc::new(RecordingRepository {
        template,
        renewal_behavior: RenewalBehavior::BlockCommittedThenSucceed,
        terminal_behavior: TerminalBehavior::Succeed,
        claim_calls: Mutex::new(Vec::new()),
        claim_count: AtomicUsize::new(0),
        reclaim_enabled: AtomicBool::new(false),
        claimed_at: Mutex::new(None),
        renewals: Mutex::new(Vec::new()),
        renewal_called: Notify::new(),
        completions: Mutex::new(Vec::new()),
        retries: Mutex::new(Vec::new()),
        rejections: Mutex::new(Vec::new()),
        inventory: Mutex::new(None),
        progress: Mutex::new(Vec::new()),
        terminal_entered: Notify::new(),
        terminal_release: CancellationToken::new(),
        renewal_apply_gate: renewal_apply_gate.clone(),
    });
    let credentials = Arc::new(RecordingCredentialProvider::new(
        credential_behavior,
        renewal_apply_gate.clone(),
    ));
    let source = RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        ExactRevision::new(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive(BTreeMap::from([(
            ".ci/workflows/ci.yml",
            PATH_FILTER_WORKFLOW.to_vec(),
        )])),
    );
    let source = Arc::new(RecordingSourcePort::new(source, None));
    let clock = Arc::new(ManualClock::new(INITIAL_NOW));
    let worker_id =
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("worker identity");
    let objects = Arc::new(FixtureBlobStore {
        descriptor,
        bytes: body,
        reads: AtomicUsize::new(0),
    });
    let changed_files = Arc::new(match first_error {
        Some(error) => RenewalRacingChangedFiles::new(error, renewal_apply_gate.clone()),
        None => RenewalRacingChangedFiles::path_miss(renewal_apply_gate.clone()),
    });
    let admission = WorkflowAdmissionService::with_system_ports(
        objects.clone(),
        Arc::new(UnreachableLogicalAdmissions),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let processor = Arc::new(CountingWorkflowProcessor::new(
        GithubDeliveryWorkflowAdmissionProcessor::new(admission)
            .with_changed_files_provider(changed_files.clone()),
    ));
    let service = if visibility == ProviderRepositoryVisibility::Private {
        GithubDeliveryService::new_with_private_source_credentials(
            objects.clone(),
            source.clone(),
            processor.clone(),
            repository.clone(),
            credentials.clone(),
            clock.clone(),
            worker_id,
            GithubDeliveryWorkerConfig::default(),
            service_config(),
        )
    } else {
        GithubDeliveryService::new_public_only(
            objects.clone(),
            source.clone(),
            processor.clone(),
            repository.clone(),
            clock.clone(),
            worker_id,
            GithubDeliveryWorkerConfig::default(),
            service_config(),
        )
    }
    .expect("delivery service");
    (
        Harness {
            service: Arc::new(service),
            objects,
            repository,
            credentials,
            source,
            clock,
            worker_id,
            renewal_apply_gate,
        },
        processor,
        changed_files,
    )
}

fn service_config() -> GithubDeliveryServiceConfig {
    GithubDeliveryServiceConfig::new(CLAIM_MILLIS, 2, 10).expect("service config")
}

async fn wait_for_renewal_count(repository: &RecordingRepository, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let notified = repository.renewal_called.notified();
            if repository.renewals.lock().expect("renewals lock").len() >= expected {
                break;
            }
            notified.await;
        }
    })
    .await
    .expect("expected claim renewal count");
}

fn assert_single_skipped_completion(harness: &Harness, fence: u64) {
    let completions = harness
        .repository
        .completions
        .lock()
        .expect("completions lock");
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].claim().fence(), fence);
    assert_eq!(completions[0].outcomes().len(), 1);
    assert!(matches!(
        completions[0].outcomes()[0].conclusion(),
        ProviderDeliveryWorkflowConclusion::Skipped { reason }
            if reason.as_str() == "github.workflow.event_filters_not_matched"
    ));
    drop(completions);
    assert!(
        harness
            .repository
            .retries
            .lock()
            .expect("retries lock")
            .is_empty()
    );
    assert!(
        harness
            .repository
            .rejections
            .lock()
            .expect("rejections lock")
            .is_empty()
    );
}

async fn advance_successful_renewals(
    harness: &Harness,
    claim_started_at: tokio::time::Instant,
    renew_after_millis: i64,
    renewal_count: usize,
) {
    for expected in 1..=renewal_count {
        let offset = i64::try_from(expected).expect("bounded iteration") * renew_after_millis;
        harness.clock.set(INITIAL_NOW + offset);
        tokio::task::yield_now().await;
        let target = claim_started_at
            .checked_add(Duration::from_millis(
                u64::try_from(offset).expect("positive elapsed claim time"),
            ))
            .expect("renewal target");
        assert!(tokio::time::Instant::now() <= target);
        tokio::time::advance(target.saturating_duration_since(tokio::time::Instant::now())).await;
        for _ in 0..32 {
            if harness
                .repository
                .renewals
                .lock()
                .expect("renewals lock")
                .len()
                >= expected
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            harness
                .repository
                .renewals
                .lock()
                .expect("renewals lock")
                .len(),
            expected
        );
    }
}

fn delivery_template(
    identity_visibility: ProviderRepositoryVisibility,
    stored_visibility: ProviderRepositoryVisibility,
    deleted: bool,
) -> (DeliveryTemplate, BlobDescriptor, Bytes) {
    let body = push_body(stored_visibility, deleted);
    let digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let key_text = format!("provider-deliveries/github/event/sha256/{digest}.json");
    let descriptor = BlobDescriptor::new(
        BlobKey::new(key_text.clone()).expect("blob key"),
        digest,
        u64::try_from(body.len()).expect("body length"),
        MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE).expect("media type"),
    );
    let raw_event = AdmissionObject::new(
        digest,
        ObjectKey::new(key_text).expect("object key"),
        descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(1)).expect("delivery ID");
    let repository = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
        identity_visibility,
        format!("{OWNER}/{REPOSITORY}"),
    )
    .expect("repository coordinates");
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-private").expect("tenant"),
        "github",
        ProviderConnectionId::from_uuid(Uuid::from_u128(3)).expect("connection"),
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        repository,
        "delivery-service-1",
    )
    .expect("delivery identity");
    (
        DeliveryTemplate {
            delivery_id,
            identity,
            request_digest: Sha256Digest::from_bytes([0x42; 32]),
            raw_event,
            check_head_sha: fixture_check_head_sha(if deleted { BEFORE } else { AFTER }),
        },
        descriptor,
        body,
    )
}

fn push_body(visibility: ProviderRepositoryVisibility, deleted: bool) -> Bytes {
    let (private, visibility) = match visibility {
        ProviderRepositoryVisibility::Public => (false, "public"),
        ProviderRepositoryVisibility::Private => (true, "private"),
    };
    let after = if deleted { ZERO } else { AFTER };
    Bytes::from(format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE}","after":"{after}","created":false,"deleted":{deleted},"forced":false,"repository":{{"id":{REPOSITORY_ID},"private":{private},"visibility":"{visibility}","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"commits":[]}}"#,
    ))
}

fn repository_source() -> RepositorySource {
    RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        ExactRevision::new(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive(BTreeMap::from([(
            ".ci/workflows/ci.yml",
            b"on: push\n".to_vec(),
        )])),
    )
}

fn archive(files: BTreeMap<&str, Vec<u8>>) -> Bytes {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    append_archive_entry(&mut builder, "repository-root", EntryType::Directory, &[]);
    for (path, bytes) in files {
        append_archive_entry(
            &mut builder,
            &format!("repository-root/{path}"),
            EntryType::Regular,
            &bytes,
        );
    }
    let encoder = builder.into_inner().expect("finish tar");
    Bytes::from(encoder.finish().expect("finish gzip"))
}

fn append_archive_entry(
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

async fn run_once(
    service: Arc<GithubDeliveryService>,
    shutdown: CancellationToken,
) -> Result<GithubDeliveryServiceOutcome, GithubDeliveryServiceError> {
    tokio::time::timeout(Duration::from_secs(2), service.run_once(shutdown))
        .await
        .expect("bounded service invocation")
}

#[tokio::test]
async fn success_uses_one_stable_worker_and_exact_request_scoped_credential() {
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
    );
    assert_eq!(harness.service.worker_id(), harness.worker_id);

    let outcome = run_once(harness.service.clone(), CancellationToken::new())
        .await
        .expect("delivery completion");
    assert!(matches!(
        outcome,
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert!(harness.source.credential_present.load(Ordering::SeqCst));
    assert!(harness.source.credential_matched.load(Ordering::SeqCst));
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
    {
        let observations = harness
            .credentials
            .observations
            .lock()
            .expect("credential observations lock");
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].repository_owner_id,
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID")
        );
        assert_eq!(observations[0].claim.fence(), 7);
        assert_eq!(observations[0].attempt, 1);
        assert_eq!(observations[0].observed_at, UnixMillis::new(INITIAL_NOW));
        let expected_evidence = fixture_subject_evidence(
            harness.repository.template.delivery_id,
            &harness.repository.template.identity,
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
            UnixMillis::new(50),
            0x7200,
        );
        assert_eq!(
            &observations[0].authority_selector,
            expected_evidence
                .private_source_authority()
                .expect("private delivery pins source authority")
        );
        assert_eq!(
            observations[0].consumer.action(),
            GithubServerServiceAction::FetchPrivateRepositoryRevision
        );
        assert_eq!(observations[0].consumer.fence().get(), 7);
        assert_eq!(observations[0].consumer.revision().get(), 1);
        assert_eq!(
            observations[0].action,
            GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision
        );
        assert_eq!(
            observations[0].required_through,
            UnixMillis::new(
                INITIAL_NOW + CLAIM_MILLIS + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS
            )
        );
    }
    {
        let completions = harness
            .repository
            .completions
            .lock()
            .expect("completions lock");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].outcomes().len(), 1);
    }

    assert_eq!(
        run_once(harness.service.clone(), CancellationToken::new())
            .await
            .expect("idle second poll"),
        GithubDeliveryServiceOutcome::Idle
    );
    let claims = harness
        .repository
        .claim_calls
        .lock()
        .expect("claim calls lock");
    assert_eq!(claims.len(), 2);
    assert!(
        claims
            .iter()
            .all(|request| request.owner() == harness.worker_id)
    );
}

#[tokio::test]
async fn public_delivery_ignores_retained_private_credentials_and_fetches_anonymously() {
    for private_source_enabled in [false, true] {
        let harness = harness_with_source_policy(
            CredentialBehavior::Error(GithubDeliverySourceCredentialProviderError::Rejected),
            RenewalBehavior::Succeed,
            TerminalBehavior::Succeed,
            None,
            service_config(),
            ProviderRepositoryVisibility::Public,
            private_source_enabled,
            false,
        );

        let outcome = run_once(harness.service.clone(), CancellationToken::new())
            .await
            .expect("public delivery completion");
        assert!(matches!(
            outcome,
            GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
        ));
        if private_source_enabled {
            assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
            assert!(
                harness
                    .credentials
                    .observations
                    .lock()
                    .expect("credential observations lock")
                    .is_empty()
            );
        }
        assert_eq!(harness.objects.reads.load(Ordering::SeqCst), 1);
        assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
        assert!(!harness.source.credential_present.load(Ordering::SeqCst));
        assert!(!harness.source.credential_matched.load(Ordering::SeqCst));
        assert_eq!(harness.repository.transition_count(), 1);
    }
}

#[tokio::test]
async fn public_only_service_terminally_rejects_private_delivery_without_credential_authority() {
    let harness = harness_with_source_policy(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
        ProviderRepositoryVisibility::Private,
        false,
        false,
    );
    let debug = format!("{:?}", harness.service);
    assert!(debug.contains("source_policy: PublicOnly"));
    assert!(!debug.contains(TOKEN_MARKER));

    let outcome = run_once(harness.service, CancellationToken::new())
        .await
        .expect("unsupported private delivery is durably rejected");
    assert!(matches!(
        outcome,
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Rejected(_))
    ));
    assert_eq!(harness.objects.reads.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.repository.transition_count(), 1);
    let rejections = harness
        .repository
        .rejections
        .lock()
        .expect("rejections lock");
    assert_eq!(rejections.len(), 1);
    assert_eq!(
        rejections[0].failure_kind().as_str(),
        "github.repository_source.private_unsupported"
    );
}

#[tokio::test]
async fn public_only_service_rehydrates_private_identity_before_applying_source_policy() {
    let harness = harness_with_stored_visibility(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
        ProviderRepositoryVisibility::Private,
        ProviderRepositoryVisibility::Public,
        false,
        false,
    );

    let outcome = run_once(harness.service, CancellationToken::new())
        .await
        .expect("stored visibility mismatch is durably rejected");
    assert!(matches!(
        outcome,
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Rejected(_))
    ));
    assert_eq!(harness.objects.reads.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.repository.transition_count(), 1);
    let rejections = harness
        .repository
        .rejections
        .lock()
        .expect("rejections lock");
    assert_eq!(rejections.len(), 1);
    assert_eq!(
        rejections[0].failure_kind().as_str(),
        "github.raw_event.invalid_event"
    );
}

#[tokio::test]
async fn public_only_service_rejects_private_payload_before_anonymous_source() {
    let harness = harness_with_stored_visibility(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
        ProviderRepositoryVisibility::Public,
        ProviderRepositoryVisibility::Private,
        false,
        false,
    );

    let outcome = run_once(harness.service, CancellationToken::new())
        .await
        .expect("private payload mismatch is durably rejected");
    assert!(matches!(
        outcome,
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Rejected(_))
    ));
    assert_eq!(harness.objects.reads.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.repository.transition_count(), 1);
    let rejections = harness
        .repository
        .rejections
        .lock()
        .expect("rejections lock");
    assert_eq!(rejections.len(), 1);
    assert_eq!(
        rejections[0].failure_kind().as_str(),
        "github.raw_event.invalid_event"
    );
}

#[tokio::test]
async fn public_only_service_rejects_private_deletion_before_empty_completion() {
    let harness = harness_with_source_policy(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
        ProviderRepositoryVisibility::Private,
        false,
        true,
    );

    let outcome = run_once(harness.service, CancellationToken::new())
        .await
        .expect("unsupported private deletion is durably rejected");
    assert!(matches!(
        outcome,
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Rejected(_))
    ));
    assert_eq!(harness.objects.reads.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.repository.transition_count(), 1);
    assert!(
        harness
            .repository
            .completions
            .lock()
            .expect("completions lock")
            .is_empty()
    );
    let rejections = harness
        .repository
        .rejections
        .lock()
        .expect("rejections lock");
    assert_eq!(rejections.len(), 1);
    assert_eq!(
        rejections[0].failure_kind().as_str(),
        "github.repository_source.private_unsupported"
    );
}

#[tokio::test]
async fn public_only_private_rejection_preserves_terminal_fence_loss() {
    let harness = harness_with_source_policy(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::ClaimLost,
        None,
        service_config(),
        ProviderRepositoryVisibility::Private,
        false,
        false,
    );

    assert!(matches!(
        run_once(harness.service, CancellationToken::new()).await,
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness
            .repository
            .rejections
            .lock()
            .expect("rejections lock")
            .len(),
        1
    );
    assert!(
        harness
            .repository
            .completions
            .lock()
            .expect("completions lock")
            .is_empty()
    );
}

#[tokio::test]
async fn renewal_during_revision_fetch_discards_stale_source_and_reinvokes() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.repository.renewal_called.notified(),
    )
    .await
    .expect("claim renewal");
    harness.clock.set(AFTER_INITIAL_EXPIRY);
    gate.release.cancel();

    let outcome = task
        .await
        .expect("service task")
        .expect("renewed completion");
    assert!(matches!(
        outcome,
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let renewals = harness.repository.renewals.lock().expect("renewals lock");
    assert_eq!(renewals.len(), 1);
    assert_eq!(renewals[0].observed_at(), UnixMillis::new(RENEWED_NOW));
    assert_eq!(
        renewals[0].expires_at(),
        UnixMillis::new(RENEWED_NOW + CLAIM_MILLIS)
    );
    let renewed_claim = ProviderDeliveryClaimFence::from_durable_parts(
        renewals[0].claim().delivery_id(),
        renewals[0].claim().owner(),
        renewals[0].claim().fence() + 1,
    )
    .expect("renewed claim fence");
    drop(renewals);
    let completions = harness
        .repository
        .completions
        .lock()
        .expect("completions lock");
    assert_eq!(
        completions[0].completed_at(),
        UnixMillis::new(AFTER_INITIAL_EXPIRY)
    );
    assert_eq!(completions[0].claim(), renewed_claim);
    drop(completions);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 2);
    let observations = harness
        .credentials
        .observations
        .lock()
        .expect("credential observations lock");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].claim.fence(), 7);
    assert_eq!(observations[1].claim.fence(), 8);
}

#[tokio::test]
async fn renewal_during_revision_release_reuses_the_completed_source() {
    let harness = harness(
        CredentialBehavior::ReleaseDuringRenewalApply,
        RenewalBehavior::BlockCommittedThenSucceed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_downstream_result_ready(),
    )
    .await
    .expect("revision credential release started after source completion");
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_committed(),
    )
    .await
    .expect("renewal committed while exact release was pending");
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
    assert_eq!(harness.repository.transition_count(), 0);

    harness.renewal_apply_gate.release.cancel();
    assert!(matches!(
        task.await
            .expect("service task")
            .expect("successor-safe completion after exact release"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 1);
    let completions = harness
        .repository
        .completions
        .lock()
        .expect("completions lock");
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].claim().fence(), 8);
}

#[tokio::test]
async fn renewal_during_changed_files_release_reuses_the_completed_provider_result() {
    let (harness, processor, changed_files) = changed_files_renewal_harness(
        ProviderRepositoryVisibility::Private,
        CredentialBehavior::ReleaseChangedFilesDuringRenewalApply,
        None,
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_downstream_result_ready(),
    )
    .await
    .expect("changed-files credential release started after the provider result");
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(changed_files.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 2);
    assert_eq!(harness.repository.transition_count(), 0);

    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_committed(),
    )
    .await
    .expect("renewal committed while the changed-files release was pending");
    harness.renewal_apply_gate.release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("successor-safe completion after changed-files release"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    assert_eq!(processor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(changed_files.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 2);
    let credential_observations = harness
        .credentials
        .observations
        .lock()
        .expect("credential observations lock");
    assert_eq!(
        credential_observations
            .iter()
            .map(|observation| observation.action)
            .collect::<Vec<_>>(),
        [
            GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
            GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
        ]
    );
    drop(credential_observations);
    assert_single_skipped_completion(&harness, 8);
}

#[tokio::test]
async fn database_issued_initial_claim_time_preserves_the_requested_duration() {
    let harness = harness_with_visibility(
        CredentialBehavior::Exact,
        RenewalBehavior::DatabaseIssuedTimes,
        TerminalBehavior::Succeed,
        None,
        service_config(),
        ProviderRepositoryVisibility::Public,
    );

    assert!(matches!(
        run_once(harness.service.clone(), CancellationToken::new())
            .await
            .expect("database-issued claim is accepted"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let requests = harness
        .repository
        .claim_calls
        .lock()
        .expect("claim calls lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        harness
            .repository
            .claimed_at
            .lock()
            .expect("claimed-at lock")
            .expect("claim timestamp"),
        UnixMillis::new(requests[0].observed_at().get() - 5),
    );
}

#[tokio::test]
async fn database_issued_initial_claim_ahead_of_worker_clock_is_accepted() {
    let harness = harness_with_visibility(
        CredentialBehavior::Exact,
        RenewalBehavior::DatabaseIssuedFutureTimes,
        TerminalBehavior::Succeed,
        None,
        service_config(),
        ProviderRepositoryVisibility::Public,
    );

    assert!(matches!(
        run_once(harness.service.clone(), CancellationToken::new())
            .await
            .expect("database-issued future claim is accepted"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let requests = harness
        .repository
        .claim_calls
        .lock()
        .expect("claim calls lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        harness
            .repository
            .claimed_at
            .lock()
            .expect("claimed-at lock")
            .expect("claim timestamp"),
        UnixMillis::new(requests[0].observed_at().get() + 5),
    );
}

#[tokio::test]
async fn database_issued_renewal_time_preserves_duration_and_rotated_fence() {
    let (harness, processor) =
        snapshot_processor_harness(RenewalBehavior::DatabaseIssuedTimes, false);
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), processor.first_entered.notified())
        .await
        .expect("first workflow processor invocation");
    harness.clock.set(RENEWED_NOW);
    wait_for_renewal_count(&harness.repository, 1).await;
    processor.first_release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("database-issued renewal is accepted"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let snapshots = processor
        .snapshots
        .lock()
        .expect("snapshot observations lock");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].claimed_at(), UnixMillis::new(INITIAL_NOW - 5));
    assert_eq!(
        snapshots[1].claim().fence(),
        snapshots[0].claim().fence() + 1
    );
    assert_eq!(snapshots[1].renewed_at(), UnixMillis::new(RENEWED_NOW - 5));
    assert_eq!(
        snapshots[1].expires_at().get() - snapshots[1].renewed_at().get(),
        CLAIM_MILLIS,
    );
}

#[tokio::test]
async fn database_issued_renewal_ahead_of_worker_clock_is_accepted() {
    let (harness, processor) =
        snapshot_processor_harness(RenewalBehavior::DatabaseIssuedFutureTimes, false);
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), processor.first_entered.notified())
        .await
        .expect("first workflow processor invocation");
    harness.clock.set(RENEWED_NOW);
    wait_for_renewal_count(&harness.repository, 1).await;
    processor.first_release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("database-issued future renewal is accepted"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let snapshots = processor
        .snapshots
        .lock()
        .expect("snapshot observations lock");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].claimed_at(), UnixMillis::new(INITIAL_NOW + 5));
    assert_eq!(snapshots[1].renewed_at(), UnixMillis::new(RENEWED_NOW + 5));
    assert_eq!(
        snapshots[1].expires_at().get() - snapshots[1].renewed_at().get(),
        CLAIM_MILLIS,
    );
}

#[tokio::test]
async fn sequential_renewals_rotate_the_latest_terminal_fence() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;

    harness.clock.set(RENEWED_NOW);
    wait_for_renewal_count(&harness.repository, 1).await;
    harness.clock.set(RENEWED_NOW + 20);
    wait_for_renewal_count(&harness.repository, 2).await;
    gate.release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("twice-renewed completion"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let renewals = harness.repository.renewals.lock().expect("renewals lock");
    assert_eq!(renewals.len(), 2);
    assert_eq!(renewals[0].claim().fence(), 7);
    assert_eq!(renewals[1].claim().fence(), 8);
    assert_eq!(renewals[1].observed_at(), UnixMillis::new(RENEWED_NOW + 20));
    drop(renewals);
    let completions = harness
        .repository
        .completions
        .lock()
        .expect("completions lock");
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].claim().fence(), 9);
}

#[tokio::test]
async fn each_workflow_processor_invocation_observes_the_latest_rotated_snapshot() {
    let (harness, processor) = snapshot_refresh_harness();
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), processor.first_entered.notified())
        .await
        .expect("first workflow processor invocation");
    harness.clock.set(RENEWED_NOW);
    wait_for_renewal_count(&harness.repository, 1).await;
    processor.first_release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("multi-workflow completion"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let snapshots = processor
        .snapshots
        .lock()
        .expect("snapshot observations lock");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].claim().fence(), 7);
    assert_eq!(snapshots[1].claim().fence(), 8);
    assert_eq!(snapshots[0].attempt(), snapshots[1].attempt());
    assert_eq!(snapshots[0].claimed_at(), snapshots[1].claimed_at());
    assert!(snapshots[1].renewed_at() > snapshots[0].renewed_at());
}

#[tokio::test]
async fn stale_processor_failure_waits_for_renewal_and_is_reinvoked() {
    let (harness, processor) =
        snapshot_processor_harness(RenewalBehavior::BlockCommittedThenSucceed, true);
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), processor.first_entered.notified())
        .await
        .expect("first workflow processor invocation");
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_committed(),
    )
    .await
    .expect("renewal committed before its response was applied");
    tokio::task::yield_now().await;
    assert_eq!(harness.repository.transition_count(), 0);
    assert!(!task.is_finished());

    harness.renewal_apply_gate.release.cancel();
    assert!(matches!(
        task.await
            .expect("service task")
            .expect("successor snapshot processor replay completes"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let snapshots = processor
        .snapshots
        .lock()
        .expect("snapshot observations lock");
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].claim().fence(), 7);
    assert_eq!(snapshots[1].claim().fence(), 8);
    assert_eq!(harness.repository.transition_count(), 1);
    assert!(
        harness
            .repository
            .rejections
            .lock()
            .expect("rejections lock")
            .is_empty()
    );
}

#[tokio::test]
async fn renewal_during_credential_acquisition_reacquires_for_the_latest_horizon() {
    let harness = harness(
        CredentialBehavior::RenewDuringAcquire,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
    );
    let gate = harness
        .credentials
        .gate
        .as_ref()
        .expect("renew-during-acquire gate")
        .clone();
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .expect("first credential acquisition");
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.repository.renewal_called.notified(),
    )
    .await
    .expect("claim renewal during credential acquisition");
    gate.release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("reacquired completion"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let observations = harness
        .credentials
        .observations
        .lock()
        .expect("credential observations lock");
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].required_through,
        UnixMillis::new(INITIAL_NOW + CLAIM_MILLIS + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
    );
    assert_eq!(
        observations[1].required_through,
        UnixMillis::new(RENEWED_NOW + CLAIM_MILLIS + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
    );
    assert_eq!(observations[0].claim.fence(), 7);
    assert_eq!(observations[1].claim.fence(), 8);
    assert!(observations.iter().all(|observation| {
        observation.action == GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision
            && observation.attempt == 1
    }));
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.credentials.releases.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn authority_error_waits_for_committed_renewal_to_reach_the_live_snapshot() {
    let harness = harness(
        CredentialBehavior::RejectDuringRenewalApply,
        RenewalBehavior::BlockCommittedThenSucceed,
        TerminalBehavior::Succeed,
        None,
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), async {
        while harness.credentials.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("old-fence credential acquisition started");
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_committed(),
    )
    .await
    .expect("renewal committed before its response was applied");
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    assert_eq!(harness.repository.transition_count(), 0);

    harness.renewal_apply_gate.release.cancel();
    assert!(matches!(
        task.await
            .expect("service task")
            .expect("new-fence reacquisition completes"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let observations = harness
        .credentials
        .observations
        .lock()
        .expect("credential observations lock");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].claim.fence(), 7);
    assert_eq!(observations[1].claim.fence(), 8);
    assert_eq!(harness.repository.transition_count(), 1);
}

#[tokio::test]
async fn stale_changed_files_failures_wait_for_renewal_and_replay_on_the_successor() {
    for visibility in [
        ProviderRepositoryVisibility::Public,
        ProviderRepositoryVisibility::Private,
    ] {
        for first_error in [
            GithubPushChangedFilesError::InvalidEvidence,
            GithubPushChangedFilesError::Unavailable,
        ] {
            let (harness, processor, changed_files) = changed_files_renewal_harness(
                visibility,
                CredentialBehavior::Exact,
                Some(first_error),
            );
            let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
            tokio::time::timeout(Duration::from_secs(2), async {
                while changed_files.calls.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("fence-7 changed-files request");
            harness.clock.set(RENEWED_NOW);
            tokio::time::timeout(
                Duration::from_secs(2),
                harness.renewal_apply_gate.wait_committed(),
            )
            .await
            .expect("renewal committed before its response was applied");
            tokio::time::timeout(
                Duration::from_secs(2),
                harness.renewal_apply_gate.wait_downstream_result_ready(),
            )
            .await
            .expect("stale changed-files failure became ready");
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
            assert_eq!(harness.repository.transition_count(), 0);

            harness.renewal_apply_gate.release.cancel();
            assert!(matches!(
                task.await
                    .expect("service task")
                    .expect("successor changed-files replay completes"),
                GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
            ));
            assert_eq!(processor.calls.load(Ordering::SeqCst), 2);
            assert_eq!(changed_files.calls.load(Ordering::SeqCst), 2);
            let observations = changed_files
                .observations
                .lock()
                .expect("changed-files observations lock");
            assert_eq!(observations.len(), 2);
            assert_eq!(observations[0].claim.fence(), 7);
            assert_eq!(observations[1].claim.fence(), 8);
            assert!(observations.iter().all(|observation| {
                observation.private_authority
                    == (visibility == ProviderRepositoryVisibility::Private)
            }));
            drop(observations);
            assert_single_skipped_completion(&harness, 8);
        }
    }
}

#[tokio::test]
async fn stale_malformed_changed_files_credential_reacquires_on_the_successor() {
    let (harness, processor, changed_files) = changed_files_renewal_harness(
        ProviderRepositoryVisibility::Private,
        CredentialBehavior::WrongOwnerChangedFilesDuringRenewalApply,
        None,
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let observed_changed_files = harness
                .credentials
                .observations
                .lock()
                .expect("credential observations lock")
                .iter()
                .any(|observation| {
                    observation.action
                        == GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles
                });
            if observed_changed_files {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fence-7 changed-files credential request");
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_committed(),
    )
    .await
    .expect("renewal committed before its response was applied");
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_downstream_result_ready(),
    )
    .await
    .expect("stale malformed credential became ready");
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    assert_eq!(harness.repository.transition_count(), 0);

    harness.renewal_apply_gate.release.cancel();
    assert!(matches!(
        task.await
            .expect("service task")
            .expect("successor credential replay completes"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    assert_eq!(processor.calls.load(Ordering::SeqCst), 2);
    let credential_observations = harness
        .credentials
        .observations
        .lock()
        .expect("credential observations lock");
    assert_eq!(credential_observations.len(), 3);
    assert_eq!(
        credential_observations
            .iter()
            .map(|observation| (observation.action, observation.claim.fence()))
            .collect::<Vec<_>>(),
        [
            (
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
                7,
            ),
            (
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
                7,
            ),
            (
                GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
                8,
            ),
        ]
    );
    drop(credential_observations);
    let changed_files_observations = changed_files
        .observations
        .lock()
        .expect("changed-files observations lock");
    assert_eq!(changed_files_observations.len(), 1);
    assert_eq!(changed_files_observations[0].claim.fence(), 8);
    assert!(changed_files_observations[0].private_authority);
    drop(changed_files_observations);
    assert_single_skipped_completion(&harness, 8);
}

#[tokio::test(start_paused = true)]
async fn forward_wall_step_during_store_caps_successor_processing() {
    let source_gate = Arc::new(SourceGate::new());
    let claim_millis = 300;
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::BlockCommittedThenSucceed,
        TerminalBehavior::Succeed,
        Some(source_gate.clone()),
        GithubDeliveryServiceConfig::new(claim_millis, 5, 200).expect("service config"),
    );
    let mut task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    source_gate.wait_until_entered().await;
    harness.clock.set(INITIAL_NOW + 200);
    tokio::time::advance(Duration::from_millis(200)).await;
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.renewal_apply_gate.wait_committed(),
    )
    .await
    .expect("renewal committed before its response was applied");
    let request = harness.repository.renewals.lock().expect("renewals lock")[0];
    let successor_extension = request
        .expires_at()
        .get()
        .checked_sub(request.predecessor_expires_at().get())
        .and_then(|extension| u64::try_from(extension).ok())
        .expect("positive successor extension");
    let uncapped_successor_deadline = request
        .deadline()
        .checked_add(Duration::from_millis(successor_extension))
        .expect("uncapped successor deadline");

    harness.clock.set(INITIAL_NOW + claim_millis - 1);
    harness.renewal_apply_gate.release.cancel();
    tokio::task::yield_now().await;
    let predecessor_deadline_margin = request
        .deadline()
        .checked_add(Duration::from_millis(10))
        .expect("predecessor deadline margin");
    assert!(
        tokio::time::timeout_at(predecessor_deadline_margin, &mut task)
            .await
            .is_err(),
        "the accepted fence-8 response must outlive the immutable fence-7 deadline"
    );
    let proof_deadline = uncapped_successor_deadline
        .checked_sub(Duration::from_millis(20))
        .expect("proof deadline");
    let outcome = tokio::time::timeout_at(proof_deadline, &mut task)
        .await
        .expect("paired response cap stops work before the uncapped successor")
        .expect("service task");
    assert!(matches!(
        outcome,
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert_eq!(
        harness
            .renewal_apply_gate
            .durable_fence
            .load(Ordering::SeqCst),
        8
    );
    assert_eq!(
        harness
            .repository
            .renewals
            .lock()
            .expect("renewals lock")
            .len(),
        1,
        "a response-capped successor without retry margin must not renew again"
    );
    assert!(source_gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn never_returning_renewal_is_cancelled_at_the_predecessor_deadline() {
    let source_gate = Arc::new(SourceGate::new());
    let claim_millis = 1_000;
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::NeverReturns,
        TerminalBehavior::Succeed,
        Some(source_gate.clone()),
        GithubDeliveryServiceConfig::new(claim_millis, 100, 500).expect("service config"),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    source_gate.wait_until_entered().await;
    harness.clock.set(INITIAL_NOW + claim_millis - 1);
    wait_for_renewal_count(&harness.repository, 1).await;

    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(50), task)
            .await
            .expect("predecessor deadline cancels the Store future")
            .expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(source_gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn delayed_renewal_is_cancelled_before_reclaim_can_overlap_provider_work() {
    let source_gate = Arc::new(SourceGate::new());
    let claim_millis = 80;
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::BlockBeforeCommitThenSucceed,
        TerminalBehavior::Succeed,
        Some(source_gate.clone()),
        GithubDeliveryServiceConfig::new(claim_millis, 5, 20).expect("service config"),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    source_gate.wait_until_entered().await;
    harness.clock.set(INITIAL_NOW + 20);
    tokio::time::advance(Duration::from_millis(20)).await;
    harness.renewal_apply_gate.wait_entered().await;
    let request = harness.repository.renewals.lock().expect("renewals lock")[0];
    assert!(request.deadline() > tokio::time::Instant::now());
    harness
        .repository
        .reclaim_enabled
        .store(true, Ordering::SeqCst);
    let reclaim_owner =
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(0x44)).expect("reclaim owner");
    let observed_at = UnixMillis::new(INITIAL_NOW + claim_millis);
    let expires_at = UnixMillis::new(INITIAL_NOW + claim_millis * 2);
    let repository = harness.repository.clone();
    let predecessor_deadline = request.deadline();
    let reclaim = tokio::spawn(async move {
        tokio::time::sleep_until(predecessor_deadline).await;
        repository
            .claim_provider_delivery(
                ClaimProviderDelivery::new(reclaim_owner, observed_at, expires_at)
                    .expect("valid reclaim request"),
            )
            .await
    });
    harness.clock.set(request.predecessor_expires_at().get());
    tokio::time::advance(
        predecessor_deadline.saturating_duration_since(tokio::time::Instant::now()),
    )
    .await;
    let (service_result, reclaim_result) = tokio::join!(task, reclaim);
    assert!(matches!(
        service_result.expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(
        harness
            .renewal_apply_gate
            .future_dropped
            .load(Ordering::SeqCst),
        "the uncommitted renewal future must be cancelled at predecessor expiry"
    );
    let reclaimed = reclaim_result
        .expect("reclaim task")
        .expect("reclaim repository")
        .expect("expired predecessor is reclaimable");
    assert_eq!(reclaimed.claim().owner(), reclaim_owner);
    assert_eq!(reclaimed.claim().fence(), 8);
    assert_eq!(reclaimed.attempt(), 1);
    assert_eq!(
        harness
            .renewal_apply_gate
            .durable_fence
            .load(Ordering::SeqCst),
        8,
        "the cancelled renewal must not commit before the one exact reclaim"
    );
    assert!(source_gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn one_hour_claim_cap_expires_exactly_before_reclaim_and_without_extra_work() {
    let claim_millis = MAX_PROVIDER_DELIVERY_CLAIM_MILLIS;
    let renew_after_millis = 10 * 60 * 1_000;
    let (harness, processor) = snapshot_processor_harness_with_config(
        RenewalBehavior::Succeed,
        false,
        GithubDeliveryServiceConfig::new(claim_millis, 1_000, renew_after_millis)
            .expect("service config"),
    );
    let claim_started_at = tokio::time::Instant::now();
    let service = harness.service.clone();
    let task = tokio::spawn(async move { service.run_once(CancellationToken::new()).await });
    processor.first_entered.notified().await;

    advance_successful_renewals(&harness, claim_started_at, renew_after_millis, 5).await;

    let hard_expires_at = UnixMillis::new(INITIAL_NOW + MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS);
    {
        let renewals = harness.repository.renewals.lock().expect("renewals lock");
        assert!(renewals.iter().all(|request| {
            request.attempt() == 1
                && request.claimed_at() == UnixMillis::new(INITIAL_NOW)
                && request.expires_at() <= hard_expires_at
        }));
        assert_eq!(
            renewals.last().expect("final capped renewal").expires_at(),
            hard_expires_at
        );
    }
    assert!(!task.is_finished());

    let last_fence = u64::try_from(
        harness
            .renewal_apply_gate
            .durable_fence
            .load(Ordering::SeqCst),
    )
    .expect("positive durable fence");
    harness
        .repository
        .reclaim_enabled
        .store(true, Ordering::SeqCst);
    let reclaim_owner =
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(0x45)).expect("reclaim owner");
    let hard_deadline = claim_started_at
        .checked_add(Duration::from_millis(
            u64::try_from(MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS)
                .expect("positive total claim cap"),
        ))
        .expect("hard deadline");
    let repository = harness.repository.clone();
    let reclaim = tokio::spawn(async move {
        tokio::time::sleep_until(hard_deadline).await;
        repository
            .claim_provider_delivery(
                ClaimProviderDelivery::new(
                    reclaim_owner,
                    hard_expires_at,
                    UnixMillis::new(hard_expires_at.get() + claim_millis),
                )
                .expect("valid reclaim request"),
            )
            .await
    });
    harness.clock.set(hard_expires_at.get());
    tokio::time::advance(hard_deadline.saturating_duration_since(tokio::time::Instant::now()))
        .await;
    let (service_result, reclaim_result) = tokio::join!(task, reclaim);
    assert!(matches!(
        service_result.expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(processor.first_future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
    assert_eq!(
        harness
            .repository
            .renewals
            .lock()
            .expect("renewals lock")
            .len(),
        5,
        "hard expiry must not start a sixth renewal"
    );
    let reclaimed = reclaim_result
        .expect("reclaim task")
        .expect("reclaim repository")
        .expect("hard-capped predecessor is reclaimable");
    assert_eq!(reclaimed.claim().owner(), reclaim_owner);
    assert_eq!(reclaimed.claim().fence(), last_fence + 1);
    assert_eq!(reclaimed.attempt(), 1);
    assert_eq!(harness.source.calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewal_wall_sample_pause_past_the_confirmed_deadline_is_claim_loss() {
    let claim_millis = 80;
    let clock = Arc::new(BlockingClock::new(INITIAL_NOW, 3));
    let harness = blocking_clock_harness(
        clock.clone(),
        GithubDeliveryServiceConfig::new(claim_millis, 5, 20).expect("service config"),
    );
    let task = tokio::spawn(run_once(harness.service, CancellationToken::new()));
    harness.source_gate.wait_until_entered().await;
    clock.wait_until_blocked().await;

    let confirmed_deadline_upper = clock
        .observation(0)
        .checked_add(Duration::from_millis(
            u64::try_from(claim_millis).expect("claim duration"),
        ))
        .expect("confirmed deadline upper bound");
    std::thread::sleep(
        confirmed_deadline_upper.saturating_duration_since(tokio::time::Instant::now()),
    );
    clock.release();

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("expired wall sample stops supervision")
            .expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(
        harness
            .repository
            .renewals
            .lock()
            .expect("renewals lock")
            .is_empty()
    );
    assert!(harness.source_gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_wall_sample_cannot_widen_the_confirmed_predecessor_deadline() {
    let claim_millis = 160;
    let clock = Arc::new(BlockingClock::new(INITIAL_NOW, 3));
    let harness = blocking_clock_harness(
        clock.clone(),
        GithubDeliveryServiceConfig::new(claim_millis, 5, 20).expect("service config"),
    );
    let task = tokio::spawn(run_once(harness.service, CancellationToken::new()));
    harness.source_gate.wait_until_entered().await;
    clock.set(INITIAL_NOW + 1);
    clock.wait_until_blocked().await;
    let initial_observation = clock.observation(0);
    let renewal_observation = clock.observation(3);
    clock.release();
    wait_for_renewal_count(&harness.repository, 1).await;

    let request = {
        let renewals = harness.repository.renewals.lock().expect("renewals lock");
        renewals[0]
    };
    let confirmed_deadline_upper = initial_observation
        .checked_add(Duration::from_millis(
            u64::try_from(claim_millis).expect("claim duration"),
        ))
        .expect("confirmed deadline upper bound");
    let slow_wall_remaining = request
        .predecessor_expires_at()
        .get()
        .checked_sub(request.observed_at().get())
        .and_then(|remaining| u64::try_from(remaining).ok())
        .expect("positive slow-wall remainder");
    let widened_deadline = renewal_observation
        .checked_add(Duration::from_millis(slow_wall_remaining))
        .expect("uncapped slow-wall deadline");
    assert!(widened_deadline > confirmed_deadline_upper);
    assert!(request.deadline() <= confirmed_deadline_upper);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("confirmed predecessor deadline stops Store and processing")
            .expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(harness.source_gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forward_wall_sample_can_shrink_the_predecessor_deadline() {
    let claim_millis = 160;
    let clock = Arc::new(BlockingClock::new(INITIAL_NOW, 3));
    let harness = blocking_clock_harness(
        clock.clone(),
        GithubDeliveryServiceConfig::new(claim_millis, 5, 20).expect("service config"),
    );
    let task = tokio::spawn(run_once(harness.service, CancellationToken::new()));
    harness.source_gate.wait_until_entered().await;
    clock.set(INITIAL_NOW + claim_millis - 20);
    clock.wait_until_blocked().await;
    let initial_observation = clock.observation(0);
    clock.release();
    wait_for_renewal_count(&harness.repository, 1).await;

    let request = harness.repository.renewals.lock().expect("renewals lock")[0];
    let confirmed_deadline_upper = initial_observation
        .checked_add(Duration::from_millis(
            u64::try_from(claim_millis).expect("claim duration"),
        ))
        .expect("confirmed deadline upper bound");
    assert!(request.deadline() < confirmed_deadline_upper);

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("shrunk predecessor deadline stops Store and processing")
            .expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(harness.source_gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn ambiguous_renewal_retries_the_exact_request_before_terminal_work() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::AmbiguousOnce,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;
    harness.clock.set(RENEWED_NOW);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if harness
                .repository
                .renewals
                .lock()
                .expect("renewals lock")
                .len()
                >= 2
            {
                break;
            }
            harness.repository.renewal_called.notified().await;
        }
    })
    .await
    .expect("ambiguous renewal exact retry");
    gate.release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("renewed completion"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    let renewals = harness.repository.renewals.lock().expect("renewals lock");
    assert_eq!(renewals.len(), 2);
    assert_eq!(renewals[0], renewals[1]);
}

#[tokio::test(start_paused = true)]
async fn ambiguous_renewal_never_outlives_the_confirmed_predecessor() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::Unavailable,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        GithubDeliveryServiceConfig::new(CLAIM_MILLIS, 5, 10).expect("service config"),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;
    harness.clock.set(RENEWED_NOW);
    tokio::time::advance(Duration::from_millis(10)).await;
    wait_for_renewal_count(&harness.repository, 1).await;
    harness.clock.set(INITIAL_NOW + CLAIM_MILLIS);
    tokio::time::advance(Duration::from_millis(5)).await;
    for _ in 0..32 {
        if task.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(matches!(
        task.await.expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert_eq!(
        harness
            .repository
            .renewals
            .lock()
            .expect("renewals lock")
            .len(),
        1,
        "wall expiry during backoff must prevent a second Store call"
    );
    assert!(gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn non_successor_renewal_is_rejected_before_terminal_work() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::SameFence,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;
    harness.clock.set(RENEWED_NOW);

    assert!(matches!(
        task.await.expect("service task"),
        Err(GithubDeliveryServiceError::InvalidRenewal)
    ));
    assert!(gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn renewal_that_changes_the_delivery_attempt_is_rejected() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::WrongAttempt,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;
    harness.clock.set(RENEWED_NOW);

    assert!(matches!(
        task.await.expect("service task"),
        Err(GithubDeliveryServiceError::InvalidRenewal)
    ));
    assert!(gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn lost_renewal_cancels_in_flight_source_work() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::ClaimLost,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    gate.wait_until_entered().await;
    harness.clock.set(RENEWED_NOW);
    assert!(matches!(
        task.await.expect("service task"),
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert!(gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn shutdown_cancels_in_flight_source_work() {
    let gate = Arc::new(SourceGate::new());
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::Succeed,
        Some(gate.clone()),
        GithubDeliveryServiceConfig::new(1_000, 100, 500).expect("service config"),
    );
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_once(harness.service.clone(), shutdown.clone()));
    gate.wait_until_entered().await;
    shutdown.cancel();
    assert!(matches!(
        task.await.expect("service task"),
        Err(GithubDeliveryServiceError::Shutdown)
    ));
    assert!(gate.future_dropped.load(Ordering::SeqCst));
    assert_eq!(harness.repository.transition_count(), 0);
}

#[tokio::test]
async fn credential_authority_failures_have_closed_retry_or_terminal_outcomes() {
    for (error, expected_state, expected_kind) in [
        (
            GithubDeliverySourceCredentialProviderError::Unavailable,
            ProviderDeliveryState::RetryPending,
            "github.repository_source.credential_unavailable",
        ),
        (
            GithubDeliverySourceCredentialProviderError::Rejected,
            ProviderDeliveryState::Rejected,
            "github.repository_source.credential_rejected",
        ),
        (
            GithubDeliverySourceCredentialProviderError::InvariantViolation,
            ProviderDeliveryState::Rejected,
            "github.repository_source.credential_invalid",
        ),
    ] {
        let harness = harness(
            CredentialBehavior::Error(error),
            RenewalBehavior::Succeed,
            TerminalBehavior::Succeed,
            None,
            service_config(),
        );
        let outcome = run_once(harness.service, CancellationToken::new())
            .await
            .expect("durable credential classification");
        let GithubDeliveryServiceOutcome::Processed(outcome) = outcome else {
            panic!("credential failure must produce a durable worker outcome")
        };
        assert_eq!(outcome.receipt().state(), expected_state);
        assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
        if expected_state == ProviderDeliveryState::RetryPending {
            let retries = harness.repository.retries.lock().expect("retries lock");
            assert_eq!(retries[0].failure_kind().as_str(), expected_kind);
        } else {
            let rejections = harness
                .repository
                .rejections
                .lock()
                .expect("rejections lock");
            assert_eq!(rejections[0].failure_kind().as_str(), expected_kind);
        }
    }
}

#[tokio::test]
async fn credential_identity_and_expiry_mismatch_reject_before_source_io() {
    for behavior in [
        CredentialBehavior::WrongTenant,
        CredentialBehavior::WrongConnection,
        CredentialBehavior::WrongInstallation,
        CredentialBehavior::WrongRepository,
        CredentialBehavior::WrongOwner,
        CredentialBehavior::WrongRoute,
        CredentialBehavior::WrongFence,
        CredentialBehavior::WrongAttempt,
        CredentialBehavior::WrongAction,
        CredentialBehavior::WrongSelector,
        CredentialBehavior::WrongHorizon,
        CredentialBehavior::Expired,
    ] {
        let harness = harness(
            behavior,
            RenewalBehavior::Succeed,
            TerminalBehavior::Succeed,
            None,
            service_config(),
        );
        let outcome = run_once(harness.service, CancellationToken::new())
            .await
            .expect("credential mismatch rejection");
        assert_eq!(
            outcome,
            GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Rejected(
                harness.repository.receipt(ProviderDeliveryState::Rejected)
            ))
        );
        assert_eq!(harness.source.calls.load(Ordering::SeqCst), 0);
        let rejections = harness
            .repository
            .rejections
            .lock()
            .expect("rejections lock");
        assert_eq!(
            rejections[0].failure_kind().as_str(),
            "github.repository_source.credential_invalid"
        );
    }
}

#[tokio::test]
async fn terminal_fence_loss_is_reported_as_nonfatal_claim_loss() {
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::Succeed,
        TerminalBehavior::ClaimLost,
        None,
        service_config(),
    );
    assert!(matches!(
        run_once(harness.service, CancellationToken::new()).await,
        Err(GithubDeliveryServiceError::ClaimLost)
    ));
    assert_eq!(
        harness
            .repository
            .completions
            .lock()
            .expect("completions lock")
            .len(),
        1
    );
}

#[tokio::test]
async fn terminal_completion_stops_a_waiting_lost_renewal() {
    let harness = harness(
        CredentialBehavior::Exact,
        RenewalBehavior::ClaimLost,
        TerminalBehavior::BlockThenSucceed,
        None,
        service_config(),
    );
    let task = tokio::spawn(run_once(harness.service.clone(), CancellationToken::new()));
    tokio::time::timeout(
        Duration::from_secs(2),
        harness.repository.terminal_entered.notified(),
    )
    .await
    .expect("terminal transition entered");
    harness.clock.set(RENEWED_NOW);
    tokio::time::sleep(Duration::from_millis(25)).await;
    harness.repository.terminal_release.cancel();

    assert!(matches!(
        task.await
            .expect("service task")
            .expect("terminal completion"),
        GithubDeliveryServiceOutcome::Processed(GithubDeliveryWorkerOutcome::Completed(_))
    ));
    assert!(
        harness
            .repository
            .renewals
            .lock()
            .expect("renewals lock")
            .is_empty(),
        "a renewal waiting behind an owned terminal transition must stop"
    );
}

#[test]
fn timing_configuration_is_bounded_and_coherent() {
    assert_eq!(
        GithubDeliveryServiceConfig::new(MAX_PROVIDER_DELIVERY_CLAIM_MILLIS + 1, 1, 2),
        Err(GithubDeliveryServiceConfigurationError::InvalidClaimDuration)
    );
    assert_eq!(
        GithubDeliveryServiceConfig::new(10, 0, 2),
        Err(GithubDeliveryServiceConfigurationError::InvalidPollDuration)
    );
    assert_eq!(
        GithubDeliveryServiceConfig::new(10, 2, 10),
        Err(GithubDeliveryServiceConfigurationError::InvalidRenewalDuration)
    );
    assert_eq!(
        GithubDeliveryServiceConfig::new(10, 4, 6),
        Err(GithubDeliveryServiceConfigurationError::InvalidRenewalDuration)
    );
}
