use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_auth::secret::SecretString;
use automata_ci_blob::{BlobDescriptor, BlobKey, BlobStoreErrorKind, MediaType};
use automata_ci_core::GitObjectId;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github::{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX, GithubPushRefKind};
use automata_ci_github_delivery::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubDeliveryClock, GithubDeliverySourceAuthority,
    GithubDeliveryWorker, GithubDeliveryWorkerConfig, GithubDeliveryWorkerConfigurationError,
    GithubDeliveryWorkerError, GithubDeliveryWorkerOutcome, GithubDeliveryWorkerPrerequisite,
    GithubDeliveryWorkflowProcessor, GithubDeliveryWorkflowProcessorCompletion,
    GithubDeliveryWorkflowProcessorError, GithubDeliveryWorkflowRequest,
};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_scm::{
    ArchiveFormat, RepositoryId as ScmRepositoryId, RepositorySnapshot, RepositorySource,
    RepositorySourcePort, RepositorySourceRequest, ScmError, ScmProvider, ScmProviderId,
    SnapshotRequest,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubRepositoryDispatch, AcceptProviderDelivery, AdmissionObject,
    ClaimProviderDelivery, ClaimedProviderDelivery, CompleteProviderDelivery,
    GithubAuthenticatedEvent, GithubAuthenticatedEventKind, GithubCheckName, GithubCheckSubjectId,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryDispatchEvidenceRepository,
    GithubRepositoryDispatchResolution, GithubRepositoryDispatchResolutionAuthority,
    GithubRepositoryName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubSubjectEvidenceRepository,
    GithubSubjectEvidenceStoreError, GithubWorkflowRunSubjectEvidence,
    ManifestPinnedGithubDeliveryEvidence, ManifestPinnedGithubDeliveryReceipt, ObjectKey,
    PendingGithubRepositoryDispatchEvidence, PendingGithubRepositoryDispatchReceipt,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryEventEnvelope,
    ProviderDeliveryFailureKind, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderDeliveryReceipt, ProviderDeliveryRepository, ProviderDeliveryState,
    ProviderDeliveryStoreError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowInventoryReceipt, ProviderDeliveryWorkflowOutcome,
    ProviderInstallationId, ProviderRepositoryCoordinates, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    RecordProviderDeliveryWorkflowProgress, RegisterProviderDeliveryWorkflowInventory,
    RejectProviderDelivery, RepositoryId as StoreRepositoryId, ResolveGithubRepositoryDispatch,
    RetryProviderDelivery, TenantScope,
};
use automata_ci_workflow_actions::RepositoryWorkflowDiscoveryLimits;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::subject_evidence::{
    fixture_all_direct_subject_evidence, fixture_check_head_sha, fixture_github_runtime_policy,
    fixture_subject_evidence, fixture_subject_evidence_with_head,
};
use super::support::{
    AFTER, BEFORE, INSTALLATION_ID, OWNER, ProviderDeliveryLedger, REPOSITORY, REPOSITORY_ID,
    REPOSITORY_OWNER_ID, VerifiedBlobStore, ZERO, archive, provider_event_envelope, push_body,
};

const STALE_MERGE: &str = "89abcdef0123456789abcdef0123456789abcdef";
const DELIVERY: &str = "delivery-worker-1";
const CREDENTIAL_MARKER: &str = "installation-token-private-marker";

#[derive(Debug)]
struct FixedClock(UnixMillis);

impl GithubDeliveryClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceObservation {
    repository: String,
    revision: String,
    credential_present: bool,
    credential_matches: bool,
    maximum_bytes: u64,
    debug: String,
}

#[derive(Debug)]
struct RecordingSourcePort {
    provider: ScmProviderId,
    result: Mutex<Result<RepositorySource, ScmError>>,
    observations: Mutex<Vec<SourceObservation>>,
}

impl RecordingSourcePort {
    fn returning(source: RepositorySource) -> Self {
        Self {
            provider: ScmProviderId::new("github").expect("provider"),
            result: Mutex::new(Ok(source)),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn failing(error: ScmError) -> Self {
        Self {
            provider: ScmProviderId::new("github").expect("provider"),
            result: Mutex::new(Err(error)),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn with_provider(provider: &str, source: RepositorySource) -> Self {
        Self {
            provider: ScmProviderId::new(provider).expect("provider"),
            result: Mutex::new(Ok(source)),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<SourceObservation> {
        self.observations
            .lock()
            .expect("source observations lock")
            .clone()
    }
}

#[async_trait]
impl RepositorySourcePort for RecordingSourcePort {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_repository_source(
        &self,
        request: RepositorySourceRequest<'_>,
    ) -> Result<RepositorySource, ScmError> {
        self.observations
            .lock()
            .expect("source observations lock")
            .push(SourceObservation {
                repository: request.repository().as_str().to_owned(),
                revision: request.revision().to_string(),
                credential_present: request.credential().is_some(),
                credential_matches: request
                    .credential()
                    .is_some_and(|credential| credential.expose_secret() == CREDENTIAL_MARKER),
                maximum_bytes: request.limits().maximum_bytes(),
                debug: format!("{request:?}"),
            });
        self.result.lock().expect("source result lock").clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolverObservation {
    repository: String,
    revision: String,
    credential_present: bool,
    credential_matches: bool,
    debug: String,
}

#[derive(Debug)]
struct RecordingResolver {
    provider: ScmProviderId,
    results: Mutex<Vec<Result<RepositorySnapshot, ScmError>>>,
    observations: Mutex<Vec<ResolverObservation>>,
}

impl RecordingResolver {
    fn returning(results: Vec<RepositorySnapshot>) -> Self {
        assert!(!results.is_empty(), "resolver fixture needs one response");
        Self {
            provider: ScmProviderId::new("github").expect("provider"),
            results: Mutex::new(results.into_iter().map(Ok).collect()),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn failing(error: ScmError) -> Self {
        Self {
            provider: ScmProviderId::new("github").expect("provider"),
            results: Mutex::new(vec![Err(error)]),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<ResolverObservation> {
        self.observations
            .lock()
            .expect("resolver observations lock")
            .clone()
    }
}

#[async_trait]
impl ScmProvider for RecordingResolver {
    fn provider_id(&self) -> &ScmProviderId {
        &self.provider
    }

    async fn fetch_snapshot(
        &self,
        request: SnapshotRequest<'_>,
    ) -> Result<RepositorySnapshot, ScmError> {
        self.observations
            .lock()
            .expect("resolver observations lock")
            .push(ResolverObservation {
                repository: request.repository().as_str().to_owned(),
                revision: request.revision().as_str().to_owned(),
                credential_present: request.credential().is_some(),
                credential_matches: request
                    .credential()
                    .is_some_and(|credential| credential.expose_secret() == CREDENTIAL_MARKER),
                debug: format!("{request:?}"),
            });
        let mut results = self.results.lock().expect("resolver results lock");
        if results.len() > 1 {
            results.remove(0)
        } else {
            results[0].clone()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkflowObservation {
    path: String,
    ref_kind: GithubPushRefKind,
    revision: String,
    source_bytes: usize,
    manifest_revision: u64,
    private_source_authority_present: bool,
    debug: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventWorkflowObservation {
    event_name: String,
    event_envelope_digest: Sha256Digest,
    git_ref: String,
    revision: String,
    raw_media_type: String,
    raw_body: Bytes,
    debug: String,
}

#[derive(Clone, Debug)]
enum ProcessorBehavior {
    Conclusion(ProviderDeliveryWorkflowConclusion),
    Error(GithubDeliveryWorkflowProcessorError),
}

#[derive(Debug)]
struct RecordingProcessor {
    behaviors: Mutex<Vec<ProcessorBehavior>>,
    observations: Mutex<Vec<WorkflowObservation>>,
    event_observations: Mutex<Vec<EventWorkflowObservation>>,
}

impl RecordingProcessor {
    fn returning(conclusion: ProviderDeliveryWorkflowConclusion) -> Self {
        Self {
            behaviors: Mutex::new(vec![ProcessorBehavior::Conclusion(conclusion)]),
            observations: Mutex::new(Vec::new()),
            event_observations: Mutex::new(Vec::new()),
        }
    }

    fn failing(error: GithubDeliveryWorkflowProcessorError) -> Self {
        Self {
            behaviors: Mutex::new(vec![ProcessorBehavior::Error(error)]),
            observations: Mutex::new(Vec::new()),
            event_observations: Mutex::new(Vec::new()),
        }
    }

    fn returning_sequence(behaviors: Vec<ProcessorBehavior>) -> Self {
        assert!(!behaviors.is_empty(), "processor sequence is nonempty");
        Self {
            behaviors: Mutex::new(behaviors),
            observations: Mutex::new(Vec::new()),
            event_observations: Mutex::new(Vec::new()),
        }
    }

    fn next_behavior(&self) -> ProcessorBehavior {
        let mut behaviors = self.behaviors.lock().expect("processor behaviors lock");
        if behaviors.len() > 1 {
            behaviors.remove(0)
        } else {
            behaviors[0].clone()
        }
    }

    fn observations(&self) -> Vec<WorkflowObservation> {
        self.observations
            .lock()
            .expect("processor observations lock")
            .clone()
    }

    fn event_observations(&self) -> Vec<EventWorkflowObservation> {
        self.event_observations
            .lock()
            .expect("event processor observations lock")
            .clone()
    }
}

#[async_trait]
impl GithubDeliveryWorkflowProcessor for RecordingProcessor {
    async fn process_workflow(
        &self,
        request: GithubDeliveryWorkflowRequest<'_>,
    ) -> GithubDeliveryWorkflowProcessorCompletion {
        if let automata_ci_github::VerifiedGithubWebhook::Push(push) = request.event() {
            self.observations
                .lock()
                .expect("processor observations lock")
                .push(WorkflowObservation {
                    path: request.workflow_path().to_owned(),
                    ref_kind: push.git_ref().kind(),
                    revision: request.repository_source().revision().to_string(),
                    source_bytes: request.workflow_source().len(),
                    manifest_revision: request.manifest_pinned_evidence().manifest_revision().get(),
                    private_source_authority_present: request
                        .manifest_pinned_evidence()
                        .private_source_authority()
                        .is_some(),
                    debug: format!("{request:?}"),
                });
        }
        let event = request.manifest_pinned_evidence().authenticated_event();
        self.event_observations
            .lock()
            .expect("event processor observations lock")
            .push(EventWorkflowObservation {
                event_name: request.event().event_name().to_owned(),
                event_envelope_digest: request.event_envelope().digest(),
                git_ref: event.git_ref().to_owned(),
                revision: request.repository_source().revision().to_string(),
                raw_media_type: request.raw_event().media_type().to_owned(),
                raw_body: request.event().raw_body().clone(),
                debug: format!("{request:?}"),
            });
        let result = match self.next_behavior() {
            ProcessorBehavior::Conclusion(conclusion) => Ok(conclusion),
            ProcessorBehavior::Error(error) => Err(error),
        };
        request.finish(result).await
    }
}

#[derive(Debug)]
struct RecordingDeliveries {
    claimed_delivery_id: ProviderDeliveryId,
    ledger: ProviderDeliveryLedger,
    reject_completion_outcome_run: bool,
}

impl RecordingDeliveries {
    fn new(claimed_receipt: ProviderDeliveryReceipt) -> Self {
        Self {
            claimed_delivery_id: claimed_receipt.id(),
            ledger: ProviderDeliveryLedger::new(
                claimed_receipt.attempts(),
                claimed_receipt.accepted_at(),
            ),
            reject_completion_outcome_run: false,
        }
    }

    fn rejecting_completion_outcome_run(claimed_receipt: ProviderDeliveryReceipt) -> Self {
        Self {
            claimed_delivery_id: claimed_receipt.id(),
            ledger: ProviderDeliveryLedger::new(
                claimed_receipt.attempts(),
                claimed_receipt.accepted_at(),
            ),
            reject_completion_outcome_run: true,
        }
    }

    fn receipt(&self, state: ProviderDeliveryState) -> ProviderDeliveryReceipt {
        self.ledger.receipt(self.claimed_delivery_id, state)
    }

    fn transition_count(&self) -> usize {
        self.ledger.transition_count()
    }
}

#[async_trait]
impl ProviderDeliveryRepository for RecordingDeliveries {
    async fn accept_provider_delivery(
        &self,
        _request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        panic!("acceptance is outside the worker")
    }

    async fn claim_provider_delivery(
        &self,
        _request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError> {
        panic!("claiming is outside this already-claimed worker boundary")
    }

    async fn complete_provider_delivery(
        &self,
        request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        self.ledger.record_completion(request);
        if self.reject_completion_outcome_run {
            return Err(ProviderDeliveryStoreError::OutcomeRunRejected);
        }
        Ok(self.receipt(ProviderDeliveryState::Completed))
    }

    async fn register_provider_delivery_workflow_inventory(
        &self,
        request: RegisterProviderDeliveryWorkflowInventory,
    ) -> Result<ProviderDeliveryWorkflowInventoryReceipt, ProviderDeliveryStoreError> {
        if request.claim().delivery_id() != self.claimed_delivery_id {
            return Err(ProviderDeliveryStoreError::ClaimRejected);
        }
        self.ledger.register_workflow_inventory(&request)
    }

    async fn record_provider_delivery_workflow_progress(
        &self,
        request: RecordProviderDeliveryWorkflowProgress,
    ) -> Result<ProviderDeliveryWorkflowOutcome, ProviderDeliveryStoreError> {
        if request.claim().delivery_id() != self.claimed_delivery_id {
            return Err(ProviderDeliveryStoreError::ClaimRejected);
        }
        self.ledger.record_workflow_progress(&request)
    }

    async fn retry_provider_delivery(
        &self,
        request: RetryProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        self.ledger.record_retry(request);
        Ok(self.receipt(ProviderDeliveryState::RetryPending))
    }

    async fn reject_provider_delivery(
        &self,
        request: RejectProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        self.ledger.record_rejection(request);
        Ok(self.receipt(ProviderDeliveryState::Rejected))
    }
}

#[derive(Clone)]
struct FixtureSubjectEvidence(ManifestPinnedGithubDeliveryEvidence);

impl FixtureSubjectEvidence {
    fn from_claimed(claimed: &ClaimedProviderDelivery, check_head_sha: GitObjectId) -> Self {
        let identity = claimed.identity();
        let repository_owner_id =
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID");
        let evidence = if check_head_sha == fixture_check_head_sha(AFTER) {
            fixture_subject_evidence(
                claimed.receipt().id(),
                identity,
                repository_owner_id,
                claimed.receipt().accepted_at(),
                0x7100,
            )
        } else {
            fixture_subject_evidence_with_head(
                claimed.receipt().id(),
                identity,
                repository_owner_id,
                claimed.receipt().accepted_at(),
                0x7100,
                check_head_sha,
            )
        };
        Self(evidence)
    }

    fn historical(
        claimed: &ClaimedProviderDelivery,
        check_head_sha: GitObjectId,
        manifest_revision: u64,
        seed: u128,
    ) -> Self {
        let identity = claimed.identity();
        let app_revision =
            GithubServerServiceRevision::new(manifest_revision).expect("historical App revision");
        let policy_revision = GithubServerServiceRevision::new(manifest_revision)
            .expect("historical policy revision");
        let webhook_fingerprint =
            GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(
                [u8::try_from(manifest_revision).expect("small revision"); 32],
            ))
            .expect("historical webhook fingerprint");
        let webhook_revision = GithubServerServiceRevision::new(manifest_revision)
            .expect("historical webhook revision");
        let runtime_policy = fixture_github_runtime_policy(manifest_revision);
        let manifest = GithubProviderManifest::new(
            identity.tenant().clone(),
            identity.connection_id(),
            identity.installation_id(),
            identity.repository_id(),
            GithubRepositoryName::new(identity.repository_identity().to_owned())
                .expect("historical repository name"),
            identity.repository_visibility(),
            GithubServerServiceAppId::new(1).expect("App ID"),
            GithubServerServiceAppClientId::new("Iv1.historical").expect("App client ID"),
            GithubServerServiceJwtIssuer::AppClientId,
            Sha256Digest::from_bytes([0x61; 32]),
            app_revision,
            webhook_fingerprint,
            webhook_revision,
            policy_revision,
            automata_ci_core::JobAuthorityProfile::Standard,
            runtime_policy.runner_policy,
            runtime_policy.revision,
            runtime_policy.semantic_digest,
            GithubCheckName::new("Automata CI").expect("Check name"),
            GithubProviderOrigins::github_dot_com(),
            GithubProviderManifestLimits::github_dot_com_ci(),
            GithubProviderManifestRevision::new(manifest_revision)
                .expect("historical manifest revision"),
        );
        let checks_authority = GithubServerServiceAuthoritySelector::from_durable_parts(
            identity.tenant().clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(seed))
                .expect("historical checks selector"),
            Sha256Digest::from_bytes([0x62; 32]),
            app_revision,
            policy_revision,
        );
        let private_source_authority = GithubServerServiceAuthoritySelector::from_durable_parts(
            identity.tenant().clone(),
            GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(seed + 1))
                .expect("historical source selector"),
            Sha256Digest::from_bytes([0x63; 32]),
            app_revision,
            policy_revision,
        );
        let evidence = ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
            claimed.receipt().id(),
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
            manifest,
            webhook_fingerprint,
            webhook_revision,
            checks_authority,
            Some(private_source_authority),
            GithubCheckSubjectId::from_uuid(Uuid::from_u128(seed + 2))
                .expect("historical Check subject"),
            check_head_sha,
            GithubAuthenticatedEvent::new(GithubAuthenticatedEventKind::Push, "refs/heads/main")
                .expect("authenticated event"),
            claimed.receipt().accepted_at(),
        )
        .expect("historical subject evidence");
        Self(evidence)
    }

    fn all_direct(claimed: &ClaimedProviderDelivery, git_ref: &str) -> Self {
        let identity = claimed.identity();
        Self(fixture_all_direct_subject_evidence(
            claimed.receipt().id(),
            identity,
            ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner ID"),
            claimed.receipt().accepted_at(),
            0x7_500,
            GithubProviderGitRef::new(git_ref).expect("manifest branch ref"),
        ))
    }

    fn authenticated_event(
        claimed: &ClaimedProviderDelivery,
        check_head_sha: GitObjectId,
        kind: GithubAuthenticatedEventKind,
        git_ref: &str,
    ) -> Self {
        let base = Self::from_claimed(claimed, check_head_sha).0;
        let event = GithubAuthenticatedEvent::new(kind, git_ref).expect("event coordinates");
        let private_pull_request_files_authority = (base.repository_visibility()
            == ProviderRepositoryVisibility::Private
            && kind == GithubAuthenticatedEventKind::PullRequest)
            .then(|| {
                GithubServerServiceAuthoritySelector::from_durable_parts(
                    base.tenant().clone(),
                    GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(0x7_5ff))
                        .expect("private pull-request-files selector"),
                    Sha256Digest::from_bytes([0x64; 32]),
                    base.checks_authority().app_configuration_revision(),
                    base.checks_authority().policy_revision(),
                )
            });
        let evidence = ManifestPinnedGithubDeliveryEvidence::from_durable_parts_with_pull_request_files_authority(
            base.delivery_id(),
            base.repository_owner_id(),
            base.manifest().clone(),
            base.authenticated_webhook_verifier_fingerprint(),
            base.authenticated_webhook_verifier_revision(),
            base.checks_authority().clone(),
            base.private_source_authority().cloned(),
            private_pull_request_files_authority,
            base.check_subject_id(),
            base.check_head_sha(),
            event,
            base.accepted_at(),
        )
        .expect("authenticated event evidence");
        Self(evidence)
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for FixtureSubjectEvidence {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        _request: automata_ci_store::AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        panic!("acceptance is outside the worker")
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
        panic!("run evidence is outside the worker")
    }
}

#[derive(Debug)]
struct RecordingRepositoryDispatchEvidence {
    pending: PendingGithubRepositoryDispatchEvidence,
    resolved: Mutex<Option<ManifestPinnedGithubDeliveryEvidence>>,
    resolutions: Mutex<Vec<GithubRepositoryDispatchResolution>>,
}

impl RecordingRepositoryDispatchEvidence {
    fn new(pending: PendingGithubRepositoryDispatchEvidence) -> Self {
        Self {
            pending,
            resolved: Mutex::new(None),
            resolutions: Mutex::new(Vec::new()),
        }
    }

    fn resolution_count(&self) -> usize {
        self.resolutions.lock().expect("resolutions lock").len()
    }

    fn has_resolved_evidence(&self) -> bool {
        self.resolved
            .lock()
            .expect("resolved evidence lock")
            .is_some()
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for RecordingRepositoryDispatchEvidence {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        _request: automata_ci_store::AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        panic!("acceptance is outside the worker")
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        if self.pending.tenant() != tenant || self.pending.delivery_id() != delivery_id {
            return Err(GithubSubjectEvidenceStoreError::NotFound);
        }
        self.resolved
            .lock()
            .expect("resolved evidence lock")
            .clone()
            .ok_or(GithubSubjectEvidenceStoreError::NotFound)
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        _tenant: &TenantScope,
        _repository_id: StoreRepositoryId,
        _run_id: automata_ci_core::RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        panic!("run evidence is outside the worker")
    }
}

#[async_trait]
impl GithubRepositoryDispatchEvidenceRepository for RecordingRepositoryDispatchEvidence {
    async fn accept_manifest_pinned_github_repository_dispatch(
        &self,
        _request: AcceptManifestPinnedGithubRepositoryDispatch,
    ) -> Result<PendingGithubRepositoryDispatchReceipt, GithubSubjectEvidenceStoreError> {
        panic!("acceptance is outside the worker")
    }

    async fn load_pending_github_repository_dispatch_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<PendingGithubRepositoryDispatchEvidence, GithubSubjectEvidenceStoreError> {
        if self.pending.tenant() != tenant || self.pending.delivery_id() != delivery_id {
            return Err(GithubSubjectEvidenceStoreError::NotFound);
        }
        if self
            .resolved
            .lock()
            .expect("resolved evidence lock")
            .is_some()
        {
            return Err(GithubSubjectEvidenceStoreError::NotFound);
        }
        Ok(self.pending.clone())
    }

    async fn resolve_github_repository_dispatch(
        &self,
        request: ResolveGithubRepositoryDispatch,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        assert_eq!(request.pending(), &self.pending);
        let resolution = request.resolution();
        self.resolutions
            .lock()
            .expect("resolutions lock")
            .push(resolution);
        let evidence =
            ManifestPinnedGithubDeliveryEvidence::from_durable_parts_resolved_repository_dispatch(
                self.pending.delivery_id(),
                self.pending.repository_owner_id(),
                self.pending.manifest().clone(),
                self.pending.authenticated_webhook_verifier_fingerprint(),
                self.pending.authenticated_webhook_verifier_revision(),
                self.pending.checks_authority().clone(),
                self.pending.private_source_authority().cloned(),
                GithubCheckSubjectId::from_uuid(Uuid::from_u128(0x9_100))
                    .expect("dispatch Check subject"),
                resolution.source_revision(),
                self.pending.event().clone(),
                resolution,
                self.pending.accepted_at(),
            )
            .expect("resolved dispatch evidence");
        *self.resolved.lock().expect("resolved evidence lock") = Some(evidence.clone());
        Ok(evidence)
    }
}

struct ClaimedFixture {
    claimed: ClaimedProviderDelivery,
    receipt: ProviderDeliveryReceipt,
    descriptor: BlobDescriptor,
    body: Bytes,
    check_head_sha: GitObjectId,
}

fn claimed_with_event_envelope(
    claimed: &ClaimedProviderDelivery,
    event_envelope: ProviderDeliveryEventEnvelope,
) -> ClaimedProviderDelivery {
    ClaimedProviderDelivery::from_durable_parts(
        claimed.receipt(),
        claimed.identity().clone(),
        claimed.request_digest(),
        claimed.raw_event().clone(),
        event_envelope,
        claimed.claim(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )
    .expect("claimed delivery with replacement envelope")
}

fn claimed_fixture(git_ref: &str, deleted: bool, attempt: u16) -> ClaimedFixture {
    claimed_fixture_with_visibility(
        git_ref,
        deleted,
        attempt,
        ProviderRepositoryVisibility::Private,
    )
}

fn claimed_fixture_with_visibility(
    git_ref: &str,
    deleted: bool,
    attempt: u16,
    visibility: ProviderRepositoryVisibility,
) -> ClaimedFixture {
    let after = if deleted { ZERO } else { AFTER };
    let body = push_body(git_ref, after, deleted, 0, visibility);
    let digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let key_text = format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{digest}.json");
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
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(1)).expect("delivery id");
    let receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Claimed,
        attempt,
        UnixMillis::new(50),
    )
    .expect("claimed receipt");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 7).expect("claim fence");
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
    let claimed = ClaimedProviderDelivery::from_durable_parts(
        receipt,
        identity,
        Sha256Digest::from_bytes([0x42; 32]),
        raw_event,
        provider_event_envelope(&body, &descriptor, "push", DELIVERY, visibility),
        claim,
        UnixMillis::new(100),
        UnixMillis::new(10_000),
    )
    .expect("claimed delivery");
    ClaimedFixture {
        claimed,
        receipt,
        descriptor,
        body,
        check_head_sha: fixture_check_head_sha(if deleted { BEFORE } else { AFTER }),
    }
}

fn pull_request_claimed_fixture() -> ClaimedFixture {
    let body = Bytes::from(format!(
        r#"{{"action":"opened","number":7,"pull_request":{{"number":7,"merged":false,"merge_commit_sha":"{STALE_MERGE}","head":{{"ref":"feature/topic","sha":"{AFTER}","repo":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}}}},"base":{{"ref":"main","sha":"{BEFORE}","repo":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}}}}}},"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ));
    let digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let key_text = format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{digest}.json");
    let descriptor = BlobDescriptor::new(
        BlobKey::new(key_text.clone()).expect("blob key"),
        digest,
        u64::try_from(body.len()).expect("body length"),
        MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE).expect("media type"),
    );
    let raw_event = AdmissionObject::new_event(
        digest,
        ObjectKey::new(key_text).expect("object key"),
        descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(11)).expect("delivery id");
    let receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Claimed,
        1,
        UnixMillis::new(50),
    )
    .expect("claimed receipt");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(12)).expect("owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 7).expect("claim fence");
    let repository = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
        ProviderRepositoryVisibility::Private,
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
    let claimed = ClaimedProviderDelivery::from_durable_parts(
        receipt,
        identity,
        Sha256Digest::from_bytes([0x43; 32]),
        raw_event,
        provider_event_envelope(
            &body,
            &descriptor,
            "pull_request",
            DELIVERY,
            ProviderRepositoryVisibility::Private,
        ),
        claim,
        UnixMillis::new(100),
        UnixMillis::new(10_000),
    )
    .expect("claimed delivery");
    ClaimedFixture {
        claimed,
        receipt,
        descriptor,
        body,
        check_head_sha: fixture_check_head_sha(AFTER),
    }
}

fn repository_dispatch_claimed_fixture(visibility: ProviderRepositoryVisibility) -> ClaimedFixture {
    let (private, visibility_name) = match visibility {
        ProviderRepositoryVisibility::Public => (false, "public"),
        ProviderRepositoryVisibility::Private => (true, "private"),
    };
    let body = Bytes::from(format!(
        r#"{{"action":"synthetic_signal","branch":"main","client_payload":{{"sequence":3}},"repository":{{"id":{REPOSITORY_ID},"private":{private},"visibility":"{visibility_name}","default_branch":"main","name":"{REPOSITORY}","full_name":"{OWNER}/{REPOSITORY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ));
    let digest = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let key_text = format!("{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{digest}.json");
    let descriptor = BlobDescriptor::new(
        BlobKey::new(key_text.clone()).expect("blob key"),
        digest,
        u64::try_from(body.len()).expect("body length"),
        MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE).expect("media type"),
    );
    let raw_event = AdmissionObject::new_event(
        digest,
        ObjectKey::new(key_text).expect("object key"),
        descriptor.size(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(21)).expect("delivery id");
    let receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Claimed,
        1,
        UnixMillis::new(50),
    )
    .expect("claimed receipt");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(22)).expect("owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 7).expect("claim fence");
    let repository = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
        visibility,
        format!("{OWNER}/{REPOSITORY}"),
    )
    .expect("repository coordinates");
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-dispatch").expect("tenant"),
        "github",
        ProviderConnectionId::from_uuid(Uuid::from_u128(23)).expect("connection"),
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        repository,
        DELIVERY,
    )
    .expect("identity");
    let claimed = ClaimedProviderDelivery::from_durable_parts(
        receipt,
        identity,
        Sha256Digest::from_bytes([0x44; 32]),
        raw_event,
        provider_event_envelope(
            &body,
            &descriptor,
            "repository_dispatch",
            DELIVERY,
            visibility,
        ),
        claim,
        UnixMillis::new(100),
        UnixMillis::new(10_000),
    )
    .expect("claimed delivery");
    ClaimedFixture {
        claimed,
        receipt,
        descriptor,
        body,
        check_head_sha: fixture_check_head_sha(AFTER),
    }
}

fn pending_repository_dispatch_evidence(
    fixture: &ClaimedFixture,
) -> PendingGithubRepositoryDispatchEvidence {
    let base = FixtureSubjectEvidence::from_claimed(&fixture.claimed, fixture.check_head_sha).0;
    PendingGithubRepositoryDispatchEvidence::from_durable_parts(
        base.delivery_id(),
        base.repository_owner_id(),
        base.manifest().clone(),
        base.authenticated_webhook_verifier_fingerprint(),
        base.authenticated_webhook_verifier_revision(),
        base.checks_authority().clone(),
        base.private_source_authority().cloned(),
        GithubAuthenticatedEvent::new(
            GithubAuthenticatedEventKind::RepositoryDispatch,
            "refs/heads/main",
        )
        .expect("dispatch coordinates"),
        base.accepted_at(),
    )
    .expect("pending repository dispatch")
}

fn repository_source(archive: Bytes) -> RepositorySource {
    RepositorySource::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        GitObjectId::from_provider_hex(AFTER).expect("revision"),
        ArchiveFormat::TarGzip,
        archive,
    )
}

fn repository_snapshot(archive: Bytes, resolved_revision: &str) -> RepositorySnapshot {
    RepositorySnapshot::from_bytes(
        ScmProviderId::new("github").expect("provider"),
        ScmRepositoryId::new(format!("{OWNER}/{REPOSITORY}")).expect("repository"),
        automata_ci_scm::RevisionSpec::new("refs/heads/main").expect("default branch"),
        GitObjectId::from_provider_hex(resolved_revision).expect("resolved revision"),
        ArchiveFormat::TarGzip,
        archive,
    )
}

fn worker(
    fixture: &ClaimedFixture,
    source: Arc<RecordingSourcePort>,
    processor: Arc<RecordingProcessor>,
    deliveries: Arc<RecordingDeliveries>,
    config: GithubDeliveryWorkerConfig,
) -> (GithubDeliveryWorker, Arc<VerifiedBlobStore>) {
    let subject_evidence =
        FixtureSubjectEvidence::from_claimed(&fixture.claimed, fixture.check_head_sha);
    worker_with_evidence(
        fixture,
        source,
        processor,
        deliveries,
        config,
        subject_evidence,
    )
}

fn worker_with_evidence(
    fixture: &ClaimedFixture,
    source: Arc<RecordingSourcePort>,
    processor: Arc<RecordingProcessor>,
    deliveries: Arc<RecordingDeliveries>,
    config: GithubDeliveryWorkerConfig,
    subject_evidence: FixtureSubjectEvidence,
) -> (GithubDeliveryWorker, Arc<VerifiedBlobStore>) {
    let objects = Arc::new(VerifiedBlobStore::exact(
        fixture.descriptor.clone(),
        fixture.body.clone(),
    ));
    let worker = GithubDeliveryWorker::new(
        objects.clone(),
        source,
        processor,
        deliveries,
        Arc::new(subject_evidence),
        Arc::new(FixedClock(UnixMillis::new(500))),
        config,
    )
    .expect("worker");
    (worker, objects)
}

fn repository_dispatch_worker(
    fixture: &ClaimedFixture,
    source: Arc<RecordingSourcePort>,
    resolver: Arc<RecordingResolver>,
    processor: Arc<RecordingProcessor>,
    deliveries: Arc<RecordingDeliveries>,
    evidence: Arc<RecordingRepositoryDispatchEvidence>,
) -> (GithubDeliveryWorker, Arc<VerifiedBlobStore>) {
    let objects = Arc::new(VerifiedBlobStore::exact(
        fixture.descriptor.clone(),
        fixture.body.clone(),
    ));
    let subject_evidence: Arc<dyn GithubSubjectEvidenceRepository> = evidence.clone();
    let repository_dispatches: Arc<dyn GithubRepositoryDispatchEvidenceRepository> = evidence;
    let worker = GithubDeliveryWorker::new_with_repository_dispatch(
        objects.clone(),
        source,
        resolver,
        processor,
        deliveries,
        subject_evidence,
        repository_dispatches,
        Arc::new(FixedClock(UnixMillis::new(500))),
        GithubDeliveryWorkerConfig::default(),
    )
    .expect("repository-dispatch worker");
    (worker, objects)
}

fn skipped() -> ProviderDeliveryWorkflowConclusion {
    ProviderDeliveryWorkflowConclusion::Skipped {
        reason: ProviderDeliveryFailureKind::new("github.workflow.not_selected")
            .expect("failure kind"),
    }
}

#[tokio::test]
async fn exact_source_and_all_direct_workflows_complete_deterministically() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let workflow_marker = b"private-workflow-marker\n".to_vec();
    let archive = archive(BTreeMap::from([
        (".ci/workflows/ci.yml", workflow_marker.clone()),
        (".ci/workflows/empty.yml", Vec::new()),
        (".ci/workflows/large.yaml", vec![b'x'; 65]),
        (".ci/workflows/a.yml", workflow_marker),
        ("README.md", b"ignored".to_vec()),
    ]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive)));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let config =
        GithubDeliveryWorkerConfig::new(RepositoryWorkflowDiscoveryLimits::default(), 1_500)
            .expect("config");
    let (worker, objects) = worker(
        &fixture,
        source.clone(),
        processor.clone(),
        deliveries.clone(),
        config,
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    let first = worker
        .process_claimed(
            fixture.claimed.clone(),
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        )
        .await
        .expect("first completion");
    let second = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        )
        .await
        .expect("exact replay");
    assert!(matches!(first, GithubDeliveryWorkerOutcome::Completed(_)));
    assert_eq!(first, second);
    assert_eq!(objects.read_count(), 2);

    let source_observations = source.observations();
    assert_eq!(source_observations.len(), 2);
    for observation in source_observations {
        assert_eq!(observation.repository, format!("{OWNER}/{REPOSITORY}"));
        assert_eq!(observation.revision, AFTER);
        assert!(observation.credential_present);
        assert!(observation.credential_matches);
        assert_eq!(observation.maximum_bytes, 256 * 1_024 * 1_024);
        assert!(!observation.debug.contains(CREDENTIAL_MARKER));
    }
    let workflow_observations = processor.observations();
    let observed_paths = workflow_observations
        .iter()
        .map(|observation| observation.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        observed_paths,
        [
            ".ci/workflows/a.yml",
            ".ci/workflows/ci.yml",
            ".ci/workflows/large.yaml",
        ]
    );
    assert!(workflow_observations.iter().all(|observation| {
        observation.ref_kind == GithubPushRefKind::Branch
            && observation.revision == AFTER
            && observation.manifest_revision == 1
            && observation.private_source_authority_present
            && !observation.debug.contains("private-workflow-marker")
            && !observation.debug.contains(OWNER)
    }));

    let completions = deliveries.ledger.completions();
    assert_eq!(completions.len(), 2);
    assert_eq!(completions[0], completions[1]);
    let outcomes = completions[0].outcomes();
    assert_eq!(
        outcomes
            .iter()
            .map(automata_ci_store::ProviderDeliveryWorkflowOutcome::workflow_path)
            .collect::<Vec<_>>(),
        [
            ".ci/workflows/a.yml",
            ".ci/workflows/ci.yml",
            ".ci/workflows/empty.yml",
            ".ci/workflows/large.yaml",
        ]
    );
}

#[tokio::test]
async fn all_direct_retry_resumes_after_durable_per_workflow_progress() {
    const DEFAULT_BRANCH_REF: &str = "refs/heads/refs/release";
    let fixture = claimed_fixture(DEFAULT_BRANCH_REF, false, 1);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::from([
            (".ci/workflows/a.yml", b"on: push\njobs: {}\n".to_vec()),
            (".ci/workflows/b.yaml", b"on: push\njobs: {}\n".to_vec()),
            (".ci/workflows/empty.yml", Vec::new()),
            (".ci/workflows/nested/ignored.yml", b"ignored\n".to_vec()),
            (".ci/workflows/ignored.txt", b"ignored\n".to_vec()),
        ]),
    ))));
    let processor = Arc::new(RecordingProcessor::returning_sequence(vec![
        ProcessorBehavior::Conclusion(skipped()),
        ProcessorBehavior::Error(GithubDeliveryWorkflowProcessorError::Unavailable),
        ProcessorBehavior::Conclusion(skipped()),
    ]));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let evidence = FixtureSubjectEvidence::all_direct(&fixture.claimed, DEFAULT_BRANCH_REF);
    let (worker, _) = worker_with_evidence(
        &fixture,
        Arc::clone(&source),
        Arc::clone(&processor),
        Arc::clone(&deliveries),
        GithubDeliveryWorkerConfig::default(),
        evidence,
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    let first = worker
        .process_claimed(
            fixture.claimed.clone(),
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        )
        .await
        .expect("second workflow schedules a durable retry");
    assert!(
        matches!(first, GithubDeliveryWorkerOutcome::RetryScheduled(_)),
        "unexpected first outcome: {first:?}"
    );
    assert!(deliveries.ledger.completions().is_empty());
    assert_eq!(deliveries.ledger.progress().len(), 1);

    let second = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        )
        .await
        .expect("retry resumes from durable progress");
    assert!(matches!(second, GithubDeliveryWorkerOutcome::Completed(_)));

    assert_eq!(source.observations().len(), 2);
    assert_eq!(
        processor
            .observations()
            .iter()
            .map(|observation| observation.path.as_str())
            .collect::<Vec<_>>(),
        [
            ".ci/workflows/a.yml",
            ".ci/workflows/b.yaml",
            ".ci/workflows/b.yaml",
        ]
    );
    assert_eq!(deliveries.ledger.retries().len(), 1);
    assert_eq!(deliveries.ledger.progress().len(), 3);
    let completions = deliveries.ledger.completions();
    assert_eq!(completions.len(), 1);
    assert_eq!(
        completions[0]
            .outcomes()
            .iter()
            .map(ProviderDeliveryWorkflowOutcome::workflow_path)
            .collect::<Vec<_>>(),
        [
            ".ci/workflows/a.yml",
            ".ci/workflows/b.yaml",
            ".ci/workflows/empty.yml",
        ]
    );
}

#[tokio::test]
async fn pull_request_uses_checked_head_when_webhook_merge_revision_is_stale() {
    let fixture = pull_request_claimed_fixture();
    let expected_event_envelope_digest = fixture.claimed.event_envelope().digest();
    let archive = archive(BTreeMap::from([(
        ".ci/workflows/ci.yml",
        b"on: pull_request\njobs: {}\n".to_vec(),
    )]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive)));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let evidence = FixtureSubjectEvidence::authenticated_event(
        &fixture.claimed,
        fixture.check_head_sha,
        GithubAuthenticatedEventKind::PullRequest,
        "refs/pull/7/merge",
    );
    let config = GithubDeliveryWorkerConfig::default();
    let (worker, objects) = worker_with_evidence(
        &fixture,
        Arc::clone(&source),
        Arc::clone(&processor),
        Arc::clone(&deliveries),
        config,
        evidence,
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        )
        .await
        .expect("pull-request completion");

    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Completed(_)));
    assert_eq!(objects.read_count(), 1);
    assert_eq!(source.observations()[0].revision, AFTER);
    let observations = processor.event_observations();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].event_name, "pull_request");
    assert_eq!(
        observations[0].event_envelope_digest,
        expected_event_envelope_digest
    );
    assert_eq!(observations[0].git_ref, "refs/pull/7/merge");
    assert_eq!(observations[0].revision, AFTER);
    assert_eq!(
        observations[0].raw_media_type,
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
    );
    assert!(!observations[0].debug.contains(OWNER));
    assert!(!observations[0].debug.contains(REPOSITORY));
}

#[tokio::test]
async fn private_repository_dispatch_resolves_once_then_retries_the_pinned_sha() {
    let fixture = repository_dispatch_claimed_fixture(ProviderRepositoryVisibility::Private);
    let source_archive = archive(BTreeMap::from([(
        ".ci/workflows/ci.yml",
        b"on: repository_dispatch\njobs: {}\n".to_vec(),
    )]));
    let resolver = Arc::new(RecordingResolver::returning(vec![
        repository_snapshot(source_archive.clone(), AFTER),
        repository_snapshot(source_archive.clone(), BEFORE),
    ]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(
        source_archive,
    )));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let evidence = Arc::new(RecordingRepositoryDispatchEvidence::new(
        pending_repository_dispatch_evidence(&fixture),
    ));
    let (worker, objects) = repository_dispatch_worker(
        &fixture,
        source.clone(),
        resolver.clone(),
        processor.clone(),
        deliveries,
        evidence.clone(),
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    for claimed in [fixture.claimed.clone(), fixture.claimed] {
        assert!(matches!(
            worker
                .process_claimed(
                    claimed,
                    GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                        credential: &credential,
                        changed_files_credentials: None,
                    },
                )
                .await
                .expect("dispatch completion"),
            GithubDeliveryWorkerOutcome::Completed(_)
        ));
    }

    assert_eq!(objects.read_count(), 2);
    assert_eq!(evidence.resolution_count(), 1);
    assert!(evidence.has_resolved_evidence());
    assert_eq!(
        evidence.resolutions.lock().expect("resolutions lock")[0],
        GithubRepositoryDispatchResolution::new(
            fixture_check_head_sha(AFTER),
            GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority,
        )
    );
    let resolver_observations = resolver.observations();
    assert_eq!(resolver_observations.len(), 1);
    assert_eq!(
        resolver_observations[0].repository,
        format!("{OWNER}/{REPOSITORY}")
    );
    assert_eq!(resolver_observations[0].revision, "refs/heads/main");
    assert!(resolver_observations[0].credential_present);
    assert!(resolver_observations[0].credential_matches);
    assert!(!resolver_observations[0].debug.contains(CREDENTIAL_MARKER));
    let source_observations = source.observations();
    assert_eq!(source_observations.len(), 1);
    assert_eq!(source_observations[0].revision, AFTER);
    assert!(source_observations[0].credential_matches);
    let workflow_observations = processor.event_observations();
    assert_eq!(workflow_observations.len(), 1);
    assert!(workflow_observations.iter().all(|observation| {
        observation.event_name == "repository_dispatch"
            && observation.git_ref == "refs/heads/main"
            && observation.revision == AFTER
            && observation.raw_media_type == GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
            && observation.raw_body == fixture.body
    }));
}

#[tokio::test]
async fn public_repository_dispatch_resolution_is_credential_free() {
    let fixture = repository_dispatch_claimed_fixture(ProviderRepositoryVisibility::Public);
    let source_archive = archive(BTreeMap::from([(
        ".ci/workflows/ci.yml",
        b"on: repository_dispatch\njobs: {}\n".to_vec(),
    )]));
    let resolver = Arc::new(RecordingResolver::returning(vec![repository_snapshot(
        source_archive.clone(),
        AFTER,
    )]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(
        source_archive,
    )));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let evidence = Arc::new(RecordingRepositoryDispatchEvidence::new(
        pending_repository_dispatch_evidence(&fixture),
    ));
    let (worker, _) = repository_dispatch_worker(
        &fixture,
        source.clone(),
        resolver.clone(),
        processor.clone(),
        deliveries,
        evidence.clone(),
    );

    assert!(matches!(
        worker
            .process_claimed(
                fixture.claimed,
                GithubDeliverySourceAuthority::PublicAnonymous,
            )
            .await
            .expect("public dispatch completion"),
        GithubDeliveryWorkerOutcome::Completed(_)
    ));

    assert_eq!(evidence.resolution_count(), 1);
    assert_eq!(
        evidence.resolutions.lock().expect("resolutions lock")[0],
        GithubRepositoryDispatchResolution::new(
            fixture_check_head_sha(AFTER),
            GithubRepositoryDispatchResolutionAuthority::PublicAnonymous,
        )
    );
    let observations = resolver.observations();
    assert_eq!(observations.len(), 1);
    assert!(!observations[0].credential_present);
    assert!(!observations[0].credential_matches);
    assert!(source.observations().is_empty());
    assert_eq!(processor.event_observations().len(), 1);
}

#[tokio::test]
async fn repository_dispatch_resolution_failure_creates_no_check_or_workflow() {
    let fixture = repository_dispatch_claimed_fixture(ProviderRepositoryVisibility::Private);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::<&str, Vec<u8>>::new(),
    ))));
    let resolver = Arc::new(RecordingResolver::failing(ScmError::new(
        automata_ci_scm::ScmErrorKind::Unavailable,
    )));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let evidence = Arc::new(RecordingRepositoryDispatchEvidence::new(
        pending_repository_dispatch_evidence(&fixture),
    ));
    let (worker, _) = repository_dispatch_worker(
        &fixture,
        source.clone(),
        resolver.clone(),
        processor.clone(),
        deliveries.clone(),
        evidence.clone(),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                changed_files_credentials: None,
            },
        )
        .await
        .expect("resolution failure is durably retried");

    assert!(matches!(
        outcome,
        GithubDeliveryWorkerOutcome::RetryScheduled(_)
    ));
    assert_eq!(resolver.observations().len(), 1);
    assert!(source.observations().is_empty());
    assert_eq!(evidence.resolution_count(), 0);
    assert!(!evidence.has_resolved_evidence());
    assert!(processor.event_observations().is_empty());
    assert!(deliveries.ledger.completions().is_empty());
    assert_eq!(deliveries.ledger.retries().len(), 1);
}

#[tokio::test]
async fn no_direct_workflows_completes_with_an_empty_outcome_set() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::from([("README.md", b"no workflow here\n".to_vec())]),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (worker, _) = worker(
        &fixture,
        source,
        processor.clone(),
        deliveries.clone(),
        GithubDeliveryWorkerConfig::default(),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                changed_files_credentials: None,
            },
        )
        .await
        .expect("missing configured workflow is a durable terminal outcome");

    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Completed(_)));
    assert!(processor.observations().is_empty());
    let completions = deliveries.ledger.completions();
    assert_eq!(completions.len(), 1);
    let outcomes = completions[0].outcomes();
    assert!(outcomes.is_empty());
}

#[tokio::test]
async fn historical_manifest_evidence_survives_a_later_manifest_rotation() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let historical =
        FixtureSubjectEvidence::historical(&fixture.claimed, fixture.check_head_sha, 2, 0x8100);
    let rotated_current =
        FixtureSubjectEvidence::historical(&fixture.claimed, fixture.check_head_sha, 3, 0x8200);
    assert_ne!(
        historical.0.manifest_digest(),
        rotated_current.0.manifest_digest()
    );
    assert_ne!(
        historical.0.private_source_authority(),
        rotated_current.0.private_source_authority()
    );
    let objects = Arc::new(VerifiedBlobStore::exact(
        fixture.descriptor.clone(),
        fixture.body.clone(),
    ));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::from([(".ci/workflows/ci.yml", b"on: push\n".to_vec())]),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let worker = GithubDeliveryWorker::new(
        objects,
        source,
        processor.clone(),
        deliveries,
        Arc::new(historical),
        Arc::new(FixedClock(UnixMillis::new(500))),
        GithubDeliveryWorkerConfig::default(),
    )
    .expect("worker");
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    for claimed in [fixture.claimed.clone(), fixture.claimed] {
        assert!(matches!(
            worker
                .process_claimed(
                    claimed,
                    GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                        credential: &credential,
                        changed_files_credentials: None,
                    },
                )
                .await
                .expect("historical replay"),
            GithubDeliveryWorkerOutcome::Completed(_)
        ));
    }

    let observations = processor.observations();
    assert_eq!(observations.len(), 1);
    assert!(observations.iter().all(|observation| {
        observation.manifest_revision == 2 && observation.private_source_authority_present
    }));
}

#[tokio::test]
async fn public_live_ref_uses_anonymous_source_request_without_a_credential() {
    let fixture = claimed_fixture_with_visibility(
        "refs/heads/main",
        false,
        1,
        ProviderRepositoryVisibility::Public,
    );
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::from([(".ci/workflows/ci.yml", b"on: push\n".to_vec())]),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (worker, _) = worker(
        &fixture,
        source.clone(),
        processor.clone(),
        deliveries,
        GithubDeliveryWorkerConfig::default(),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PublicAnonymous,
        )
        .await
        .expect("public source completes anonymously");
    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Completed(_)));
    let observations = source.observations();
    assert_eq!(observations.len(), 1);
    assert!(!observations[0].credential_present);
    assert!(!observations[0].credential_matches);
    assert_eq!(observations[0].maximum_bytes, 256 * 1_024 * 1_024);
    let workflow_observations = processor.observations();
    assert_eq!(workflow_observations.len(), 1);
    assert!(!workflow_observations[0].private_source_authority_present);
}

#[tokio::test]
async fn historical_manifest_uses_pinned_limits_below_a_wider_local_ceiling() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::from([(".ci/workflows/ci.yml", b"on: push\n".to_vec())]),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let wider_limits = RepositoryWorkflowDiscoveryLimits::new(
        512 * 1_024 * 1_024,
        4 * 1_024 * 1_024 * 1_024,
        200_000,
        2 * 1_024 * 1_024 * 1_024,
        8 * 1_024,
        256,
        2 * 1_024 * 1_024,
    )
    .expect("wider local limits remain structurally valid");
    let (worker, objects) = worker(
        &fixture,
        source.clone(),
        processor.clone(),
        deliveries,
        GithubDeliveryWorkerConfig::new(wider_limits, 1_000).expect("worker config"),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                changed_files_credentials: None,
            },
        )
        .await
        .expect("historical manifest remains valid under a wider local ceiling");

    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Completed(_)));
    assert_eq!(objects.read_count(), 1);
    let source_observations = source.observations();
    assert_eq!(source_observations.len(), 1);
    assert_eq!(source_observations[0].maximum_bytes, 256 * 1_024 * 1_024);
    let workflow_observations = processor.observations();
    assert_eq!(workflow_observations.len(), 1);
    assert_eq!(workflow_observations[0].manifest_revision, 1);
}

#[tokio::test]
async fn pinned_manifest_exceeding_a_local_ceiling_rejects_before_source_io() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::from([(".ci/workflows/ci.yml", b"on: push\n".to_vec())]),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let drifted_limits = RepositoryWorkflowDiscoveryLimits::new(
        64 * 1_024,
        256 * 1_024,
        32,
        256 * 1_024,
        4 * 1_024,
        8,
        64,
    )
    .expect("drifted local limits remain structurally valid");
    let (worker, objects) = worker(
        &fixture,
        source.clone(),
        processor.clone(),
        deliveries.clone(),
        GithubDeliveryWorkerConfig::new(drifted_limits, 1_000).expect("worker config"),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                changed_files_credentials: None,
            },
        )
        .await
        .expect("over-ceiling policy is durably rejected");

    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Rejected(_)));
    assert_eq!(objects.read_count(), 0);
    assert!(source.observations().is_empty());
    assert!(processor.observations().is_empty());
    assert_eq!(
        deliveries.ledger.rejections()[0].failure_kind().as_str(),
        "github.subject_evidence.mismatch"
    );
}

#[tokio::test]
async fn deleted_pinned_branch_completes_without_source_authority_or_processing() {
    let fixture = claimed_fixture("refs/heads/main", true, 1);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::<&str, Vec<u8>>::new(),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (worker, _) = worker(
        &fixture,
        source.clone(),
        processor.clone(),
        deliveries.clone(),
        GithubDeliveryWorkerConfig::default(),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                changed_files_credentials: None,
            },
        )
        .await
        .expect("deleted completion");
    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Completed(_)));
    assert!(source.observations().is_empty());
    assert!(processor.observations().is_empty());
    let completions = deliveries.ledger.completions();
    assert_eq!(completions.len(), 1);
    assert!(completions[0].outcomes().is_empty());
}

#[tokio::test]
async fn non_pinned_git_ref_rejects_before_source_or_workflow_processing() {
    let fixture = claimed_fixture("refs/tags/v1.2.3", false, 1);
    let archive = archive(BTreeMap::from([(
        ".ci/workflows/ci.yml",
        b"on: push\n".to_vec(),
    )]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive)));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (worker, _) = worker(
        &fixture,
        source.clone(),
        processor.clone(),
        deliveries,
        GithubDeliveryWorkerConfig::default(),
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    assert!(matches!(
        worker
            .process_claimed(
                fixture.claimed,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential: &credential,
                    changed_files_credentials: None,
                },
            )
            .await
            .expect("ref mismatch is durably rejected"),
        GithubDeliveryWorkerOutcome::Rejected(_)
    ));
    assert!(source.observations().is_empty());
    assert!(processor.observations().is_empty());
}

#[tokio::test]
async fn private_live_ref_rejects_public_authority_before_provider_io() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::<&str, Vec<u8>>::new(),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (worker, objects) = worker(
        &fixture,
        source.clone(),
        processor,
        deliveries.clone(),
        GithubDeliveryWorkerConfig::default(),
    );

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PublicAnonymous,
        )
        .await
        .expect("authority mismatch is durably rejected");
    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Rejected(_)));
    assert_eq!(objects.read_count(), 1);
    assert!(source.observations().is_empty());
    assert_eq!(deliveries.transition_count(), 1);
}

#[tokio::test]
async fn rehydrated_push_head_must_match_the_pinned_check_before_source_io() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let objects = Arc::new(VerifiedBlobStore::exact(
        fixture.descriptor.clone(),
        fixture.body.clone(),
    ));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
        BTreeMap::<&str, Vec<u8>>::new(),
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let mismatched_evidence = Arc::new(FixtureSubjectEvidence::from_claimed(
        &fixture.claimed,
        fixture_check_head_sha(BEFORE),
    ));
    let worker = GithubDeliveryWorker::new(
        objects.clone(),
        source.clone(),
        processor.clone(),
        deliveries.clone(),
        mismatched_evidence,
        Arc::new(FixedClock(UnixMillis::new(500))),
        GithubDeliveryWorkerConfig::default(),
    )
    .expect("worker");
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    let outcome = worker
        .process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        )
        .await
        .expect("pinned head mismatch is durably rejected");

    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Rejected(_)));
    assert_eq!(objects.read_count(), 1);
    assert!(source.observations().is_empty());
    assert!(processor.observations().is_empty());
    assert_eq!(deliveries.transition_count(), 1);
    assert_eq!(
        deliveries.ledger.rejections()[0].failure_kind().as_str(),
        "github.subject_evidence.mismatch"
    );
}

#[tokio::test]
async fn invalid_or_rebound_event_envelopes_reject_before_blob_or_source_io() {
    for case in ["unsupported", "corrupt", "raw-rebound", "identity-rebound"] {
        let mut fixture = claimed_fixture("refs/heads/main", false, 1);
        let durable = fixture.claimed.event_envelope();
        let event_envelope = match case {
            "unsupported" => ProviderDeliveryEventEnvelope::new(
                2,
                durable.registry_schema(),
                durable.digest(),
                durable.canonical_bytes().to_vec(),
                durable.media_type(),
            )
            .expect("store-valid unsupported envelope"),
            "corrupt" => ProviderDeliveryEventEnvelope::new(
                durable.schema(),
                durable.registry_schema(),
                Sha256Digest::from_bytes([0xEE; 32]),
                durable.canonical_bytes().to_vec(),
                durable.media_type(),
            )
            .expect("store-valid corrupt envelope"),
            "raw-rebound" => {
                let other_body = push_body(
                    "refs/heads/other",
                    AFTER,
                    false,
                    0,
                    ProviderRepositoryVisibility::Private,
                );
                let other_digest = Sha256Digest::from_bytes(Sha256::digest(&other_body).into());
                let other_descriptor = BlobDescriptor::new(
                    BlobKey::new(format!(
                        "{GITHUB_RAW_EVENT_OBJECT_KEY_PREFIX}/{other_digest}.json"
                    ))
                    .expect("other raw key"),
                    other_digest,
                    u64::try_from(other_body.len()).expect("other raw size"),
                    MediaType::new(GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE)
                        .expect("other raw media type"),
                );
                provider_event_envelope(
                    &other_body,
                    &other_descriptor,
                    "push",
                    DELIVERY,
                    ProviderRepositoryVisibility::Private,
                )
            }
            "identity-rebound" => provider_event_envelope(
                &fixture.body,
                &fixture.descriptor,
                "push",
                "other-delivery",
                ProviderRepositoryVisibility::Private,
            ),
            _ => unreachable!("closed test cases"),
        };
        fixture.claimed = claimed_with_event_envelope(&fixture.claimed, event_envelope);
        let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
            BTreeMap::<&str, Vec<u8>>::new(),
        ))));
        let processor = Arc::new(RecordingProcessor::returning(skipped()));
        let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
        let (worker, objects) = worker(
            &fixture,
            source.clone(),
            processor.clone(),
            deliveries.clone(),
            GithubDeliveryWorkerConfig::default(),
        );

        let outcome = worker
            .process_claimed(
                fixture.claimed,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                    changed_files_credentials: None,
                },
            )
            .await
            .expect("event envelope failure is durably rejected");
        assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Rejected(_)));
        assert_eq!(objects.read_count(), 0, "case {case}");
        assert!(source.observations().is_empty(), "case {case}");
        assert!(processor.observations().is_empty(), "case {case}");
        let expected_kind = match case {
            "unsupported" => "github.event_envelope.unsupported_schema",
            "corrupt" => "github.event_envelope.invalid",
            "raw-rebound" => "github.event_envelope.raw_identity_mismatch",
            "identity-rebound" => "github.event_envelope.identity_mismatch",
            _ => unreachable!("closed test cases"),
        };
        assert_eq!(
            deliveries.ledger.rejections()[0].failure_kind().as_str(),
            expected_kind,
            "case {case}",
        );
    }
}

#[tokio::test]
async fn immutable_object_failures_are_durably_classified_before_source_io() {
    for (failure, expected_state, expected_kind) in [
        (
            BlobStoreErrorKind::Integrity,
            ProviderDeliveryState::Rejected,
            "github.raw_event.invalid_object",
        ),
        (
            BlobStoreErrorKind::Unavailable,
            ProviderDeliveryState::RetryPending,
            "github.raw_event.unavailable",
        ),
    ] {
        let fixture = claimed_fixture("refs/heads/main", false, 1);
        let objects = Arc::new(VerifiedBlobStore::failing(
            fixture.descriptor.clone(),
            fixture.body.clone(),
            failure,
        ));
        let source = Arc::new(RecordingSourcePort::returning(repository_source(archive(
            BTreeMap::<&str, Vec<u8>>::new(),
        ))));
        let processor = Arc::new(RecordingProcessor::returning(skipped()));
        let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
        let subject_evidence = Arc::new(FixtureSubjectEvidence::from_claimed(
            &fixture.claimed,
            fixture.check_head_sha,
        ));
        let worker = GithubDeliveryWorker::new(
            objects,
            source.clone(),
            processor,
            deliveries.clone(),
            subject_evidence,
            Arc::new(FixedClock(UnixMillis::new(500))),
            GithubDeliveryWorkerConfig::new(RepositoryWorkflowDiscoveryLimits::default(), 1_234)
                .expect("config"),
        )
        .expect("worker");

        let outcome = worker
            .process_claimed(
                fixture.claimed,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential: &SecretString::new(CREDENTIAL_MARKER).expect("credential"),
                    changed_files_credentials: None,
                },
            )
            .await
            .expect("durable classification");
        assert_eq!(outcome.receipt().state(), expected_state);
        assert!(source.observations().is_empty());
        if expected_state == ProviderDeliveryState::Rejected {
            let rejections = deliveries.ledger.rejections();
            assert_eq!(rejections[0].failure_kind().as_str(), expected_kind);
        } else {
            let retries = deliveries.ledger.retries();
            assert_eq!(retries[0].failure_kind().as_str(), expected_kind);
            assert_eq!(retries[0].retry_at(), UnixMillis::new(1_734));
        }
    }
}

#[tokio::test]
async fn source_rate_limit_and_processor_prerequisite_never_commit_partial_paths() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let rate_limited = Arc::new(RecordingSourcePort::failing(ScmError::rate_limited(Some(
        9,
    ))));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (rate_limited_worker, _) = worker(
        &fixture,
        rate_limited,
        processor,
        deliveries.clone(),
        GithubDeliveryWorkerConfig::default(),
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");
    assert!(matches!(
        rate_limited_worker
            .process_claimed(
                fixture.claimed,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential: &credential,
                    changed_files_credentials: None,
                },
            )
            .await
            .expect("retry scheduled"),
        GithubDeliveryWorkerOutcome::RetryScheduled(_)
    ));
    {
        let retries = deliveries.ledger.retries();
        assert_eq!(retries[0].retry_at(), UnixMillis::new(9_500));
    }

    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let archive = archive(BTreeMap::from([(
        ".ci/workflows/ci.yml",
        b"on: push\n".to_vec(),
    )]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive)));
    let processor = Arc::new(RecordingProcessor::failing(
        GithubDeliveryWorkflowProcessorError::Prerequisite(
            GithubDeliveryWorkerPrerequisite::ProviderChangedFiles,
        ),
    ));
    let deliveries = Arc::new(RecordingDeliveries::new(fixture.receipt));
    let (worker, _) = worker(
        &fixture,
        source,
        processor,
        deliveries.clone(),
        GithubDeliveryWorkerConfig::default(),
    );
    assert_eq!(
        worker
            .process_claimed(
                fixture.claimed,
                GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                    credential: &credential,
                    changed_files_credentials: None,
                },
            )
            .await,
        Err(GithubDeliveryWorkerError::Prerequisite(
            GithubDeliveryWorkerPrerequisite::ProviderChangedFiles
        ))
    );
    assert_eq!(deliveries.transition_count(), 0);
}

#[tokio::test]
async fn rejected_admitted_run_reuses_the_owned_terminal_operation() {
    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let archive = archive(BTreeMap::from([(
        ".ci/workflows/ci.yml",
        b"on: push\n".to_vec(),
    )]));
    let source = Arc::new(RecordingSourcePort::returning(repository_source(archive)));
    let processor = Arc::new(RecordingProcessor::returning(skipped()));
    let deliveries = Arc::new(RecordingDeliveries::rejecting_completion_outcome_run(
        fixture.receipt,
    ));
    let (worker, _) = worker(
        &fixture,
        source,
        processor,
        deliveries.clone(),
        GithubDeliveryWorkerConfig::default(),
    );
    let credential = SecretString::new(CREDENTIAL_MARKER).expect("credential");

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        worker.process_claimed(
            fixture.claimed,
            GithubDeliverySourceAuthority::PrivateInstallationContentsRead {
                credential: &credential,
                changed_files_credentials: None,
            },
        ),
    )
    .await
    .expect("terminal fallback must not wait on its own operation lock")
    .expect("invalid admitted run is durably rejected");

    assert!(matches!(outcome, GithubDeliveryWorkerOutcome::Rejected(_)));
    assert_eq!(
        deliveries.ledger.rejections()[0].failure_kind().as_str(),
        "github.workflow.invalid_admitted_run"
    );
    assert_eq!(deliveries.ledger.completions().len(), 1);
    assert_eq!(deliveries.ledger.rejections().len(), 1);
}

#[test]
fn configuration_rejects_unrepresentable_outcome_and_provider_bounds() {
    let too_many =
        RepositoryWorkflowDiscoveryLimits::new(1_024, 4_096, 512, 4_096, 1_024, 257, 128)
            .expect("source discovery permits 257 workflows");
    assert_eq!(
        GithubDeliveryWorkerConfig::new(too_many, 1_000),
        Err(GithubDeliveryWorkerConfigurationError::TooManyWorkflowOutcomes)
    );

    let fixture = claimed_fixture("refs/heads/main", false, 1);
    let subject_evidence = Arc::new(FixtureSubjectEvidence::from_claimed(
        &fixture.claimed,
        fixture.check_head_sha,
    ));
    let source = Arc::new(RecordingSourcePort::with_provider(
        "gitlab",
        repository_source(archive(BTreeMap::<&str, Vec<u8>>::new())),
    ));
    let result = GithubDeliveryWorker::new(
        Arc::new(VerifiedBlobStore::exact(fixture.descriptor, fixture.body)),
        source,
        Arc::new(RecordingProcessor::returning(skipped())),
        Arc::new(RecordingDeliveries::new(fixture.receipt)),
        subject_evidence,
        Arc::new(FixedClock(UnixMillis::new(500))),
        GithubDeliveryWorkerConfig::default(),
    );
    assert!(matches!(
        result,
        Err(GithubDeliveryWorkerConfigurationError::SourceProviderMismatch)
    ));
}
