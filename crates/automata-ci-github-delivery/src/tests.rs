use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Write as _},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_provider_github::{
    GithubWebhookError, GithubWebhookVerifier, MAX_GITHUB_WEBHOOK_BODY_BYTES, X_GITHUB_DELIVERY,
    X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptManifestPinnedGithubRepositoryDispatch,
    AcceptProviderDelivery, AdmissionObject, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    GITHUB_PROVIDER_WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN, GithubAuthenticatedEventKind,
    GithubCheckName, GithubCheckRerunRepository, GithubCheckRerunRequest,
    GithubCheckRerunStoreError, GithubCheckRerunTarget, GithubCheckSubjectId,
    GithubDeliveryCheckKind, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins, GithubProviderRunnerPolicyObject,
    GithubRepositoryDispatchEvidenceRepository, GithubRepositoryName,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthoritySelector, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubSubjectEvidenceRepository, GithubSubjectEvidenceStoreError,
    GithubWorkflowRunSubjectEvidence, ManifestPinnedGithubDeliveryEvidence,
    ManifestPinnedGithubDeliveryReceipt, ObjectKey, PendingGithubRepositoryDispatchEvidence,
    PendingGithubRepositoryDispatchReceipt, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderDeliveryReceipt, ProviderDeliveryRepository, ProviderDeliveryStoreError,
    ProviderInstallationId, ProviderRepositoryCoordinates, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RejectProviderDelivery, RepositoryId,
    ResolveGithubRepositoryDispatch, RetryProviderDelivery, TenantScope, WorkflowRerunReceipt,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyRevision,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use ring::hmac;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubDeliveryClock, GithubDeliveryConfigurationError,
    GithubDeliveryConnection, GithubDeliveryIngress, GithubDeliveryIngressError,
    GithubDeliveryRepositories, MAX_GITHUB_DELIVERY_CONNECTIONS, canonical_event_request_digest,
};

const SECRET: &[u8] = b"delivery-test-secret";
const OTHER_SECRET: &[u8] = b"rotated-delivery-test-secret";
const FINGERPRINT_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const BEFORE_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AFTER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const AFTER_COMMIT_BYTES: [u8; 20] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67,
];
const PULL_REQUEST_MERGE_COMMIT: &str = "89abcdef0123456789abcdef0123456789abcdef";
const CONNECTION_UUID: Uuid = Uuid::from_u128(0x57d02be9_1ac4_4780_a573_48d21621c2de);
const INSTALLATION_ID: u64 = 4_242;
const REPOSITORY_ID: u64 = 9_001;
const REPOSITORY_OWNER_ID: u64 = 8_001;
const FIXTURE_RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "runner_features":{"schema":1,"supported":["automata.core/bash-shell@v1","automata.core/command-files@v1","automata.core/composite-actions@v1","automata.core/default-posix-shell@v1","automata.core/javascript-actions@v1","automata.core/job-summaries@v1","automata.core/local-actions@v1","automata.core/node20-actions@v1","automata.core/node24-actions@v1","automata.core/python-shell@v1","automata.core/repository-actions@v1","automata.core/sh-shell@v1","automata.core/shell-steps@v1"]},
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read","packages":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","models":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","models":"read","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":2
}"#;

pub(crate) struct FixtureGithubRuntimePolicy {
    pub(crate) runner_policy: GithubProviderRunnerPolicyObject,
    pub(crate) revision: WorkflowRuntimePolicyRevision,
    pub(crate) semantic_digest: Sha256Digest,
}

pub(crate) fn fixture_github_runtime_policy(revision: u64) -> FixtureGithubRuntimePolicy {
    let policy = WorkflowRuntimePolicy::decode_configuration(FIXTURE_RUNTIME_POLICY)
        .expect("fixture runtime policy");
    let canonical = policy.canonical_bytes().expect("canonical runtime policy");
    let object_digest = policy.canonical_digest();
    let object = AdmissionObject::new(
        object_digest,
        ObjectKey::new(format!("github/runner-policy/v1/{object_digest}.json"))
            .expect("runner-policy object key"),
        u64::try_from(canonical.len()).expect("runner-policy size"),
        GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    )
    .expect("runner-policy object");
    FixtureGithubRuntimePolicy {
        runner_policy: GithubProviderRunnerPolicyObject::new(object)
            .expect("runner-policy descriptor"),
        revision: WorkflowRuntimePolicyRevision::new(revision).expect("runtime-policy revision"),
        semantic_digest: policy.digest(),
    }
}

#[test]
fn verifier_fingerprint_has_exact_store_manifest_domain_parity() {
    let mut expected = Sha256::new();
    expected.update(GITHUB_PROVIDER_WEBHOOK_VERIFIER_FINGERPRINT_DOMAIN);
    expected.update(FINGERPRINT_SECRET);
    let fingerprint = GithubWebhookVerifier::new(FINGERPRINT_SECRET)
        .expect("fixture verifier")
        .fingerprint();
    let expected: [u8; 32] = expected.finalize().into();

    assert_eq!(fingerprint.as_bytes(), &expected);
    assert_eq!(
        Sha256Digest::from_bytes(*fingerprint.as_bytes()).to_string(),
        "656c78c9da1c55424378c8a0de923a0958602834ca79e7f974668cfe9ee09c3e"
    );
}

#[derive(Debug)]
struct FixedClock(UnixMillis);

impl GithubDeliveryClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

#[derive(Debug)]
struct IncrementingClock(AtomicI64);

impl IncrementingClock {
    const fn new(initial: i64) -> Self {
        Self(AtomicI64::new(initial))
    }
}

impl GithubDeliveryClock for IncrementingClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

#[derive(Debug, Default)]
struct RecordingBlobStore {
    failure: Option<BlobStoreErrorKind>,
    puts: AtomicUsize,
    objects: Mutex<BTreeMap<String, BlobPayload>>,
}

impl RecordingBlobStore {
    const fn failing(kind: BlobStoreErrorKind) -> Self {
        Self {
            failure: Some(kind),
            puts: AtomicUsize::new(0),
            objects: Mutex::new(BTreeMap::new()),
        }
    }

    fn put_count(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }

    fn object_count(&self) -> usize {
        self.objects.lock().expect("blob lock is healthy").len()
    }

    fn bytes_at(&self, key: &str) -> Option<Bytes> {
        self.objects
            .lock()
            .expect("blob lock is healthy")
            .get(key)
            .map(|payload| payload.bytes().clone())
    }
}

#[async_trait]
impl ImmutableBlobStore for RecordingBlobStore {
    async fn put_if_absent(&self, payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        if let Some(kind) = self.failure {
            return Err(BlobStoreError::new(kind));
        }
        let key = payload.descriptor().key().as_str().to_owned();
        let mut objects = self.objects.lock().expect("blob lock is healthy");
        match objects.get(&key) {
            Some(existing) if existing == &payload => Ok(PutBlobOutcome::AlreadyPresent),
            Some(_) => Err(BlobStoreError::new(BlobStoreErrorKind::Conflict)),
            None => {
                objects.insert(key, payload);
                Ok(PutBlobOutcome::Created)
            }
        }
    }

    async fn get_verified(
        &self,
        descriptor: &BlobDescriptor,
        maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        if descriptor.size() > maximum_bytes {
            return Err(BlobStoreError::new(BlobStoreErrorKind::TooLarge));
        }
        let objects = self.objects.lock().expect("blob lock is healthy");
        let payload = objects
            .get(descriptor.key().as_str())
            .ok_or_else(|| BlobStoreError::new(BlobStoreErrorKind::NotFound))?;
        if payload.descriptor() != descriptor {
            return Err(BlobStoreError::new(BlobStoreErrorKind::Integrity));
        }
        Ok(VerifiedBlob::from_payload(payload.clone()))
    }
}

#[derive(Debug)]
struct RepositoryUnavailable;

impl fmt::Display for RepositoryUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test repository unavailable")
    }
}

impl Error for RepositoryUnavailable {}

#[derive(Debug, Default)]
struct RecordingDeliveryAcceptance {
    calls: AtomicUsize,
    deliveries: Mutex<BTreeMap<(String, Uuid, String), RecordedDelivery>>,
}

#[derive(Clone, Debug)]
struct RecordedDelivery {
    request: AcceptManifestPinnedGithubDelivery,
    receipt: ManifestPinnedGithubDeliveryReceipt,
}

fn fixture_manifest_receipt(
    request: &AcceptManifestPinnedGithubDelivery,
    delivery_id: ProviderDeliveryId,
    ordinal: u128,
) -> ManifestPinnedGithubDeliveryReceipt {
    let delivery = request.delivery();
    let identity = delivery.identity();
    let (manifest, checks_authority, repository_contents_authority) = fixture_manifest_authorities(
        identity,
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        ordinal,
    );
    let check_subject_id =
        GithubCheckSubjectId::from_uuid(Uuid::from_u128(200 + ordinal)).expect("check subject");
    let pull_requests_authority = (request.authenticated_event().kind()
        == GithubAuthenticatedEventKind::PullRequest)
        .then(|| {
            GithubServerServiceAuthoritySelector::from_durable_parts(
                identity.tenant().clone(),
                GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(500 + ordinal))
                    .expect("pull-requests authority"),
                Sha256Digest::from_bytes([0x63; 32]),
                checks_authority.app_configuration_revision(),
                checks_authority.policy_revision(),
            )
        });
    let evidence =
        ManifestPinnedGithubDeliveryEvidence::from_durable_parts_with_pull_requests_authority(
            delivery_id,
            request.repository_owner_id(),
            manifest,
            request.authenticated_webhook_verifier_fingerprint(),
            request.authenticated_webhook_verifier_revision(),
            checks_authority,
            repository_contents_authority,
            pull_requests_authority,
            check_subject_id,
            request.head_sha(),
            request.authenticated_event().clone(),
            request.check_kind(),
            delivery.accepted_at(),
        )
        .expect("manifest evidence");
    ManifestPinnedGithubDeliveryReceipt::from_durable_parts(evidence)
}

fn fixture_manifest_authorities(
    identity: &ProviderDeliveryIdentity,
    webhook_fingerprint: automata_ci_store::GithubProviderWebhookVerifierFingerprint,
    webhook_revision: GithubServerServiceRevision,
    ordinal: u128,
) -> (
    GithubProviderManifest,
    GithubServerServiceAuthoritySelector,
    GithubServerServiceAuthoritySelector,
) {
    let app_revision = GithubServerServiceRevision::new(1).expect("App revision");
    let policy_revision = GithubServerServiceRevision::new(1).expect("policy revision");
    let runtime_policy = fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        identity.tenant().clone(),
        identity.connection_id(),
        identity.installation_id(),
        identity.repository_id(),
        GithubRepositoryName::new(identity.repository_identity().to_owned())
            .expect("repository name"),
        identity.repository_visibility(),
        GithubServerServiceAppId::new(42).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.delivery-fixture").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x51; 32]),
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
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    );
    let checks_authority = fixture_authority_selector(
        identity.tenant(),
        Uuid::from_u128(300 + ordinal),
        [0x61; 32],
        app_revision,
        policy_revision,
    );
    let repository_contents_authority = fixture_authority_selector(
        identity.tenant(),
        Uuid::from_u128(400 + ordinal),
        [0x62; 32],
        app_revision,
        policy_revision,
    );
    (manifest, checks_authority, repository_contents_authority)
}

fn fixture_authority_selector(
    tenant: &TenantScope,
    authority_id: Uuid,
    identity_digest: [u8; 32],
    app_revision: GithubServerServiceRevision,
    policy_revision: GithubServerServiceRevision,
) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(authority_id).expect("fixture authority"),
        Sha256Digest::from_bytes(identity_digest),
        app_revision,
        policy_revision,
    )
}

impl RecordingDeliveryAcceptance {
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn entry_count(&self) -> usize {
        self.deliveries
            .lock()
            .expect("acceptance lock is healthy")
            .len()
    }

    fn requests(&self) -> Vec<AcceptManifestPinnedGithubDelivery> {
        self.deliveries
            .lock()
            .expect("acceptance lock is healthy")
            .values()
            .map(|delivery| delivery.request.clone())
            .collect()
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for RecordingDeliveryAcceptance {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let delivery = request.delivery();
        let key = (
            delivery.identity().provider().to_owned(),
            delivery.identity().connection_id().as_uuid(),
            delivery.identity().delivery_id().to_owned(),
        );
        let mut deliveries = self.deliveries.lock().expect("acceptance lock is healthy");
        match deliveries.get(&key) {
            Some(existing)
                if existing.request.delivery().identity() == request.delivery().identity()
                    && existing.request.delivery().request_digest()
                        == request.delivery().request_digest()
                    && existing.request.delivery().raw_event()
                        == request.delivery().raw_event()
                    && existing.request.repository_owner_id() == request.repository_owner_id()
                    && existing.request.head_sha() == request.head_sha()
                    && existing.request.authenticated_event() == request.authenticated_event()
                    && existing
                        .request
                        .authenticated_webhook_verifier_fingerprint()
                        == request.authenticated_webhook_verifier_fingerprint()
                    && existing.request.authenticated_webhook_verifier_revision()
                        == request.authenticated_webhook_verifier_revision() =>
            {
                Ok(existing.receipt.clone())
            }
            Some(_) => Err(GithubSubjectEvidenceStoreError::ReplayConflict),
            None => {
                let ordinal = u128::try_from(deliveries.len())
                    .expect("bounded fixture delivery count fits u128")
                    + 1;
                let id = ProviderDeliveryId::from_uuid(Uuid::from_u128(ordinal))
                    .expect("one-based fixture UUID is non-nil");
                let receipt = fixture_manifest_receipt(&request, id, ordinal);
                deliveries.insert(
                    key,
                    RecordedDelivery {
                        request,
                        receipt: receipt.clone(),
                    },
                );
                Ok(receipt)
            }
        }
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        _tenant: &TenantScope,
        _delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        panic!("evidence loading is outside delivery ingress")
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        _tenant: &TenantScope,
        _repository_id: RepositoryId,
        _run_id: automata_ci_core::RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        panic!("run evidence is outside delivery ingress")
    }
}

#[derive(Debug, Default)]
struct RecordingRepositoryDispatchAcceptance {
    calls: AtomicUsize,
    deliveries: Mutex<BTreeMap<(String, Uuid, String), RecordedRepositoryDispatch>>,
}

#[derive(Debug, Default)]
struct RecordingCheckReruns {
    requests: Mutex<Vec<GithubCheckRerunRequest>>,
}

impl RecordingCheckReruns {
    fn requests(&self) -> Vec<GithubCheckRerunRequest> {
        self.requests.lock().expect("rerun lock is healthy").clone()
    }
}

#[async_trait]
impl GithubCheckRerunRepository for RecordingCheckReruns {
    async fn rerun_github_check(
        &self,
        request: GithubCheckRerunRequest,
    ) -> Result<Vec<WorkflowRerunReceipt>, GithubCheckRerunStoreError> {
        self.requests
            .lock()
            .expect("rerun lock is healthy")
            .push(request);
        Ok(vec![
            WorkflowRerunReceipt::new(
                RunId::from_uuid(Uuid::from_u128(0x100)),
                RunId::from_uuid(Uuid::from_u128(0x101)),
                11,
                12,
                2,
                false,
            )
            .expect("rerun receipt"),
        ])
    }
}

#[derive(Clone, Debug)]
struct RecordedRepositoryDispatch {
    identity: ProviderDeliveryIdentity,
    request_digest: Sha256Digest,
    raw_event: AdmissionObject,
    repository_owner_id: ProviderRepositoryOwnerId,
    event: automata_ci_store::GithubAuthenticatedEvent,
    verifier_fingerprint: automata_ci_store::GithubProviderWebhookVerifierFingerprint,
    verifier_revision: GithubServerServiceRevision,
    receipt: PendingGithubRepositoryDispatchReceipt,
}

impl RecordingRepositoryDispatchAcceptance {
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn fixture_repository_dispatch_receipt(
    request: &AcceptManifestPinnedGithubRepositoryDispatch,
    delivery_id: ProviderDeliveryId,
    ordinal: u128,
) -> PendingGithubRepositoryDispatchReceipt {
    let delivery = request.delivery();
    let (manifest, checks_authority, repository_contents_authority) = fixture_manifest_authorities(
        delivery.identity(),
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        ordinal,
    );
    let evidence = PendingGithubRepositoryDispatchEvidence::from_durable_parts(
        delivery_id,
        request.repository_owner_id(),
        manifest,
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        checks_authority,
        repository_contents_authority,
        request.event().clone(),
        delivery.accepted_at(),
    )
    .expect("pending repository dispatch evidence");
    PendingGithubRepositoryDispatchReceipt::from_durable_parts(evidence)
}

#[async_trait]
impl GithubRepositoryDispatchEvidenceRepository for RecordingRepositoryDispatchAcceptance {
    async fn accept_manifest_pinned_github_repository_dispatch(
        &self,
        request: AcceptManifestPinnedGithubRepositoryDispatch,
    ) -> Result<PendingGithubRepositoryDispatchReceipt, GithubSubjectEvidenceStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let delivery = request.delivery();
        let key = (
            delivery.identity().provider().to_owned(),
            delivery.identity().connection_id().as_uuid(),
            delivery.identity().delivery_id().to_owned(),
        );
        let mut deliveries = self.deliveries.lock().expect("dispatch lock is healthy");
        match deliveries.get(&key) {
            Some(existing)
                if existing.identity == *delivery.identity()
                    && existing.request_digest == delivery.request_digest()
                    && existing.raw_event == *delivery.raw_event()
                    && existing.repository_owner_id == request.repository_owner_id()
                    && existing.event == *request.event()
                    && existing.verifier_fingerprint
                        == request.authenticated_webhook_verifier_fingerprint()
                    && existing.verifier_revision
                        == request.authenticated_webhook_verifier_revision() =>
            {
                Ok(existing.receipt.clone())
            }
            Some(_) => Err(GithubSubjectEvidenceStoreError::ReplayConflict),
            None => {
                let ordinal = u128::try_from(deliveries.len())
                    .expect("bounded fixture delivery count fits u128")
                    + 1;
                let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(0x700 + ordinal))
                    .expect("fixture dispatch UUID");
                let receipt = fixture_repository_dispatch_receipt(&request, delivery_id, ordinal);
                deliveries.insert(
                    key,
                    RecordedRepositoryDispatch {
                        identity: delivery.identity().clone(),
                        request_digest: delivery.request_digest(),
                        raw_event: delivery.raw_event().clone(),
                        repository_owner_id: request.repository_owner_id(),
                        event: request.event().clone(),
                        verifier_fingerprint: request.authenticated_webhook_verifier_fingerprint(),
                        verifier_revision: request.authenticated_webhook_verifier_revision(),
                        receipt: receipt.clone(),
                    },
                );
                Ok(receipt)
            }
        }
    }

    async fn load_pending_github_repository_dispatch_evidence(
        &self,
        tenant: &TenantScope,
        delivery_id: ProviderDeliveryId,
    ) -> Result<PendingGithubRepositoryDispatchEvidence, GithubSubjectEvidenceStoreError> {
        self.deliveries
            .lock()
            .expect("dispatch lock is healthy")
            .values()
            .find(|delivery| {
                delivery.receipt.evidence().tenant() == tenant
                    && delivery.receipt.delivery_id() == delivery_id
            })
            .map(|delivery| delivery.receipt.evidence().clone())
            .ok_or(GithubSubjectEvidenceStoreError::NotFound)
    }

    async fn resolve_github_repository_dispatch(
        &self,
        _request: ResolveGithubRepositoryDispatch,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        panic!("resolution is outside delivery ingress")
    }
}

#[derive(Debug, Default)]
struct UnavailableProviderRepository {
    calls: AtomicUsize,
}

impl UnavailableProviderRepository {
    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ProviderDeliveryRepository for UnavailableProviderRepository {
    async fn accept_provider_delivery(
        &self,
        _request: AcceptProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ProviderDeliveryStoreError::operation(RepositoryUnavailable))
    }

    async fn claim_provider_delivery(
        &self,
        _request: ClaimProviderDelivery,
    ) -> Result<Option<ClaimedProviderDelivery>, ProviderDeliveryStoreError> {
        panic!("claim is outside delivery ingress")
    }

    async fn complete_provider_delivery(
        &self,
        _request: CompleteProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        panic!("completion is outside delivery ingress")
    }

    async fn retry_provider_delivery(
        &self,
        _request: RetryProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        panic!("retry is outside delivery ingress")
    }

    async fn reject_provider_delivery(
        &self,
        _request: RejectProviderDelivery,
    ) -> Result<ProviderDeliveryReceipt, ProviderDeliveryStoreError> {
        panic!("rejection is outside delivery ingress")
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for UnavailableProviderRepository {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        _request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(GithubSubjectEvidenceStoreError::operation(
            RepositoryUnavailable,
        ))
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        _tenant: &TenantScope,
        _delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        panic!("evidence loading is outside delivery ingress")
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        _tenant: &TenantScope,
        _repository_id: RepositoryId,
        _run_id: automata_ci_core::RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        panic!("run evidence is outside delivery ingress")
    }
}

fn connection(
    visibility: ProviderRepositoryVisibility,
    owner: &str,
    name: &str,
) -> Result<GithubDeliveryConnection, GithubDeliveryConfigurationError> {
    configured_connection(
        "tenant-private",
        CONNECTION_UUID,
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER_ID,
        visibility,
        owner,
        name,
    )
}

#[allow(clippy::too_many_arguments)]
fn configured_connection(
    tenant: &str,
    connection_id: Uuid,
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    visibility: ProviderRepositoryVisibility,
    owner: &str,
    name: &str,
) -> Result<GithubDeliveryConnection, GithubDeliveryConfigurationError> {
    GithubDeliveryConnection::new(
        TenantScope::from_authenticated_tenant_id(tenant).expect("fixture tenant is valid"),
        ProviderConnectionId::from_uuid(connection_id).expect("fixture connection is non-nil"),
        ProviderInstallationId::new(installation_id).expect("fixture installation is positive"),
        ProviderRepositoryId::new(repository_id).expect("fixture repository is positive"),
        ProviderRepositoryOwnerId::new(repository_owner_id)
            .expect("fixture repository owner is positive"),
        visibility,
        owner,
        name,
    )
}

fn registry(
    connections: Vec<GithubDeliveryConnection>,
) -> Result<GithubDeliveryIngress, GithubDeliveryConfigurationError> {
    GithubDeliveryIngress::new(
        GithubWebhookVerifier::new(SECRET).expect("fixture secret is valid"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        connections,
        Arc::new(RecordingBlobStore::default()),
        GithubDeliveryRepositories::new(Arc::new(RecordingDeliveryAcceptance::default())),
        Arc::new(FixedClock(UnixMillis::new(100))),
    )
}

fn ingress_for_connections(
    secret: &[u8],
    connections: Vec<GithubDeliveryConnection>,
    objects: Arc<RecordingBlobStore>,
    deliveries: Arc<dyn GithubSubjectEvidenceRepository>,
    clock: Arc<dyn GithubDeliveryClock>,
) -> GithubDeliveryIngress {
    ingress_for_connections_at_revision(secret, 1, connections, objects, deliveries, clock)
}

fn ingress_for_connections_at_revision(
    secret: &[u8],
    verifier_revision: u64,
    connections: Vec<GithubDeliveryConnection>,
    objects: Arc<RecordingBlobStore>,
    deliveries: Arc<dyn GithubSubjectEvidenceRepository>,
    clock: Arc<dyn GithubDeliveryClock>,
) -> GithubDeliveryIngress {
    GithubDeliveryIngress::new(
        GithubWebhookVerifier::new(secret).expect("fixture secret is valid"),
        GithubServerServiceRevision::new(verifier_revision).expect("verifier revision"),
        connections,
        objects,
        GithubDeliveryRepositories::new(deliveries),
        clock,
    )
    .expect("fixture registry is valid")
}

fn ingress(
    secret: &[u8],
    objects: Arc<RecordingBlobStore>,
    deliveries: Arc<RecordingDeliveryAcceptance>,
    clock: Arc<dyn GithubDeliveryClock>,
) -> GithubDeliveryIngress {
    ingress_for_connections(
        secret,
        vec![
            connection(
                ProviderRepositoryVisibility::Private,
                "octo-private",
                "private-repository",
            )
            .expect("fixture connection is valid")
            .with_default_branch_ref("refs/heads/main")
            .expect("fixture default branch is valid"),
        ],
        objects,
        deliveries,
        clock,
    )
}

fn push_body(
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    owner: &str,
    name: &str,
    commits: &str,
) -> Bytes {
    push_body_with_visibility(
        installation_id,
        repository_id,
        repository_owner_id,
        owner,
        name,
        commits,
        ProviderRepositoryVisibility::Private,
    )
}

fn push_body_with_visibility(
    installation_id: u64,
    repository_id: u64,
    repository_owner_id: u64,
    owner: &str,
    name: &str,
    commits: &str,
    visibility: ProviderRepositoryVisibility,
) -> Bytes {
    let (private, visibility) = match visibility {
        ProviderRepositoryVisibility::Public => (false, "public"),
        ProviderRepositoryVisibility::Private => (true, "private"),
    };
    Bytes::from(format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE_COMMIT}","after":"{AFTER_COMMIT}","created":false,"deleted":false,"forced":false,"repository":{{"id":{repository_id},"private":{private},"visibility":"{visibility}","name":"{name}","full_name":"{owner}/{name}","owner":{{"id":{repository_owner_id},"login":"{owner}"}}}},"installation":{{"id":{installation_id}}},"commits":{commits}}}"#
    ))
}

fn check_run_control_body() -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"requested_action","requested_action":{{"identifier":"rerun_failed"}},"check_run":{{"id":66,"head_sha":"{AFTER_COMMIT}","external_id":"automata-check:00000000-0000-4000-8000-000000000123","status":"completed","conclusion":"failure","app":{{"id":88}},"check_suite":{{"id":77,"head_sha":"{AFTER_COMMIT}"}}}},"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"private-repository","full_name":"octo-private/private-repository","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"octo-private"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ))
}

fn pull_request_body(action: &str, merged: bool) -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"{action}","number":7,"pull_request":{{"number":7,"merged":{merged},"draft":false,"merge_commit_sha":"{PULL_REQUEST_MERGE_COMMIT}","head":{{"ref":"feature/topic","sha":"{AFTER_COMMIT}","repo":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"private-repository","full_name":"octo-private/private-repository","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"octo-private"}}}}}},"base":{{"ref":"main","sha":"{BEFORE_COMMIT}","repo":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"private-repository","full_name":"octo-private/private-repository","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"octo-private"}}}}}}}},"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"private-repository","full_name":"octo-private/private-repository","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"octo-private"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ))
}

fn merge_group_body() -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"checks_requested","merge_group":{{"head_sha":"{AFTER_COMMIT}","head_ref":"refs/heads/merge-queue/main/group-7","base_sha":"{BEFORE_COMMIT}","base_ref":"refs/heads/main","head_commit":{{}}}},"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","name":"private-repository","full_name":"octo-private/private-repository","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"octo-private"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ))
}

fn repository_dispatch_body(branch: &str, sequence: u64) -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"synthetic_signal","branch":"{branch}","client_payload":{{"sequence":{sequence}}},"repository":{{"id":{REPOSITORY_ID},"private":true,"visibility":"private","default_branch":"{branch}","name":"private-repository","full_name":"octo-private/private-repository","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"octo-private"}}}},"installation":{{"id":{INSTALLATION_ID}}},"sender":{{"id":301}}}}"#
    ))
}

fn bounded_connections(count: usize) -> Vec<GithubDeliveryConnection> {
    (0..count)
        .rev()
        .map(|index| {
            let ordinal = u64::try_from(index).expect("fixture count fits u64") + 1;
            let tenant = format!("tenant-{ordinal}");
            let repository = format!("repository-{ordinal}");
            configured_connection(
                &tenant,
                Uuid::from_u128(u128::from(ordinal) + 1_000),
                20_000,
                30_000 + ordinal,
                40_000,
                if ordinal % 2 == 0 {
                    ProviderRepositoryVisibility::Public
                } else {
                    ProviderRepositoryVisibility::Private
                },
                "octo",
                &repository,
            )
            .expect("bounded fixture connection")
        })
        .collect()
}

#[test]
fn registry_requires_a_closed_nonempty_bound_and_sorts_immutable_connections() {
    assert_eq!(
        registry(Vec::new()).unwrap_err(),
        GithubDeliveryConfigurationError::EmptyConnectionRegistry
    );
    assert_eq!(
        registry(bounded_connections(MAX_GITHUB_DELIVERY_CONNECTIONS + 1)).unwrap_err(),
        GithubDeliveryConfigurationError::TooManyConnections
    );

    let ingress = registry(bounded_connections(MAX_GITHUB_DELIVERY_CONNECTIONS))
        .expect("exact registry ceiling");
    assert_eq!(ingress.connections().len(), MAX_GITHUB_DELIVERY_CONNECTIONS);
    assert_eq!(ingress.connections()[0].repository_id().get(), 30_001);
    assert_eq!(
        ingress.connections()[MAX_GITHUB_DELIVERY_CONNECTIONS - 1]
            .repository_id()
            .get(),
        30_000 + u64::try_from(MAX_GITHUB_DELIVERY_CONNECTIONS).expect("limit fits u64")
    );
    assert!(ingress.connections().windows(2).all(|pair| {
        (pair[0].installation_id(), pair[0].repository_id())
            < (pair[1].installation_id(), pair[1].repository_id())
    }));
}

#[test]
fn registry_rejects_every_ambiguous_connection_identity() {
    let configured = |connection_id, installation_id, repository_id, owner, name| {
        configured_connection(
            "tenant-registry",
            connection_id,
            installation_id,
            repository_id,
            40_000,
            ProviderRepositoryVisibility::Private,
            owner,
            name,
        )
        .expect("duplicate fixture connection")
    };

    assert_eq!(
        registry(vec![
            configured(Uuid::from_u128(1), 10, 20, "octo", "one"),
            configured(Uuid::from_u128(1), 10, 21, "octo", "two"),
        ])
        .unwrap_err(),
        GithubDeliveryConfigurationError::DuplicateConnectionId
    );
    assert_eq!(
        registry(vec![
            configured(Uuid::from_u128(1), 10, 20, "octo", "one"),
            configured(Uuid::from_u128(2), 10, 20, "octo", "two"),
        ])
        .unwrap_err(),
        GithubDeliveryConfigurationError::DuplicateRepositorySelector
    );
    assert_eq!(
        registry(vec![
            configured(Uuid::from_u128(1), 10, 20, "octo", "one"),
            configured(Uuid::from_u128(2), 11, 20, "octo", "two"),
        ])
        .unwrap_err(),
        GithubDeliveryConfigurationError::DuplicateRepositoryId
    );
    assert_eq!(
        registry(vec![
            configured(Uuid::from_u128(1), 10, 20, "octo", "one"),
            configured(Uuid::from_u128(2), 11, 21, "octo", "one"),
        ])
        .unwrap_err(),
        GithubDeliveryConfigurationError::DuplicateRepositoryIdentity
    );
}

#[tokio::test]
async fn signed_public_visibility_is_persisted_in_delivery_identity() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress_for_connections(
        SECRET,
        vec![
            connection(
                ProviderRepositoryVisibility::Public,
                "octo-private",
                "private-repository",
            )
            .expect("fixture public connection"),
        ],
        objects,
        deliveries.clone(),
        Arc::new(FixedClock(UnixMillis::new(100))),
    );
    let body = push_body_with_visibility(
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER_ID,
        "octo-private",
        "private-repository",
        "[]",
        ProviderRepositoryVisibility::Public,
    );
    let headers = signed_headers(SECRET, &body, "delivery-public-visibility");

    ingress
        .accept(&headers, body)
        .await
        .expect("signed public delivery");
    let requests = deliveries.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].delivery().identity().repository_visibility(),
        ProviderRepositoryVisibility::Public
    );
    assert_eq!(requests[0].repository_owner_id().get(), REPOSITORY_OWNER_ID);
    assert_eq!(
        requests[0]
            .authenticated_webhook_verifier_fingerprint()
            .sha256()
            .as_bytes(),
        GithubWebhookVerifier::new(SECRET)
            .expect("verifier")
            .fingerprint()
            .as_bytes()
    );
    assert_eq!(
        requests[0].authenticated_webhook_verifier_revision().get(),
        1
    );
}

fn assert_routed_request(
    requests: &[AcceptManifestPinnedGithubDelivery],
    delivery_id: &str,
    tenant: &str,
    connection_id: Uuid,
    visibility: ProviderRepositoryVisibility,
    repository_owner_id: u64,
) {
    let request = requests
        .iter()
        .find(|request| request.delivery().identity().delivery_id() == delivery_id)
        .expect("routed request");
    assert_eq!(request.delivery().identity().tenant().as_str(), tenant);
    assert_eq!(
        request.delivery().identity().connection_id().as_uuid(),
        connection_id
    );
    assert_eq!(
        request.delivery().identity().repository_visibility(),
        visibility
    );
    assert_eq!(request.repository_owner_id().get(), repository_owner_id);
    assert_eq!(
        request
            .authenticated_webhook_verifier_fingerprint()
            .sha256()
            .as_bytes(),
        GithubWebhookVerifier::new(SECRET)
            .expect("fixture verifier")
            .fingerprint()
            .as_bytes()
    );
    assert_eq!(request.authenticated_webhook_verifier_revision().get(), 1);
}

#[tokio::test]
async fn one_verifier_dispatches_mixed_public_and_private_repositories_exactly() {
    const PUBLIC_CONNECTION_UUID: Uuid = Uuid::from_u128(2);
    const PUBLIC_INSTALLATION_ID: u64 = 100;
    const PUBLIC_REPOSITORY_ID: u64 = 200;
    const PUBLIC_OWNER_ID: u64 = 300;

    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let public = configured_connection(
        "tenant-public",
        PUBLIC_CONNECTION_UUID,
        PUBLIC_INSTALLATION_ID,
        PUBLIC_REPOSITORY_ID,
        PUBLIC_OWNER_ID,
        ProviderRepositoryVisibility::Public,
        "octo-public",
        "public-repository",
    )
    .expect("public connection");
    let private = connection(
        ProviderRepositoryVisibility::Private,
        "octo-private",
        "private-repository",
    )
    .expect("private connection");
    let ingress = ingress_for_connections(
        SECRET,
        vec![private, public],
        Arc::clone(&objects),
        deliveries.clone(),
        Arc::new(IncrementingClock::new(100)),
    );
    assert_eq!(
        ingress.connections()[0].repository_visibility(),
        ProviderRepositoryVisibility::Public
    );
    assert_eq!(
        ingress.connections()[1].repository_visibility(),
        ProviderRepositoryVisibility::Private
    );

    let public_body = push_body_with_visibility(
        PUBLIC_INSTALLATION_ID,
        PUBLIC_REPOSITORY_ID,
        PUBLIC_OWNER_ID,
        "octo-public",
        "public-repository",
        "[]",
        ProviderRepositoryVisibility::Public,
    );
    ingress
        .accept(
            &signed_headers(SECRET, &public_body, "delivery-public"),
            public_body,
        )
        .await
        .expect("public repository delivery");
    let private_body = fixture_body();
    ingress
        .accept(
            &signed_headers(SECRET, &private_body, "delivery-private"),
            private_body,
        )
        .await
        .expect("private repository delivery");

    let requests = deliveries.requests();
    assert_routed_request(
        &requests,
        "delivery-public",
        "tenant-public",
        PUBLIC_CONNECTION_UUID,
        ProviderRepositoryVisibility::Public,
        PUBLIC_OWNER_ID,
    );
    assert_routed_request(
        &requests,
        "delivery-private",
        "tenant-private",
        CONNECTION_UUID,
        ProviderRepositoryVisibility::Private,
        REPOSITORY_OWNER_ID,
    );
    assert_eq!(objects.object_count(), 2);
    assert_eq!(deliveries.call_count(), 2);
}

#[tokio::test]
async fn repository_dispatch_ingress_pins_raw_event_authority_and_exact_replay() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let dispatches = Arc::new(RecordingRepositoryDispatchAcceptance::default());
    let configured = connection(
        ProviderRepositoryVisibility::Private,
        "octo-private",
        "private-repository",
    )
    .expect("fixture connection")
    .with_default_branch_ref("refs/heads/main")
    .expect("configured default branch");
    let ingress = GithubDeliveryIngress::new(
        GithubWebhookVerifier::new(SECRET).expect("fixture verifier"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        vec![configured],
        objects.clone(),
        GithubDeliveryRepositories::new(deliveries.clone())
            .with_repository_dispatches(dispatches.clone()),
        Arc::new(FixedClock(UnixMillis::new(100))),
    )
    .expect("dispatch ingress");
    let body = repository_dispatch_body("main", 3);
    let headers = signed_event_headers(
        SECRET,
        &body,
        "repository_dispatch",
        "delivery-repository-dispatch",
    );

    let accepted = ingress
        .accept_repository_dispatch(&headers, body.clone())
        .await
        .expect("repository dispatch accepted");
    let replay = ingress
        .accept_repository_dispatch(&headers, body.clone())
        .await
        .expect("exact repository dispatch replay");

    assert_eq!(accepted.receipt(), replay.receipt());
    assert_eq!(accepted.request_digest(), replay.request_digest());
    assert_eq!(accepted.raw_event(), replay.raw_event());
    assert_eq!(
        accepted.receipt().evidence().event().kind(),
        GithubAuthenticatedEventKind::RepositoryDispatch
    );
    assert_eq!(
        accepted.receipt().evidence().event().git_ref(),
        "refs/heads/main"
    );
    assert_eq!(
        accepted
            .receipt()
            .evidence()
            .repository_contents_authority()
            .tenant(),
        accepted.receipt().evidence().tenant()
    );
    assert_eq!(
        accepted.raw_event().media_type(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
    );
    assert_eq!(
        objects
            .bytes_at(accepted.raw_event().object_key().as_str())
            .expect("authenticated raw event"),
        body
    );
    assert_eq!(objects.object_count(), 1);
    assert_eq!(deliveries.call_count(), 0);
    assert_eq!(dispatches.call_count(), 2);

    let changed_body = repository_dispatch_body("main", 4);
    let changed_headers = signed_event_headers(
        SECRET,
        &changed_body,
        "repository_dispatch",
        "delivery-repository-dispatch",
    );
    assert_eq!(
        ingress
            .accept_repository_dispatch(&changed_headers, changed_body)
            .await,
        Err(GithubDeliveryIngressError::ReplayConflict)
    );
    assert_eq!(dispatches.call_count(), 3);
    assert_eq!(objects.object_count(), 2);
}

#[tokio::test]
async fn check_run_control_preserves_exact_signed_identity_for_rerun_authorization() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let dispatches = Arc::new(RecordingRepositoryDispatchAcceptance::default());
    let reruns = Arc::new(RecordingCheckReruns::default());
    let configured = connection(
        ProviderRepositoryVisibility::Private,
        "octo-private",
        "private-repository",
    )
    .expect("fixture connection")
    .with_default_branch_ref("refs/heads/main")
    .expect("configured default branch");
    let ingress = GithubDeliveryIngress::new(
        GithubWebhookVerifier::new(SECRET).expect("fixture verifier"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        vec![configured],
        objects.clone(),
        GithubDeliveryRepositories::new(deliveries.clone())
            .with_repository_dispatches(dispatches)
            .with_check_reruns(reruns.clone()),
        Arc::new(FixedClock(UnixMillis::new(100))),
    )
    .expect("control ingress");
    let body = check_run_control_body();
    let headers = signed_event_headers(SECRET, &body, "check_run", "delivery-check-control");

    assert_eq!(
        ingress
            .accept_check_rerun(&headers, body)
            .await
            .expect("control accepted"),
        1
    );
    let requests = reruns.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.tenant().as_str(), "tenant-private");
    assert_eq!(request.connection_id().as_uuid(), CONNECTION_UUID);
    assert_eq!(request.installation_id(), INSTALLATION_ID);
    assert_eq!(request.github_repository_id(), REPOSITORY_ID);
    assert_eq!(request.app_id().get(), 88);
    assert_eq!(request.sender_id(), 301);
    assert_eq!(request.delivery_id(), "delivery-check-control");
    assert!(matches!(
        request.target(),
        GithubCheckRerunTarget::Run {
            run_id,
            suite_id,
            action: automata_ci_store::GithubCheckRerunAction::RerunFailed,
            ..
        } if run_id.get() == 66 && suite_id.get() == 77
    ));
    assert_eq!(objects.put_count(), 0);
    assert_eq!(deliveries.call_count(), 0);
}

#[tokio::test]
async fn repository_dispatch_default_branch_mismatch_performs_no_writes() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let dispatches = Arc::new(RecordingRepositoryDispatchAcceptance::default());
    let configured = connection(
        ProviderRepositoryVisibility::Private,
        "octo-private",
        "private-repository",
    )
    .expect("fixture connection")
    .with_default_branch_ref("refs/heads/main")
    .expect("configured default branch");
    let ingress = GithubDeliveryIngress::new(
        GithubWebhookVerifier::new(SECRET).expect("fixture verifier"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        vec![configured],
        objects.clone(),
        GithubDeliveryRepositories::new(deliveries.clone())
            .with_repository_dispatches(dispatches.clone()),
        Arc::new(FixedClock(UnixMillis::new(100))),
    )
    .expect("dispatch ingress");
    let body = repository_dispatch_body("release", 3);
    let headers = signed_event_headers(
        SECRET,
        &body,
        "repository_dispatch",
        "delivery-wrong-default-branch",
    );

    assert_eq!(
        ingress.accept_repository_dispatch(&headers, body).await,
        Err(GithubDeliveryIngressError::ConfiguredIdentityMismatch)
    );
    assert_eq!(objects.put_count(), 0);
    assert_eq!(deliveries.call_count(), 0);
    assert_eq!(dispatches.call_count(), 0);
}

fn fixture_body() -> Bytes {
    push_body(
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER_ID,
        "octo-private",
        "private-repository",
        "[]",
    )
}

fn signed_headers(secret: &[u8], body: &[u8], delivery_id: &str) -> HeaderMap {
    signed_event_headers(secret, body, "push", delivery_id)
}

fn signed_event_headers(
    secret: &[u8],
    body: &[u8],
    event_name: &str,
    delivery_id: &str,
) -> HeaderMap {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    let mut signature = String::from("sha256=");
    for byte in tag.as_ref() {
        write!(&mut signature, "{byte:02x}").expect("writing to a string cannot fail");
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_str(&signature).expect("fixture signature is a header value"),
    );
    headers.insert(
        X_GITHUB_EVENT,
        HeaderValue::from_str(event_name).expect("fixture event is a header value"),
    );
    headers.insert(
        X_GITHUB_DELIVERY,
        HeaderValue::from_str(delivery_id).expect("fixture delivery is a header value"),
    );
    headers
}

#[tokio::test]
async fn hmac_and_header_failures_perform_no_writes() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        objects.clone(),
        deliveries.clone(),
        Arc::new(FixedClock(UnixMillis::new(100))),
    );
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-auth-failure");
    let mut changed_body = body.to_vec();
    changed_body.push(b' ');

    assert_eq!(
        ingress.accept(&headers, Bytes::from(changed_body)).await,
        Err(GithubDeliveryIngressError::Webhook(
            GithubWebhookError::AuthenticationFailed
        ))
    );

    let mut duplicate_headers = headers;
    duplicate_headers.append(
        X_GITHUB_DELIVERY,
        HeaderValue::from_static("duplicate-delivery"),
    );
    assert_eq!(
        ingress.accept(&duplicate_headers, body).await,
        Err(GithubDeliveryIngressError::Webhook(
            GithubWebhookError::InvalidHeaders
        ))
    );
    assert_eq!(objects.put_count(), 0);
    assert_eq!(deliveries.call_count(), 0);
}

#[tokio::test]
async fn oversized_body_is_rejected_before_authentication_or_writes() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(100))),
    );
    let body = Bytes::from(vec![b'x'; MAX_GITHUB_WEBHOOK_BODY_BYTES + 1]);
    let headers = signed_headers(SECRET, b"not-the-body", "delivery-too-large");

    assert_eq!(
        ingress.accept(&headers, body).await,
        Err(GithubDeliveryIngressError::Webhook(
            GithubWebhookError::BodyTooLarge
        ))
    );
    assert_eq!(objects.put_count(), 0);
    assert_eq!(deliveries.call_count(), 0);
}

#[tokio::test]
async fn exact_body_ceiling_is_published_and_accepted_without_narrowing() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(100))),
    );
    let base = fixture_body();
    let mut body = Vec::with_capacity(MAX_GITHUB_WEBHOOK_BODY_BYTES);
    body.extend_from_slice(
        base.strip_suffix(b"}")
            .expect("push fixture is one JSON object"),
    );
    body.extend_from_slice(b",\"padding\":\"");
    body.resize(MAX_GITHUB_WEBHOOK_BODY_BYTES - 2, b'x');
    body.extend_from_slice(b"\"}");
    assert_eq!(body.len(), MAX_GITHUB_WEBHOOK_BODY_BYTES);
    let body = Bytes::from(body);
    let headers = signed_headers(SECRET, &body, "delivery-exact-body-limit");

    let accepted = ingress
        .accept(&headers, body)
        .await
        .expect("exact ingress ceiling");
    assert_eq!(
        accepted.raw_event().encoded_size(),
        u64::try_from(MAX_GITHUB_WEBHOOK_BODY_BYTES).expect("body ceiling fits u64")
    );
    assert_eq!(objects.object_count(), 1);
    assert_eq!(deliveries.call_count(), 1);
    assert_eq!(
        deliveries.requests()[0]
            .delivery()
            .raw_event()
            .encoded_size(),
        accepted.raw_event().encoded_size()
    );
    assert_eq!(
        objects
            .bytes_at(accepted.raw_event().object_key().as_str())
            .expect("published exact body")
            .len(),
        MAX_GITHUB_WEBHOOK_BODY_BYTES
    );
}

#[tokio::test]
async fn every_configured_identity_drift_is_rejected_before_writes() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(100))),
    );
    let bodies = [
        push_body(
            INSTALLATION_ID + 1,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID,
            "octo-private",
            "private-repository",
            "[]",
        ),
        push_body(
            INSTALLATION_ID,
            REPOSITORY_ID + 1,
            REPOSITORY_OWNER_ID,
            "octo-private",
            "private-repository",
            "[]",
        ),
        push_body(
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID + 1,
            "octo-private",
            "private-repository",
            "[]",
        ),
        push_body(
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID,
            "other-owner",
            "private-repository",
            "[]",
        ),
        push_body(
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID,
            "octo-private",
            "other-repository",
            "[]",
        ),
        push_body_with_visibility(
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID,
            "octo-private",
            "private-repository",
            "[]",
            ProviderRepositoryVisibility::Public,
        ),
    ];

    for (index, body) in bodies.into_iter().enumerate() {
        let headers = signed_headers(SECRET, &body, &format!("delivery-drift-{index}"));
        assert_eq!(
            ingress.accept(&headers, body).await,
            Err(GithubDeliveryIngressError::ConfiguredIdentityMismatch)
        );
    }
    assert_eq!(objects.put_count(), 0);
    assert_eq!(deliveries.call_count(), 0);
}

#[tokio::test]
async fn invalid_trusted_time_is_rejected_before_writes() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(-1))),
    );
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-negative-time");

    assert_eq!(
        ingress.accept(&headers, body).await,
        Err(GithubDeliveryIngressError::InvalidTrustedTime)
    );
    assert_eq!(objects.put_count(), 0);
    assert_eq!(deliveries.call_count(), 0);
}

#[tokio::test]
async fn blob_conflict_and_unavailability_stop_before_inbox_acceptance() {
    for kind in [
        BlobStoreErrorKind::Conflict,
        BlobStoreErrorKind::Unavailable,
    ] {
        let objects = Arc::new(RecordingBlobStore::failing(kind));
        let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
        let ingress = ingress(
            SECRET,
            Arc::clone(&objects),
            Arc::clone(&deliveries),
            Arc::new(FixedClock(UnixMillis::new(100))),
        );
        let body = fixture_body();
        let headers = signed_headers(SECRET, &body, "delivery-blob-failure");

        assert_eq!(
            ingress.accept(&headers, body).await,
            Err(GithubDeliveryIngressError::RawObject { kind })
        );
        assert_eq!(objects.put_count(), 1);
        assert_eq!(deliveries.call_count(), 0);
    }
}

#[tokio::test]
async fn inbox_unavailability_occurs_only_after_raw_object_persistence() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(UnavailableProviderRepository::default());
    let ingress = ingress_for_connections(
        SECRET,
        vec![
            connection(
                ProviderRepositoryVisibility::Private,
                "octo-private",
                "private-repository",
            )
            .expect("fixture connection is valid"),
        ],
        objects.clone(),
        deliveries.clone(),
        Arc::new(FixedClock(UnixMillis::new(100))),
    );
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-inbox-unavailable");

    assert_eq!(
        ingress.accept(&headers, body).await,
        Err(GithubDeliveryIngressError::InboxUnavailable)
    );
    assert_eq!(objects.put_count(), 1);
    assert_eq!(objects.object_count(), 1);
    assert_eq!(deliveries.call_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_replay_is_race_safe_across_concurrent_acceptance() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = Arc::new(ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(1_000))),
    ));
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-concurrent-replay");
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let ingress = Arc::clone(&ingress);
        let headers = headers.clone();
        let body = body.clone();
        tasks.spawn(async move { ingress.accept(&headers, body).await });
    }

    let mut accepted = Vec::new();
    while let Some(result) = tasks.join_next().await {
        accepted.push(
            result
                .expect("acceptance task must not panic")
                .expect("exact replay must succeed"),
        );
    }
    assert_eq!(accepted.len(), 32);
    assert!(accepted.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(objects.put_count(), 32);
    assert_eq!(objects.object_count(), 1);
    assert_eq!(deliveries.call_count(), 32);
    assert_eq!(deliveries.entry_count(), 1);
}

#[tokio::test]
async fn changed_body_under_same_delivery_conflicts_after_preserving_raw_evidence() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(IncrementingClock::new(1_000)),
    );
    let first_body = fixture_body();
    let second_body = push_body(
        INSTALLATION_ID,
        REPOSITORY_ID,
        REPOSITORY_OWNER_ID,
        "octo-private",
        "private-repository",
        &format!(r#"[{{"id":"{AFTER_COMMIT}"}}]"#),
    );
    let first_headers = signed_headers(SECRET, &first_body, "delivery-evidence-conflict");
    let second_headers = signed_headers(SECRET, &second_body, "delivery-evidence-conflict");

    ingress
        .accept(&first_headers, first_body)
        .await
        .expect("first acceptance succeeds");
    assert_eq!(
        ingress.accept(&second_headers, second_body).await,
        Err(GithubDeliveryIngressError::ReplayConflict)
    );
    assert_eq!(objects.put_count(), 2);
    assert_eq!(objects.object_count(), 2);
    assert_eq!(deliveries.call_count(), 2);
    assert_eq!(deliveries.entry_count(), 1);
}

#[tokio::test]
async fn delivery_header_is_part_of_identity_and_request_digest() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(IncrementingClock::new(1_000)),
    );
    let body = fixture_body();
    let first = ingress
        .accept(
            &signed_headers(SECRET, &body, "delivery-header-one"),
            body.clone(),
        )
        .await
        .expect("first delivery succeeds");
    let second = ingress
        .accept(&signed_headers(SECRET, &body, "delivery-header-two"), body)
        .await
        .expect("second delivery succeeds");

    assert_ne!(first.request_digest(), second.request_digest());
    assert_eq!(first.raw_event(), second.raw_event());
    assert_eq!(objects.object_count(), 1);
    assert_eq!(deliveries.entry_count(), 2);
}

#[test]
fn repository_visibility_is_an_independent_request_digest_field() {
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-visibility-digest");
    let push = GithubWebhookVerifier::new(SECRET)
        .expect("verifier")
        .verify(&headers, body)
        .expect("verified private push");
    let identity = |visibility| {
        let repository = ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
            visibility,
            "octo-private/private-repository",
        )
        .expect("repository coordinates");
        ProviderDeliveryIdentity::new(
            TenantScope::from_authenticated_tenant_id("tenant-private").expect("tenant"),
            "github",
            ProviderConnectionId::from_uuid(CONNECTION_UUID).expect("connection"),
            ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
            repository,
            "delivery-visibility-digest",
        )
        .expect("identity")
    };

    let event = automata_ci_provider_github::VerifiedGithubWebhook::Push(push);
    let private = canonical_event_request_digest(
        &headers,
        &event,
        &identity(ProviderRepositoryVisibility::Private),
        ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner"),
    )
    .expect("private digest");
    let public = canonical_event_request_digest(
        &headers,
        &event,
        &identity(ProviderRepositoryVisibility::Public),
        ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID).expect("owner"),
    )
    .expect("public digest");
    let changed_owner = canonical_event_request_digest(
        &headers,
        &event,
        &identity(ProviderRepositoryVisibility::Private),
        ProviderRepositoryOwnerId::new(REPOSITORY_OWNER_ID + 1).expect("changed owner"),
    )
    .expect("changed-owner digest");
    assert_ne!(private, public);
    assert_ne!(private, changed_owner);
}

#[tokio::test]
async fn changed_valid_signature_under_same_delivery_conflicts() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let first_ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(1_000))),
    );
    let second_ingress = ingress(
        OTHER_SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(2_000))),
    );
    let body = fixture_body();

    first_ingress
        .accept(
            &signed_headers(SECRET, &body, "delivery-signature-change"),
            body.clone(),
        )
        .await
        .expect("first signature is accepted");
    assert_eq!(
        second_ingress
            .accept(
                &signed_headers(OTHER_SECRET, &body, "delivery-signature-change"),
                body,
            )
            .await,
        Err(GithubDeliveryIngressError::ReplayConflict)
    );
    assert_eq!(objects.object_count(), 1);
    assert_eq!(deliveries.entry_count(), 1);
}

#[tokio::test]
async fn changed_verifier_revision_under_exact_delivery_conflicts() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let make_ingress = |revision| {
        ingress_for_connections_at_revision(
            SECRET,
            revision,
            vec![
                connection(
                    ProviderRepositoryVisibility::Private,
                    "octo-private",
                    "private-repository",
                )
                .expect("fixture connection"),
            ],
            Arc::clone(&objects),
            deliveries.clone(),
            Arc::new(FixedClock(UnixMillis::new(1_000))),
        )
    };
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-verifier-revision-change");

    make_ingress(1)
        .accept(&headers, body.clone())
        .await
        .expect("first verifier revision");
    assert_eq!(
        make_ingress(2).accept(&headers, body).await,
        Err(GithubDeliveryIngressError::ReplayConflict)
    );
    assert_eq!(deliveries.call_count(), 2);
    assert_eq!(deliveries.entry_count(), 1);
}

#[tokio::test]
async fn object_and_request_digest_are_byte_deterministic() {
    let objects = Arc::new(RecordingBlobStore::default());
    let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
    let ingress = ingress(
        SECRET,
        Arc::clone(&objects),
        Arc::clone(&deliveries),
        Arc::new(FixedClock(UnixMillis::new(1_700_000_000_123))),
    );
    let body = fixture_body();
    let headers = signed_headers(SECRET, &body, "delivery-deterministic");

    let accepted = ingress
        .accept(&headers, body.clone())
        .await
        .expect("fixture delivery is accepted");
    assert!(!accepted.receipt().delivery_id().as_uuid().is_nil());
    assert!(!accepted.receipt().check_subject_id().as_uuid().is_nil());
    assert_eq!(
        accepted.receipt().accepted_at(),
        UnixMillis::new(1_700_000_000_123)
    );
    assert_eq!(
        accepted.raw_event().digest().to_string(),
        "1ecc82ee43e49add114ac478563db3701c1eb110e2487c8fc940ead9736b3542"
    );
    assert_eq!(
        accepted.raw_event().object_key().as_str(),
        "provider-deliveries/github/event/sha256/1ecc82ee43e49add114ac478563db3701c1eb110e2487c8fc940ead9736b3542.json"
    );
    assert_eq!(
        accepted.raw_event().media_type(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
    );
    assert_eq!(
        accepted.raw_event().encoded_size(),
        u64::try_from(body.len()).expect("fixture body length fits u64")
    );
    assert_eq!(
        accepted.request_digest().to_string(),
        "6a9391c73fa801b09222a1765764d06ef0c8f891fb580c646e5d999ded8fdea9"
    );
    assert_eq!(
        objects.bytes_at(accepted.raw_event().object_key().as_str()),
        Some(body)
    );

    let requests = deliveries.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    let delivery = request.delivery();
    assert_eq!(delivery.request_digest(), accepted.request_digest());
    assert_eq!(delivery.raw_event(), accepted.raw_event());
    assert_eq!(delivery.identity().tenant().as_str(), "tenant-private");
    assert_eq!(delivery.identity().provider(), "github");
    assert_eq!(
        delivery.identity().connection_id().as_uuid(),
        CONNECTION_UUID
    );
    assert_eq!(delivery.identity().installation_id().get(), INSTALLATION_ID);
    assert_eq!(delivery.identity().repository_id().get(), REPOSITORY_ID);
    assert_eq!(
        delivery.identity().repository_visibility(),
        ProviderRepositoryVisibility::Private
    );
    assert_eq!(
        delivery.identity().repository_identity(),
        "octo-private/private-repository"
    );
    assert_eq!(delivery.identity().delivery_id(), "delivery-deterministic");
    assert_eq!(delivery.accepted_at(), UnixMillis::new(1_700_000_000_123));
}

#[tokio::test]
async fn generic_ingress_persists_typed_event_coordinates_without_event_kind_aliasing() {
    for (body, event_name, delivery_id, expected_kind, expected_ref, expected_check_kind) in [
        (
            fixture_body(),
            "push",
            "delivery-push-v1",
            GithubAuthenticatedEventKind::Push,
            "refs/heads/main",
            GithubDeliveryCheckKind::Required,
        ),
        (
            Bytes::from(
                String::from_utf8(fixture_body().to_vec())
                    .expect("fixture is UTF-8")
                    .replace("refs/heads/main", "refs/heads/feature/topic"),
            ),
            "push",
            "delivery-feature-push-v1",
            GithubAuthenticatedEventKind::Push,
            "refs/heads/feature/topic",
            GithubDeliveryCheckKind::JobsOnly,
        ),
        (
            pull_request_body("opened", false),
            "pull_request",
            "delivery-pr-v1",
            GithubAuthenticatedEventKind::PullRequest,
            "refs/pull/7/merge",
            GithubDeliveryCheckKind::Required,
        ),
        (
            pull_request_body("auto_merge_enabled", false),
            "pull_request",
            "delivery-pr-metadata-v1",
            GithubAuthenticatedEventKind::PullRequest,
            "refs/pull/7/merge",
            GithubDeliveryCheckKind::JobsOnly,
        ),
        (
            merge_group_body(),
            "merge_group",
            "delivery-group-v1",
            GithubAuthenticatedEventKind::MergeGroup,
            "refs/heads/merge-queue/main/group-7",
            GithubDeliveryCheckKind::Required,
        ),
    ] {
        let objects = Arc::new(RecordingBlobStore::default());
        let deliveries = Arc::new(RecordingDeliveryAcceptance::default());
        let ingress = ingress(
            SECRET,
            Arc::clone(&objects),
            Arc::clone(&deliveries),
            Arc::new(FixedClock(UnixMillis::new(1_700_000_000_123))),
        );
        let headers = signed_event_headers(SECRET, &body, event_name, delivery_id);
        let accepted = ingress
            .accept(&headers, body.clone())
            .await
            .expect("generic event is accepted");

        assert_eq!(
            accepted.raw_event().media_type(),
            GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
        );
        assert!(
            accepted
                .raw_event()
                .object_key()
                .as_str()
                .starts_with("provider-deliveries/github/event/sha256/")
        );
        assert_eq!(
            objects.bytes_at(accepted.raw_event().object_key().as_str()),
            Some(body)
        );
        let requests = deliveries.requests();
        let event = requests[0].authenticated_event();
        assert_eq!(event.kind(), expected_kind);
        assert_eq!(event.git_ref(), expected_ref);
        assert_eq!(requests[0].head_sha().as_bytes(), AFTER_COMMIT_BYTES);
        assert_eq!(requests[0].check_kind(), expected_check_kind);
        assert_eq!(requests[0].delivery().identity().delivery_id(), delivery_id);
    }
}

#[test]
fn configuration_and_debug_surfaces_do_not_expose_sensitive_text() {
    for invalid in ["", ".", "..", "with/slash", "private.git", "private.GIT"] {
        assert_eq!(
            connection(
                ProviderRepositoryVisibility::Private,
                "octo-private",
                invalid,
            )
            .unwrap_err(),
            GithubDeliveryConfigurationError::InvalidRepositoryIdentity
        );
    }
    for invalid in [
        "",
        "main",
        "refs/tags/main",
        "refs/heads/",
        "refs/heads/@",
        "refs/heads/.hidden",
        "refs/heads/feature//nested",
        "refs/heads/feature..nested",
        "refs/heads/component.lock",
        "refs/heads/with space",
    ] {
        assert_eq!(
            connection(
                ProviderRepositoryVisibility::Private,
                "octo-private",
                "private-repository",
            )
            .expect("fixture connection")
            .with_default_branch_ref(invalid)
            .unwrap_err(),
            GithubDeliveryConfigurationError::InvalidDefaultBranchRef
        );
    }

    let configured = connection(
        ProviderRepositoryVisibility::Private,
        "octo-private",
        "private-repository",
    )
    .expect("fixture connection is valid")
    .with_default_branch_ref("refs/heads/refs/release")
    .expect("canonical default branch");
    let configured_debug = format!("{configured:?}");
    assert!(!configured_debug.contains("delivery-test-secret"));
    assert!(!configured_debug.contains("tenant-private"));
    assert!(!configured_debug.contains("octo-private"));
    assert!(!configured_debug.contains("private-repository"));
    assert!(!configured_debug.contains("refs/release"));

    let service = ingress_for_connections(
        SECRET,
        vec![configured],
        Arc::new(RecordingBlobStore::default()),
        Arc::new(UnavailableProviderRepository::default()),
        Arc::new(FixedClock(UnixMillis::new(1_000))),
    );
    let service_debug = format!("{service:?}");
    assert!(!service_debug.contains("delivery-test-secret"));
    assert!(!service_debug.contains("tenant-private"));
    assert!(!service_debug.contains("octo-private"));
    assert!(!service_debug.contains("private-repository"));

    let error_debug = format!(
        "{:?}",
        GithubDeliveryIngressError::ConfiguredIdentityMismatch
    );
    assert!(!error_debug.contains("octo-private"));
    assert!(!error_debug.contains("private-repository"));
}
