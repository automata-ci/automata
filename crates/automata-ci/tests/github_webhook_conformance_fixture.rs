use std::{
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci::app::conformance_fixture::GithubWebhookFixtureIngress;
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, ImmutableBlobStore, PutBlobOutcome, VerifiedBlob,
};
use automata_ci_conformance::RawWebhookFixture;
use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_github::GithubWebhookVerifier;
use automata_ci_github_delivery::{
    GithubDeliveryClock, GithubDeliveryConnection, GithubDeliveryIngress,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AdmissionObject, GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    GithubCheckName, GithubCheckSubjectId, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins, GithubProviderRunnerPolicyObject,
    GithubRepositoryName, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubSubjectEvidenceRepository,
    GithubSubjectEvidenceStoreError, GithubWorkflowRunSubjectEvidence,
    ManifestPinnedGithubDeliveryEvidence, ManifestPinnedGithubDeliveryReceipt, ObjectKey,
    ProviderConnectionId, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RepositoryId, TenantScope,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyRevision,
};
use axum::{body::to_bytes, http::StatusCode};
use sha2::{Digest as _, Sha256};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const BEFORE_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AFTER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const CHANGED_COMMIT: &str = "1111111111111111111111111111111111111111";
const FIXTURE_RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"contents":"read"},"write_all":{"contents":"write"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

#[derive(Debug)]
struct FixedClock;

impl GithubDeliveryClock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(1_000)
    }
}

#[derive(Debug, Default)]
struct FixtureBlobStore {
    calls: AtomicUsize,
}

impl FixtureBlobStore {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ImmutableBlobStore for FixtureBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PutBlobOutcome::Created)
    }

    async fn get_verified(
        &self,
        _descriptor: &BlobDescriptor,
        _maximum_bytes: u64,
    ) -> Result<VerifiedBlob, BlobStoreError> {
        panic!("object reads are outside webhook ingress")
    }
}

#[derive(Debug, Default)]
struct ReplaySubjectStore {
    accepted: Mutex<
        Option<(
            AcceptManifestPinnedGithubDelivery,
            ManifestPinnedGithubDeliveryReceipt,
        )>,
    >,
    calls: AtomicUsize,
    commits: AtomicUsize,
}

impl ReplaySubjectStore {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn commits(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl GithubSubjectEvidenceRepository for ReplaySubjectStore {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut accepted = self
            .accepted
            .lock()
            .expect("replay fixture lock is healthy");
        if let Some((original, receipt)) = accepted.as_ref() {
            return if original == &request {
                Ok(receipt.clone())
            } else {
                Err(GithubSubjectEvidenceStoreError::ReplayConflict)
            };
        }
        let receipt = fixture_receipt(&request);
        *accepted = Some((request, receipt.clone()));
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(receipt)
    }

    async fn load_manifest_pinned_github_delivery_evidence(
        &self,
        _tenant: &TenantScope,
        _delivery_id: ProviderDeliveryId,
    ) -> Result<ManifestPinnedGithubDeliveryEvidence, GithubSubjectEvidenceStoreError> {
        panic!("worker evidence loading is outside webhook ingress")
    }

    async fn load_github_workflow_run_subject_evidence(
        &self,
        _tenant: &TenantScope,
        _repository_id: RepositoryId,
        _run_id: RunId,
    ) -> Result<GithubWorkflowRunSubjectEvidence, GithubSubjectEvidenceStoreError> {
        panic!("run evidence loading is outside webhook ingress")
    }
}

fn fixture_receipt(
    request: &AcceptManifestPinnedGithubDelivery,
) -> ManifestPinnedGithubDeliveryReceipt {
    let identity = request.delivery().identity();
    let app_revision = GithubServerServiceRevision::new(1).expect("App revision");
    let policy_revision = GithubServerServiceRevision::new(1).expect("policy revision");
    let (runner_policy, runtime_policy_revision, runtime_policy_digest) = fixture_runtime_policy();
    let manifest = GithubProviderManifest::new(
        identity.tenant().clone(),
        identity.connection_id(),
        identity.installation_id(),
        identity.repository_id(),
        GithubRepositoryName::new(identity.repository_identity().to_owned()).expect("repository"),
        identity.repository_visibility(),
        GithubServerServiceAppId::new(42).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.conformance-fixture").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x51; 32]),
        app_revision,
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        policy_revision,
        automata_ci_core::JobAuthorityProfile::Standard,
        runner_policy,
        runtime_policy_revision,
        runtime_policy_digest,
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    );
    let checks = authority(
        identity.tenant(),
        "00000000-0000-0000-0000-000000000301",
        0x61,
    );
    let evidence = ManifestPinnedGithubDeliveryEvidence::from_durable_parts(
        ProviderDeliveryId::from_uuid(
            "00000000-0000-0000-0000-000000000101"
                .parse()
                .expect("fixture UUID"),
        )
        .expect("delivery ID"),
        request.repository_owner_id(),
        manifest,
        request.authenticated_webhook_verifier_fingerprint(),
        request.authenticated_webhook_verifier_revision(),
        checks,
        None,
        GithubCheckSubjectId::from_uuid(
            "00000000-0000-0000-0000-000000000201"
                .parse()
                .expect("fixture UUID"),
        )
        .expect("Check subject"),
        request.head_sha(),
        request.authenticated_event().clone(),
        request.delivery().accepted_at(),
    )
    .expect("fixture manifest evidence");
    ManifestPinnedGithubDeliveryReceipt::from_durable_parts(evidence)
}

fn fixture_runtime_policy() -> (
    GithubProviderRunnerPolicyObject,
    WorkflowRuntimePolicyRevision,
    Sha256Digest,
) {
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
    (
        GithubProviderRunnerPolicyObject::new(object).expect("runner-policy descriptor"),
        WorkflowRuntimePolicyRevision::new(1).expect("runtime-policy revision"),
        policy.digest(),
    )
}

fn authority(
    tenant: &TenantScope,
    authority_id: &str,
    digest_byte: u8,
) -> GithubServerServiceAuthoritySelector {
    GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(authority_id.parse().expect("fixture UUID"))
            .expect("authority ID"),
        Sha256Digest::from_bytes([digest_byte; 32]),
        GithubServerServiceRevision::new(1).expect("App revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
    )
}

fn fixture_ingress() -> (
    GithubWebhookFixtureIngress,
    Arc<FixtureBlobStore>,
    Arc<ReplaySubjectStore>,
) {
    let objects = Arc::new(FixtureBlobStore::default());
    let deliveries = Arc::new(ReplaySubjectStore::default());
    let connection = GithubDeliveryConnection::new(
        TenantScope::from_authenticated_tenant_id("tenant-conformance").expect("tenant"),
        ProviderConnectionId::from_uuid(
            "00000000-0000-0000-0000-000000000011"
                .parse()
                .expect("fixture UUID"),
        )
        .expect("connection ID"),
        ProviderInstallationId::new(11).expect("installation ID"),
        ProviderRepositoryId::new(101).expect("repository ID"),
        ProviderRepositoryOwnerId::new(1_001).expect("owner ID"),
        ProviderRepositoryVisibility::Public,
        "octo-public",
        "public-repository",
    )
    .expect("connection");
    let ingress = GithubDeliveryIngress::new(
        GithubWebhookVerifier::new(SECRET).expect("verifier"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        vec![connection],
        objects.clone(),
        deliveries.clone(),
        Arc::new(FixedClock),
    )
    .expect("fixture ingress");
    (
        GithubWebhookFixtureIngress::new(Arc::new(ingress)),
        objects,
        deliveries,
    )
}

fn push_body(after: &str) -> Vec<u8> {
    format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE_COMMIT}","after":"{after}","created":false,"deleted":false,"forced":false,"repository":{{"id":101,"private":false,"visibility":"public","name":"public-repository","full_name":"octo-public/public-repository","owner":{{"id":1001,"login":"octo-public"}}}},"installation":{{"id":11}},"commits":[]}}"#
    )
    .into_bytes()
}

fn fixture(delivery_id: &str, after: &str) -> RawWebhookFixture {
    let body = push_body(after);
    RawWebhookFixture::new("push", delivery_id, signature(&body), body)
        .expect("raw webhook fixture")
}

fn signature(body: &[u8]) -> String {
    let mut signature = String::from("sha256=");
    for byte in hmac_sha256(SECRET, body) {
        write!(&mut signature, "{byte:02x}").expect("writing to a string cannot fail");
    }
    signature
}

fn hmac_sha256(secret: &[u8], body: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    assert!(secret.len() <= BLOCK_BYTES);
    let mut inner_pad = [0x36; BLOCK_BYTES];
    let mut outer_pad = [0x5c; BLOCK_BYTES];
    for (index, byte) in secret.iter().copied().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(body);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

async fn assert_empty_status(response: axum::response::Response, expected: StatusCode) {
    assert_eq!(response.status(), expected);
    assert!(
        to_bytes(response.into_body(), 1)
            .await
            .expect("bounded response body")
            .is_empty()
    );
}

#[tokio::test]
async fn raw_fixture_uses_real_ingress_and_preserves_durable_replay_semantics() {
    let (ingress, objects, deliveries) = fixture_ingress();
    let body = push_body(AFTER_COMMIT);
    let wrong_signature = RawWebhookFixture::new(
        "push",
        "delivery-byte-lock",
        "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        body,
    )
    .expect("structurally valid signature fixture");
    assert_empty_status(
        ingress
            .inject(&wrong_signature)
            .await
            .expect("product response"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(objects.calls(), 0);
    assert_eq!(deliveries.calls(), 0);

    let original = fixture("delivery-replay", AFTER_COMMIT);
    assert_empty_status(
        ingress.inject(&original).await.expect("initial response"),
        StatusCode::ACCEPTED,
    )
    .await;
    assert_empty_status(
        ingress.inject(&original).await.expect("replay response"),
        StatusCode::ACCEPTED,
    )
    .await;

    let changed = fixture("delivery-replay", CHANGED_COMMIT);
    assert_ne!(original.body_sha256(), changed.body_sha256());
    assert_empty_status(
        ingress.inject(&changed).await.expect("conflict response"),
        StatusCode::CONFLICT,
    )
    .await;

    assert_eq!(objects.calls(), 3);
    assert_eq!(deliveries.calls(), 3);
    assert_eq!(deliveries.commits(), 1);
}
