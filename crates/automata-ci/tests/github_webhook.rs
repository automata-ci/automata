use std::{
    error::Error,
    fmt::{self, Write as _},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};

use async_trait::async_trait;
use automata_ci::server::{
    GITHUB_WEBHOOK_HTTP_DEADLINE, GITHUB_WEBHOOK_PATH, MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES,
    router_with_github_webhook_outside_human_auth,
};
use automata_ci_blob::{
    BlobDescriptor, BlobPayload, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore,
    PutBlobOutcome, VerifiedBlob,
};
use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_github::{
    GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE, GithubWebhookVerifier, MAX_GITHUB_WEBHOOK_BODY_BYTES,
    X_GITHUB_DELIVERY, X_GITHUB_EVENT, X_HUB_SIGNATURE_256,
};
use automata_ci_github_delivery::{
    GithubDeliveryClock, GithubDeliveryConnection, GithubDeliveryIngress,
    GithubDeliveryRepositories,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AdmissionObject, GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    GithubAuthenticatedEventKind, GithubCheckName, GithubCheckSubjectId, GithubProviderManifest,
    GithubProviderManifestLimits, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderRunnerPolicyObject, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubSubjectEvidenceRepository,
    GithubSubjectEvidenceStoreError, GithubWorkflowRunSubjectEvidence,
    ManifestPinnedGithubDeliveryEvidence, ManifestPinnedGithubDeliveryReceipt, ObjectKey,
    ProviderConnectionId, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    ProviderRepositoryOwnerId, ProviderRepositoryVisibility, RepositoryId, TenantScope,
    WorkflowRuntimePolicy, WorkflowRuntimePolicyRevision,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tower::ServiceExt as _;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const BEFORE_COMMIT: &str = "fedcba9876543210fedcba9876543210fedcba98";
const AFTER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const WEBHOOK_ADMISSION_CAPACITY: usize = 4;
const STRUCTURALLY_VALID_SIGNATURE: &str =
    "sha256=0000000000000000000000000000000000000000000000000000000000000000";
const FIXTURE_RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"actions":"read","artifact-metadata":"read","attestations":"read","checks":"read","code-quality":"read","contents":"read","deployments":"read","discussions":"read","issues":"read","packages":"read","pages":"read","pull-requests":"read","security-events":"read","statuses":"read","vulnerability-alerts":"read"},"write_all":{"actions":"write","artifact-metadata":"write","attestations":"write","checks":"write","code-quality":"write","contents":"write","deployments":"write","discussions":"write","id-token":"write","issues":"write","packages":"write","pages":"write","pull-requests":"write","security-events":"write","statuses":"write","vulnerability-alerts":"read"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

fn fixture_github_runtime_policy(
    revision: u64,
) -> (
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
        WorkflowRuntimePolicyRevision::new(revision).expect("runtime-policy revision"),
        policy.digest(),
    )
}

#[derive(Debug)]
struct FixedClock;

impl GithubDeliveryClock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(1_000)
    }
}

#[derive(Debug)]
struct FakeBlobStore {
    delay: Duration,
    failure: Option<BlobStoreErrorKind>,
    calls: AtomicUsize,
    completed: AtomicUsize,
}

impl FakeBlobStore {
    fn new(delay: Duration, failure: Option<BlobStoreErrorKind>) -> Self {
        Self {
            delay,
            failure,
            calls: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ImmutableBlobStore for FakeBlobStore {
    async fn put_if_absent(&self, _payload: BlobPayload) -> Result<PutBlobOutcome, BlobStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        if let Some(kind) = self.failure {
            return Err(BlobStoreError::new(kind));
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubjectOutcome {
    Accept,
    Unavailable,
    Conflict,
    Reject,
}

#[derive(Debug)]
struct FakeSubjectStore {
    delay: Duration,
    outcome: SubjectOutcome,
    calls: AtomicUsize,
    completed: AtomicUsize,
    requests: Mutex<Vec<AcceptManifestPinnedGithubDelivery>>,
}

impl FakeSubjectStore {
    fn new(delay: Duration, outcome: SubjectOutcome) -> Self {
        Self {
            delay,
            outcome,
            calls: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn completed(&self) -> usize {
        self.completed.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<AcceptManifestPinnedGithubDelivery> {
        self.requests
            .lock()
            .expect("subject-store fixture lock is healthy")
            .clone()
    }
}

#[derive(Debug)]
struct FixtureUnavailable;

impl fmt::Display for FixtureUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fixture unavailable")
    }
}

impl Error for FixtureUnavailable {}

#[async_trait]
impl GithubSubjectEvidenceRepository for FakeSubjectStore {
    async fn accept_manifest_pinned_github_delivery(
        &self,
        request: AcceptManifestPinnedGithubDelivery,
    ) -> Result<ManifestPinnedGithubDeliveryReceipt, GithubSubjectEvidenceStoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        match self.outcome {
            SubjectOutcome::Accept => {
                let receipt = fixture_receipt(&request);
                self.requests
                    .lock()
                    .expect("subject-store fixture lock is healthy")
                    .push(request);
                self.completed.fetch_add(1, Ordering::SeqCst);
                Ok(receipt)
            }
            SubjectOutcome::Unavailable => Err(GithubSubjectEvidenceStoreError::operation(
                FixtureUnavailable,
            )),
            SubjectOutcome::Conflict => Err(GithubSubjectEvidenceStoreError::ReplayConflict),
            SubjectOutcome::Reject => Err(GithubSubjectEvidenceStoreError::AuthorityRejected),
        }
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
    let (runner_policy, runtime_policy_revision, runtime_policy_digest) =
        fixture_github_runtime_policy(1);
    let manifest = GithubProviderManifest::new(
        identity.tenant().clone(),
        identity.connection_id(),
        identity.installation_id(),
        identity.repository_id(),
        GithubRepositoryName::new(identity.repository_identity().to_owned()).expect("repository"),
        identity.repository_visibility(),
        GithubServerServiceAppId::new(42).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.webhook-fixture").expect("App client ID"),
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
    let private_source =
        (identity.repository_visibility() == ProviderRepositoryVisibility::Private).then(|| {
            authority(
                identity.tenant(),
                "00000000-0000-0000-0000-000000000401",
                0x62,
            )
        });
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
        private_source,
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

fn connection(visibility: ProviderRepositoryVisibility) -> GithubDeliveryConnection {
    let (tenant, connection_id, installation_id, repository_id, owner_id, owner, repository) =
        match visibility {
            ProviderRepositoryVisibility::Public => (
                "tenant-public",
                "00000000-0000-0000-0000-000000000011",
                11,
                101,
                1_001,
                "octo-public",
                "public-repository",
            ),
            ProviderRepositoryVisibility::Private => (
                "tenant-private",
                "00000000-0000-0000-0000-000000000022",
                22,
                202,
                2_002,
                "octo-private",
                "private-repository",
            ),
        };
    GithubDeliveryConnection::new(
        TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        ProviderConnectionId::from_uuid(connection_id.parse().expect("fixture UUID"))
            .expect("connection ID"),
        ProviderInstallationId::new(installation_id).expect("installation ID"),
        ProviderRepositoryId::new(repository_id).expect("repository ID"),
        ProviderRepositoryOwnerId::new(owner_id).expect("owner ID"),
        visibility,
        owner,
        repository,
    )
    .expect("connection")
}

fn registry(
    blobs: Arc<FakeBlobStore>,
    subjects: Arc<FakeSubjectStore>,
) -> Arc<GithubDeliveryIngress> {
    let connections = vec![
        connection(ProviderRepositoryVisibility::Public),
        connection(ProviderRepositoryVisibility::Private),
    ];
    Arc::new(
        GithubDeliveryIngress::new(
            GithubWebhookVerifier::new(SECRET).expect("verifier"),
            GithubServerServiceRevision::new(1).expect("verifier revision"),
            connections,
            blobs,
            GithubDeliveryRepositories::new(subjects),
            Arc::new(FixedClock),
        )
        .expect("mixed registry"),
    )
}

fn push_body(
    installation_id: u64,
    repository_id: u64,
    owner_id: u64,
    owner: &str,
    repository: &str,
    visibility: ProviderRepositoryVisibility,
) -> Bytes {
    let (private, visibility) = match visibility {
        ProviderRepositoryVisibility::Public => (false, "public"),
        ProviderRepositoryVisibility::Private => (true, "private"),
    };
    Bytes::from(format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE_COMMIT}","after":"{AFTER_COMMIT}","created":false,"deleted":false,"forced":false,"repository":{{"id":{repository_id},"private":{private},"visibility":"{visibility}","name":"{repository}","full_name":"{owner}/{repository}","owner":{{"id":{owner_id},"login":"{owner}"}}}},"installation":{{"id":{installation_id}}},"commits":[]}}"#
    ))
}

fn public_body() -> Bytes {
    push_body(
        11,
        101,
        1_001,
        "octo-public",
        "public-repository",
        ProviderRepositoryVisibility::Public,
    )
}

fn private_body() -> Bytes {
    push_body(
        22,
        202,
        2_002,
        "octo-private",
        "private-repository",
        ProviderRepositoryVisibility::Private,
    )
}

fn public_pull_request_body() -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"opened","number":7,"pull_request":{{"number":7,"merged":false,"merge_commit_sha":"{AFTER_COMMIT}","head":{{"ref":"feature/topic","sha":"{AFTER_COMMIT}","repo":{{"id":101,"private":false,"visibility":"public","name":"public-repository","full_name":"octo-public/public-repository","owner":{{"id":1001,"login":"octo-public"}}}}}},"base":{{"ref":"main","sha":"{BEFORE_COMMIT}","repo":{{"id":101,"private":false,"visibility":"public","name":"public-repository","full_name":"octo-public/public-repository","owner":{{"id":1001,"login":"octo-public"}}}}}}}},"repository":{{"id":101,"private":false,"visibility":"public","name":"public-repository","full_name":"octo-public/public-repository","owner":{{"id":1001,"login":"octo-public"}}}},"installation":{{"id":11}},"sender":{{"id":301}}}}"#
    ))
}

fn public_merge_group_body() -> Bytes {
    Bytes::from(format!(
        r#"{{"action":"checks_requested","merge_group":{{"head_sha":"{AFTER_COMMIT}","head_ref":"refs/heads/merge-queue/main/group-7","base_sha":"{BEFORE_COMMIT}","base_ref":"refs/heads/main","head_commit":{{}}}},"repository":{{"id":101,"private":false,"visibility":"public","name":"public-repository","full_name":"octo-public/public-repository","owner":{{"id":1001,"login":"octo-public"}}}},"installation":{{"id":11}},"sender":{{"id":301}}}}"#
    ))
}

fn hmac_sha256(secret: &[u8], body: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    assert!(
        secret.len() <= BLOCK_BYTES,
        "fixture key fits one SHA-256 block"
    );
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

fn signature(body: &[u8]) -> String {
    let mut signature = String::from("sha256=");
    for byte in hmac_sha256(SECRET, body) {
        write!(&mut signature, "{byte:02x}").expect("writing to a string cannot fail");
    }
    signature
}

fn signed_request(uri: &str, delivery_id: &str, body: Bytes) -> Request {
    signed_event_request(uri, delivery_id, "push", body)
}

fn signed_event_request(uri: &str, delivery_id: &str, event_name: &str, body: Bytes) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(X_HUB_SIGNATURE_256, signature(&body))
        .header(X_GITHUB_EVENT, event_name)
        .header(X_GITHUB_DELIVERY, delivery_id)
        .body(Body::from(body))
        .expect("request")
}

fn structurally_valid_request(uri: &str, delivery_id: &str, body: Body) -> Request {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(X_HUB_SIGNATURE_256, STRUCTURALLY_VALID_SIGNATURE)
        .header(X_GITHUB_EVENT, "push")
        .header(X_GITHUB_DELIVERY, delivery_id)
        .body(body)
        .expect("request")
}

fn stalled_structurally_valid_request(delivery_id: &str, body_polled: Arc<AtomicBool>) -> Request {
    let body = Body::from_stream(futures::stream::poll_fn(move |_| {
        body_polled.store(true, Ordering::SeqCst);
        Poll::<Option<Result<Bytes, std::io::Error>>>::Pending
    }));
    structurally_valid_request(GITHUB_WEBHOOK_PATH, delivery_id, body)
}

fn app(blobs: Arc<FakeBlobStore>, subjects: Arc<FakeSubjectStore>) -> Router {
    router_with_github_webhook_outside_human_auth(Router::new(), registry(blobs, subjects))
}

async fn assert_fixed_response(response: Response, expected: StatusCode) {
    assert_eq!(response.status(), expected);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    if expected == StatusCode::METHOD_NOT_ALLOWED {
        assert_eq!(response.headers()[header::ALLOW], "POST");
    }
    assert!(
        to_bytes(response.into_body(), 1)
            .await
            .expect("bounded response body")
            .is_empty()
    );
}

async fn assert_unauthorized_without_polling(
    app: &Router,
    request: Request,
    body_polled: &AtomicBool,
) {
    let response = tokio::time::timeout(Duration::from_secs(1), app.clone().oneshot(request))
        .await
        .expect("invalid headers are rejected before the body can stall")
        .expect("response");
    assert_fixed_response(response, StatusCode::UNAUTHORIZED).await;
    assert!(!body_polled.load(Ordering::SeqCst));
}

fn default_ports() -> (Arc<FakeBlobStore>, Arc<FakeSubjectStore>) {
    (
        Arc::new(FakeBlobStore::new(Duration::ZERO, None)),
        Arc::new(FakeSubjectStore::new(
            Duration::ZERO,
            SubjectOutcome::Accept,
        )),
    )
}

async fn require_human_session(request: Request, next: Next) -> Response {
    if request
        .headers()
        .get("x-human-session")
        .is_some_and(|value| value == "valid")
    {
        next.run(request).await
    } else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        response
    }
}

#[test]
fn route_policy_is_fixed_and_matches_the_verified_body_ceiling() {
    assert_eq!(GITHUB_WEBHOOK_PATH, "/webhooks/github");
    assert_eq!(MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES, 26_214_400);
    assert_eq!(
        MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES,
        MAX_GITHUB_WEBHOOK_BODY_BYTES
    );
    assert_eq!(GITHUB_WEBHOOK_HTTP_DEADLINE, Duration::from_secs(7));
}

#[tokio::test]
async fn one_public_router_accepts_mixed_repositories_outside_human_auth() {
    let (blobs, subjects) = default_ports();
    let human = Router::new()
        .route("/human", get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(require_human_session));
    let app = router_with_github_webhook_outside_human_auth(
        human,
        registry(Arc::clone(&blobs), Arc::clone(&subjects)),
    );

    let human_response = app
        .clone()
        .oneshot(Request::get("/human").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(human_response.status(), StatusCode::UNAUTHORIZED);
    let public = app
        .clone()
        .oneshot(signed_request(
            GITHUB_WEBHOOK_PATH,
            "public-delivery",
            public_body(),
        ))
        .await
        .expect("public response");
    assert_fixed_response(public, StatusCode::ACCEPTED).await;
    let private = app
        .oneshot(signed_request(
            GITHUB_WEBHOOK_PATH,
            "private-delivery",
            private_body(),
        ))
        .await
        .expect("private response");
    assert_fixed_response(private, StatusCode::ACCEPTED).await;

    let requests = subjects.requests();
    assert_eq!(blobs.completed(), 2);
    assert_eq!(subjects.completed(), 2);
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().any(|request| {
        request.delivery().identity().repository_visibility()
            == ProviderRepositoryVisibility::Public
    }));
    assert!(requests.iter().any(|request| {
        request.delivery().identity().repository_visibility()
            == ProviderRepositoryVisibility::Private
    }));
}

#[tokio::test]
async fn product_router_routes_every_supported_event_through_one_canonical_ingress() {
    let (blobs, subjects) = default_ports();
    let app = app(Arc::clone(&blobs), Arc::clone(&subjects));
    for (event_name, delivery_id, body) in [
        ("push", "routed-push", public_body()),
        (
            "pull_request",
            "routed-pull-request",
            public_pull_request_body(),
        ),
        (
            "merge_group",
            "routed-merge-group",
            public_merge_group_body(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(signed_event_request(
                GITHUB_WEBHOOK_PATH,
                delivery_id,
                event_name,
                body,
            ))
            .await
            .expect("routed event response");
        assert_fixed_response(response, StatusCode::ACCEPTED).await;
    }

    let requests = subjects.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(blobs.completed(), 3);
    let push = &requests[0];
    assert_eq!(
        push.authenticated_event().kind(),
        GithubAuthenticatedEventKind::Push
    );
    assert_eq!(
        push.delivery().raw_event().media_type(),
        GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
    );

    for (request, expected_kind, expected_ref) in [
        (
            &requests[1],
            GithubAuthenticatedEventKind::PullRequest,
            "refs/pull/7/merge",
        ),
        (
            &requests[2],
            GithubAuthenticatedEventKind::MergeGroup,
            "refs/heads/merge-queue/main/group-7",
        ),
    ] {
        let event = request.authenticated_event();
        assert_eq!(event.kind(), expected_kind);
        assert_eq!(event.git_ref(), expected_ref);
        assert_eq!(
            request.delivery().raw_event().media_type(),
            GITHUB_AUTHENTICATED_EVENT_MEDIA_TYPE
        );
        assert!(
            request
                .delivery()
                .raw_event()
                .object_key()
                .as_str()
                .starts_with("provider-deliveries/github/event/sha256/")
        );
    }
}

#[tokio::test]
async fn query_media_type_method_and_adjacent_paths_fail_closed() {
    let (blobs, subjects) = default_ports();
    let app = app(Arc::clone(&blobs), Arc::clone(&subjects));
    let query = app
        .clone()
        .oneshot(signed_request(
            "/webhooks/github?probe=1",
            "query",
            public_body(),
        ))
        .await
        .expect("query response");
    assert_fixed_response(query, StatusCode::BAD_REQUEST).await;

    for media_type in [
        "application/json; charset=utf-8",
        "Application/JSON",
        "text/json",
    ] {
        let mut request = signed_request(GITHUB_WEBHOOK_PATH, "media", public_body());
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
        let response = app.clone().oneshot(request).await.expect("media response");
        assert_fixed_response(response, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;
    }
    let mut duplicate = signed_request(GITHUB_WEBHOOK_PATH, "duplicate", public_body());
    duplicate.headers_mut().append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert_fixed_response(
        app.clone().oneshot(duplicate).await.expect("response"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
    )
    .await;

    for method in [
        Method::GET,
        Method::HEAD,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
        Method::TRACE,
    ] {
        let request = Request::builder()
            .method(method)
            .uri(GITHUB_WEBHOOK_PATH)
            .body(Body::empty())
            .expect("request");
        assert_fixed_response(
            app.clone().oneshot(request).await.expect("response"),
            StatusCode::METHOD_NOT_ALLOWED,
        )
        .await;
    }
    for path in [
        "/webhooks",
        "/webhooks/github/",
        "/webhooks/github/extra",
        "/webhooks/gitlab",
    ] {
        let request = Request::post(path).body(Body::empty()).expect("request");
        assert_fixed_response(
            app.clone().oneshot(request).await.expect("response"),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    assert_eq!(blobs.calls(), 0);
    assert_eq!(subjects.calls(), 0);
}

#[tokio::test]
async fn malformed_or_ambiguous_github_headers_are_rejected_before_body_polling() {
    let (blobs, subjects) = default_ports();
    let app = app(Arc::clone(&blobs), Arc::clone(&subjects));

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut missing_signature =
        stalled_structurally_valid_request("missing-signature", Arc::clone(&body_polled));
    missing_signature.headers_mut().remove(X_HUB_SIGNATURE_256);
    assert_unauthorized_without_polling(&app, missing_signature, &body_polled).await;

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut duplicate_signature =
        stalled_structurally_valid_request("duplicate-signature", Arc::clone(&body_polled));
    duplicate_signature.headers_mut().append(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_static(STRUCTURALLY_VALID_SIGNATURE),
    );
    assert_unauthorized_without_polling(&app, duplicate_signature, &body_polled).await;

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut malformed_signature =
        stalled_structurally_valid_request("malformed-signature", Arc::clone(&body_polled));
    malformed_signature.headers_mut().insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_static(
            "sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    );
    assert_unauthorized_without_polling(&app, malformed_signature, &body_polled).await;

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut duplicate_event =
        stalled_structurally_valid_request("duplicate-event", Arc::clone(&body_polled));
    duplicate_event
        .headers_mut()
        .append(X_GITHUB_EVENT, HeaderValue::from_static("push"));
    assert_unauthorized_without_polling(&app, duplicate_event, &body_polled).await;

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut malformed_event =
        stalled_structurally_valid_request("malformed-event", Arc::clone(&body_polled));
    malformed_event
        .headers_mut()
        .insert(X_GITHUB_EVENT, HeaderValue::from_static("Push"));
    assert_unauthorized_without_polling(&app, malformed_event, &body_polled).await;

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut duplicate_delivery =
        stalled_structurally_valid_request("duplicate-delivery", Arc::clone(&body_polled));
    duplicate_delivery.headers_mut().append(
        X_GITHUB_DELIVERY,
        HeaderValue::from_static("second-delivery"),
    );
    assert_unauthorized_without_polling(&app, duplicate_delivery, &body_polled).await;

    let body_polled = Arc::new(AtomicBool::new(false));
    let mut malformed_delivery =
        stalled_structurally_valid_request("malformed-delivery", Arc::clone(&body_polled));
    malformed_delivery.headers_mut().insert(
        X_GITHUB_DELIVERY,
        HeaderValue::from_static("invalid/delivery"),
    );
    assert_unauthorized_without_polling(&app, malformed_delivery, &body_polled).await;

    let body = public_body();
    let mut unsupported_event = signed_request(GITHUB_WEBHOOK_PATH, "unsupported-event", body);
    unsupported_event
        .headers_mut()
        .insert(X_GITHUB_EVENT, HeaderValue::from_static("issues"));
    assert_fixed_response(
        app.clone()
            .oneshot(unsupported_event)
            .await
            .expect("response"),
        StatusCode::BAD_REQUEST,
    )
    .await;

    assert_eq!(blobs.calls(), 0);
    assert_eq!(subjects.calls(), 0);
}

#[tokio::test]
async fn saturated_webhook_admission_rejects_before_body_polling() {
    let (blobs, subjects) = default_ports();
    let app = app(Arc::clone(&blobs), Arc::clone(&subjects));
    let mut holders = Vec::new();
    let mut holder_bodies_polled = Vec::new();

    for index in 0..WEBHOOK_ADMISSION_CAPACITY {
        let body_polled = Arc::new(AtomicBool::new(false));
        let request = stalled_structurally_valid_request(
            &format!("admission-holder-{index}"),
            Arc::clone(&body_polled),
        );
        let holder_app = app.clone();
        holder_bodies_polled.push(body_polled);
        holders.push(tokio::spawn(
            async move { holder_app.oneshot(request).await },
        ));
    }

    tokio::time::timeout(Duration::from_secs(1), async {
        while !holder_bodies_polled
            .iter()
            .all(|body_polled| body_polled.load(Ordering::SeqCst))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the fixed number of holders acquires admission");

    let overflow_body_polled = Arc::new(AtomicBool::new(false));
    let overflow =
        stalled_structurally_valid_request("admission-overflow", Arc::clone(&overflow_body_polled));
    let response = tokio::time::timeout(Duration::from_secs(1), app.oneshot(overflow))
        .await
        .expect("saturated admission fails without waiting for request timeout")
        .expect("response");
    assert_fixed_response(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert!(!overflow_body_polled.load(Ordering::SeqCst));
    assert_eq!(blobs.calls(), 0);
    assert_eq!(subjects.calls(), 0);

    for holder in holders {
        holder.abort();
        assert!(
            holder
                .await
                .expect_err("stalled admission holder is cancelled")
                .is_cancelled()
        );
    }
}

#[tokio::test]
async fn raw_body_stream_is_capped_at_the_exact_ceiling() {
    let (blobs, subjects) = default_ports();
    let app = app(Arc::clone(&blobs), Arc::clone(&subjects));
    let exact = structurally_valid_request(
        GITHUB_WEBHOOK_PATH,
        "exact-body-ceiling",
        Body::from(vec![b' '; MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES]),
    );
    assert_fixed_response(
        app.clone().oneshot(exact).await.expect("response"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let one_over_stream = futures::stream::iter([
        Ok::<Bytes, std::io::Error>(Bytes::from(vec![b' '; MAX_GITHUB_WEBHOOK_HTTP_BODY_BYTES])),
        Ok(Bytes::from_static(b" ")),
    ]);
    let one_over = structurally_valid_request(
        GITHUB_WEBHOOK_PATH,
        "over-body-ceiling",
        Body::from_stream(one_over_stream),
    );
    assert_fixed_response(
        app.clone().oneshot(one_over).await.expect("response"),
        StatusCode::PAYLOAD_TOO_LARGE,
    )
    .await;
    let failed_stream = Body::from_stream(futures::stream::once(async {
        Err::<Bytes, _>(std::io::Error::other("fixture body failure"))
    }));
    let failed =
        structurally_valid_request(GITHUB_WEBHOOK_PATH, "failed-body-stream", failed_stream);
    assert_fixed_response(
        app.oneshot(failed).await.expect("response"),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(blobs.calls(), 0);
    assert_eq!(subjects.calls(), 0);
}

async fn mapped_response(
    body: Bytes,
    blobs: Arc<FakeBlobStore>,
    subjects: Arc<FakeSubjectStore>,
) -> Response {
    app(blobs, subjects)
        .oneshot(signed_request(GITHUB_WEBHOOK_PATH, "mapped", body))
        .await
        .expect("response")
}

#[tokio::test]
async fn authentication_identity_and_durable_errors_have_closed_statuses() {
    let (blobs, subjects) = default_ports();
    let app = app(blobs, subjects);
    let mut unauthenticated = signed_request(GITHUB_WEBHOOK_PATH, "auth", public_body());
    unauthenticated.headers_mut().insert(
        X_HUB_SIGNATURE_256,
        HeaderValue::from_static(
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );
    assert_fixed_response(
        app.oneshot(unauthenticated).await.expect("response"),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    let (blobs, subjects) = default_ports();
    assert_fixed_response(
        mapped_response(Bytes::from_static(b"{}"), blobs, subjects).await,
        StatusCode::BAD_REQUEST,
    )
    .await;
    let (blobs, subjects) = default_ports();
    let unknown = push_body(
        99,
        909,
        9_009,
        "unknown",
        "repository",
        ProviderRepositoryVisibility::Public,
    );
    assert_fixed_response(
        mapped_response(unknown, blobs, subjects).await,
        StatusCode::FORBIDDEN,
    )
    .await;
    let blobs = Arc::new(FakeBlobStore::new(
        Duration::ZERO,
        Some(BlobStoreErrorKind::Unavailable),
    ));
    let subjects = Arc::new(FakeSubjectStore::new(
        Duration::ZERO,
        SubjectOutcome::Accept,
    ));
    assert_fixed_response(
        mapped_response(public_body(), blobs, subjects).await,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    let blobs = Arc::new(FakeBlobStore::new(Duration::ZERO, None));
    let subjects = Arc::new(FakeSubjectStore::new(
        Duration::ZERO,
        SubjectOutcome::Conflict,
    ));
    assert_fixed_response(
        mapped_response(public_body(), blobs, subjects).await,
        StatusCode::CONFLICT,
    )
    .await;
    let blobs = Arc::new(FakeBlobStore::new(Duration::ZERO, None));
    let subjects = Arc::new(FakeSubjectStore::new(
        Duration::ZERO,
        SubjectOutcome::Reject,
    ));
    assert_fixed_response(
        mapped_response(public_body(), blobs, subjects).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await;
    let blobs = Arc::new(FakeBlobStore::new(Duration::ZERO, None));
    let subjects = Arc::new(FakeSubjectStore::new(
        Duration::ZERO,
        SubjectOutcome::Unavailable,
    ));
    assert_fixed_response(
        mapped_response(public_body(), blobs, subjects).await,
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
}

#[tokio::test]
async fn one_absolute_deadline_covers_blob_and_atomic_acceptance() {
    let blobs = Arc::new(FakeBlobStore::new(Duration::from_secs(4), None));
    let subjects = Arc::new(FakeSubjectStore::new(
        Duration::from_secs(4),
        SubjectOutcome::Accept,
    ));
    let response = app(Arc::clone(&blobs), Arc::clone(&subjects))
        .oneshot(signed_request(
            GITHUB_WEBHOOK_PATH,
            "deadline",
            public_body(),
        ))
        .await
        .expect("response");
    assert_fixed_response(response, StatusCode::GATEWAY_TIMEOUT).await;
    assert_eq!(blobs.calls(), 1);
    assert_eq!(blobs.completed(), 1);
    assert_eq!(subjects.calls(), 1);
    assert_eq!(subjects.completed(), 0);
}
