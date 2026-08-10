use std::{
    io::ErrorKind,
    net::{SocketAddr, TcpListener as StdTcpListener},
    time::Duration,
};

use automata_ci_auth::secret::SecretString;
use automata_ci_core::{Sha256Digest, UnixMillis};
use automata_ci_github::{
    GITHUB_API_VERSION, GithubHttpEndpoint, GithubHttpLimits, GithubRepositoryVisibility,
    GithubWebhookBodyDigest, StoredAuthenticatedGithubPush, VerifiedGithubPush,
    rehydrate_stored_authenticated_github_push,
};
use automata_ci_store::{
    AdmissionObject, ClaimedProviderDelivery, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryId,
    ProviderDeliveryIdentity, ProviderDeliveryReceipt, ProviderDeliveryState,
    ProviderInstallationId, ProviderRepositoryCoordinates, ProviderRepositoryId,
    ProviderRepositoryVisibility, TenantScope,
};
use automata_ci_workflow_github::GithubChangedFilesV1;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
    time::Instant,
};
use uuid::Uuid;

use super::{
    GithubPushChangedFilesAuthority, GithubPushChangedFilesError, GithubPushChangedFilesProvider,
    GithubPushChangedFilesRequest,
};
use crate::{
    GITHUB_PUSH_EVENT_MEDIA_TYPE, GithubRestPushChangedFilesProvider,
    service::provider_required_through,
    worker::{GithubDeliveryClaimLease, GithubDeliveryClaimSnapshot},
};

const BEFORE: &str = "1111111111111111111111111111111111111111";
const AFTER: &str = "2222222222222222222222222222222222222222";
const OWNER: &str = "octo-private";
const REPOSITORY: &str = "private-repository";
const REPOSITORY_IDENTITY: &str = "octo-private/private-repository";
const OTHER_REPOSITORY_IDENTITY: &str = "octo-private/other";
const REPOSITORY_ID: u64 = 9_001;
const REPOSITORY_OWNER_ID: u64 = 8_001;
const INSTALLATION_ID: u64 = 4_242;
const DELIVERY: &str = "changed-files-provider-test";
const OTHER_DELIVERY: &str = "other-changed-files-delivery";
const CHANGED_PATH: &str = "src/lib.rs";
const MAX_CAPTURED_REQUEST_BYTES: usize = 16 * 1_024;

struct DeliveryFixture {
    claimed: ClaimedProviderDelivery,
    push: VerifiedGithubPush,
    snapshot: GithubDeliveryClaimSnapshot,
}

struct HttpFixture {
    provider: GithubRestPushChangedFilesProvider,
    server: JoinHandle<String>,
}

impl HttpFixture {
    async fn spawn(response_body: String) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind changed-files HTTP fixture");
        let address = listener.local_addr().expect("fixture address");
        let provider = provider_for(address);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept provider request");
            let mut captured = Vec::with_capacity(2_048);
            let mut chunk = [0_u8; 1_024];
            loop {
                let read = socket
                    .read(&mut chunk)
                    .await
                    .expect("read provider request");
                assert_ne!(read, 0, "provider request ended before its headers");
                captured.extend_from_slice(&chunk[..read]);
                assert!(
                    captured.len() <= MAX_CAPTURED_REQUEST_BYTES,
                    "provider request exceeded the fixture bound"
                );
                if captured.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let response_head = format!(
                "HTTP/1.1 200 OK\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\r\n",
                response_body.len()
            );
            socket
                .write_all(response_head.as_bytes())
                .await
                .expect("write response headers");
            socket
                .write_all(response_body.as_bytes())
                .await
                .expect("write response body");
            socket.shutdown().await.expect("close fixture response");
            String::from_utf8(captured).expect("HTTP request is UTF-8")
        });
        Self { provider, server }
    }

    async fn finish(self) -> String {
        tokio::time::timeout(Duration::from_secs(5), self.server)
            .await
            .expect("HTTP fixture deadline")
            .expect("HTTP fixture task")
    }
}

fn provider_for(address: SocketAddr) -> GithubRestPushChangedFilesProvider {
    let limits = GithubHttpLimits::new(
        1_048_576,
        8,
        1,
        Duration::from_millis(250),
        Duration::from_secs(2),
    )
    .expect("fixture limits");
    let endpoint = GithubHttpEndpoint::new_for_loopback_testing(
        format!("http://{address}/")
            .parse()
            .expect("loopback OAuth origin"),
        format!("http://{address}/api/")
            .parse()
            .expect("loopback API origin"),
        "automata-changed-files-provider-test/0.1.0",
        limits,
    )
    .expect("loopback endpoint");
    GithubRestPushChangedFilesProvider::new(endpoint)
}

fn delivery_fixture(visibility: ProviderRepositoryVisibility) -> DeliveryFixture {
    let (body, github_visibility) = push_body(visibility);
    let digest = Sha256::digest(&body);
    let mut digest_bytes = [0_u8; 32];
    digest_bytes.copy_from_slice(&digest);
    let encoded_size = u64::try_from(body.len()).expect("push body size");
    let object_suffix = match visibility {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    };
    let raw_event = AdmissionObject::new(
        Sha256Digest::from_bytes(digest_bytes),
        ObjectKey::new(format!(
            "provider-deliveries/github/push/{object_suffix}.json"
        ))
        .expect("raw event key"),
        encoded_size,
        GITHUB_PUSH_EVENT_MEDIA_TYPE,
    )
    .expect("raw event");
    let push = rehydrate_stored_authenticated_github_push(
        StoredAuthenticatedGithubPush::from_durable_coordinates(
            body,
            GithubWebhookBodyDigest::from_bytes(digest_bytes),
            encoded_size,
            GITHUB_PUSH_EVENT_MEDIA_TYPE,
            DELIVERY,
            INSTALLATION_ID,
            REPOSITORY_ID,
            REPOSITORY_OWNER_ID,
            github_visibility,
            OWNER,
            REPOSITORY,
        ),
    )
    .expect("verified push");

    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(1)).expect("delivery ID");
    let receipt = ProviderDeliveryReceipt::from_durable_parts(
        delivery_id,
        ProviderDeliveryState::Claimed,
        1,
        UnixMillis::new(50),
    )
    .expect("claim receipt");
    let claim = ProviderDeliveryClaimFence::from_durable_parts(
        delivery_id,
        ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(2)).expect("claim owner"),
        7,
    )
    .expect("claim fence");
    let claimed = ClaimedProviderDelivery::from_durable_parts(
        receipt,
        identity(
            visibility,
            REPOSITORY_ID,
            INSTALLATION_ID,
            REPOSITORY_IDENTITY,
        ),
        Sha256Digest::from_bytes([0x42; 32]),
        raw_event,
        claim,
        UnixMillis::new(100),
        UnixMillis::new(10_000),
    )
    .expect("claimed delivery");
    let lease =
        GithubDeliveryClaimLease::new(claimed.clone(), Instant::now() + Duration::from_secs(5));
    let snapshot = lease.latest().expect("claim snapshot");
    DeliveryFixture {
        claimed,
        push,
        snapshot,
    }
}

fn identity(
    visibility: ProviderRepositoryVisibility,
    repository_id: u64,
    installation_id: u64,
    repository_identity: &str,
) -> ProviderDeliveryIdentity {
    identity_with_provider_and_delivery(
        "github",
        DELIVERY,
        visibility,
        repository_id,
        installation_id,
        repository_identity,
    )
}

fn identity_with_provider_and_delivery(
    provider: &str,
    delivery_id: &str,
    visibility: ProviderRepositoryVisibility,
    repository_id: u64,
    installation_id: u64,
    repository_identity: &str,
) -> ProviderDeliveryIdentity {
    let repository = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(repository_id).expect("repository ID"),
        visibility,
        repository_identity.to_owned(),
    )
    .expect("repository coordinates");
    ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-adapter").expect("tenant"),
        provider,
        ProviderConnectionId::from_uuid(Uuid::from_u128(3)).expect("connection"),
        ProviderInstallationId::new(installation_id).expect("installation"),
        repository,
        delivery_id,
    )
    .expect("delivery identity")
}

fn push_body(visibility: ProviderRepositoryVisibility) -> (Bytes, GithubRepositoryVisibility) {
    let (private, label, github_visibility) = match visibility {
        ProviderRepositoryVisibility::Public => {
            (false, "public", GithubRepositoryVisibility::Public)
        }
        ProviderRepositoryVisibility::Private => {
            (true, "private", GithubRepositoryVisibility::Private)
        }
    };
    let body = Bytes::from(format!(
        r#"{{"ref":"refs/heads/main","before":"{BEFORE}","after":"{AFTER}","created":false,"deleted":false,"forced":false,"repository":{{"id":{REPOSITORY_ID},"private":{private},"visibility":"{label}","name":"{REPOSITORY}","full_name":"{REPOSITORY_IDENTITY}","owner":{{"id":{REPOSITORY_OWNER_ID},"login":"{OWNER}"}}}},"installation":{{"id":{INSTALLATION_ID}}},"commits":[{{"id":"{AFTER}"}}]}}"#
    ));
    (body, github_visibility)
}

fn changed_files_request<'a>(
    fixture: &'a DeliveryFixture,
    identity: &'a ProviderDeliveryIdentity,
    authority: GithubPushChangedFilesAuthority<'a>,
) -> GithubPushChangedFilesRequest<'a> {
    let observed_at = UnixMillis::new(200);
    let required_through =
        provider_required_through(fixture.snapshot, observed_at).expect("provider horizon");
    GithubPushChangedFilesRequest {
        identity,
        request_digest: fixture.claimed.request_digest(),
        push: &fixture.push,
        snapshot: fixture.snapshot,
        observed_at,
        required_through,
        authority,
    }
}

fn comparison_response() -> String {
    format!(
        r#"{{"status":"ahead","ahead_by":1,"behind_by":0,"total_commits":1,"base_commit":{{"sha":"{BEFORE}"}},"merge_base_commit":{{"sha":"{BEFORE}"}},"commits":[{{"sha":"{AFTER}"}}],"files":[{{"filename":"{CHANGED_PATH}","status":"modified"}}]}}"#
    )
}

fn header_value<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
    request
        .lines()
        .skip(1)
        .map(|line| line.trim_end_matches('\r'))
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then_some(value.trim())
        })
}

fn assert_common_request(request: &str) {
    let expected_target = format!(
        "GET /api/repos/{OWNER}/{REPOSITORY}/compare/\
         {BEFORE}...{AFTER}?per_page=100&page=1 HTTP/1.1"
    );
    assert_eq!(request.lines().next(), Some(expected_target.as_str()));
    assert_eq!(
        header_value(request, "accept"),
        Some("application/vnd.github+json")
    );
    assert_eq!(
        header_value(request, "x-github-api-version"),
        Some(GITHUB_API_VERSION)
    );
}

async fn assert_invalid(
    provider: &GithubRestPushChangedFilesProvider,
    request: GithubPushChangedFilesRequest<'_>,
) {
    assert_eq!(
        provider.changed_files(request).await.unwrap_err(),
        GithubPushChangedFilesError::InvalidEvidence
    );
}

#[tokio::test]
async fn public_request_is_anonymous_at_the_real_http_boundary() {
    let delivery = delivery_fixture(ProviderRepositoryVisibility::Public);
    let http = HttpFixture::spawn(comparison_response()).await;

    let outcome = http
        .provider
        .changed_files(changed_files_request(
            &delivery,
            delivery.claimed.identity(),
            GithubPushChangedFilesAuthority::PublicAnonymous,
        ))
        .await
        .expect("public changed files");
    assert_eq!(outcome, GithubChangedFilesV1::complete([CHANGED_PATH]));

    let captured = http.finish().await;
    assert_common_request(&captured);
    assert!(header_value(&captured, "authorization").is_none());
}

#[tokio::test]
async fn private_request_sends_only_the_exact_token_at_the_real_http_boundary() {
    let delivery = delivery_fixture(ProviderRepositoryVisibility::Private);
    let http = HttpFixture::spawn(comparison_response()).await;
    let token = SecretString::new("ghs_exact_changed_files_adapter").expect("token");

    let outcome = http
        .provider
        .changed_files(changed_files_request(
            &delivery,
            delivery.claimed.identity(),
            GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(&token),
        ))
        .await
        .expect("private changed files");
    assert_eq!(outcome, GithubChangedFilesV1::complete([CHANGED_PATH]));

    let captured = http.finish().await;
    assert_common_request(&captured);
    assert_eq!(
        header_value(&captured, "authorization"),
        Some("Bearer ghs_exact_changed_files_adapter")
    );
}

#[tokio::test]
async fn binding_mismatches_are_rejected_before_any_http_io() {
    let delivery = delivery_fixture(ProviderRepositoryVisibility::Public);
    let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind no-I/O fixture");
    listener
        .set_nonblocking(true)
        .expect("make no-I/O fixture nonblocking");
    let provider = provider_for(listener.local_addr().expect("no-I/O fixture address"));

    let mismatched_identities = [
        identity_with_provider_and_delivery(
            "gitlab",
            DELIVERY,
            ProviderRepositoryVisibility::Public,
            REPOSITORY_ID,
            INSTALLATION_ID,
            REPOSITORY_IDENTITY,
        ),
        identity_with_provider_and_delivery(
            "github",
            OTHER_DELIVERY,
            ProviderRepositoryVisibility::Public,
            REPOSITORY_ID,
            INSTALLATION_ID,
            REPOSITORY_IDENTITY,
        ),
        identity(
            ProviderRepositoryVisibility::Public,
            REPOSITORY_ID,
            INSTALLATION_ID,
            OTHER_REPOSITORY_IDENTITY,
        ),
        identity(
            ProviderRepositoryVisibility::Public,
            REPOSITORY_ID + 1,
            INSTALLATION_ID,
            REPOSITORY_IDENTITY,
        ),
        identity(
            ProviderRepositoryVisibility::Public,
            REPOSITORY_ID,
            INSTALLATION_ID + 1,
            REPOSITORY_IDENTITY,
        ),
    ];
    for mismatched in &mismatched_identities {
        assert_invalid(
            &provider,
            changed_files_request(
                &delivery,
                mismatched,
                GithubPushChangedFilesAuthority::PublicAnonymous,
            ),
        )
        .await;
    }

    let token = SecretString::new("ghs_must_not_reach_http").expect("token");
    let private_identity = identity(
        ProviderRepositoryVisibility::Private,
        REPOSITORY_ID,
        INSTALLATION_ID,
        REPOSITORY_IDENTITY,
    );
    assert_invalid(
        &provider,
        changed_files_request(
            &delivery,
            &private_identity,
            GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(&token),
        ),
    )
    .await;
    assert_invalid(
        &provider,
        changed_files_request(
            &delivery,
            delivery.claimed.identity(),
            GithubPushChangedFilesAuthority::PrivateInstallationContentsRead(&token),
        ),
    )
    .await;

    let mut expired = changed_files_request(
        &delivery,
        delivery.claimed.identity(),
        GithubPushChangedFilesAuthority::PublicAnonymous,
    );
    expired.required_through = expired.observed_at;
    assert_invalid(&provider, expired).await;

    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected no-I/O fixture error: {error}"),
        Ok(_) => panic!("a binding mismatch reached the HTTP listener"),
    }
}
