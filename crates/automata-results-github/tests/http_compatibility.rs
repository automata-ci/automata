use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_blob::MemoryBlobStore;
use automata_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use automata_results_github::{
    ArtifactBlock, ArtifactId, ArtifactName, ArtifactPublicationState, ArtifactRepository,
    ArtifactRepositoryError, ArtifactService, CommitArtifactBlocks, CommittedArtifact,
    CreateArtifact, CreateArtifactOutcome, ExecutionAuthority, FinalizeArtifact,
    FinalizeArtifactOutcome, GithubResultsApi, GithubResultsHttpLimits, HmacResultsAuthority,
    HmacResultsAuthorityConfig, PublishedArtifact, ResultsClock, ResultsIdGenerator, ResultsLimits,
    ResultsPublicEndpoint, RuntimeTokenIssuer as _, StageArtifactBlock, UploadId,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use sha2::Digest as _;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

#[derive(Debug)]
struct FixedClock(u64);

impl ResultsClock for FixedClock {
    fn now_seconds(&self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
struct FixedIds(UploadId);

impl ResultsIdGenerator for FixedIds {
    fn next_upload_id(&self) -> UploadId {
        self.0
    }
}

#[derive(Debug)]
struct FakeRepository {
    artifact_id: ArtifactId,
    upload_id: UploadId,
    state: Mutex<FakeState>,
}

#[derive(Debug, Default)]
struct FakeState {
    create: Option<CreateArtifact>,
    blocks: Vec<ArtifactBlock>,
    committed: Option<CommittedArtifact>,
    published: Option<PublishedArtifact>,
}

#[async_trait]
impl ArtifactRepository for FakeRepository {
    async fn create(
        &self,
        request: CreateArtifact,
    ) -> Result<CreateArtifactOutcome, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("fake repository lock");
        if let Some(existing) = &state.create {
            assert_eq!(existing.authority, request.authority);
            assert_eq!(existing.name, request.name);
        } else {
            state.create = Some(request);
        }
        Ok(CreateArtifactOutcome {
            artifact_id: self.artifact_id,
            upload_id: self.upload_id,
        })
    }

    async fn authorize_upload(&self, upload_id: UploadId) -> Result<(), ArtifactRepositoryError> {
        assert_eq!(upload_id, self.upload_id);
        assert!(
            self.state
                .lock()
                .expect("fake repository lock")
                .create
                .is_some()
        );
        Ok(())
    }

    async fn record_block(
        &self,
        request: StageArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        assert_eq!(request.upload_id, self.upload_id);
        let mut state = self.state.lock().expect("fake repository lock");
        if let Some(existing) = state
            .blocks
            .iter()
            .find(|block| block.block_id() == request.block.block_id())
        {
            assert_eq!(existing, &request.block);
        } else {
            state.blocks.push(request.block);
        }
        Ok(())
    }

    async fn commit_blocks(
        &self,
        request: CommitArtifactBlocks,
    ) -> Result<CommittedArtifact, ArtifactRepositoryError> {
        assert_eq!(request.upload_id, self.upload_id);
        let mut state = self.state.lock().expect("fake repository lock");
        let create = state.create.as_ref().expect("artifact created");
        let blocks = request
            .block_ids
            .iter()
            .map(|id| {
                state
                    .blocks
                    .iter()
                    .find(|block| block.block_id() == id)
                    .cloned()
                    .expect("staged block")
            })
            .collect::<Vec<_>>();
        let committed = CommittedArtifact {
            artifact_id: self.artifact_id,
            upload_id: self.upload_id,
            authority: create.authority,
            name: create.name.clone(),
            mime_type: create.mime_type.clone(),
            size: blocks.iter().map(|block| block.descriptor().size()).sum(),
            blocks,
        };
        state.committed = Some(committed.clone());
        Ok(committed)
    }

    async fn publication_state(
        &self,
        _authority: ExecutionAuthority,
        _name: &ArtifactName,
    ) -> Result<ArtifactPublicationState, ArtifactRepositoryError> {
        let state = self.state.lock().expect("fake repository lock");
        Ok(state.published.clone().map_or_else(
            || ArtifactPublicationState::Committed(state.committed.clone().expect("committed")),
            ArtifactPublicationState::Published,
        ))
    }

    async fn finalize(
        &self,
        request: FinalizeArtifact,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        let published = PublishedArtifact {
            artifact_id: self.artifact_id,
            content_digest: request.content_digest,
            size: request.size,
            manifest: request.manifest,
        };
        self.state.lock().expect("fake repository lock").published = Some(published);
        Ok(FinalizeArtifactOutcome {
            artifact_id: self.artifact_id,
            content_digest: request.content_digest,
            size: request.size,
        })
    }
}

struct Fixture {
    router: axum::Router,
    token: String,
    execution: ExecutionAuthority,
}

fn fixture() -> Fixture {
    fixture_with_url("http://results.automata.localhost:8080/")
}

fn fixture_with_url(public_url: &str) -> Fixture {
    let now = 1_000_000;
    let clock = Arc::new(FixedClock(now));
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let repository = Arc::new(FakeRepository {
        artifact_id: ArtifactId::new(41).expect("artifact id"),
        upload_id,
        state: Mutex::new(FakeState::default()),
    });
    let service = Arc::new(ArtifactService::new(
        repository,
        Arc::new(MemoryBlobStore::default()),
        clock.clone(),
        Arc::new(FixedIds(upload_id)),
        ResultsLimits::default(),
    ));
    let public_url = Url::parse(public_url).expect("URL");
    let listener_bind = format!(
        "127.0.0.1:{}",
        public_url.port_or_known_default().expect("HTTP port")
    )
    .parse()
    .expect("loopback listener");
    let token_authority = Arc::new(
        HmacResultsAuthority::new(
            b"http-contract-results-signing-key-material-v1",
            HmacResultsAuthorityConfig::new(
                "automata-test",
                "actions-results",
                "test-v1",
                ResultsPublicEndpoint::loopback_development(public_url, listener_bind)
                    .expect("loopback development endpoint"),
                900,
                900,
                0,
            )
            .expect("token config"),
            clock,
        )
        .expect("token authority"),
    );
    let execution = ExecutionAuthority::new(
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
        FencingToken::new(3).expect("fence"),
    );
    let token = token_authority
        .issue(execution, 600)
        .expect("runtime token")
        .expose_secret()
        .to_owned();
    let router = GithubResultsApi::new(
        service,
        token_authority.clone(),
        token_authority,
        GithubResultsHttpLimits::default(),
    )
    .router();
    Fixture {
        router,
        token,
        execution,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Node >=24 and AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE"]
async fn official_actions_artifact_6_2_client_completes_the_full_protocol() {
    let module_path = std::env::var_os("AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE")
        .map(PathBuf::from)
        .expect(
            "set AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE to @actions/artifact 6.2.0 lib/internal/client.js",
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind action-client fixture");
    let address = listener.local_addr().expect("listener address");
    let fixture = fixture_with_url(&format!("http://{address}/"));
    let router = fixture.router.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("action-client fixture server");
    });

    let scratch = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/agent-scratch/artifact-results/action-client-run")
        .join(Uuid::new_v4().simple().to_string());
    std::fs::create_dir_all(&scratch).expect("create repository-local test scratch");
    let input = scratch.join("automata-static-musl.tar.gz");
    std::fs::write(
        &input,
        b"official @actions/artifact 6.2.0 integration bytes",
    )
    .expect("write fixture input");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/official_artifact_client.mjs");
    let token = fixture.token;
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("node")
            .arg(script)
            .env("ACTIONS_RUNTIME_TOKEN", token)
            .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
            .env("GITHUB_SERVER_URL", "http://automata-git.ghe.com:8088/")
            .env("GITHUB_WORKSPACE", &scratch)
            .env("AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE", module_path)
            .env("AUTOMATA_TEST_ARTIFACT_INPUT", input)
            .env("AUTOMATA_TEST_ARTIFACT_ROOT", scratch)
            .status()
            .expect("run official artifact client")
    })
    .await
    .expect("join Node client");
    server.abort();
    assert!(status.success(), "official artifact client must complete");
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One readable request/response transcript verifies the full protocol order.
async fn exact_v7_twirp_and_azure_block_upload_flow_succeeds() {
    let fixture = fixture();
    let create_body = serde_json::json!({
        "workflow_run_backend_id": fixture.execution.run_id().to_string(),
        "workflow_job_run_backend_id": fixture.execution.job_id().to_string(),
        "name": "automata-linux-x64",
        "version": 7,
        "mime_type": "application/zip"
    });
    let response = fixture
        .router
        .clone()
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact",
            &fixture.token,
            &create_body,
        ))
        .await
        .expect("create response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let create: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("create JSON");
    assert_eq!(create["ok"], true);
    let signed_url = Url::parse(create["signed_upload_url"].as_str().expect("URL")).expect("URL");

    let artifact_bytes = Bytes::from_static(b"immutable automata artifact bytes");
    let block_id = STANDARD.encode([7_u8; 48]);
    let mut stage_url = signed_url.clone();
    stage_url
        .query_pairs_mut()
        .append_pair("comp", "block")
        .append_pair("blockid", &block_id);
    let response = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path_and_query(&stage_url))
                .header(header::CONTENT_LENGTH, artifact_bytes.len())
                .body(Body::from(artifact_bytes.clone()))
                .expect("stage request"),
        )
        .await
        .expect("stage response");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-ms-version"], "2025-11-05");

    let mut commit_url = signed_url;
    commit_url
        .query_pairs_mut()
        .append_pair("comp", "blocklist");
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BlockList><Latest>{block_id}</Latest></BlockList>"
    );
    let response = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path_and_query(&commit_url))
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .expect("commit request"),
        )
        .await
        .expect("commit response");
    assert_eq!(response.status(), StatusCode::CREATED);

    let digest = Sha256Digest::from_bytes(sha2::Sha256::digest(&artifact_bytes).into());
    let finalize_body = serde_json::json!({
        "workflow_run_backend_id": fixture.execution.run_id().to_string(),
        "workflow_job_run_backend_id": fixture.execution.job_id().to_string(),
        "name": "automata-linux-x64",
        "size": artifact_bytes.len().to_string(),
        "hash": format!("sha256:{digest}")
    });
    let response = fixture
        .router
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/FinalizeArtifact",
            &fixture.token,
            &finalize_body,
        ))
        .await
        .expect("finalize response");
    assert_eq!(response.status(), StatusCode::OK);
    let finalize: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("finalize JSON");
    assert_eq!(finalize["artifact_id"], "41");
}

#[tokio::test]
async fn auth_job_binding_signed_url_and_xml_parser_fail_closed() {
    let fixture = fixture();
    let valid_body = serde_json::json!({
        "workflow_run_backend_id": fixture.execution.run_id().to_string(),
        "workflow_job_run_backend_id": fixture.execution.job_id().to_string(),
        "name": "artifact",
        "version": 7,
        "mime_type": "application/zip"
    });
    let missing = Request::builder()
        .method("POST")
        .uri("/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(valid_body.to_string()))
        .expect("request");
    let response = fixture
        .router
        .clone()
        .oneshot(missing)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let mut wrong_job = valid_body.clone();
    wrong_job["workflow_job_run_backend_id"] = serde_json::json!(JobId::new().to_string());
    let response = fixture
        .router
        .clone()
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact",
            &fixture.token,
            &wrong_job,
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = fixture
        .router
        .clone()
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact",
            &fixture.token,
            &valid_body,
        ))
        .await
        .expect("create response");
    let create: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("JSON");
    let mut signed_url =
        Url::parse(create["signed_upload_url"].as_str().expect("URL")).expect("URL");
    let pairs = signed_url.query_pairs().into_owned().collect::<Vec<_>>();
    signed_url.set_query(None);
    for (key, mut value) in pairs {
        if key == "sig" {
            value.replace_range(..1, if value.starts_with('A') { "B" } else { "A" });
        }
        signed_url.query_pairs_mut().append_pair(&key, &value);
    }
    signed_url
        .query_pairs_mut()
        .append_pair("comp", "blocklist");
    let response = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path_and_query(&signed_url))
                .body(Body::from("<BlockList/>"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut signed_url =
        Url::parse(create["signed_upload_url"].as_str().expect("URL")).expect("URL");
    signed_url
        .query_pairs_mut()
        .append_pair("comp", "blocklist");
    let malicious =
        "<!DOCTYPE BlockList [<!ENTITY x 'AAAA'>]><BlockList><Latest>&x;</Latest></BlockList>";
    let response = fixture
        .router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path_and_query(&signed_url))
                .body(Body::from(malicious))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

fn twirp_request(path: &str, token: &str, value: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
        .expect("request")
}

fn path_and_query(url: &Url) -> String {
    url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    )
}
