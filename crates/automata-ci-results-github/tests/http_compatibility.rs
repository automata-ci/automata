mod fixture_support;
mod http_support;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType, MemoryBlobStore};
use automata_ci_core::{AttemptId, FencingToken, JobId, Sha256Digest};
use automata_ci_results_github::{
    ArtifactBlock, ArtifactBlockReservation, ArtifactFinalizationClaim,
    ArtifactFinalizationReservation, ArtifactFinalizationWork, ArtifactId, ArtifactRepository,
    ArtifactRepositoryError, ArtifactRepositoryErrorKind, ArtifactService,
    BeginArtifactFinalization, CommitArtifactBlocks, CommittedArtifact, CompleteArtifactBlock,
    CompleteArtifactFinalization, CreateArtifact, CreateArtifactOutcome, ExecutionAuthority,
    FinalizeArtifactOutcome, GithubResultsApi, GithubResultsHttpLimits, HmacResultsAuthority,
    HmacResultsAuthorityConfig, ListArtifacts, LoadArtifactFinalization, PublishedArtifactMetadata,
    RecordArtifactVerification, RenewArtifactFinalization, ReserveArtifactBlock,
    ResolveArtifactDownload, ResultsLimits, ResultsPublicEndpoint, RuntimeTokenIssuer as _,
    UploadId, VerifiedArtifactFinalization,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use fixture_support::{
    FixedClock, FixedIds, fresh_execution_authority, read_write_cache_authority,
};
use http_body_util::BodyExt as _;
use http_support::{assert_private_rejection, isolated_node_command, path_and_query};
use sha2::Digest as _;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

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
    ready_blocks: Vec<String>,
    committed: Option<CommittedArtifact>,
    finalization: Option<FakeFinalization>,
    published: Option<FinalizeArtifactOutcome>,
}

#[derive(Clone, Debug)]
struct FakeFinalization {
    claim: ArtifactFinalizationClaim,
    expires_at_seconds: u64,
    verified: Option<VerifiedArtifactFinalization>,
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

    async fn reserve_block(
        &self,
        request: ReserveArtifactBlock,
    ) -> Result<ArtifactBlockReservation, ArtifactRepositoryError> {
        assert_eq!(request.upload_id, self.upload_id);
        let mut state = self.state.lock().expect("fake repository lock");
        if let Some(existing) = state
            .blocks
            .iter()
            .find(|block| block.block_id() == request.block.block_id())
        {
            if existing != &request.block {
                return Err(ArtifactRepositoryError::new(
                    ArtifactRepositoryErrorKind::Conflict,
                ));
            }
            return Ok(
                if state
                    .ready_blocks
                    .iter()
                    .any(|block_id| block_id == request.block.block_id())
                {
                    ArtifactBlockReservation::Ready
                } else {
                    ArtifactBlockReservation::UploadRequired
                },
            );
        }
        state.blocks.push(request.block);
        Ok(ArtifactBlockReservation::UploadRequired)
    }

    async fn complete_block(
        &self,
        request: CompleteArtifactBlock,
    ) -> Result<(), ArtifactRepositoryError> {
        assert_eq!(request.upload_id, self.upload_id);
        let mut state = self.state.lock().expect("fake repository lock");
        let Some(existing) = state
            .blocks
            .iter()
            .find(|block| block.block_id() == request.block.block_id())
        else {
            return Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::NotFound,
            ));
        };
        if existing != &request.block {
            return Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::Conflict,
            ));
        }
        if !state
            .ready_blocks
            .iter()
            .any(|block_id| block_id == request.block.block_id())
        {
            state.ready_blocks.push(request.block.block_id().to_owned());
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
                    .find(|block| {
                        block.block_id() == id && state.ready_blocks.iter().any(|ready| ready == id)
                    })
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

    async fn begin_finalization(
        &self,
        request: BeginArtifactFinalization,
    ) -> Result<ArtifactFinalizationReservation, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("fake repository lock");
        let committed = state.committed.as_ref().expect("committed");
        if committed.authority != request.authority
            || committed.name != request.name
            || committed.size != request.claimed_size
        {
            return Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::Conflict,
            ));
        }
        if let Some(published) = state.published {
            if request
                .claimed_digest
                .is_some_and(|digest| digest != published.content_digest)
            {
                return Err(ArtifactRepositoryError::new(
                    ArtifactRepositoryErrorKind::Conflict,
                ));
            }
            return Ok(ArtifactFinalizationReservation::Published(published));
        }
        if let Some(finalization) = &state.finalization
            && finalization.expires_at_seconds > request.observed_at_seconds
        {
            return Ok(ArtifactFinalizationReservation::InProgress {
                retry_at_seconds: finalization.expires_at_seconds,
            });
        }
        let generation = state
            .finalization
            .as_ref()
            .map_or(1, |finalization| finalization.claim.generation() + 1);
        let claim = ArtifactFinalizationClaim::new(
            self.artifact_id,
            request.authority,
            request.name,
            generation,
        );
        let verified = state
            .finalization
            .as_ref()
            .and_then(|finalization| finalization.verified.clone());
        state.finalization = Some(FakeFinalization {
            claim: claim.clone(),
            expires_at_seconds: request.observed_at_seconds + request.lease_seconds,
            verified,
        });
        Ok(ArtifactFinalizationReservation::Claimed(claim))
    }

    async fn load_finalization(
        &self,
        request: LoadArtifactFinalization,
    ) -> Result<ArtifactFinalizationWork, ArtifactRepositoryError> {
        let state = self.state.lock().expect("fake repository lock");
        let finalization = require_fake_claim(&state, &request.claim, request.observed_at_seconds)?;
        Ok(finalization.verified.clone().map_or_else(
            || ArtifactFinalizationWork::Verify(state.committed.clone().expect("committed")),
            ArtifactFinalizationWork::Publish,
        ))
    }

    async fn renew_finalization(
        &self,
        request: RenewArtifactFinalization,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("fake repository lock");
        let finalization =
            require_fake_claim_mut(&mut state, &request.claim, request.observed_at_seconds)?;
        finalization.expires_at_seconds = finalization
            .expires_at_seconds
            .max(request.observed_at_seconds + request.lease_seconds);
        Ok(())
    }

    async fn record_verification(
        &self,
        request: RecordArtifactVerification,
    ) -> Result<(), ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("fake repository lock");
        let size = state.committed.as_ref().expect("committed").size;
        let finalization =
            require_fake_claim_mut(&mut state, &request.claim, request.observed_at_seconds)?;
        finalization.verified = Some(VerifiedArtifactFinalization {
            artifact_id: self.artifact_id,
            content_digest: request.content_digest,
            size,
            manifest: request.manifest,
            manifest_bytes: request.manifest_bytes,
        });
        finalization.expires_at_seconds = finalization
            .expires_at_seconds
            .max(request.observed_at_seconds + request.lease_seconds);
        Ok(())
    }

    async fn complete_finalization(
        &self,
        request: CompleteArtifactFinalization,
    ) -> Result<FinalizeArtifactOutcome, ArtifactRepositoryError> {
        let mut state = self.state.lock().expect("fake repository lock");
        if let Some(published) = state.published {
            return Ok(published);
        }
        let finalization = require_fake_claim(&state, &request.claim, request.observed_at_seconds)?;
        let verified = finalization.verified.as_ref().ok_or_else(|| {
            ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::InvalidState)
        })?;
        let outcome = FinalizeArtifactOutcome {
            artifact_id: self.artifact_id,
            content_digest: verified.content_digest,
            size: verified.size,
        };
        state.published = Some(outcome);
        Ok(outcome)
    }

    async fn list(
        &self,
        request: ListArtifacts,
    ) -> Result<Vec<PublishedArtifactMetadata>, ArtifactRepositoryError> {
        let state = self.state.lock().expect("fake repository lock");
        let metadata = match fake_metadata(&state, self.artifact_id, self.upload_id) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ArtifactRepositoryErrorKind::NotFound => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        if request.authority.run_id() != metadata.authority.run_id() {
            return Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::Unauthorized,
            ));
        }
        if metadata
            .expires_at_seconds
            .is_some_and(|expires_at| expires_at <= request.observed_at_seconds)
            || request
                .name
                .as_ref()
                .is_some_and(|name| name != &metadata.name)
            || request
                .artifact_id
                .is_some_and(|artifact_id| artifact_id != metadata.artifact_id)
        {
            return Ok(Vec::new());
        }
        Ok(vec![metadata])
    }

    async fn resolve_download(
        &self,
        request: ResolveArtifactDownload,
    ) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
        let state = self.state.lock().expect("fake repository lock");
        let metadata = fake_metadata(&state, self.artifact_id, self.upload_id)?;
        if request.artifact_id != metadata.artifact_id
            || request.content_digest != metadata.content_digest
            || metadata
                .expires_at_seconds
                .is_some_and(|expires_at| expires_at <= request.observed_at_seconds)
        {
            return Err(ArtifactRepositoryError::new(
                ArtifactRepositoryErrorKind::NotFound,
            ));
        }
        Ok(metadata)
    }
}

fn fake_metadata(
    state: &FakeState,
    artifact_id: ArtifactId,
    upload_id: UploadId,
) -> Result<PublishedArtifactMetadata, ArtifactRepositoryError> {
    let create = state
        .create
        .as_ref()
        .ok_or_else(|| ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::NotFound))?;
    let published = state
        .published
        .as_ref()
        .ok_or_else(|| ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::NotFound))?;
    let verified = state
        .finalization
        .as_ref()
        .and_then(|finalization| finalization.verified.as_ref())
        .ok_or_else(|| ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::NotFound))?;
    Ok(PublishedArtifactMetadata {
        artifact_id,
        upload_id,
        authority: create.authority,
        name: create.name.clone(),
        mime_type: create.mime_type.clone(),
        content_digest: published.content_digest,
        size: published.size,
        manifest: verified.manifest.clone(),
        created_at_seconds: create.observed_at_seconds,
        expires_at_seconds: create.expires_at_seconds,
    })
}

fn require_fake_claim<'a>(
    state: &'a FakeState,
    claim: &ArtifactFinalizationClaim,
    observed_at_seconds: u64,
) -> Result<&'a FakeFinalization, ArtifactRepositoryError> {
    let finalization = state
        .finalization
        .as_ref()
        .ok_or_else(|| ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::Unauthorized))?;
    if finalization.claim != *claim || finalization.expires_at_seconds <= observed_at_seconds {
        return Err(ArtifactRepositoryError::new(
            ArtifactRepositoryErrorKind::Unauthorized,
        ));
    }
    Ok(finalization)
}

fn require_fake_claim_mut<'a>(
    state: &'a mut FakeState,
    claim: &ArtifactFinalizationClaim,
    observed_at_seconds: u64,
) -> Result<&'a mut FakeFinalization, ArtifactRepositoryError> {
    let finalization = state
        .finalization
        .as_mut()
        .ok_or_else(|| ArtifactRepositoryError::new(ArtifactRepositoryErrorKind::Unauthorized))?;
    if finalization.claim != *claim || finalization.expires_at_seconds <= observed_at_seconds {
        return Err(ArtifactRepositoryError::new(
            ArtifactRepositoryErrorKind::Unauthorized,
        ));
    }
    Ok(finalization)
}

struct Fixture {
    router: axum::Router,
    token: String,
    execution: ExecutionAuthority,
    repository: Arc<FakeRepository>,
    token_authority: Arc<HmacResultsAuthority>,
}

fn fixture() -> Fixture {
    fixture_with_url_and_limits(
        "http://results.automata.localhost:8080/",
        GithubResultsHttpLimits::default(),
    )
}

fn fixture_with_url(public_url: &str) -> Fixture {
    fixture_with_url_and_limits(public_url, GithubResultsHttpLimits::default())
}

fn fixture_with_limits(limits: GithubResultsHttpLimits) -> Fixture {
    fixture_with_url_and_limits("http://results.automata.localhost:8080/", limits)
}

fn fixture_with_url_and_limits(public_url: &str, limits: GithubResultsHttpLimits) -> Fixture {
    let now = 1_000_000;
    let clock = Arc::new(FixedClock(now));
    let upload_id = UploadId::from_uuid(Uuid::new_v4());
    let repository = Arc::new(FakeRepository {
        artifact_id: ArtifactId::new(41).expect("artifact id"),
        upload_id,
        state: Mutex::new(FakeState::default()),
    });
    let service = Arc::new(ArtifactService::new(
        repository.clone(),
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
    let execution = fresh_execution_authority(3);
    let token = token_authority
        .issue(
            execution,
            read_write_cache_authority("automata-ci/automata", "refs/heads/main"),
            600,
        )
        .expect("runtime token")
        .expose_secret()
        .to_owned();
    let router = GithubResultsApi::new(
        service,
        token_authority.clone(),
        token_authority.clone(),
        token_authority.clone(),
        limits,
    )
    .router();
    Fixture {
        router,
        token,
        execution,
        repository,
        token_authority,
    }
}

#[tokio::test]
async fn artifact_router_and_extractor_rejections_are_private() {
    let fixture = fixture_with_limits(
        GithubResultsHttpLimits::new(64, 8).expect("focused artifact HTTP limits"),
    );
    let upload_path = format!("/_apis/results/artifacts/{}/blob", Uuid::new_v4());
    let cases = [
        (
            StatusCode::BAD_REQUEST,
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "{upload_path}?se=invalid&sig=x&comp=block&blockid=x"
                ))
                .body(Body::empty())
                .expect("malformed query request"),
        ),
        (
            StatusCode::METHOD_NOT_ALLOWED,
            Request::builder()
                .method("GET")
                .uri("/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact")
                .body(Body::empty())
                .expect("method rejection request"),
        ),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            Request::builder()
                .method("PUT")
                .uri(format!("{upload_path}?se=1&sig=x&comp=block&blockid=x"))
                .header(header::CONTENT_LENGTH, 9)
                .body(Body::from(vec![0_u8; 9]))
                .expect("body-limit rejection request"),
        ),
    ];

    for (status, request) in cases {
        let response = fixture
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("artifact rejection response");
        assert_private_rejection(&response, status);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Node >=24 and AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE"]
async fn official_actions_artifact_6_2_client_completes_the_full_protocol() {
    let upload_module_path = std::env::var_os("AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE")
        .map(PathBuf::from)
        .expect(
            "set AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE to @actions/artifact 6.2.0 lib/internal/client.js",
        );
    run_official_artifact_clients(upload_module_path, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Node >=24 and both exact upload/download @actions/artifact modules"]
async fn official_download_action_artifact_6_2_1_client_completes_the_full_protocol() {
    let upload_module_path = std::env::var_os("AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE")
        .map(PathBuf::from)
        .expect(
            "set AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE to @actions/artifact 6.2.0 lib/internal/client.js",
        );
    let download_module_path = std::env::var_os("AUTOMATA_TEST_ACTIONS_DOWNLOAD_ARTIFACT_MODULE")
        .map(PathBuf::from)
        .expect(
            "set AUTOMATA_TEST_ACTIONS_DOWNLOAD_ARTIFACT_MODULE to download-artifact v8.0.1 @actions/artifact 6.2.1 lib/internal/client.js",
        );
    run_official_artifact_clients(upload_module_path, Some(download_module_path)).await;
}

async fn run_official_artifact_clients(
    upload_module_path: PathBuf,
    download_module_path: Option<PathBuf>,
) {
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
    let token = fixture.token.clone();
    let upload_scratch = scratch.clone();
    let upload_input = input.clone();
    let output = tokio::task::spawn_blocking(move || {
        isolated_node_command()
            .arg(script)
            .env("ACTIONS_RUNTIME_TOKEN", token)
            .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
            .env("GITHUB_SERVER_URL", "http://automata-git.ghe.com:8088/")
            .env("GITHUB_WORKSPACE", &upload_scratch)
            .env("AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE", upload_module_path)
            .env("AUTOMATA_TEST_ACTIONS_ARTIFACT_VERSION", "6.2.0")
            .env("AUTOMATA_TEST_ARTIFACT_INPUT", upload_input)
            .env("AUTOMATA_TEST_ARTIFACT_ROOT", upload_scratch)
            .output()
            .expect("run official artifact client")
    })
    .await
    .expect("join Node client");
    assert!(
        output.status.success(),
        "official artifact client exited with {}",
        output.status
    );

    if let Some(download_module_path) = download_module_path {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/official_artifact_download_client.mjs");
        let token = fixture.token;
        let download_output = tokio::task::spawn_blocking(move || {
            isolated_node_command()
                .arg(script)
                .env("ACTIONS_RUNTIME_TOKEN", token)
                .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
                .env("GITHUB_SERVER_URL", "http://automata-git.ghe.com:8088/")
                .env("GITHUB_WORKSPACE", &scratch)
                .env(
                    "AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE",
                    download_module_path,
                )
                .env("AUTOMATA_TEST_ACTIONS_ARTIFACT_VERSION", "6.2.1")
                .env("AUTOMATA_TEST_ARTIFACT_INPUT", input)
                .env("AUTOMATA_TEST_ARTIFACT_ROOT", scratch)
                .output()
                .expect("run official download action artifact client")
        })
        .await
        .expect("join Node download client");
        assert!(
            download_output.status.success(),
            "official download action artifact client exited with {}",
            download_output.status
        );
    }
    server.abort();
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
        .clone()
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

    let list_body = serde_json::json!({
        "workflow_run_backend_id": fixture.execution.run_id().to_string(),
        "workflow_job_run_backend_id": fixture.execution.job_id().to_string()
    });
    let response = fixture
        .router
        .clone()
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts",
            &fixture.token,
            &list_body,
        ))
        .await
        .expect("list response");
    assert_eq!(response.status(), StatusCode::OK);
    let list: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("list JSON");
    assert_eq!(list["artifacts"][0]["database_id"], "41");
    assert_eq!(list["artifacts"][0]["name"], "automata-linux-x64");
    assert_eq!(
        list["artifacts"][0]["size"],
        artifact_bytes.len().to_string()
    );
    assert_eq!(list["artifacts"][0]["digest"], format!("sha256:{digest}"));
    assert_eq!(list["artifacts"][0]["created_at"], "1970-01-12T13:46:40Z");

    let filtered_list_body = serde_json::json!({
        "workflow_run_backend_id": fixture.execution.run_id().to_string(),
        "workflow_job_run_backend_id": fixture.execution.job_id().to_string(),
        "name_filter": "automata-linux-x64",
        "id_filter": "41"
    });
    let response = fixture
        .router
        .clone()
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts",
            &fixture.token,
            &filtered_list_body,
        ))
        .await
        .expect("filtered list response");
    assert_eq!(response.status(), StatusCode::OK);
    let filtered: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("filtered list JSON");
    assert_eq!(filtered["artifacts"].as_array().map(Vec::len), Some(1));

    let signed_download_body = serde_json::json!({
        "workflow_run_backend_id": fixture.execution.run_id().to_string(),
        "workflow_job_run_backend_id": fixture.execution.job_id().to_string(),
        "name": "automata-linux-x64"
    });
    let consumer = ExecutionAuthority::new(
        fixture.execution.run_id(),
        JobId::new(),
        AttemptId::new(),
        FencingToken::new(4).expect("consumer fence"),
    );
    let consumer_token = fixture
        .token_authority
        .issue(
            consumer,
            read_write_cache_authority("automata-ci/automata", "refs/heads/main"),
            600,
        )
        .expect("consumer runtime token")
        .expose_secret()
        .to_owned();
    let response = fixture
        .router
        .clone()
        .oneshot(twirp_request(
            "/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL",
            &consumer_token,
            &signed_download_body,
        ))
        .await
        .expect("signed download response");
    assert_eq!(response.status(), StatusCode::OK);
    let signed: serde_json::Value = serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes(),
    )
    .expect("signed download JSON");
    let signed_url = Url::parse(signed["signed_url"].as_str().expect("signed URL"))
        .expect("signed download URL");

    for _ in 0..2 {
        let response = fixture
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path_and_query(&signed_url))
                    .body(Body::empty())
                    .expect("download request"),
            )
            .await
            .expect("download response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
        assert_eq!(
            response.headers()[header::ETAG],
            format!("\"sha256:{digest}\"")
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let downloaded = response
            .into_body()
            .collect()
            .await
            .expect("immutable download body")
            .to_bytes();
        assert_eq!(downloaded, artifact_bytes);
    }

    let mut tampered = signed_url.clone();
    let other_digest = Sha256Digest::from_bytes([0x55; 32]);
    tampered.set_path(&format!(
        "/_apis/results/artifacts/41/{other_digest}/download.zip"
    ));
    let response = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path_and_query(&tampered))
                .body(Body::empty())
                .expect("tampered download request"),
        )
        .await
        .expect("tampered download response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    fixture
        .repository
        .state
        .lock()
        .expect("fake repository lock")
        .finalization
        .as_mut()
        .and_then(|finalization| finalization.verified.as_mut())
        .expect("verified artifact")
        .manifest = BlobDescriptor::new(
        BlobKey::new("artifacts/v1/missing/manifest.json").expect("missing manifest key"),
        Sha256Digest::from_bytes([0x77; 32]),
        17,
        MediaType::new("application/vnd.automata.artifact-manifest+json")
            .expect("manifest media type"),
    );
    let response = fixture
        .router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path_and_query(&signed_url))
                .body(Body::empty())
                .expect("missing manifest request"),
        )
        .await
        .expect("missing manifest response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
