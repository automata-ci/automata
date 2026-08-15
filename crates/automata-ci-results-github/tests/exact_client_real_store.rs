mod support;

use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
    time::Duration,
};

use automata_ci_blob::ImmutableBlobStore;
use automata_ci_blob_s3::{
    S3AtRestEncryption, S3BlobStore, S3BlobStoreConfig, StaticS3Credentials,
};
use automata_ci_control::adapter_spi::{
    AcquireLease, InternalAttemptRepository as _, QueuedAttempt,
};
use automata_ci_core::{AttemptId, AttemptNumber, LeaseId, UnixMillis};
use automata_ci_results_github::{
    ArtifactRepository, ArtifactService, CacheAccessScope, CacheAuthority, CacheLimits,
    CachePermission, CacheRepository, CacheService, ExecutionAuthority, GithubCacheApi,
    GithubCacheHttpLimits, GithubResultsApi, GithubResultsHttpLimits, HmacResultsAuthority,
    HmacResultsAuthorityConfig, ObservedResultsArtifactRepository, ObservedResultsBlobStore,
    PostgresArtifactRepository, PostgresCacheRepository, ResultsBlobOperation,
    ResultsBlobOperationOutcome, ResultsClock, ResultsHttpMethod, ResultsHttpRoute,
    ResultsHttpStatusClass, ResultsLimits, ResultsObserver, ResultsPublicEndpoint,
    RuntimeTokenIssuer as _, SystemResultsIdGenerator,
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use support::postgres::{TestDatabase, TestResult, run_with_database, seed_control_plane};
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const ARTIFACT_NAME: &str = "official-actions-artifact-client";
const CACHE_KEY: &str = "official-actions-cache-v5-0-5";

struct RealStoreEnvironment {
    upload_artifact_module: PathBuf,
    download_artifact_module: PathBuf,
    cache_module: PathBuf,
    s3_endpoint: Url,
    s3_bucket: String,
    s3_access_key: String,
    s3_secret_key: String,
    s3_kms_key_id: String,
}

impl RealStoreEnvironment {
    fn load() -> TestResult<Self> {
        require_node_major(24)?;
        Ok(Self {
            upload_artifact_module: required_pinned_module(
                "AUTOMATA_TEST_UPLOAD_ARTIFACT_ACTION_ROOT",
                "AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE",
                "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
                "node_modules/@actions/artifact/lib/internal/client.js",
            )?,
            download_artifact_module: required_pinned_module(
                "AUTOMATA_TEST_DOWNLOAD_ARTIFACT_ACTION_ROOT",
                "AUTOMATA_TEST_ACTIONS_DOWNLOAD_ARTIFACT_MODULE",
                "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
                "node_modules/@actions/artifact/lib/internal/client.js",
            )?,
            cache_module: required_pinned_module(
                "AUTOMATA_TEST_CACHE_ACTION_ROOT",
                "AUTOMATA_TEST_ACTIONS_CACHE_MODULE",
                "27d5ce7f107fe9357f9df03efb73ab90386fccae",
                "node_modules/@actions/cache/lib/cache.js",
            )?,
            s3_endpoint: Url::parse(&required("AUTOMATA_TEST_S3_ENDPOINT")?)?,
            s3_bucket: required("AUTOMATA_TEST_S3_BUCKET")?,
            s3_access_key: required("AUTOMATA_TEST_S3_ACCESS_KEY")?,
            s3_secret_key: required("AUTOMATA_TEST_S3_SECRET_KEY")?,
            s3_kms_key_id: required("AUTOMATA_TEST_S3_KMS_KEY_ID")?,
        })
    }
}

fn required(name: &str) -> TestResult<String> {
    env::var(name).map_err(|_| format!("set {name} for exact-client real-store acceptance").into())
}

fn required_path(name: &str) -> TestResult<PathBuf> {
    let path = PathBuf::from(required(name)?);
    if !path.is_absolute() || !path.is_file() {
        return Err(format!("{name} must name one absolute regular file").into());
    }
    Ok(path.canonicalize()?)
}

fn required_pinned_module(
    root_environment: &str,
    module_environment: &str,
    expected_commit: &str,
    module_relative_path: &str,
) -> TestResult<PathBuf> {
    let root = PathBuf::from(required(root_environment)?)
        .canonicalize()
        .map_err(|error| format!("canonicalize {root_environment}: {error}"))?;
    if !root.is_dir() {
        return Err(format!("{root_environment} must name one directory").into());
    }
    let commit = git_output(&root, &["rev-parse", "HEAD"])?;
    if commit != expected_commit {
        return Err(format!("{root_environment} has unexpected commit {commit}").into());
    }
    if !git_output(&root, &["status", "--short", "--untracked-files=no"])?.is_empty() {
        return Err(format!("{root_environment} has tracked mutations").into());
    }
    let expected_module = root.join(module_relative_path).canonicalize()?;
    let configured_module = required_path(module_environment)?;
    if expected_module != configured_module {
        return Err(format!("{module_environment} is outside its pinned action root").into());
    }
    Ok(configured_module)
}

fn git_output(root: &Path, arguments: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err("exact-client Git identity verification failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn require_node_major(expected: u8) -> TestResult {
    let output = Command::new("node").arg("--version").output()?;
    if !output.status.success()
        || !String::from_utf8(output.stdout)?.starts_with(&format!("v{expected}."))
    {
        return Err(format!("exact-client acceptance requires Node {expected}").into());
    }
    Ok(())
}

fn isolated_node_command() -> Command {
    let mut command = Command::new("node");
    command.env_clear();
    for name in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TMP",
        "TEMP",
    ] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

#[derive(Debug)]
struct FixedClock(u64);

impl ResultsClock for FixedClock {
    fn now_seconds(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpRecord {
    method: ResultsHttpMethod,
    route: ResultsHttpRoute,
    status: ResultsHttpStatusClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobRecord {
    operation: ResultsBlobOperation,
    outcome: ResultsBlobOperationOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobBytes {
    operation: ResultsBlobOperation,
    bytes: u64,
}

#[derive(Debug, Default)]
struct RecordingObserver {
    http_records: Mutex<Vec<HttpRecord>>,
    blob_records: Mutex<Vec<BlobRecord>>,
    blob_bytes: Mutex<Vec<BlobBytes>>,
}

impl RecordingObserver {
    fn http_records(&self) -> Vec<HttpRecord> {
        self.http_records.lock().expect("observer lock").clone()
    }

    fn blob_records(&self) -> Vec<BlobRecord> {
        self.blob_records.lock().expect("observer lock").clone()
    }

    fn blob_bytes(&self) -> Vec<BlobBytes> {
        self.blob_bytes.lock().expect("observer lock").clone()
    }
}

impl ResultsObserver for RecordingObserver {
    fn observe_results_http_request(
        &self,
        method: ResultsHttpMethod,
        route: ResultsHttpRoute,
        status: ResultsHttpStatusClass,
        _duration: Duration,
    ) {
        self.http_records
            .lock()
            .expect("observer lock")
            .push(HttpRecord {
                method,
                route,
                status,
            });
    }

    fn observe_blob_operation(
        &self,
        operation: ResultsBlobOperation,
        outcome: ResultsBlobOperationOutcome,
        _duration: Duration,
    ) {
        self.blob_records
            .lock()
            .expect("observer lock")
            .push(BlobRecord { operation, outcome });
    }

    fn observe_blob_bytes(&self, operation: ResultsBlobOperation, bytes: u64) {
        self.blob_bytes
            .lock()
            .expect("observer lock")
            .push(BlobBytes { operation, bytes });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires PostgreSQL, production S3, Node >=24, and exact offline artifact/cache modules"]
async fn exact_clients_cross_real_http_postgres_and_object_storage() -> TestResult {
    let environment = RealStoreEnvironment::load()?;
    run_with_database(move |database| async move { run_exact_clients(database, environment).await })
        .await
}

async fn run_exact_clients(
    database: Arc<TestDatabase>,
    environment: RealStoreEnvironment,
) -> TestResult {
    let (execution, now_seconds) = active_attempt(&database).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let public_url = Url::parse(&format!("http://{address}/"))?;
    let (router, token, expired_token, observer) = real_results_router(
        &database,
        &environment,
        execution,
        now_seconds,
        public_url,
        address,
    )?;
    let adversarial_router = router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, router).await });

    let scratch = test_scratch("exact-client-real-store");
    std::fs::create_dir_all(&scratch)?;
    let client_result = run_clients(&environment, &scratch, &token, address);
    let adversarial_result =
        run_real_store_adversarial_matrix(&adversarial_router, &token, &expired_token, execution)
            .await;
    server.abort();
    client_result?;
    adversarial_result?;

    assert_durable_publication(&database, execution).await?;
    write_redacted_transcript(
        &scratch,
        &observer.http_records(),
        &observer.blob_records(),
        &observer.blob_bytes(),
        &[
            token.as_str(),
            environment.s3_access_key.as_str(),
            environment.s3_secret_key.as_str(),
            environment.s3_kms_key_id.as_str(),
            environment.s3_bucket.as_str(),
            environment.s3_endpoint.as_str(),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn real_results_router(
    database: &TestDatabase,
    environment: &RealStoreEnvironment,
    execution: ExecutionAuthority,
    now_seconds: u64,
    public_url: Url,
    listener_address: std::net::SocketAddr,
) -> TestResult<(Router, String, String, Arc<RecordingObserver>)> {
    let s3_config = S3BlobStoreConfig::loopback_development(
        environment.s3_endpoint.clone(),
        "us-east-1",
        environment.s3_bucket.clone(),
        Some(format!("exact-clients/{}", Uuid::new_v4().simple())),
        Duration::from_secs(20),
    )?
    .with_at_rest_encryption(S3AtRestEncryption::aws_kms(
        environment.s3_kms_key_id.clone(),
    )?);
    let objects: Arc<dyn ImmutableBlobStore> = Arc::new(S3BlobStore::new(
        s3_config.client(StaticS3Credentials::new(
            environment.s3_access_key.clone(),
            environment.s3_secret_key.clone(),
            None,
        )?),
        &s3_config,
    ));
    let observer = Arc::new(RecordingObserver::default());
    let public_observer: Arc<dyn ResultsObserver> = observer.clone();
    let objects: Arc<dyn ImmutableBlobStore> = Arc::new(ObservedResultsBlobStore::new(
        objects,
        Arc::clone(&public_observer),
    ));
    let artifact_repository: Arc<dyn ArtifactRepository> =
        Arc::new(ObservedResultsArtifactRepository::new(
            Arc::new(PostgresArtifactRepository::new(database.pool().clone())),
            Arc::clone(&public_observer),
        ));
    let cache_repository: Arc<dyn CacheRepository> =
        Arc::new(PostgresCacheRepository::new(database.pool().clone()));
    let clock: Arc<dyn ResultsClock> = Arc::new(FixedClock(now_seconds));
    let ids = Arc::new(SystemResultsIdGenerator);
    let artifacts = Arc::new(
        ArtifactService::new(
            artifact_repository,
            Arc::clone(&objects),
            Arc::clone(&clock),
            ids.clone(),
            ResultsLimits::default(),
        )
        .with_observer(Arc::clone(&public_observer)),
    );
    let caches = Arc::new(CacheService::new(
        cache_repository,
        objects,
        Arc::clone(&clock),
        ids,
        CacheLimits::default(),
    ));
    let (authority, token, expired_token) =
        results_authority_and_tokens(public_url, listener_address, now_seconds, execution, clock)?;
    let router = GithubResultsApi::new(
        artifacts,
        authority.clone(),
        authority.clone(),
        authority.clone(),
        GithubResultsHttpLimits::default(),
    )
    .with_observer(Arc::clone(&public_observer))
    .router()
    .merge(
        GithubCacheApi::new(
            caches,
            authority.clone(),
            authority,
            GithubCacheHttpLimits::default(),
        )
        .with_observer(public_observer)
        .router(),
    );
    Ok((router, token, expired_token, observer))
}

fn results_authority_and_tokens(
    public_url: Url,
    listener_address: std::net::SocketAddr,
    now_seconds: u64,
    execution: ExecutionAuthority,
    clock: Arc<dyn ResultsClock>,
) -> TestResult<(Arc<HmacResultsAuthority>, String, String)> {
    let authority_config = HmacResultsAuthorityConfig::new(
        "automata-tests",
        "actions-results",
        "exact-client-v1",
        ResultsPublicEndpoint::loopback_development(public_url, listener_address)?,
        900,
        900,
        0,
    )?;
    let authority = Arc::new(HmacResultsAuthority::new(
        b"exact-client-real-store-signing-key-v1",
        authority_config.clone(),
        clock,
    )?);
    let cache = CacheAuthority::new(
        "automata/results-test",
        vec![CacheAccessScope::new(
            "refs/heads/main",
            CachePermission::ReadWrite,
        )?],
    )?;
    let token = authority
        .issue(execution, cache.clone(), 600)?
        .expose_secret()
        .to_owned();
    let expired_clock: Arc<dyn ResultsClock> =
        Arc::new(FixedClock(now_seconds.saturating_sub(1_200)));
    let expired_token = HmacResultsAuthority::new(
        b"exact-client-real-store-signing-key-v1",
        authority_config,
        expired_clock,
    )?
    .issue(execution, cache, 60)?
    .expose_secret()
    .to_owned();
    Ok((authority, token, expired_token))
}

fn run_clients(
    environment: &RealStoreEnvironment,
    scratch: &Path,
    token: &str,
    address: std::net::SocketAddr,
) -> TestResult {
    let artifact_root = scratch.join("artifact");
    let cache_root = scratch.join("cache");
    std::fs::create_dir_all(&artifact_root)?;
    std::fs::create_dir_all(&cache_root)?;

    let artifact_input = artifact_root.join("immutable-input.txt");
    std::fs::write(
        &artifact_input,
        b"exact official artifact client through PostgreSQL and production S3",
    )?;
    let artifact_script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/official_artifact_client.mjs");
    run_node(
        "artifact",
        isolated_node_command()
            .arg(artifact_script)
            .env("ACTIONS_RUNTIME_TOKEN", token)
            .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
            .env("GITHUB_SERVER_URL", "http://automata-git.ghe.com:8088/")
            .env("GITHUB_WORKSPACE", &artifact_root)
            .env(
                "AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE",
                &environment.upload_artifact_module,
            )
            .env("AUTOMATA_TEST_ACTIONS_ARTIFACT_VERSION", "6.2.0")
            .env("AUTOMATA_TEST_ARTIFACT_INPUT", &artifact_input)
            .env("AUTOMATA_TEST_ARTIFACT_ROOT", &artifact_root),
    )?;

    let download_script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/official_artifact_download_client.mjs");
    run_node(
        "download-artifact",
        isolated_node_command()
            .arg(download_script)
            .env("ACTIONS_RUNTIME_TOKEN", token)
            .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
            .env("GITHUB_SERVER_URL", "http://automata-git.ghe.com:8088/")
            .env("GITHUB_WORKSPACE", &artifact_root)
            .env(
                "AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE",
                &environment.download_artifact_module,
            )
            .env("AUTOMATA_TEST_ACTIONS_ARTIFACT_VERSION", "6.2.1")
            .env("AUTOMATA_TEST_ARTIFACT_INPUT", &artifact_input)
            .env("AUTOMATA_TEST_ARTIFACT_ROOT", &artifact_root),
    )?;

    let cache_input = cache_root.join("cache-input.txt");
    let runner_temp = cache_root.join("runner-temp");
    std::fs::create_dir_all(&runner_temp)?;
    std::fs::write(
        &cache_input,
        b"exact official cache client through PostgreSQL and production S3",
    )?;
    let cache_script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/official_cache_v2_client.mjs");
    run_node(
        "cache",
        isolated_node_command()
            .arg(cache_script)
            .env("ACTIONS_RUNTIME_TOKEN", token)
            .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
            .env("ACTIONS_CACHE_SERVICE_V2", "true")
            .env("GITHUB_WORKSPACE", &cache_root)
            .env("RUNNER_TEMP", runner_temp)
            .env(
                "AUTOMATA_TEST_ACTIONS_CACHE_MODULE",
                &environment.cache_module,
            )
            .env("AUTOMATA_TEST_CACHE_INPUT", cache_input),
    )
}

#[allow(clippy::too_many_lines)] // One ordered real-store transcript covers every RES-01 adversarial case.
async fn run_real_store_adversarial_matrix(
    router: &Router,
    token: &str,
    expired_token: &str,
    execution: ExecutionAuthority,
) -> TestResult {
    let malformed_route = send_json(
        router,
        token,
        "/twirp/github.actions.results.api.v1.CacheService/UnsupportedOperation",
        serde_json::json!({}),
    )
    .await?;
    require_status("malformed route", &malformed_route, StatusCode::NOT_FOUND)?;

    let truncated_json = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))?,
        )
        .await?;
    require_status("truncated JSON", &truncated_json, StatusCode::BAD_REQUEST)?;

    let expired = send_json(
        router,
        expired_token,
        "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
        serde_json::json!({"key":"expired", "version":"v1"}),
    )
    .await?;
    require_status("expired token", &expired, StatusCode::UNAUTHORIZED)?;

    let wrong_scope = send_json(
        router,
        token,
        "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact",
        serde_json::json!({
            "workflow_run_backend_id": execution.run_id().to_string(),
            "workflow_job_run_backend_id": Uuid::new_v4().to_string(),
            "name": "wrong-scope",
            "version": 7,
            "mime_type": "application/zip"
        }),
    )
    .await?;
    require_status("wrong execution scope", &wrong_scope, StatusCode::FORBIDDEN)?;

    let cache_key = "real-store-adversarial-cache-v1";
    let cache_version = "version-v1";
    let create = send_json(
        router,
        token,
        "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
        serde_json::json!({"key":cache_key, "version":cache_version}),
    )
    .await?;
    require_status("cache create", &create, StatusCode::OK)?;
    let created = json_body(create).await?;
    let upload_url = Url::parse(
        created["signed_upload_url"]
            .as_str()
            .ok_or("cache create omitted its signed upload URL")?,
    )?;
    let cache_bytes = Bytes::from_static(b"0123456789");
    for label in ["cache upload", "cache upload exact replay"] {
        let upload = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(path_and_query(&upload_url))
                    .header(header::CONTENT_LENGTH, cache_bytes.len())
                    .body(Body::from(cache_bytes.clone()))?,
            )
            .await?;
        require_status(label, &upload, StatusCode::CREATED)?;
    }

    let finalize_body = serde_json::json!({
        "key":cache_key,
        "version":cache_version,
        "size_bytes":cache_bytes.len().to_string()
    });
    for label in ["cache finalize", "cache duplicate finalize"] {
        let finalized = send_json(
            router,
            token,
            "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
            finalize_body.clone(),
        )
        .await?;
        require_status(label, &finalized, StatusCode::OK)?;
    }
    let size_mismatch = send_json(
        router,
        token,
        "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
        serde_json::json!({
            "key":cache_key,
            "version":cache_version,
            "size_bytes":cache_bytes.len() - 1
        }),
    )
    .await?;
    require_status("cache size mismatch", &size_mismatch, StatusCode::CONFLICT)?;

    let lookup = send_json(
        router,
        token,
        "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
        serde_json::json!({
            "key":cache_key,
            "version":cache_version,
            "restore_keys":[]
        }),
    )
    .await?;
    require_status("cache lookup", &lookup, StatusCode::OK)?;
    let lookup = json_body(lookup).await?;
    let download_url = Url::parse(
        lookup["signed_download_url"]
            .as_str()
            .ok_or("cache lookup omitted its signed download URL")?,
    )?;
    let range = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path_and_query(&download_url))
                .header(header::RANGE, "bytes=2-5")
                .body(Body::empty())?,
        )
        .await?;
    require_status("cache range", &range, StatusCode::PARTIAL_CONTENT)?;
    if range.headers()[header::CONTENT_RANGE] != "bytes 2-5/10" {
        return Err("cache range returned the wrong Content-Range".into());
    }
    let range_bytes = range.into_body().collect().await?.to_bytes();
    if range_bytes != Bytes::from_static(b"2345") {
        return Err("cache range returned the wrong bytes".into());
    }
    Ok(())
}

async fn send_json(
    router: &Router,
    token: &str,
    path: &str,
    value: serde_json::Value,
) -> TestResult<Response> {
    Ok(router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&value)?))?,
        )
        .await?)
}

async fn json_body(response: Response) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_slice(
        &response.into_body().collect().await?.to_bytes(),
    )?)
}

fn require_status(label: &str, response: &Response, expected: StatusCode) -> TestResult {
    if response.status() == expected {
        return Ok(());
    }
    Err(format!(
        "{label} returned {}, expected {expected}",
        response.status()
    )
    .into())
}

fn path_and_query(url: &Url) -> String {
    url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    )
}

fn run_node(label: &'static str, command: &mut Command) -> TestResult {
    let output = command.output()?;
    require_success(label, &output)
}

fn require_success(label: &str, output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(format!("exact {label} client exited with {}", output.status).into())
}

async fn assert_durable_publication(
    database: &TestDatabase,
    execution: ExecutionAuthority,
) -> TestResult {
    let artifact: (i64, Option<i32>, Option<i64>, Option<bool>) = sqlx::query_as(
        "SELECT count(*), min(octet_length(content_digest)), min(content_size_bytes), bool_and(manifest_state = 'ready' AND manifest_object_key IS NOT NULL) FROM workflow_artifacts WHERE run_id = $1 AND job_id = $2 AND attempt_id = $3 AND name = $4 AND state = 'finalized'",
    )
    .bind(execution.run_id().as_uuid())
    .bind(execution.job_id().as_uuid())
    .bind(execution.attempt_id().as_uuid())
    .bind(ARTIFACT_NAME)
    .fetch_one(database.pool())
    .await?;
    let cache: (i64, Option<i32>, Option<i64>) = sqlx::query_as(
        "SELECT count(*), min(octet_length(content_digest)), min(content_size_bytes) FROM github_actions_cache_entries WHERE run_id = $1 AND job_id = $2 AND attempt_id = $3 AND cache_key = $4 AND state = 'finalized'",
    )
    .bind(execution.run_id().as_uuid())
    .bind(execution.job_id().as_uuid())
    .bind(execution.attempt_id().as_uuid())
    .bind(CACHE_KEY)
    .fetch_one(database.pool())
    .await?;
    if artifact.0 != 1
        || artifact.1 != Some(32)
        || artifact.2.is_none_or(|size| size <= 0)
        || artifact.3 != Some(true)
        || cache.0 != 1
        || cache.1 != Some(32)
        || cache.2.is_none_or(|size| size <= 0)
    {
        return Err(format!(
            "exact clients published invalid durable artifact {artifact:?} or cache {cache:?} metadata"
        )
        .into());
    }
    Ok(())
}

fn write_redacted_transcript(
    scratch: &Path,
    http_records: &[HttpRecord],
    blob_records: &[BlobRecord],
    blob_bytes: &[BlobBytes],
    sensitive_values: &[&str],
) -> TestResult {
    let routes = http_records
        .iter()
        .map(|record| format!("{:?}", record.route))
        .collect::<BTreeSet<_>>();
    let required_routes = BTreeSet::from([
        "CacheDownload".to_owned(),
        "CacheUpload".to_owned(),
        "CreateArtifact".to_owned(),
        "CreateCache".to_owned(),
        "Download".to_owned(),
        "FinalizeArtifact".to_owned(),
        "FinalizeCache".to_owned(),
        "GetCacheDownloadUrl".to_owned(),
        "GetSignedArtifactUrl".to_owned(),
        "ListArtifacts".to_owned(),
        "Upload".to_owned(),
    ]);
    let has_expected_rejection = http_records
        .iter()
        .any(|record| record.status == ResultsHttpStatusClass::ClientError);
    let has_unsafe_http_outcome = http_records.iter().any(|record| {
        matches!(
            record.status,
            ResultsHttpStatusClass::ServerError | ResultsHttpStatusClass::Cancelled
        )
    });
    if !required_routes.is_subset(&routes) || !has_expected_rejection || has_unsafe_http_outcome {
        return Err(
            "exact-client transcript is incomplete or contains an unsafe HTTP outcome".into(),
        );
    }
    let has_successful_get = blob_records.iter().any(|record| {
        record.operation == ResultsBlobOperation::Get
            && record.outcome == ResultsBlobOperationOutcome::Success
    });
    let has_created_put = blob_records.iter().any(|record| {
        record.operation == ResultsBlobOperation::Put
            && record.outcome == ResultsBlobOperationOutcome::Created
    });
    if !has_successful_get
        || !has_created_put
        || !blob_bytes
            .iter()
            .any(|record| record.operation == ResultsBlobOperation::Get && record.bytes > 0)
        || !blob_bytes
            .iter()
            .any(|record| record.operation == ResultsBlobOperation::Put && record.bytes > 0)
    {
        return Err("production object-store transcript is incomplete".into());
    }
    let requests = http_records
        .iter()
        .map(|record| {
            serde_json::json!({
                "method": format!("{:?}", record.method),
                "route": format!("{:?}", record.route),
                "status": format!("{:?}", record.status),
            })
        })
        .collect::<Vec<_>>();
    let storage = blob_records
        .iter()
        .map(|record| {
            serde_json::json!({
                "operation": format!("{:?}", record.operation),
                "outcome": format!("{:?}", record.outcome),
            })
        })
        .collect::<Vec<_>>();
    let storage_bytes = blob_bytes
        .iter()
        .map(|record| {
            serde_json::json!({
                "operation": format!("{:?}", record.operation),
                "bytes": record.bytes,
            })
        })
        .collect::<Vec<_>>();
    let transcript = serde_json::to_string_pretty(&serde_json::json!({
        "schema": 1,
        "redaction": "closed-enum-no-identifiers",
        "requests": requests,
        "storage": storage,
        "storage_bytes": storage_bytes,
    }))?;
    if sensitive_values
        .iter()
        .any(|value| !value.is_empty() && transcript.contains(value))
        || transcript.contains("Authorization")
        || transcript.contains("sig=")
    {
        return Err("redacted transcript contains credential material".into());
    }
    std::fs::write(
        scratch.join("redacted-results-transcript.json"),
        format!("{transcript}\n"),
    )?;
    Ok(())
}

fn test_scratch(label: &str) -> PathBuf {
    let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_directory
        .parent()
        .and_then(|crates| crates.parent())
        .expect("results crate is nested under the workspace crates directory")
        .join("target/agent-scratch")
        .join(label)
        .join(Uuid::new_v4().simple().to_string())
}

async fn active_attempt(database: &TestDatabase) -> TestResult<(ExecutionAuthority, u64)> {
    let seed = seed_control_plane(database.pool()).await?;
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            seed.job_id,
            AttemptNumber::new(1)?,
            seed.observed_at,
        ))
        .await?;
    let lease = database
        .store()
        .acquire_lease(
            AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                seed.session_fence,
                automata_ci_store::StableRunnerSlot::new(1)?,
                seed.observed_at,
                UnixMillis::new(seed.observed_at.get() + 300_000),
            )
            .expect("valid lease request"),
        )
        .await?;
    let now_seconds = u64::try_from(seed.observed_at.get())? / 1_000;
    Ok((
        ExecutionAuthority::new(seed.run_id, seed.job_id, attempt_id, lease.fencing_token()),
        now_seconds,
    ))
}
