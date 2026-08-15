use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_blob::MemoryBlobStore;
use automata_ci_core::{AttemptId, FencingToken, JobId, RunId, Sha256Digest};
use automata_ci_results_github::{
    CacheAccessScope, CacheAuthority, CacheBlock, CacheEntryId, CacheFinalizationPreparation,
    CacheLimits, CachePermission, CacheProtocolEntryId, CacheRepository, CacheRepositoryError,
    CacheRepositoryErrorKind, CacheService, CommitCacheBlocks, CompleteCacheBlock,
    CompleteCacheFinalization, CreateCacheEntry, CreatedCacheEntry, ExecutionAuthority,
    FinalizedCacheEntry, GithubCacheApi, GithubCacheHttpLimits, HmacResultsAuthority,
    HmacResultsAuthorityConfig, LookupCacheEntry, NoopResultsObserver, PrepareCacheFinalization,
    PreparedCacheFinalization, ReserveCacheBlock, ResolveCacheDownload, ResultsClock,
    ResultsHttpMethod, ResultsHttpRoute, ResultsHttpStatusClass, ResultsIdGenerator,
    ResultsObserver, ResultsPublicEndpoint, RuntimeTokenIssuer as _, UploadId,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl ResultsClock for FixedClock {
    fn now_seconds(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
struct FixedIds(UploadId);

impl ResultsIdGenerator for FixedIds {
    fn next_upload_id(&self) -> UploadId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpEvent {
    Started(ResultsHttpMethod, ResultsHttpRoute),
    Completed(ResultsHttpMethod, ResultsHttpRoute, ResultsHttpStatusClass),
    Finished(ResultsHttpMethod, ResultsHttpRoute),
}

#[derive(Debug, Default)]
struct RecordingObserver {
    events: Mutex<Vec<HttpEvent>>,
    started: tokio::sync::Notify,
}

impl RecordingObserver {
    fn events(&self) -> Vec<HttpEvent> {
        self.events.lock().expect("observer events").clone()
    }
}

impl ResultsObserver for RecordingObserver {
    fn results_http_request_started(&self, method: ResultsHttpMethod, route: ResultsHttpRoute) {
        self.events
            .lock()
            .expect("observer events")
            .push(HttpEvent::Started(method, route));
        self.started.notify_one();
    }

    fn observe_results_http_request(
        &self,
        method: ResultsHttpMethod,
        route: ResultsHttpRoute,
        status: ResultsHttpStatusClass,
        _duration: Duration,
    ) {
        self.events
            .lock()
            .expect("observer events")
            .push(HttpEvent::Completed(method, route, status));
    }

    fn results_http_request_finished(&self, method: ResultsHttpMethod, route: ResultsHttpRoute) {
        self.events
            .lock()
            .expect("observer events")
            .push(HttpEvent::Finished(method, route));
    }
}

#[derive(Debug, Default)]
struct MemoryCacheRepository {
    state: Mutex<Option<MemoryEntry>>,
}

#[derive(Debug)]
struct MemoryEntry {
    id: CacheEntryId,
    execution: ExecutionAuthority,
    cache: CacheAuthority,
    cache_ref: String,
    key: automata_ci_results_github::CacheKey,
    version: automata_ci_results_github::CacheVersion,
    blocks: BTreeMap<String, (CacheBlock, bool)>,
    commit: Option<(Sha256Digest, Vec<String>, u64)>,
    finalized: Option<(Sha256Digest, u64)>,
}

impl MemoryEntry {
    fn finalized(&self) -> Result<FinalizedCacheEntry, CacheRepositoryError> {
        let (digest, size) = self
            .finalized
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::InvalidState))?;
        let (_, block_ids, committed_size) = self
            .commit
            .as_ref()
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::CorruptData))?;
        if *committed_size != size {
            return Err(repository_error(CacheRepositoryErrorKind::CorruptData));
        }
        let blocks = block_ids
            .iter()
            .map(|id| {
                self.blocks
                    .get(id)
                    .filter(|(_, ready)| *ready)
                    .map(|(block, _)| block.clone())
                    .ok_or_else(|| repository_error(CacheRepositoryErrorKind::CorruptData))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FinalizedCacheEntry {
            entry_id: self.id,
            protocol_entry_id: CacheProtocolEntryId::new(1).expect("protocol entry ID"),
            repository: self.cache.repository().to_owned(),
            cache_ref: self.cache_ref.clone(),
            key: self.key.clone(),
            version: self.version.clone(),
            digest,
            size,
            blocks,
        })
    }
}

#[async_trait]
impl CacheRepository for MemoryCacheRepository {
    async fn create(
        &self,
        request: CreateCacheEntry,
    ) -> Result<CreatedCacheEntry, CacheRepositoryError> {
        let cache_ref = request
            .cache
            .writable_scope()
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::Unauthorized))?
            .to_owned();
        let mut state = self.state.lock().expect("memory cache state");
        if let Some(entry) = state.as_ref() {
            if entry.execution == request.execution
                && entry.cache == request.cache
                && entry.cache_ref == cache_ref
                && entry.key == request.key
                && entry.version == request.version
                && entry.finalized.is_none()
            {
                return Ok(CreatedCacheEntry { entry_id: entry.id });
            }
            return Err(repository_error(CacheRepositoryErrorKind::Conflict));
        }
        *state = Some(MemoryEntry {
            id: request.entry_id,
            execution: request.execution,
            cache: request.cache,
            cache_ref,
            key: request.key,
            version: request.version,
            blocks: BTreeMap::new(),
            commit: None,
            finalized: None,
        });
        Ok(CreatedCacheEntry {
            entry_id: request.entry_id,
        })
    }

    async fn reserve_block(
        &self,
        request: ReserveCacheBlock,
    ) -> Result<bool, CacheRepositoryError> {
        let mut state = self.state.lock().expect("memory cache state");
        let entry = exact_entry_mut(&mut state, request.entry_id)?;
        if entry.finalized.is_some() {
            return Err(repository_error(CacheRepositoryErrorKind::InvalidState));
        }
        if let Some((block, ready)) = entry.blocks.get(request.block.block_id()) {
            if block != &request.block {
                return Err(repository_error(CacheRepositoryErrorKind::Conflict));
            }
            if !ready && entry.commit.is_some() {
                return Err(repository_error(CacheRepositoryErrorKind::InvalidState));
            }
            return Ok(!ready);
        }
        if entry.commit.is_some() {
            return Err(repository_error(CacheRepositoryErrorKind::InvalidState));
        }
        let staged_size = entry.blocks.values().try_fold(0_u64, |total, (block, _)| {
            total.checked_add(block.descriptor().size())
        });
        if entry.blocks.len() >= request.maximum_blocks
            || staged_size
                .and_then(|size| size.checked_add(request.block.descriptor().size()))
                .is_none_or(|size| size > request.maximum_entry_bytes)
        {
            return Err(repository_error(
                CacheRepositoryErrorKind::ResourceExhausted,
            ));
        }
        entry
            .blocks
            .insert(request.block.block_id().to_owned(), (request.block, false));
        Ok(true)
    }

    async fn complete_block(
        &self,
        request: CompleteCacheBlock,
    ) -> Result<(), CacheRepositoryError> {
        let mut state = self.state.lock().expect("memory cache state");
        let entry = exact_entry_mut(&mut state, request.entry_id)?;
        let (block, ready) = entry
            .blocks
            .get_mut(request.block.block_id())
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::NotFound))?;
        if block != &request.block {
            return Err(repository_error(CacheRepositoryErrorKind::Conflict));
        }
        *ready = true;
        Ok(())
    }

    async fn commit_blocks(&self, request: CommitCacheBlocks) -> Result<(), CacheRepositoryError> {
        let mut state = self.state.lock().expect("memory cache state");
        let entry = exact_entry_mut(&mut state, request.entry_id)?;
        if let Some((digest, ids, _)) = &entry.commit {
            return if *digest == request.list_digest && *ids == request.block_ids {
                Ok(())
            } else {
                Err(repository_error(CacheRepositoryErrorKind::Conflict))
            };
        }
        if request.block_ids.len() > request.maximum_blocks {
            return Err(repository_error(
                CacheRepositoryErrorKind::ResourceExhausted,
            ));
        }
        let size = request.block_ids.iter().try_fold(0_u64, |total, id| {
            let (block, ready) = entry
                .blocks
                .get(id)
                .ok_or_else(|| repository_error(CacheRepositoryErrorKind::NotFound))?;
            if !ready {
                return Err(repository_error(CacheRepositoryErrorKind::InvalidState));
            }
            total
                .checked_add(block.descriptor().size())
                .ok_or_else(|| repository_error(CacheRepositoryErrorKind::ResourceExhausted))
        })?;
        if size > request.maximum_entry_bytes {
            return Err(repository_error(
                CacheRepositoryErrorKind::ResourceExhausted,
            ));
        }
        entry.commit = Some((request.list_digest, request.block_ids, size));
        Ok(())
    }

    async fn prepare_finalization(
        &self,
        request: PrepareCacheFinalization,
    ) -> Result<CacheFinalizationPreparation, CacheRepositoryError> {
        let state = self.state.lock().expect("memory cache state");
        let entry = state
            .as_ref()
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::NotFound))?;
        if entry.execution != request.execution
            || entry.cache != request.cache
            || entry.key != request.key
            || entry.version != request.version
        {
            return Err(repository_error(CacheRepositoryErrorKind::Unauthorized));
        }
        if entry.finalized.is_some() {
            let finalized = entry.finalized()?;
            if finalized.size != request.claimed_size {
                return Err(repository_error(CacheRepositoryErrorKind::Conflict));
            }
            return Ok(CacheFinalizationPreparation::Finalized(finalized));
        }
        let (_, ids, size) = entry
            .commit
            .as_ref()
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::InvalidState))?;
        if *size != request.claimed_size {
            return Err(repository_error(CacheRepositoryErrorKind::Conflict));
        }
        let blocks = ids
            .iter()
            .map(|id| {
                entry
                    .blocks
                    .get(id)
                    .map(|(block, _)| block.clone())
                    .ok_or_else(|| repository_error(CacheRepositoryErrorKind::CorruptData))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CacheFinalizationPreparation::Verify(
            PreparedCacheFinalization {
                entry_id: entry.id,
                blocks,
                size: *size,
            },
        ))
    }

    async fn complete_finalization(
        &self,
        request: CompleteCacheFinalization,
    ) -> Result<FinalizedCacheEntry, CacheRepositoryError> {
        let mut state = self.state.lock().expect("memory cache state");
        let entry = exact_entry_mut(&mut state, request.entry_id)?;
        if entry.execution != request.execution
            || entry.cache != request.cache
            || entry.key != request.key
            || entry.version != request.version
        {
            return Err(repository_error(CacheRepositoryErrorKind::Unauthorized));
        }
        if request.size > request.repository_quota_bytes {
            return Err(repository_error(
                CacheRepositoryErrorKind::ResourceExhausted,
            ));
        }
        if let Some(finalized) = entry.finalized {
            if finalized != (request.digest, request.size) {
                return Err(repository_error(CacheRepositoryErrorKind::Conflict));
            }
        } else {
            entry.finalized = Some((request.digest, request.size));
        }
        entry.finalized()
    }

    async fn lookup(
        &self,
        request: LookupCacheEntry,
    ) -> Result<Option<FinalizedCacheEntry>, CacheRepositoryError> {
        let state = self.state.lock().expect("memory cache state");
        let Some(entry) = state.as_ref() else {
            return Ok(None);
        };
        if request.cache.repository() != entry.cache.repository()
            || request.version != entry.version
            || !request.cache.can_read(&entry.cache_ref)
            || entry.finalized.is_none()
        {
            return Ok(None);
        }
        let matched = entry.key == request.key
            || entry.key.as_str().starts_with(request.key.as_str())
            || request
                .restore_keys
                .iter()
                .any(|key| entry.key.as_str().starts_with(key.as_str()));
        matched.then(|| entry.finalized()).transpose()
    }

    async fn resolve_download(
        &self,
        request: ResolveCacheDownload,
    ) -> Result<FinalizedCacheEntry, CacheRepositoryError> {
        let state = self.state.lock().expect("memory cache state");
        let entry = state
            .as_ref()
            .filter(|entry| entry.id == request.entry_id)
            .ok_or_else(|| repository_error(CacheRepositoryErrorKind::NotFound))?;
        let finalized = entry.finalized()?;
        if finalized.digest != request.digest {
            return Err(repository_error(CacheRepositoryErrorKind::NotFound));
        }
        Ok(finalized)
    }
}

fn exact_entry_mut(
    state: &mut Option<MemoryEntry>,
    entry_id: CacheEntryId,
) -> Result<&mut MemoryEntry, CacheRepositoryError> {
    state
        .as_mut()
        .filter(|entry| entry.id == entry_id)
        .ok_or_else(|| repository_error(CacheRepositoryErrorKind::NotFound))
}

const fn repository_error(kind: CacheRepositoryErrorKind) -> CacheRepositoryError {
    CacheRepositoryError::new(kind)
}

struct Fixture {
    router: axum::Router,
    token: String,
    read_only_token: String,
    fallback_token: String,
    wrong_ref_token: String,
    wrong_repository_token: String,
}

fn fixture() -> Fixture {
    fixture_with_observer(Arc::new(NoopResultsObserver))
}

fn fixture_with_url(public_url: &str) -> Fixture {
    fixture_with_url_and_observer(public_url, Arc::new(NoopResultsObserver))
}

fn fixture_with_observer(observer: Arc<dyn ResultsObserver>) -> Fixture {
    fixture_with_url_and_observer("http://results.automata.localhost:8080/", observer)
}

fn fixture_with_url_and_observer(public_url: &str, observer: Arc<dyn ResultsObserver>) -> Fixture {
    fixture_with_url_observer_and_limits(public_url, observer, GithubCacheHttpLimits::default())
}

fn fixture_with_limits(limits: GithubCacheHttpLimits) -> Fixture {
    fixture_with_url_observer_and_limits(
        "http://results.automata.localhost:8080/",
        Arc::new(NoopResultsObserver),
        limits,
    )
}

fn issue_cache_token(
    authority: &HmacResultsAuthority,
    execution: ExecutionAuthority,
    repository: &str,
    scopes: &[(&str, CachePermission)],
) -> String {
    let scopes = scopes
        .iter()
        .map(|(cache_ref, permission)| {
            CacheAccessScope::new(*cache_ref, *permission).expect("cache scope")
        })
        .collect();
    let cache = CacheAuthority::new(repository, scopes).expect("cache authority");
    authority
        .issue(execution, cache, 600)
        .expect("token")
        .expose_secret()
        .to_owned()
}

fn fixture_with_url_observer_and_limits(
    public_url: &str,
    observer: Arc<dyn ResultsObserver>,
    limits: GithubCacheHttpLimits,
) -> Fixture {
    let clock: Arc<dyn ResultsClock> = Arc::new(FixedClock(10_000));
    let repository: Arc<dyn CacheRepository> = Arc::new(MemoryCacheRepository::default());
    let entry_id = CacheEntryId::new(Uuid::from_u128(0x1234)).expect("entry ID");
    let service = Arc::new(CacheService::new(
        repository,
        Arc::new(MemoryBlobStore::default()),
        Arc::clone(&clock),
        Arc::new(FixedIds(UploadId::from_uuid(entry_id.as_uuid()))),
        CacheLimits::default(),
    ));
    let authority = Arc::new(
        HmacResultsAuthority::new(
            b"cache-http-test-signing-key-material-v1",
            HmacResultsAuthorityConfig::new(
                "automata-tests",
                "actions-results",
                "cache-v1",
                ResultsPublicEndpoint::loopback_development(
                    Url::parse(public_url).expect("URL"),
                    format!(
                        "127.0.0.1:{}",
                        Url::parse(public_url)
                            .expect("URL")
                            .port_or_known_default()
                            .expect("URL port")
                    )
                    .parse()
                    .expect("bind"),
                )
                .expect("development endpoint"),
                900,
                900,
                0,
            )
            .expect("authority config"),
            clock,
        )
        .expect("authority"),
    );
    let execution = ExecutionAuthority::new(
        RunId::new(),
        JobId::new(),
        AttemptId::new(),
        FencingToken::new(9).expect("fence"),
    );
    let token = issue_cache_token(
        authority.as_ref(),
        execution,
        "owner/repository",
        &[("refs/heads/main", CachePermission::ReadWrite)],
    );
    let read_only_token = issue_cache_token(
        authority.as_ref(),
        execution,
        "owner/repository",
        &[("refs/heads/main", CachePermission::Read)],
    );
    let fallback_token = issue_cache_token(
        authority.as_ref(),
        execution,
        "owner/repository",
        &[
            ("refs/heads/feature", CachePermission::ReadWrite),
            ("refs/heads/main", CachePermission::Read),
        ],
    );
    let wrong_ref_token = issue_cache_token(
        authority.as_ref(),
        execution,
        "owner/repository",
        &[("refs/heads/feature", CachePermission::ReadWrite)],
    );
    let wrong_repository_token = issue_cache_token(
        authority.as_ref(),
        execution,
        "sibling/repository",
        &[("refs/heads/main", CachePermission::Read)],
    );
    let router = GithubCacheApi::new(service, authority.clone(), authority, limits)
        .with_observer(observer)
        .router();
    Fixture {
        router,
        token,
        read_only_token,
        fallback_token,
        wrong_ref_token,
        wrong_repository_token,
    }
}

fn assert_private_rejection(response: &axum::response::Response, status: StatusCode) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn cache_router_and_extractor_rejections_are_private() {
    let fixture =
        fixture_with_limits(GithubCacheHttpLimits::new(64, 8).expect("focused cache HTTP limits"));
    let upload_path = format!("/_apis/results/caches/{}/blob", Uuid::from_u128(0x1234));
    let cases = [
        (
            StatusCode::BAD_REQUEST,
            Request::builder()
                .method("PUT")
                .uri(format!("{upload_path}?se=invalid&sig=x"))
                .body(Body::empty())
                .expect("malformed query request"),
        ),
        (
            StatusCode::METHOD_NOT_ALLOWED,
            Request::builder()
                .method("POST")
                .uri(format!("{upload_path}?se=1&sig=x"))
                .body(Body::empty())
                .expect("method rejection request"),
        ),
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            Request::builder()
                .method("PUT")
                .uri(format!("{upload_path}?se=1&sig=x"))
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
            .expect("cache rejection response");
        assert_private_rejection(&response, status);
    }
}

#[tokio::test]
async fn cache_routes_emit_balanced_closed_http_observations() {
    let observer = Arc::new(RecordingObserver::default());
    let fixture = fixture_with_observer(observer.clone());
    let cases = [
        (
            "POST",
            "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
            ResultsHttpMethod::Post,
            ResultsHttpRoute::CreateCache,
        ),
        (
            "POST",
            "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
            ResultsHttpMethod::Post,
            ResultsHttpRoute::FinalizeCache,
        ),
        (
            "POST",
            "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
            ResultsHttpMethod::Post,
            ResultsHttpRoute::GetCacheDownloadUrl,
        ),
        (
            "PUT",
            "/_apis/results/caches/not-an-entry/blob?se=1&sig=x",
            ResultsHttpMethod::Put,
            ResultsHttpRoute::CacheUpload,
        ),
        (
            "GET",
            "/_apis/results/caches/not-an-entry/not-a-digest/download?se=1&sig=x",
            ResultsHttpMethod::Get,
            ResultsHttpRoute::CacheDownload,
        ),
        (
            "HEAD",
            "/_apis/results/caches/not-an-entry/not-a-digest/download?se=1&sig=x",
            ResultsHttpMethod::Other,
            ResultsHttpRoute::CacheDownload,
        ),
    ];

    for (method, path, expected_method, expected_route) in cases {
        let response = fixture
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("cache observation request"),
            )
            .await
            .expect("cache observation response");
        assert!(response.status().is_client_error());

        let events = observer.events();
        let offset = events.len() - 3;
        assert_eq!(
            &events[offset..],
            [
                HttpEvent::Started(expected_method, expected_route),
                HttpEvent::Completed(
                    expected_method,
                    expected_route,
                    ResultsHttpStatusClass::ClientError,
                ),
                HttpEvent::Finished(expected_method, expected_route),
            ]
        );
    }
}

#[tokio::test]
async fn dropped_cache_request_records_cancelled_and_balances_in_flight() {
    let observer = Arc::new(RecordingObserver::default());
    let fixture = fixture_with_observer(observer.clone());
    let started = observer.started.notified();
    let request = Request::builder()
        .method("POST")
        .uri("/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(futures::stream::pending::<
            Result<Bytes, std::convert::Infallible>,
        >()))
        .expect("pending cache request");
    let request_task = tokio::spawn(fixture.router.oneshot(request));
    started.await;
    assert_eq!(
        observer.events(),
        vec![HttpEvent::Started(
            ResultsHttpMethod::Post,
            ResultsHttpRoute::CreateCache,
        )]
    );

    request_task.abort();
    assert!(
        request_task
            .await
            .expect_err("request task must be cancelled")
            .is_cancelled()
    );
    assert_eq!(
        observer.events(),
        vec![
            HttpEvent::Started(ResultsHttpMethod::Post, ResultsHttpRoute::CreateCache),
            HttpEvent::Completed(
                ResultsHttpMethod::Post,
                ResultsHttpRoute::CreateCache,
                ResultsHttpStatusClass::Cancelled,
            ),
            HttpEvent::Finished(ResultsHttpMethod::Post, ResultsHttpRoute::CreateCache),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Node >=24 and @actions/cache 5.0.5 from AUTOMATA_TEST_ACTIONS_CACHE_MODULE"]
async fn official_actions_cache_5_0_5_client_completes_cache_v2_offline() {
    let module_path = std::env::var_os("AUTOMATA_TEST_ACTIONS_CACHE_MODULE")
        .map(PathBuf::from)
        .expect("set AUTOMATA_TEST_ACTIONS_CACHE_MODULE to @actions/cache 5.0.5 lib/cache.js");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind cache-client fixture");
    let address = listener.local_addr().expect("listener address");
    let fixture = fixture_with_url(&format!("http://{address}/"));
    let router = fixture.router.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("cache-client fixture server");
    });

    let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_directory
        .parent()
        .and_then(|crates| crates.parent())
        .expect("results crate is nested under the workspace crates directory");
    let scratch = workspace_root
        .join("target/agent-scratch/cache-results/action-client-run")
        .join(Uuid::new_v4().simple().to_string());
    std::fs::create_dir_all(&scratch).expect("create repository-local test scratch");
    let input = scratch.join("cache-input.txt");
    std::fs::write(&input, b"official @actions/cache 5.0.5 integration bytes")
        .expect("write fixture input");
    let runner_temp = scratch.join("runner-temp");
    std::fs::create_dir_all(&runner_temp).expect("create runner temp");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/official_cache_v2_client.mjs");
    let token = fixture.token;
    let process_scratch = scratch.clone();
    let output = tokio::task::spawn_blocking(move || {
        isolated_node_command()
            .arg(script)
            .env("ACTIONS_RUNTIME_TOKEN", token)
            .env("ACTIONS_RESULTS_URL", format!("http://{address}/"))
            .env("ACTIONS_CACHE_SERVICE_V2", "true")
            .env("GITHUB_WORKSPACE", &process_scratch)
            .env("RUNNER_TEMP", runner_temp)
            .env("AUTOMATA_TEST_ACTIONS_CACHE_MODULE", module_path)
            .env("AUTOMATA_TEST_CACHE_INPUT", input)
            .output()
            .expect("run official cache client")
    })
    .await
    .expect("join Node cache client");
    server.abort();
    std::fs::remove_dir_all(&scratch).expect("remove cache-client fixture scratch");
    assert!(
        output.status.success(),
        "official cache-v2 client exited with {}",
        output.status
    );
}

fn isolated_node_command() -> std::process::Command {
    let mut command = std::process::Command::new("node");
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
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One ordered transcript verifies the complete current cache protocol.
async fn snake_case_cache_v2_round_trip_replays_races_and_supports_ranges() {
    let fixture = fixture();
    let create = send_json(
        &fixture.router,
        &fixture.token,
        "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
        serde_json::json!({"key":"cargo-linux-v1", "version":"version-1"}),
    )
    .await;
    assert_eq!(create.status(), StatusCode::OK);
    let created = json_body(create).await;
    assert_eq!(created["ok"], true);
    assert_eq!(created["message"], "");
    let upload_url = Url::parse(created["signed_upload_url"].as_str().expect("upload URL"))
        .expect("signed upload URL");
    let upload = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path_and_query(&upload_url))
                .header(header::CONTENT_LENGTH, 10)
                .body(Body::from(Bytes::from_static(b"0123456789")))
                .expect("upload request"),
        )
        .await
        .expect("upload response");
    assert_eq!(upload.status(), StatusCode::CREATED);
    let upload_replay = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path_and_query(&upload_url))
                .header(header::CONTENT_LENGTH, 10)
                .body(Body::from(Bytes::from_static(b"0123456789")))
                .expect("upload replay request"),
        )
        .await
        .expect("upload replay response");
    assert_eq!(upload_replay.status(), StatusCode::CREATED);

    let (finalized, finalized_racer) = tokio::join!(
        send_json(
            &fixture.router,
            &fixture.token,
            "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
            serde_json::json!({
                "key":"cargo-linux-v1", "version":"version-1", "size_bytes":"10"
            }),
        ),
        send_json(
            &fixture.router,
            &fixture.token,
            "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
            serde_json::json!({
                "key":"cargo-linux-v1", "version":"version-1", "size_bytes":10
            }),
        )
    );
    assert_eq!(finalized.status(), StatusCode::OK);
    assert_eq!(finalized_racer.status(), StatusCode::OK);
    let finalized = json_body(finalized).await;
    let finalized_racer = json_body(finalized_racer).await;
    assert_eq!(finalized["ok"], true);
    assert_eq!(finalized["message"], "");
    let protocol_entry_id = finalized["entry_id"]
        .as_str()
        .expect("protobuf int64 string")
        .parse::<i64>()
        .expect("positive protobuf int64");
    assert!(protocol_entry_id > 0);
    assert_eq!(finalized_racer["entry_id"], protocol_entry_id.to_string());
    let conflicting_finalize = send_json(
        &fixture.router,
        &fixture.token,
        "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
        serde_json::json!({
            "key":"cargo-linux-v1", "version":"version-1", "size_bytes":9
        }),
    )
    .await;
    assert_eq!(conflicting_finalize.status(), StatusCode::CONFLICT);

    let lookup = send_json(
        &fixture.router,
        &fixture.token,
        "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
        serde_json::json!({
            "key":"missing-primary", "version":"version-1", "restore_keys":["cargo-"]
        }),
    )
    .await;
    assert_eq!(lookup.status(), StatusCode::OK);
    let matched = json_body(lookup).await;
    assert_eq!(matched["ok"], true);
    assert_eq!(matched["matched_key"], "cargo-linux-v1");
    let fallback = send_json(
        &fixture.router,
        &fixture.fallback_token,
        "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
        serde_json::json!({
            "key":"missing-primary", "version":"version-1", "restore_keys":["cargo-"]
        }),
    )
    .await;
    assert_eq!(fallback.status(), StatusCode::OK);
    assert_eq!(json_body(fallback).await["matched_key"], "cargo-linux-v1");
    for token in [&fixture.wrong_ref_token, &fixture.wrong_repository_token] {
        let denied = send_json(
            &fixture.router,
            token,
            "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
            serde_json::json!({
                "key":"cargo-linux-v1", "version":"version-1", "restore_keys":[]
            }),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::OK);
        assert_eq!(json_body(denied).await["ok"], false);
    }
    let download_url = Url::parse(
        matched["signed_download_url"]
            .as_str()
            .expect("download URL"),
    )
    .expect("signed download URL");

    let head = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(path_and_query(&download_url))
                .body(Body::empty())
                .expect("HEAD request"),
        )
        .await
        .expect("HEAD response");
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()[header::CONTENT_LENGTH], "10");
    assert_eq!(head.headers()[header::ACCEPT_RANGES], "bytes");

    let partial = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path_and_query(&download_url))
                .header(header::RANGE, "bytes=2-5")
                .body(Body::empty())
                .expect("range request"),
        )
        .await
        .expect("range response");
    assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(partial.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
    assert_eq!(
        partial
            .into_body()
            .collect()
            .await
            .expect("range body")
            .to_bytes(),
        Bytes::from_static(b"2345")
    );

    let unsatisfiable = fixture
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path_and_query(&download_url))
                .header(header::RANGE, "bytes=10-")
                .body(Body::empty())
                .expect("invalid range request"),
        )
        .await
        .expect("invalid range response");
    assert_eq!(unsatisfiable.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(unsatisfiable.headers()[header::CONTENT_RANGE], "bytes */10");
}

#[tokio::test]
async fn caller_authority_and_snake_case_are_fail_closed() {
    let fixture = fixture();
    let read_only = send_json(
        &fixture.router,
        &fixture.read_only_token,
        "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry",
        serde_json::json!({"key":"denied", "version":"version-1"}),
    )
    .await;
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

    let camel_case = send_json(
        &fixture.router,
        &fixture.token,
        "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
        serde_json::json!({
            "key":"key", "version":"version-1", "restoreKeys":[]
        }),
    )
    .await;
    assert_eq!(camel_case.status(), StatusCode::BAD_REQUEST);

    let omitted_default_restore_keys = send_json(
        &fixture.router,
        &fixture.token,
        "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL",
        serde_json::json!({"key":"key", "version":"version-1"}),
    )
    .await;
    assert_eq!(omitted_default_restore_keys.status(), StatusCode::OK);
    assert_eq!(json_body(omitted_default_restore_keys).await["ok"], false);

    let malformed_int64 = send_json(
        &fixture.router,
        &fixture.token,
        "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload",
        serde_json::json!({
            "key":"key", "version":"version-1", "size_bytes":"ten"
        }),
    )
    .await;
    assert_eq!(malformed_int64.status(), StatusCode::BAD_REQUEST);
}

async fn send_json(
    router: &axum::Router,
    token: &str,
    path: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("JSON body")))
                .expect("request"),
        )
        .await
        .expect("response")
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes(),
    )
    .expect("JSON response")
}

fn path_and_query(url: &Url) -> String {
    url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    )
}
