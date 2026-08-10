use std::{str::FromStr as _, sync::Arc};

use automata_ci_core::Sha256Digest;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, MatchedPath, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{StreamExt as _, stream};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CacheEntryId, CacheService, CacheServiceError, CacheServiceErrorKind, ResultsHttpRoute,
    ResultsObserver, RuntimeTokenClaims, RuntimeTokenVerifier, SignedCacheCapability, TokenError,
    azure::{AzureProtocolError, parse_block_list, validate_block_id},
    http::{admit_results_upload, harden_results_response, results_upload_admission},
    observer::{NoopResultsObserver, ResultsHttpObservation},
};

const CREATE_CACHE_PATH: &str =
    "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry";
const FINALIZE_CACHE_PATH: &str =
    "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload";
const GET_CACHE_PATH: &str =
    "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL";
const CACHE_UPLOAD_PATH: &str = "/_apis/results/caches/{entry_id}/blob";
const CACHE_DOWNLOAD_PATH: &str = "/_apis/results/caches/{entry_id}/{digest}/download";
const MAXIMUM_SIGNATURE_BYTES: usize = 256;
const MAXIMUM_TWIRP_BODY_BYTES: usize = 64 * 1024;
const MAXIMUM_AZURE_BODY_BYTES: usize = 128 * 1024 * 1024;

/// Independent HTTP body ceilings for cache Twirp requests and Azure blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubCacheHttpLimits {
    maximum_twirp_body_bytes: usize,
    maximum_azure_body_bytes: usize,
}

impl GithubCacheHttpLimits {
    /// Creates nonzero body ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero or a value outside the platform's addressable body size.
    pub const fn new(
        maximum_twirp_body_bytes: usize,
        maximum_azure_body_bytes: usize,
    ) -> Result<Self, GithubCacheHttpLimitsError> {
        if maximum_twirp_body_bytes == 0
            || maximum_twirp_body_bytes > MAXIMUM_TWIRP_BODY_BYTES
            || maximum_azure_body_bytes == 0
            || maximum_azure_body_bytes > MAXIMUM_AZURE_BODY_BYTES
        {
            return Err(GithubCacheHttpLimitsError);
        }
        Ok(Self {
            maximum_twirp_body_bytes,
            maximum_azure_body_bytes,
        })
    }
}

impl Default for GithubCacheHttpLimits {
    fn default() -> Self {
        Self {
            maximum_twirp_body_bytes: 64 * 1024,
            maximum_azure_body_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Invalid cache HTTP body limits.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
#[error("GitHub cache HTTP body limits are zero or exceed the supported ceilings")]
pub struct GithubCacheHttpLimitsError;

#[derive(Clone)]
struct CacheApiState {
    service: Arc<CacheService>,
    runtime_tokens: Arc<dyn RuntimeTokenVerifier>,
    capabilities: Arc<dyn SignedCacheCapability>,
}

impl std::fmt::Debug for CacheApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheApiState")
            .field("service", &self.service)
            .field("runtime_tokens", &self.runtime_tokens)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

/// Current GitHub Actions `CacheService` v2 HTTP adapter.
#[derive(Clone, Debug)]
pub struct GithubCacheApi {
    state: CacheApiState,
    limits: GithubCacheHttpLimits,
    observer: Arc<dyn ResultsObserver>,
}

impl GithubCacheApi {
    /// Composes the HTTP adapter from cache, token, and capability ports.
    #[must_use]
    pub fn new(
        service: Arc<CacheService>,
        runtime_tokens: Arc<dyn RuntimeTokenVerifier>,
        capabilities: Arc<dyn SignedCacheCapability>,
        limits: GithubCacheHttpLimits,
    ) -> Self {
        Self {
            state: CacheApiState {
                service,
                runtime_tokens,
                capabilities,
            },
            limits,
            observer: Arc::new(NoopResultsObserver),
        }
    }

    /// Installs an infallible identifier-free HTTP observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn ResultsObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// Returns routes suitable for merging into the Results listener.
    pub fn router(self) -> Router {
        let twirp = Router::new()
            .route(CREATE_CACHE_PATH, post(create_cache))
            .route(FINALIZE_CACHE_PATH, post(finalize_cache))
            .route(GET_CACHE_PATH, post(get_cache))
            .layer(DefaultBodyLimit::max(self.limits.maximum_twirp_body_bytes));
        let upload = Router::new()
            .route(CACHE_UPLOAD_PATH, put(cache_blob))
            .layer(DefaultBodyLimit::max(self.limits.maximum_azure_body_bytes))
            .layer(middleware::from_fn_with_state(
                results_upload_admission(),
                admit_results_upload,
            ));
        let download =
            Router::new().route(CACHE_DOWNLOAD_PATH, get(download_cache).head(head_cache));
        twirp
            .merge(upload)
            .merge(download)
            .with_state(self.state)
            .layer(middleware::from_fn_with_state(self.observer, observe_http))
    }
}

async fn observe_http(
    State(observer): State<Arc<dyn ResultsObserver>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let observation = ResultsHttpObservation::new(
        observer,
        request.method(),
        cache_http_route(
            request
                .extensions()
                .get::<MatchedPath>()
                .map(MatchedPath::as_str),
        ),
    );
    let mut response = next.run(request).await;
    harden_results_response(&mut response);
    observation.finish(response.status());
    response
}

fn cache_http_route(matched_path: Option<&str>) -> ResultsHttpRoute {
    match matched_path {
        Some(CREATE_CACHE_PATH) => ResultsHttpRoute::CreateCache,
        Some(FINALIZE_CACHE_PATH) => ResultsHttpRoute::FinalizeCache,
        Some(GET_CACHE_PATH) => ResultsHttpRoute::GetCacheDownloadUrl,
        Some(CACHE_UPLOAD_PATH) => ResultsHttpRoute::CacheUpload,
        Some(CACHE_DOWNLOAD_PATH) => ResultsHttpRoute::CacheDownload,
        _ => ResultsHttpRoute::Unknown,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateCacheRequest {
    key: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct CreateCacheResponse {
    ok: bool,
    signed_upload_url: String,
    message: String,
}

async fn create_cache(
    State(state): State<CacheApiState>,
    headers: HeaderMap,
    request: Result<Json<CreateCacheRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    let created = match state
        .service
        .create(
            claims.authority(),
            claims.cache().clone(),
            request.key,
            request.version,
        )
        .await
    {
        Ok(created) => created,
        Err(error) => return twirp_service_error(error),
    };
    let Ok(signed_url) = state
        .capabilities
        .issue_cache_upload_url(created.entry_id, claims.expires_at_seconds())
    else {
        return twirp_error(TwirpErrorClass::Internal);
    };
    no_store(Json(CreateCacheResponse {
        ok: true,
        signed_upload_url: signed_url.to_string(),
        message: String::new(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeCacheRequest {
    key: String,
    version: String,
    #[serde(deserialize_with = "deserialize_proto_u64")]
    size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct FinalizeCacheResponse {
    ok: bool,
    entry_id: String,
    message: String,
}

async fn finalize_cache(
    State(state): State<CacheApiState>,
    headers: HeaderMap,
    request: Result<Json<FinalizeCacheRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    match state
        .service
        .finalize(
            claims.authority(),
            claims.cache().clone(),
            request.key,
            request.version,
            request.size_bytes,
        )
        .await
    {
        Ok(entry) => no_store(Json(FinalizeCacheResponse {
            ok: true,
            entry_id: entry.protocol_entry_id.get().to_string(),
            message: String::new(),
        })),
        Err(error) => twirp_service_error(error),
    }
}

fn deserialize_proto_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ProtoU64 {
        Number(u64),
        String(String),
    }

    match ProtoU64::deserialize(deserializer)? {
        ProtoU64::Number(value) => Ok(value),
        ProtoU64::String(value) => value
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid protobuf uint64")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetCacheRequest {
    key: String,
    version: String,
    #[serde(default)]
    restore_keys: Vec<String>,
}

#[derive(Debug, Serialize)]
struct GetCacheResponse {
    ok: bool,
    signed_download_url: String,
    matched_key: String,
}

async fn get_cache(
    State(state): State<CacheApiState>,
    headers: HeaderMap,
    request: Result<Json<GetCacheRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    let entry = match state
        .service
        .lookup(
            claims.authority(),
            claims.cache().clone(),
            request.key,
            request.restore_keys,
            request.version,
        )
        .await
    {
        Ok(entry) => entry,
        Err(error) => return twirp_service_error(error),
    };
    let Some(entry) = entry else {
        return no_store(Json(GetCacheResponse {
            ok: false,
            signed_download_url: String::new(),
            matched_key: String::new(),
        }));
    };
    let Ok(signed_url) = state.capabilities.issue_cache_download_url(
        entry.entry_id,
        entry.digest,
        claims.expires_at_seconds(),
    ) else {
        return twirp_error(TwirpErrorClass::Internal);
    };
    no_store(Json(GetCacheResponse {
        ok: true,
        signed_download_url: signed_url.to_string(),
        matched_key: entry.key.as_str().to_owned(),
    }))
}

#[derive(Debug, Deserialize)]
struct CacheUploadQuery {
    se: u64,
    sig: String,
    #[serde(default)]
    comp: Option<String>,
    #[serde(default)]
    blockid: Option<String>,
}

async fn cache_blob(
    State(state): State<CacheApiState>,
    Path(entry_id): Path<String>,
    Query(query): Query<CacheUploadQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(entry_id) = parse_entry_id(&entry_id) else {
        return azure_error(AzureErrorClass::InvalidRequest);
    };
    if query.sig.is_empty()
        || query.sig.len() > MAXIMUM_SIGNATURE_BYTES
        || state
            .capabilities
            .verify_cache_upload(entry_id, query.se, &query.sig)
            .is_err()
    {
        return azure_error(AzureErrorClass::AuthenticationFailed);
    }
    match (query.comp.as_deref(), query.blockid) {
        (Some("block"), Some(block_id)) => {
            let Ok(block_id) = validate_block_id(&block_id) else {
                return azure_error(AzureErrorClass::InvalidRequest);
            };
            if !content_length_matches(&headers, body.len()) {
                return azure_error(AzureErrorClass::InvalidRequest);
            }
            match state.service.stage_block(entry_id, block_id, body).await {
                Ok(()) => azure_success(),
                Err(error) => azure_service_error(error),
            }
        }
        (Some("blocklist"), None) => {
            let block_ids = match parse_block_list(&body, state.service.limits().maximum_blocks()) {
                Ok(block_ids) => block_ids,
                Err(AzureProtocolError::TooManyBlocks) => {
                    return azure_error(AzureErrorClass::TooLarge);
                }
                Err(_) => return azure_error(AzureErrorClass::InvalidRequest),
            };
            match state.service.commit_blocks(entry_id, block_ids).await {
                Ok(()) => azure_success(),
                Err(error) => azure_service_error(error),
            }
        }
        (None, None) => {
            if !content_length_matches(&headers, body.len()) {
                return azure_error(AzureErrorClass::InvalidRequest);
            }
            let block_id = STANDARD.encode([0_u8; 16]);
            if let Err(error) = state
                .service
                .stage_block(entry_id, block_id.clone(), body)
                .await
            {
                return azure_service_error(error);
            }
            if let Err(error) = state.service.commit_blocks(entry_id, vec![block_id]).await {
                return azure_service_error(error);
            }
            azure_success()
        }
        _ => azure_error(AzureErrorClass::InvalidRequest),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadQuery {
    se: u64,
    sig: String,
}

async fn head_cache(
    State(state): State<CacheApiState>,
    Path((entry_id, digest)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> Response {
    let (entry_id, digest) = match verify_download_path(&state, &entry_id, &digest, &query) {
        Ok(value) => value,
        Err(status) => return download_error(status),
    };
    match state.service.prepare_download(entry_id, digest, None).await {
        Ok(prepared) => download_headers(StatusCode::OK, &prepared, Body::empty()),
        Err(error) => download_service_error(error),
    }
}

async fn download_cache(
    State(state): State<CacheApiState>,
    Path((entry_id, digest)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
    headers: HeaderMap,
) -> Response {
    let (entry_id, digest) = match verify_download_path(&state, &entry_id, &digest, &query) {
        Ok(value) => value,
        Err(status) => return download_error(status),
    };
    let metadata = match state.service.prepare_download(entry_id, digest, None).await {
        Ok(prepared) => prepared,
        Err(error) => return download_service_error(error),
    };
    let Ok(range) = parse_range(&headers, metadata.metadata.size) else {
        return range_not_satisfiable(metadata.metadata.size);
    };
    let prepared = match state
        .service
        .prepare_download(entry_id, digest, range.clone())
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return download_service_error(error),
    };
    let service = Arc::clone(&state.service);
    let body = Body::from_stream(
        stream::iter(prepared.segments.clone()).then(move |segment| {
            let service = Arc::clone(&service);
            async move { service.read_download_segment(&segment).await }
        }),
    );
    let status = if range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    download_headers(status, &prepared, body)
}

fn verify_download_path(
    state: &CacheApiState,
    entry_id: &str,
    digest: &str,
    query: &DownloadQuery,
) -> Result<(CacheEntryId, Sha256Digest), StatusCode> {
    let entry_id = parse_entry_id(entry_id).map_err(|()| StatusCode::BAD_REQUEST)?;
    let parsed_digest = Sha256Digest::from_str(digest)
        .ok()
        .filter(|parsed| parsed.to_string() == digest)
        .ok_or(StatusCode::BAD_REQUEST)?;
    if query.sig.is_empty()
        || query.sig.len() > MAXIMUM_SIGNATURE_BYTES
        || state
            .capabilities
            .verify_cache_download(entry_id, parsed_digest, query.se, &query.sig)
            .is_err()
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((entry_id, parsed_digest))
}

fn download_headers(
    status: StatusCode,
    prepared: &crate::PreparedCacheDownload,
    body: Body,
) -> Response {
    let length = prepared.range.end.saturating_sub(prepared.range.start);
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, length)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(
            header::ETAG,
            format!("\"sha256:{}\"", prepared.metadata.digest),
        );
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                prepared.range.start,
                prepared.range.end.saturating_sub(1),
                prepared.metadata.size
            ),
        );
    }
    no_store(
        builder
            .body(body)
            .unwrap_or_else(|_| download_error(StatusCode::INTERNAL_SERVER_ERROR)),
    )
}

fn parse_range(headers: &HeaderMap, size: u64) -> Result<Option<std::ops::Range<u64>>, ()> {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || size == 0 {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let value = value.strip_prefix("bytes=").ok_or(())?;
    if value.contains(',') {
        return Err(());
    }
    let (start, end) = value.split_once('-').ok_or(())?;
    if start.is_empty() {
        let suffix = parse_canonical_u64(end)?;
        if suffix == 0 {
            return Err(());
        }
        let length = suffix.min(size);
        return Ok(Some(size - length..size));
    }
    let start = parse_canonical_u64(start)?;
    if start >= size {
        return Err(());
    }
    let end = if end.is_empty() {
        size
    } else {
        parse_canonical_u64(end)?.saturating_add(1).min(size)
    };
    if end <= start {
        return Err(());
    }
    Ok(Some(start..end))
}

fn authenticate(
    state: &CacheApiState,
    headers: &HeaderMap,
) -> Result<RuntimeTokenClaims, TokenError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(TokenError::Malformed)?;
    if values.next().is_some() {
        return Err(TokenError::Malformed);
    }
    let value = value.to_str().map_err(|_| TokenError::Malformed)?;
    let (scheme, credential) = value.split_once(' ').ok_or(TokenError::Malformed)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || credential.is_empty()
        || credential.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(TokenError::Malformed);
    }
    state.runtime_tokens.verify(credential)
}

fn parse_entry_id(value: &str) -> Result<CacheEntryId, ()> {
    let uuid = Uuid::parse_str(value).map_err(|_| ())?;
    if uuid.to_string() != value {
        return Err(());
    }
    CacheEntryId::new(uuid).map_err(|_| ())
}

fn content_length_matches(headers: &HeaderMap, actual: usize) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| parse_canonical_u64(value).ok())
        .and_then(|value| usize::try_from(value).ok())
        == Some(actual)
}

fn parse_canonical_u64(value: &str) -> Result<u64, ()> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(());
    }
    value.parse().map_err(|_| ())
}

#[derive(Clone, Copy, Debug)]
enum TwirpErrorClass {
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    FailedPrecondition,
    ResourceExhausted,
    Unavailable,
    Internal,
}

#[derive(Debug, Serialize)]
struct TwirpErrorBody {
    code: &'static str,
    msg: &'static str,
}

fn twirp_error(class: TwirpErrorClass) -> Response {
    let (status, code, message) = match class {
        TwirpErrorClass::InvalidArgument => (
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "cache request is invalid",
        ),
        TwirpErrorClass::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "authentication is required",
        ),
        TwirpErrorClass::PermissionDenied => (
            StatusCode::FORBIDDEN,
            "permission_denied",
            "cache request is not authorized",
        ),
        TwirpErrorClass::NotFound => (StatusCode::NOT_FOUND, "not_found", "cache was not found"),
        TwirpErrorClass::AlreadyExists => (
            StatusCode::CONFLICT,
            "already_exists",
            "cache already exists with different immutable metadata",
        ),
        TwirpErrorClass::FailedPrecondition => (
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "cache is not in the required state",
        ),
        TwirpErrorClass::ResourceExhausted => (
            StatusCode::TOO_MANY_REQUESTS,
            "resource_exhausted",
            "cache resource limit was exceeded",
        ),
        TwirpErrorClass::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "cache service is temporarily unavailable",
        ),
        TwirpErrorClass::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal cache service error",
        ),
    };
    no_store((status, Json(TwirpErrorBody { code, msg: message })))
}

fn twirp_token_error(_error: TokenError) -> Response {
    twirp_error(TwirpErrorClass::Unauthenticated)
}

fn twirp_service_error(error: CacheServiceError) -> Response {
    twirp_error(match error.kind() {
        CacheServiceErrorKind::InvalidArgument => TwirpErrorClass::InvalidArgument,
        CacheServiceErrorKind::PermissionDenied => TwirpErrorClass::PermissionDenied,
        CacheServiceErrorKind::NotFound => TwirpErrorClass::NotFound,
        CacheServiceErrorKind::Conflict => TwirpErrorClass::AlreadyExists,
        CacheServiceErrorKind::FailedPrecondition => TwirpErrorClass::FailedPrecondition,
        CacheServiceErrorKind::ResourceExhausted => TwirpErrorClass::ResourceExhausted,
        CacheServiceErrorKind::Unavailable => TwirpErrorClass::Unavailable,
        CacheServiceErrorKind::Internal => TwirpErrorClass::Internal,
    })
}

#[derive(Clone, Copy, Debug)]
enum AzureErrorClass {
    InvalidRequest,
    AuthenticationFailed,
    NotFound,
    Conflict,
    InvalidState,
    TooLarge,
    Unavailable,
    Internal,
}

fn azure_success() -> Response {
    no_store((
        StatusCode::CREATED,
        [
            (
                header::HeaderName::from_static("x-ms-version"),
                "2025-11-05",
            ),
            (
                header::HeaderName::from_static("x-ms-request-server-encrypted"),
                "true",
            ),
        ],
    ))
}

fn azure_error(class: AzureErrorClass) -> Response {
    let (status, code, message) = match class {
        AzureErrorClass::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "InvalidQueryParameterValue",
            "The request is invalid.",
        ),
        AzureErrorClass::AuthenticationFailed => (
            StatusCode::FORBIDDEN,
            "AuthenticationFailed",
            "Authentication failed.",
        ),
        AzureErrorClass::NotFound => (
            StatusCode::NOT_FOUND,
            "BlobNotFound",
            "The cache upload was not found.",
        ),
        AzureErrorClass::Conflict => (
            StatusCode::CONFLICT,
            "BlobAlreadyExists",
            "Immutable cache upload metadata conflicts.",
        ),
        AzureErrorClass::InvalidState => (
            StatusCode::CONFLICT,
            "InvalidBlobOrBlock",
            "The cache upload is not in the required state.",
        ),
        AzureErrorClass::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "RequestBodyTooLarge",
            "The cache resource limit was exceeded.",
        ),
        AzureErrorClass::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ServerBusy",
            "The cache service is temporarily unavailable.",
        ),
        AzureErrorClass::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The cache service failed.",
        ),
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    no_store((
        status,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        body,
    ))
}

fn azure_service_error(error: CacheServiceError) -> Response {
    azure_error(match error.kind() {
        CacheServiceErrorKind::InvalidArgument => AzureErrorClass::InvalidRequest,
        CacheServiceErrorKind::PermissionDenied => AzureErrorClass::AuthenticationFailed,
        CacheServiceErrorKind::NotFound => AzureErrorClass::NotFound,
        CacheServiceErrorKind::Conflict => AzureErrorClass::Conflict,
        CacheServiceErrorKind::FailedPrecondition => AzureErrorClass::InvalidState,
        CacheServiceErrorKind::ResourceExhausted => AzureErrorClass::TooLarge,
        CacheServiceErrorKind::Unavailable => AzureErrorClass::Unavailable,
        CacheServiceErrorKind::Internal => AzureErrorClass::Internal,
    })
}

fn download_service_error(error: CacheServiceError) -> Response {
    download_error(match error.kind() {
        CacheServiceErrorKind::InvalidArgument => StatusCode::BAD_REQUEST,
        CacheServiceErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        CacheServiceErrorKind::NotFound => StatusCode::NOT_FOUND,
        CacheServiceErrorKind::Conflict | CacheServiceErrorKind::FailedPrecondition => {
            StatusCode::CONFLICT
        }
        CacheServiceErrorKind::ResourceExhausted => StatusCode::PAYLOAD_TOO_LARGE,
        CacheServiceErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        CacheServiceErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    })
}

fn range_not_satisfiable(size: u64) -> Response {
    no_store((
        StatusCode::RANGE_NOT_SATISFIABLE,
        [(header::CONTENT_RANGE, format!("bytes */{size}"))],
    ))
}

fn download_error(status: StatusCode) -> Response {
    no_store(status)
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    harden_results_response(&mut response);
    response
}
