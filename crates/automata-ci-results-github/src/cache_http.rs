use std::{str::FromStr as _, sync::Arc};

use automata_ci_core::Sha256Digest;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{StreamExt as _, stream};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CacheEntryId, CacheService, CacheServiceError, CacheServiceErrorKind, ResultsHttpRoute,
    ResultsObserver, RuntimeTokenVerifier, SignedCacheCapability,
    azure::{AzureProtocolError, parse_block_list, validate_block_id},
    http_support::{
        AzureErrorClass, SignedUrlQuery, TwirpErrorBody, TwirpErrorClass, admit_results_upload,
        authenticate_runtime_token, content_length_matches, no_store, observe_results_http,
        parse_canonical_u64, results_upload_admission, signature_has_valid_shape,
    },
    observer::NoopResultsObserver,
};

const CREATE_CACHE_PATH: &str =
    "/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry";
const FINALIZE_CACHE_PATH: &str =
    "/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload";
const GET_CACHE_PATH: &str =
    "/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL";
const CACHE_UPLOAD_PATH: &str = "/_apis/results/caches/{entry_id}/blob";
const CACHE_DOWNLOAD_PATH: &str = "/_apis/results/caches/{entry_id}/{digest}/download";
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
    observe_results_http(observer, cache_http_route, request, next).await
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

#[derive(Clone, PartialEq, prost::Message)]
struct ProtoCacheMetadata {}

#[derive(Clone, PartialEq, prost::Message)]
struct ProtoCreateCacheRequest {
    #[prost(message, optional, tag = "1")]
    metadata: Option<ProtoCacheMetadata>,
    #[prost(string, tag = "2")]
    key: String,
    #[prost(string, tag = "3")]
    version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ProtoCreateCacheResponse {
    #[prost(bool, tag = "1")]
    ok: bool,
    #[prost(string, tag = "2")]
    signed_upload_url: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TwirpEncoding {
    Json,
    Protobuf,
}

async fn create_cache(
    State(state): State<CacheApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(claims) = authenticate_runtime_token(state.runtime_tokens.as_ref(), &headers) else {
        return twirp_error(TwirpErrorClass::Unauthenticated);
    };
    let Ok((encoding, request)) = decode_create_request(&headers, &body) else {
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
    create_cache_response(encoding, signed_url.to_string())
}

fn decode_create_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(TwirpEncoding, CreateCacheRequest), ()> {
    let encoding = twirp_encoding(headers)?;
    let request = match encoding {
        TwirpEncoding::Json => serde_json::from_slice(body).map_err(|_| ())?,
        TwirpEncoding::Protobuf => {
            let request = ProtoCreateCacheRequest::decode(body).map_err(|_| ())?;
            if request.metadata.is_some() {
                return Err(());
            }
            CreateCacheRequest {
                key: request.key,
                version: request.version,
            }
        }
    };
    Ok((encoding, request))
}

fn create_cache_response(encoding: TwirpEncoding, signed_upload_url: String) -> Response {
    match encoding {
        TwirpEncoding::Json => no_store(Json(CreateCacheResponse {
            ok: true,
            signed_upload_url,
            message: String::new(),
        })),
        TwirpEncoding::Protobuf => protobuf_response(&ProtoCreateCacheResponse {
            ok: true,
            signed_upload_url,
        }),
    }
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

#[derive(Clone, PartialEq, prost::Message)]
struct ProtoFinalizeCacheRequest {
    #[prost(message, optional, tag = "1")]
    metadata: Option<ProtoCacheMetadata>,
    #[prost(string, tag = "2")]
    key: String,
    #[prost(int64, tag = "3")]
    size_bytes: i64,
    #[prost(string, tag = "4")]
    version: String,
}

#[derive(Clone, Copy, PartialEq, prost::Message)]
struct ProtoFinalizeCacheResponse {
    #[prost(bool, tag = "1")]
    ok: bool,
    #[prost(int64, tag = "2")]
    entry_id: i64,
}

async fn finalize_cache(
    State(state): State<CacheApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(claims) = authenticate_runtime_token(state.runtime_tokens.as_ref(), &headers) else {
        return twirp_error(TwirpErrorClass::Unauthenticated);
    };
    let Ok((encoding, request)) = decode_finalize_request(&headers, &body) else {
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
        Ok(entry) => finalize_cache_response(encoding, entry.protocol_entry_id.get()),
        Err(error) => twirp_service_error(error),
    }
}

fn decode_finalize_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(TwirpEncoding, FinalizeCacheRequest), ()> {
    let encoding = twirp_encoding(headers)?;
    let request = match encoding {
        TwirpEncoding::Json => serde_json::from_slice(body).map_err(|_| ())?,
        TwirpEncoding::Protobuf => {
            let request = ProtoFinalizeCacheRequest::decode(body).map_err(|_| ())?;
            if request.metadata.is_some() {
                return Err(());
            }
            FinalizeCacheRequest {
                key: request.key,
                version: request.version,
                size_bytes: u64::try_from(request.size_bytes).map_err(|_| ())?,
            }
        }
    };
    Ok((encoding, request))
}

fn finalize_cache_response(encoding: TwirpEncoding, entry_id: i64) -> Response {
    match encoding {
        TwirpEncoding::Json => no_store(Json(FinalizeCacheResponse {
            ok: true,
            entry_id: entry_id.to_string(),
            message: String::new(),
        })),
        TwirpEncoding::Protobuf => {
            protobuf_response(&ProtoFinalizeCacheResponse { ok: true, entry_id })
        }
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

#[derive(Clone, PartialEq, prost::Message)]
struct ProtoGetCacheRequest {
    #[prost(message, optional, tag = "1")]
    metadata: Option<ProtoCacheMetadata>,
    #[prost(string, tag = "2")]
    key: String,
    #[prost(string, repeated, tag = "3")]
    restore_keys: Vec<String>,
    #[prost(string, tag = "4")]
    version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct ProtoGetCacheResponse {
    #[prost(bool, tag = "1")]
    ok: bool,
    #[prost(string, tag = "2")]
    signed_download_url: String,
    #[prost(string, tag = "3")]
    matched_key: String,
}

async fn get_cache(
    State(state): State<CacheApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(claims) = authenticate_runtime_token(state.runtime_tokens.as_ref(), &headers) else {
        return twirp_error(TwirpErrorClass::Unauthenticated);
    };
    let Ok((encoding, request)) = decode_get_request(&headers, &body) else {
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
        return get_cache_response(encoding, false, String::new(), String::new());
    };
    let Ok(signed_url) = state.capabilities.issue_cache_download_url(
        entry.entry_id,
        entry.digest,
        claims.expires_at_seconds(),
    ) else {
        return twirp_error(TwirpErrorClass::Internal);
    };
    get_cache_response(
        encoding,
        true,
        signed_url.to_string(),
        entry.key.as_str().to_owned(),
    )
}

fn decode_get_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(TwirpEncoding, GetCacheRequest), ()> {
    let encoding = twirp_encoding(headers)?;
    let request = match encoding {
        TwirpEncoding::Json => serde_json::from_slice(body).map_err(|_| ())?,
        TwirpEncoding::Protobuf => {
            let request = ProtoGetCacheRequest::decode(body).map_err(|_| ())?;
            if request.metadata.is_some() {
                return Err(());
            }
            GetCacheRequest {
                key: request.key,
                version: request.version,
                restore_keys: request.restore_keys,
            }
        }
    };
    Ok((encoding, request))
}

fn get_cache_response(
    encoding: TwirpEncoding,
    ok: bool,
    signed_download_url: String,
    matched_key: String,
) -> Response {
    match encoding {
        TwirpEncoding::Json => no_store(Json(GetCacheResponse {
            ok,
            signed_download_url,
            matched_key,
        })),
        TwirpEncoding::Protobuf => protobuf_response(&ProtoGetCacheResponse {
            ok,
            signed_download_url,
            matched_key,
        }),
    }
}

fn twirp_encoding(headers: &HeaderMap) -> Result<TwirpEncoding, ()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .ok_or(())?
        .to_str()
        .map_err(|_| ())?;
    match content_type {
        "application/json" => Ok(TwirpEncoding::Json),
        "application/protobuf" => Ok(TwirpEncoding::Protobuf),
        _ => Err(()),
    }
}

fn protobuf_response(message: &impl prost::Message) -> Response {
    no_store((
        [(header::CONTENT_TYPE, "application/protobuf")],
        message.encode_to_vec(),
    ))
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
    if !signature_has_valid_shape(&query.sig)
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

async fn head_cache(
    State(state): State<CacheApiState>,
    Path((entry_id, digest)): Path<(String, String)>,
    Query(query): Query<SignedUrlQuery>,
) -> Response {
    let (entry_id, digest) = match verify_download_path(&state, &entry_id, &digest, &query) {
        Ok(value) => value,
        Err(status) => return no_store(status),
    };
    match state.service.prepare_download(entry_id, digest, None).await {
        Ok(prepared) => download_headers(StatusCode::OK, &prepared, Body::empty()),
        Err(error) => download_service_error(error),
    }
}

async fn download_cache(
    State(state): State<CacheApiState>,
    Path((entry_id, digest)): Path<(String, String)>,
    Query(query): Query<SignedUrlQuery>,
    headers: HeaderMap,
) -> Response {
    let (entry_id, digest) = match verify_download_path(&state, &entry_id, &digest, &query) {
        Ok(value) => value,
        Err(status) => return no_store(status),
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
    query: &SignedUrlQuery,
) -> Result<(CacheEntryId, Sha256Digest), StatusCode> {
    let entry_id = parse_entry_id(entry_id).map_err(|()| StatusCode::BAD_REQUEST)?;
    let parsed_digest = Sha256Digest::from_str(digest)
        .ok()
        .filter(|parsed| parsed.to_string() == digest)
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !signature_has_valid_shape(&query.sig)
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
            .unwrap_or_else(|_| no_store(StatusCode::INTERNAL_SERVER_ERROR)),
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

fn parse_entry_id(value: &str) -> Result<CacheEntryId, ()> {
    let uuid = Uuid::parse_str(value).map_err(|_| ())?;
    if uuid.to_string() != value {
        return Err(());
    }
    CacheEntryId::new(uuid).map_err(|_| ())
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
    no_store(match error.kind() {
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
