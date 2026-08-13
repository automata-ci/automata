use std::{
    str::FromStr as _,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use automata_ci_core::{JobId, RunId, Sha256Digest};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, MatchedPath, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use futures::{StreamExt as _, stream};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    ArtifactId, ArtifactService, PublishedArtifactMetadata, ResultsHttpRoute, ResultsObserver,
    ResultsServiceError, ResultsServiceErrorKind, ResultsTransferDirection, RuntimeTokenClaims,
    RuntimeTokenVerifier, SignedDownloadCapability, SignedUploadCapability, TokenError, UploadId,
    azure::{AzureProtocolError, parse_block_list, validate_block_id},
    observer::{NoopResultsObserver, ResultsHttpObservation},
};

// foundation-governance: derived-contract owner=github-runtime kind=wire-discriminator
const CREATE_ARTIFACT_PATH: &str =
    "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact";
// foundation-governance: derived-contract owner=github-runtime kind=wire-discriminator
const FINALIZE_ARTIFACT_PATH: &str =
    "/twirp/github.actions.results.api.v1.ArtifactService/FinalizeArtifact";
// foundation-governance: derived-contract owner=github-runtime kind=wire-discriminator
const LIST_ARTIFACTS_PATH: &str =
    "/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts";
// foundation-governance: derived-contract owner=github-runtime kind=wire-discriminator
const GET_SIGNED_ARTIFACT_URL_PATH: &str =
    "/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL";
const UPLOAD_PATH: &str = "/_apis/results/artifacts/{upload_id}/blob";
const DOWNLOAD_PATH: &str = "/_apis/results/artifacts/{artifact_id}/{content_digest}/download.zip";
const DEFAULT_MIME_TYPE: &str = "application/octet-stream";
const MAXIMUM_SIGNATURE_BYTES: usize = 256;
/// Four maximum-size cache blocks bound upload buffering to 512 MiB per process.
const MAXIMUM_CONCURRENT_RESULTS_UPLOADS: usize = 4;
const RESULTS_UPLOAD_RETRY_AFTER_SECONDS: &str = "1";
const RESULTS_UPLOAD_OVERLOAD_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>ServerBusy</Code><Message>The Results upload service is temporarily unavailable.</Message></Error>";
const X_CONTENT_TYPE_OPTIONS: header::HeaderName =
    header::HeaderName::from_static("x-content-type-options");

#[derive(Debug)]
pub(crate) struct ResultsUploadAdmission {
    in_flight: AtomicUsize,
}

impl ResultsUploadAdmission {
    const fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ResultsUploadPermit> {
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                (in_flight < MAXIMUM_CONCURRENT_RESULTS_UPLOADS).then_some(in_flight + 1)
            })
            .ok()
            .map(|_| ResultsUploadPermit {
                admission: Arc::clone(self),
            })
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct ResultsUploadPermit {
    admission: Arc<ResultsUploadAdmission>,
}

impl Drop for ResultsUploadPermit {
    fn drop(&mut self) {
        let previous = self.admission.in_flight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "Results upload admission underflow");
    }
}

pub(crate) fn results_upload_admission() -> Arc<ResultsUploadAdmission> {
    static ADMISSION: OnceLock<Arc<ResultsUploadAdmission>> = OnceLock::new();
    Arc::clone(ADMISSION.get_or_init(|| Arc::new(ResultsUploadAdmission::new())))
}

pub(crate) async fn admit_results_upload(
    State(admission): State<Arc<ResultsUploadAdmission>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(_permit) = admission.try_acquire() else {
        return results_upload_overloaded();
    };
    next.run(request).await
}

fn results_upload_overloaded() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::RETRY_AFTER, RESULTS_UPLOAD_RETRY_AFTER_SECONDS),
        ],
        RESULTS_UPLOAD_OVERLOAD_BODY,
    )
        .into_response();
    harden_results_response(&mut response);
    response
}

pub(crate) fn harden_results_response(response: &mut Response) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
}

/// Independent HTTP-body ceilings for the Twirp and Azure compatibility surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubResultsHttpLimits {
    maximum_twirp_body_bytes: usize,
    maximum_azure_body_bytes: usize,
}

impl GithubResultsHttpLimits {
    /// Largest supported Twirp request body.
    pub const MAXIMUM_TWIRP_BODY_BYTES: usize = 1024 * 1024;
    /// Largest supported Azure-compatible block request body.
    pub const MAXIMUM_AZURE_BODY_BYTES: usize = 128 * 1024 * 1024;

    /// Creates nonzero, hard-bounded body ceilings.
    ///
    /// # Errors
    ///
    /// Rejects a zero ceiling or one above the supported in-memory bound.
    pub const fn new(
        maximum_twirp_body_bytes: usize,
        maximum_azure_body_bytes: usize,
    ) -> Result<Self, GithubResultsHttpLimitsError> {
        if maximum_twirp_body_bytes == 0
            || maximum_twirp_body_bytes > Self::MAXIMUM_TWIRP_BODY_BYTES
            || maximum_azure_body_bytes == 0
            || maximum_azure_body_bytes > Self::MAXIMUM_AZURE_BODY_BYTES
        {
            return Err(GithubResultsHttpLimitsError);
        }
        Ok(Self {
            maximum_twirp_body_bytes,
            maximum_azure_body_bytes,
        })
    }
}

impl Default for GithubResultsHttpLimits {
    fn default() -> Self {
        Self {
            maximum_twirp_body_bytes: 64 * 1024,
            maximum_azure_body_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Invalid HTTP Results limits.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
#[error("GitHub Results HTTP body limits are outside the supported bounds")]
pub struct GithubResultsHttpLimitsError;

#[derive(Clone)]
struct ApiState {
    service: Arc<ArtifactService>,
    runtime_tokens: Arc<dyn RuntimeTokenVerifier>,
    upload_capabilities: Arc<dyn SignedUploadCapability>,
    download_capabilities: Arc<dyn SignedDownloadCapability>,
    observer: Arc<dyn ResultsObserver>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiState")
            .field("service", &self.service)
            .field("runtime_tokens", &self.runtime_tokens)
            .field("upload_capabilities", &self.upload_capabilities)
            .field("download_capabilities", &self.download_capabilities)
            .field("observer", &self.observer)
            .finish()
    }
}

/// GitHub Actions Results v7 HTTP adapter.
#[derive(Clone, Debug)]
pub struct GithubResultsApi {
    state: ApiState,
    limits: GithubResultsHttpLimits,
}

impl GithubResultsApi {
    /// Composes the HTTP adapter from application and credential ports.
    #[must_use]
    pub fn new(
        service: Arc<ArtifactService>,
        runtime_tokens: Arc<dyn RuntimeTokenVerifier>,
        upload_capabilities: Arc<dyn SignedUploadCapability>,
        download_capabilities: Arc<dyn SignedDownloadCapability>,
        limits: GithubResultsHttpLimits,
    ) -> Self {
        Self {
            state: ApiState {
                service,
                runtime_tokens,
                upload_capabilities,
                download_capabilities,
                observer: Arc::new(NoopResultsObserver),
            },
            limits,
        }
    }

    /// Installs an infallible identifier-free application and HTTP observer.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn ResultsObserver>) -> Self {
        self.state.observer = observer;
        self
    }

    /// Returns routes suitable for merging into the product HTTP listener.
    pub fn router(self) -> Router {
        let twirp = Router::new()
            .route(CREATE_ARTIFACT_PATH, post(create_artifact))
            .route(FINALIZE_ARTIFACT_PATH, post(finalize_artifact))
            .route(LIST_ARTIFACTS_PATH, post(list_artifacts))
            .route(GET_SIGNED_ARTIFACT_URL_PATH, post(get_signed_artifact_url))
            .layer(DefaultBodyLimit::max(self.limits.maximum_twirp_body_bytes));
        let azure = Router::new()
            .route(UPLOAD_PATH, put(azure_blob))
            .layer(DefaultBodyLimit::max(self.limits.maximum_azure_body_bytes))
            .layer(middleware::from_fn_with_state(
                results_upload_admission(),
                admit_results_upload,
            ));
        let download = Router::new().route(DOWNLOAD_PATH, get(download_artifact));
        let observer = Arc::clone(&self.state.observer);
        twirp
            .merge(azure)
            .merge(download)
            .with_state(self.state)
            .layer(middleware::from_fn_with_state(observer, observe_http))
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
        results_http_route(
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

fn results_http_route(matched_path: Option<&str>) -> ResultsHttpRoute {
    match matched_path {
        Some(CREATE_ARTIFACT_PATH) => ResultsHttpRoute::CreateArtifact,
        Some(FINALIZE_ARTIFACT_PATH) => ResultsHttpRoute::FinalizeArtifact,
        Some(LIST_ARTIFACTS_PATH) => ResultsHttpRoute::ListArtifacts,
        Some(GET_SIGNED_ARTIFACT_URL_PATH) => ResultsHttpRoute::GetSignedArtifactUrl,
        Some(UPLOAD_PATH) => ResultsHttpRoute::Upload,
        Some(DOWNLOAD_PATH) => ResultsHttpRoute::Download,
        _ => ResultsHttpRoute::Unknown,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateArtifactRequest {
    workflow_run_backend_id: String,
    workflow_job_run_backend_id: String,
    name: String,
    #[serde(default)]
    expires_at: Option<String>,
    version: i32,
    #[serde(default)]
    mime_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateArtifactResponse {
    ok: bool,
    signed_upload_url: String,
}

async fn create_artifact(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Result<Json<CreateArtifactRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    if !request_ids_match(
        &claims,
        &request.workflow_run_backend_id,
        &request.workflow_job_run_backend_id,
    ) {
        return twirp_error(TwirpErrorClass::PermissionDenied);
    }
    let expires_at = match request.expires_at {
        Some(value) => match parse_timestamp(&value) {
            Ok(value) => Some(value),
            Err(()) => return twirp_error(TwirpErrorClass::InvalidArgument),
        },
        None => None,
    };
    let created = match state
        .service
        .create(
            claims.authority(),
            request.name,
            request.version,
            request
                .mime_type
                .unwrap_or_else(|| DEFAULT_MIME_TYPE.to_owned()),
            expires_at,
        )
        .await
    {
        Ok(created) => created,
        Err(error) => return twirp_service_error(error),
    };
    let Ok(signed_url) = state
        .upload_capabilities
        .issue_url(created.upload_id, claims.expires_at_seconds())
    else {
        return twirp_error(TwirpErrorClass::Internal);
    };
    no_store(Json(CreateArtifactResponse {
        ok: true,
        signed_upload_url: signed_url.to_string(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeArtifactRequest {
    workflow_run_backend_id: String,
    workflow_job_run_backend_id: String,
    name: String,
    size: String,
    #[serde(default)]
    hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct FinalizeArtifactResponse {
    ok: bool,
    artifact_id: String,
}

async fn finalize_artifact(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Result<Json<FinalizeArtifactRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    if !request_ids_match(
        &claims,
        &request.workflow_run_backend_id,
        &request.workflow_job_run_backend_id,
    ) {
        return twirp_error(TwirpErrorClass::PermissionDenied);
    }
    let Ok(size) = parse_canonical_u64(&request.size) else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    let digest = match request.hash {
        Some(value) => match value
            .strip_prefix("sha256:")
            .and_then(|digest| Sha256Digest::from_str(digest).ok())
        {
            Some(digest) => Some(digest),
            None => return twirp_error(TwirpErrorClass::InvalidArgument),
        },
        None => None,
    };
    match state
        .service
        .finalize(claims.authority(), request.name, size, digest)
        .await
    {
        Ok(finalized) => no_store(Json(FinalizeArtifactResponse {
            ok: true,
            artifact_id: finalized.artifact_id.to_string(),
        })),
        Err(error) => twirp_service_error(error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArtifactsRequest {
    workflow_run_backend_id: String,
    workflow_job_run_backend_id: String,
    #[serde(default)]
    name_filter: Option<String>,
    #[serde(default)]
    id_filter: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListArtifactsResponse {
    artifacts: Vec<ListedArtifactResponse>,
}

#[derive(Debug, Serialize)]
struct ListedArtifactResponse {
    workflow_run_backend_id: String,
    workflow_job_run_backend_id: String,
    database_id: String,
    name: String,
    size: String,
    created_at: String,
    digest: String,
}

async fn list_artifacts(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Result<Json<ListArtifactsRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    if !request_ids_match(
        &claims,
        &request.workflow_run_backend_id,
        &request.workflow_job_run_backend_id,
    ) {
        return twirp_error(TwirpErrorClass::PermissionDenied);
    }
    let artifact_id = match request.id_filter {
        Some(value) => match parse_artifact_id(&value) {
            Ok(value) => Some(value),
            Err(()) => return twirp_error(TwirpErrorClass::InvalidArgument),
        },
        None => None,
    };
    let artifacts = match state
        .service
        .list(claims.authority(), request.name_filter, artifact_id)
        .await
    {
        Ok(artifacts) => artifacts,
        Err(error) => return twirp_service_error(error),
    };
    let Ok(artifacts) = artifacts
        .iter()
        .map(listed_artifact_response)
        .collect::<Result<Vec<_>, ()>>()
    else {
        return twirp_error(TwirpErrorClass::Internal);
    };
    no_store(Json(ListArtifactsResponse { artifacts }))
}

fn listed_artifact_response(
    artifact: &PublishedArtifactMetadata,
) -> Result<ListedArtifactResponse, ()> {
    let created_at = i64::try_from(artifact.created_at_seconds)
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|timestamp| timestamp.format(&Rfc3339).ok())
        .ok_or(())?;
    Ok(ListedArtifactResponse {
        workflow_run_backend_id: artifact.authority.run_id().to_string(),
        workflow_job_run_backend_id: artifact.authority.job_id().to_string(),
        database_id: artifact.artifact_id.to_string(),
        name: artifact.name.as_str().to_owned(),
        size: artifact.size.to_string(),
        created_at,
        digest: format!("sha256:{}", artifact.content_digest),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetSignedArtifactUrlRequest {
    workflow_run_backend_id: String,
    workflow_job_run_backend_id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct GetSignedArtifactUrlResponse {
    signed_url: String,
}

async fn get_signed_artifact_url(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Result<Json<GetSignedArtifactUrlRequest>, JsonRejection>,
) -> Response {
    let claims = match authenticate(&state, &headers) {
        Ok(claims) => claims,
        Err(error) => return twirp_token_error(error),
    };
    let Ok(Json(request)) = request else {
        return twirp_error(TwirpErrorClass::InvalidArgument);
    };
    let Ok(request_run_id) = RunId::from_str(&request.workflow_run_backend_id) else {
        return twirp_error(TwirpErrorClass::PermissionDenied);
    };
    let Ok(request_job_id) = JobId::from_str(&request.workflow_job_run_backend_id) else {
        return twirp_error(TwirpErrorClass::PermissionDenied);
    };
    if request_run_id != claims.authority().run_id() {
        return twirp_error(TwirpErrorClass::PermissionDenied);
    }
    let artifacts = match state
        .service
        .list(claims.authority(), Some(request.name), None)
        .await
    {
        Ok(artifacts) => artifacts,
        Err(error) => return twirp_service_error(error),
    };
    let [artifact] = artifacts.as_slice() else {
        return twirp_error(if artifacts.is_empty() {
            TwirpErrorClass::NotFound
        } else {
            TwirpErrorClass::Internal
        });
    };
    if artifact.authority.run_id() != request_run_id
        || artifact.authority.job_id() != request_job_id
    {
        return twirp_error(TwirpErrorClass::NotFound);
    }
    let Ok(signed_url) = state.download_capabilities.issue_download_url(
        artifact.artifact_id,
        artifact.content_digest,
        claims.expires_at_seconds(),
    ) else {
        return twirp_error(TwirpErrorClass::Internal);
    };
    no_store(Json(GetSignedArtifactUrlResponse {
        signed_url: signed_url.to_string(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadQuery {
    se: u64,
    sig: String,
}

async fn download_artifact(
    State(state): State<ApiState>,
    Path((artifact_id, content_digest)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> Response {
    let Ok(artifact_id) = parse_artifact_id(&artifact_id) else {
        return download_error(StatusCode::BAD_REQUEST);
    };
    let content_digest = match Sha256Digest::from_str(&content_digest) {
        Ok(value) if value.to_string() == content_digest => value,
        _ => return download_error(StatusCode::BAD_REQUEST),
    };
    if query.sig.is_empty()
        || query.sig.len() > MAXIMUM_SIGNATURE_BYTES
        || state
            .download_capabilities
            .verify_download(artifact_id, content_digest, query.se, &query.sig)
            .is_err()
    {
        return download_error(StatusCode::FORBIDDEN);
    }
    let prepared = match state
        .service
        .prepare_download(artifact_id, content_digest)
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return download_service_error(error),
    };
    let service = Arc::clone(&state.service);
    let observer = Arc::clone(&state.observer);
    let body = Body::from_stream(stream::iter(prepared.blocks).then(move |descriptor| {
        let service = Arc::clone(&service);
        let observer = Arc::clone(&observer);
        async move {
            let result = service.read_download_block(&descriptor).await;
            if let Ok(bytes) = &result {
                observer.observe_transfer_bytes(
                    ResultsTransferDirection::Download,
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                );
            }
            result
        }
    }));
    let etag = format!("\"sha256:{content_digest}\"");
    let disposition = format!(
        "attachment; filename=\"artifact-{}.zip\"",
        prepared.metadata.artifact_id
    );
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_LENGTH, prepared.metadata.size)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::ETAG, etag)
        .body(body)
        .unwrap_or_else(|_| download_error(StatusCode::INTERNAL_SERVER_ERROR));
    no_store(response)
}

fn download_error(status: StatusCode) -> Response {
    no_store(status)
}

fn download_service_error(error: ResultsServiceError) -> Response {
    download_error(match error.kind() {
        ResultsServiceErrorKind::InvalidArgument => StatusCode::BAD_REQUEST,
        ResultsServiceErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        ResultsServiceErrorKind::NotFound => StatusCode::NOT_FOUND,
        ResultsServiceErrorKind::Conflict | ResultsServiceErrorKind::FailedPrecondition => {
            StatusCode::CONFLICT
        }
        ResultsServiceErrorKind::ResourceExhausted => StatusCode::PAYLOAD_TOO_LARGE,
        ResultsServiceErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ResultsServiceErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    })
}

#[derive(Debug, Deserialize)]
struct AzureQuery {
    se: u64,
    sig: String,
    comp: String,
    #[serde(default)]
    blockid: Option<String>,
}

async fn azure_blob(
    State(state): State<ApiState>,
    Path(upload_id): Path<String>,
    Query(query): Query<AzureQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let upload_id = match Uuid::parse_str(&upload_id) {
        Ok(value) => UploadId::from_uuid(value),
        Err(_) => return azure_error(AzureErrorClass::InvalidRequest),
    };
    if query.sig.is_empty() || query.sig.len() > MAXIMUM_SIGNATURE_BYTES {
        return azure_error(AzureErrorClass::AuthenticationFailed);
    }
    if state
        .upload_capabilities
        .verify(upload_id, query.se, &query.sig)
        .is_err()
    {
        return azure_error(AzureErrorClass::AuthenticationFailed);
    }
    match (query.comp.as_str(), query.blockid) {
        ("block", Some(block_id)) => {
            let Ok(block_id) = validate_block_id(&block_id) else {
                return azure_error(AzureErrorClass::InvalidRequest);
            };
            if !content_length_matches(&headers, body.len()) {
                return azure_error(AzureErrorClass::InvalidRequest);
            }
            let bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
            match state.service.stage_block(upload_id, block_id, body).await {
                Ok(()) => {
                    state
                        .observer
                        .observe_transfer_bytes(ResultsTransferDirection::Upload, bytes);
                    azure_success()
                }
                Err(error) => azure_service_error(error),
            }
        }
        ("blocklist", None) => {
            let block_ids = match parse_block_list(&body, state.service.limits().maximum_blocks()) {
                Ok(block_ids) => block_ids,
                Err(AzureProtocolError::TooManyBlocks) => {
                    return azure_error(AzureErrorClass::TooLarge);
                }
                Err(_) => return azure_error(AzureErrorClass::InvalidRequest),
            };
            match state.service.commit_blocks(upload_id, block_ids).await {
                Ok(()) => azure_success(),
                Err(error) => azure_service_error(error),
            }
        }
        _ => azure_error(AzureErrorClass::InvalidRequest),
    }
}

fn authenticate(state: &ApiState, headers: &HeaderMap) -> Result<RuntimeTokenClaims, TokenError> {
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

fn request_ids_match(claims: &RuntimeTokenClaims, run_id: &str, job_id: &str) -> bool {
    let Ok(run_id) = RunId::from_str(run_id) else {
        return false;
    };
    let Ok(job_id) = JobId::from_str(job_id) else {
        return false;
    };
    claims.authority().run_id() == run_id && claims.authority().job_id() == job_id
}

fn parse_timestamp(value: &str) -> Result<u64, ()> {
    if value.len() > 64 {
        return Err(());
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ())?;
    u64::try_from(timestamp.unix_timestamp()).map_err(|_| ())
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

fn parse_artifact_id(value: &str) -> Result<ArtifactId, ()> {
    parse_canonical_u64(value)
        .and_then(|value| i64::try_from(value).map_err(|_| ()))
        .and_then(|value| ArtifactId::new(value).map_err(|_| ()))
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
            "request is invalid",
        ),
        TwirpErrorClass::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "authentication is required",
        ),
        TwirpErrorClass::PermissionDenied => (
            StatusCode::FORBIDDEN,
            "permission_denied",
            "request is not authorized",
        ),
        TwirpErrorClass::NotFound => (StatusCode::NOT_FOUND, "not_found", "artifact was not found"),
        TwirpErrorClass::AlreadyExists => (
            StatusCode::CONFLICT,
            "already_exists",
            "artifact already exists with different immutable metadata",
        ),
        TwirpErrorClass::FailedPrecondition => (
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "artifact is not in the required state",
        ),
        TwirpErrorClass::ResourceExhausted => (
            StatusCode::TOO_MANY_REQUESTS,
            "resource_exhausted",
            "artifact resource limit was exceeded",
        ),
        TwirpErrorClass::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "artifact service is temporarily unavailable",
        ),
        TwirpErrorClass::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal artifact service error",
        ),
    };
    no_store((status, Json(TwirpErrorBody { code, msg: message })))
}

fn twirp_token_error(_error: TokenError) -> Response {
    twirp_error(TwirpErrorClass::Unauthenticated)
}

fn twirp_service_error(error: ResultsServiceError) -> Response {
    twirp_error(match error.kind() {
        ResultsServiceErrorKind::InvalidArgument => TwirpErrorClass::InvalidArgument,
        ResultsServiceErrorKind::PermissionDenied => TwirpErrorClass::PermissionDenied,
        ResultsServiceErrorKind::NotFound => TwirpErrorClass::NotFound,
        ResultsServiceErrorKind::Conflict => TwirpErrorClass::AlreadyExists,
        ResultsServiceErrorKind::FailedPrecondition => TwirpErrorClass::FailedPrecondition,
        ResultsServiceErrorKind::ResourceExhausted => TwirpErrorClass::ResourceExhausted,
        ResultsServiceErrorKind::Unavailable => TwirpErrorClass::Unavailable,
        ResultsServiceErrorKind::Internal => TwirpErrorClass::Internal,
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
    (
        StatusCode::CREATED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::HeaderName::from_static("x-ms-version"),
                "2025-11-05",
            ),
            (
                header::HeaderName::from_static("x-ms-request-server-encrypted"),
                "true",
            ),
        ],
    )
        .into_response()
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
            "The upload was not found.",
        ),
        AzureErrorClass::Conflict => (
            StatusCode::CONFLICT,
            "BlobAlreadyExists",
            "Immutable upload metadata conflicts.",
        ),
        AzureErrorClass::InvalidState => (
            StatusCode::CONFLICT,
            "InvalidBlobOrBlock",
            "The upload is not in the required state.",
        ),
        AzureErrorClass::TooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "RequestBodyTooLarge",
            "The artifact resource limit was exceeded.",
        ),
        AzureErrorClass::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ServerBusy",
            "The artifact service is temporarily unavailable.",
        ),
        AzureErrorClass::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The artifact service failed.",
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

fn azure_service_error(error: ResultsServiceError) -> Response {
    azure_error(match error.kind() {
        ResultsServiceErrorKind::InvalidArgument => AzureErrorClass::InvalidRequest,
        ResultsServiceErrorKind::PermissionDenied => AzureErrorClass::AuthenticationFailed,
        ResultsServiceErrorKind::NotFound => AzureErrorClass::NotFound,
        ResultsServiceErrorKind::Conflict => AzureErrorClass::Conflict,
        ResultsServiceErrorKind::FailedPrecondition => AzureErrorClass::InvalidState,
        ResultsServiceErrorKind::ResourceExhausted => AzureErrorClass::TooLarge,
        ResultsServiceErrorKind::Unavailable => AzureErrorClass::Unavailable,
        ResultsServiceErrorKind::Internal => AzureErrorClass::Internal,
    })
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    harden_results_response(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Mutex, time::Duration};

    use axum::{body::Bytes, routing::put};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    const ARTIFACT_UPLOAD_TEST_PATH: &str =
        "/_apis/results/artifacts/00000000-0000-0000-0000-000000000001/blob";
    const CACHE_UPLOAD_TEST_PATH: &str =
        "/_apis/results/caches/00000000-0000-0000-0000-000000000002/blob";
    const CACHE_UPLOAD_TEST_ROUTE: &str = "/_apis/results/caches/{entry_id}/blob";

    #[derive(Debug, Default)]
    struct RecordingObserver {
        completed: Mutex<Vec<(ResultsHttpRoute, crate::ResultsHttpStatusClass)>>,
    }

    impl ResultsObserver for RecordingObserver {
        fn observe_results_http_request(
            &self,
            _method: crate::ResultsHttpMethod,
            route: ResultsHttpRoute,
            status: crate::ResultsHttpStatusClass,
            _duration: Duration,
        ) {
            self.completed
                .lock()
                .expect("completed observations")
                .push((route, status));
        }
    }

    async fn collect_upload(_body: Bytes) -> StatusCode {
        StatusCode::CREATED
    }

    fn pending_upload(path: &'static str) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(path)
            .body(Body::from_stream(futures::stream::pending::<
                Result<Bytes, Infallible>,
            >()))
            .expect("pending upload request")
    }

    async fn wait_for_uploads(admission: &ResultsUploadAdmission, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while admission.in_flight() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("upload admission count must converge");
    }

    #[tokio::test]
    async fn artifact_and_cache_uploads_share_budget_and_cancelled_request_releases_it() {
        let artifact_admission = results_upload_admission();
        let cache_admission = results_upload_admission();
        assert!(Arc::ptr_eq(&artifact_admission, &cache_admission));
        assert_eq!(artifact_admission.in_flight(), 0);

        let observer = Arc::new(RecordingObserver::default());
        let observer_state: Arc<dyn ResultsObserver> = observer.clone();
        let artifact = Router::new()
            .route(UPLOAD_PATH, put(collect_upload))
            .layer(middleware::from_fn_with_state(
                artifact_admission.clone(),
                admit_results_upload,
            ))
            .layer(middleware::from_fn_with_state(observer_state, observe_http));
        let cache = Router::new()
            .route(CACHE_UPLOAD_TEST_ROUTE, put(collect_upload))
            .layer(middleware::from_fn_with_state(
                cache_admission,
                admit_results_upload,
            ));
        let router = artifact.merge(cache);

        let mut requests = Vec::new();
        for path in [
            ARTIFACT_UPLOAD_TEST_PATH,
            CACHE_UPLOAD_TEST_PATH,
            ARTIFACT_UPLOAD_TEST_PATH,
            CACHE_UPLOAD_TEST_PATH,
        ] {
            requests.push(tokio::spawn(router.clone().oneshot(pending_upload(path))));
        }
        wait_for_uploads(&artifact_admission, MAXIMUM_CONCURRENT_RESULTS_UPLOADS).await;

        let rejected = tokio::time::timeout(
            Duration::from_secs(1),
            router
                .clone()
                .oneshot(pending_upload(ARTIFACT_UPLOAD_TEST_PATH)),
        )
        .await
        .expect("overload response must not wait for request body")
        .expect("overload response");
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
        assert_eq!(rejected.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(rejected.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let body = rejected
            .into_body()
            .collect()
            .await
            .expect("overload body")
            .to_bytes();
        assert_eq!(body.as_ref(), RESULTS_UPLOAD_OVERLOAD_BODY.as_bytes());
        assert_eq!(
            *observer.completed.lock().expect("completed observations"),
            vec![(
                ResultsHttpRoute::Upload,
                crate::ResultsHttpStatusClass::ServerError,
            )]
        );

        let cancelled = requests.remove(0);
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("admitted upload must be cancelled")
                .is_cancelled()
        );
        wait_for_uploads(&artifact_admission, MAXIMUM_CONCURRENT_RESULTS_UPLOADS - 1).await;

        let replacement = tokio::spawn(router.oneshot(pending_upload(CACHE_UPLOAD_TEST_PATH)));
        wait_for_uploads(&artifact_admission, MAXIMUM_CONCURRENT_RESULTS_UPLOADS).await;

        for request in requests {
            request.abort();
            let _ = request.await;
        }
        replacement.abort();
        let _ = replacement.await;
        wait_for_uploads(&artifact_admission, 0).await;
    }
}
