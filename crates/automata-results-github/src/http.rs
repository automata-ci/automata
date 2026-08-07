use std::{str::FromStr as _, sync::Arc};

use automata_core::{JobId, RunId, Sha256Digest};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{post, put},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    ArtifactService, ResultsServiceError, ResultsServiceErrorKind, RuntimeTokenClaims,
    RuntimeTokenVerifier, SignedUploadCapability, TokenError, UploadId,
    azure::{AzureProtocolError, parse_block_list, validate_block_id},
};

const CREATE_ARTIFACT_PATH: &str =
    "/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact";
const FINALIZE_ARTIFACT_PATH: &str =
    "/twirp/github.actions.results.api.v1.ArtifactService/FinalizeArtifact";
const UPLOAD_PATH: &str = "/_apis/results/artifacts/{upload_id}/blob";
const DEFAULT_MIME_TYPE: &str = "application/octet-stream";
const MAXIMUM_SIGNATURE_BYTES: usize = 256;

/// Independent HTTP-body ceilings for the Twirp and Azure compatibility surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubResultsHttpLimits {
    maximum_twirp_body_bytes: usize,
    maximum_azure_body_bytes: usize,
}

impl GithubResultsHttpLimits {
    /// Creates nonzero body ceilings.
    ///
    /// # Errors
    ///
    /// Rejects a zero ceiling.
    pub const fn new(
        maximum_twirp_body_bytes: usize,
        maximum_azure_body_bytes: usize,
    ) -> Result<Self, GithubResultsHttpLimitsError> {
        if maximum_twirp_body_bytes == 0 || maximum_azure_body_bytes == 0 {
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
#[error("GitHub Results HTTP body limits must be nonzero")]
pub struct GithubResultsHttpLimitsError;

#[derive(Clone)]
struct ApiState {
    service: Arc<ArtifactService>,
    runtime_tokens: Arc<dyn RuntimeTokenVerifier>,
    upload_capabilities: Arc<dyn SignedUploadCapability>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiState")
            .field("service", &self.service)
            .field("runtime_tokens", &self.runtime_tokens)
            .field("upload_capabilities", &self.upload_capabilities)
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
        limits: GithubResultsHttpLimits,
    ) -> Self {
        Self {
            state: ApiState {
                service,
                runtime_tokens,
                upload_capabilities,
            },
            limits,
        }
    }

    /// Returns routes suitable for merging into the product HTTP listener.
    pub fn router(self) -> Router {
        let twirp = Router::new()
            .route(CREATE_ARTIFACT_PATH, post(create_artifact))
            .route(FINALIZE_ARTIFACT_PATH, post(finalize_artifact))
            .layer(DefaultBodyLimit::max(self.limits.maximum_twirp_body_bytes));
        let azure = Router::new()
            .route(UPLOAD_PATH, put(azure_blob))
            .layer(DefaultBodyLimit::max(self.limits.maximum_azure_body_bytes));
        twirp.merge(azure).with_state(self.state)
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
        claims,
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
        claims,
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
            match state.service.stage_block(upload_id, block_id, body).await {
                Ok(()) => azure_success(),
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

fn request_ids_match(claims: RuntimeTokenClaims, run_id: &str, job_id: &str) -> bool {
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
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
