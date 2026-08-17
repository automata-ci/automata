use std::sync::{Arc, OnceLock};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::{HeaderMap, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    ResultsHttpRoute, ResultsObserver, RuntimeTokenClaims, RuntimeTokenVerifier, TokenError,
    observer::ResultsHttpObservation,
};

const MAXIMUM_SIGNATURE_BYTES: usize = 256;
/// Four maximum-size cache blocks bound upload buffering to 512 MiB per process.
pub(super) const MAXIMUM_CONCURRENT_RESULTS_UPLOADS: usize = 4;
const RESULTS_UPLOAD_OVERLOAD_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>ServerBusy</Code><Message>The Results upload service is temporarily unavailable.</Message></Error>";
const X_CONTENT_TYPE_OPTIONS: header::HeaderName =
    header::HeaderName::from_static("x-content-type-options");

#[derive(Debug)]
pub(super) struct ResultsUploadAdmission {
    permits: Arc<Semaphore>,
}

impl ResultsUploadAdmission {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAXIMUM_CONCURRENT_RESULTS_UPLOADS)),
        }
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.permits).acquire_owned().await
    }

    #[cfg(test)]
    pub(super) fn in_flight(&self) -> usize {
        MAXIMUM_CONCURRENT_RESULTS_UPLOADS - self.permits.available_permits()
    }
}

pub(super) fn results_upload_admission() -> Arc<ResultsUploadAdmission> {
    static ADMISSION: OnceLock<Arc<ResultsUploadAdmission>> = OnceLock::new();
    Arc::clone(ADMISSION.get_or_init(|| Arc::new(ResultsUploadAdmission::new())))
}

pub(super) async fn admit_results_upload(
    State(admission): State<Arc<ResultsUploadAdmission>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Waiting here applies bounded, FIFO backpressure before Axum starts buffering
    // another request body. Cache traffic therefore cannot turn a valid artifact
    // upload into a transient protocol failure when the shared memory budget is full.
    let Ok(_permit) = admission.acquire().await else {
        return results_upload_overloaded();
    };
    next.run(request).await
}

fn results_upload_overloaded() -> Response {
    no_store((
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        RESULTS_UPLOAD_OVERLOAD_BODY,
    ))
}

pub(super) async fn observe_results_http(
    observer: Arc<dyn ResultsObserver>,
    classifier: fn(Option<&str>) -> ResultsHttpRoute,
    request: Request<Body>,
    next: Next,
) -> Response {
    let observation = ResultsHttpObservation::new(
        observer,
        request.method(),
        classifier(
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

pub(super) fn authenticate_runtime_token(
    verifier: &dyn RuntimeTokenVerifier,
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
    verifier.verify(credential)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedUrlQuery {
    pub(super) se: u64,
    pub(super) sig: String,
}

pub(super) fn signature_has_valid_shape(signature: &str) -> bool {
    !signature.is_empty() && signature.len() <= MAXIMUM_SIGNATURE_BYTES
}

pub(super) fn parse_canonical_u64(value: &str) -> Result<u64, ()> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(());
    }
    value.parse().map_err(|_| ())
}

pub(super) fn content_length_matches(headers: &HeaderMap, actual: usize) -> bool {
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

pub(super) fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    harden_results_response(&mut response);
    response
}

fn harden_results_response(response: &mut Response) {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
}

#[derive(Clone, Copy, Debug)]
pub(super) enum TwirpErrorClass {
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

#[derive(Clone, Copy, Debug)]
pub(super) enum AzureErrorClass {
    InvalidRequest,
    AuthenticationFailed,
    NotFound,
    Conflict,
    InvalidState,
    TooLarge,
    Unavailable,
    Internal,
}

#[derive(Debug, Serialize)]
pub(super) struct TwirpErrorBody {
    pub(super) code: &'static str,
    pub(super) msg: &'static str,
}
