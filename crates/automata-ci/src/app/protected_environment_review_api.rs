//! CLI-authenticated HTTP boundary for protected-environment review.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::{
    management::{ManagementActor, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::Clock,
};
use automata_ci_core::AttemptId;
use automata_ci_store::{EnvironmentReviewDecision, JobEnvironmentGateState, RepositoryId};
use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_REQUEST_BYTES: usize = 1_024;

pub(crate) const PROTECTED_ENVIRONMENT_REVIEW_PATH: &str =
    "/api/v1/repositories/{repository_id}/attempts/{attempt_id}/environment/reviews";

/// Exact authority-bearing review request passed to product composition.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProtectedEnvironmentReviewApiRequest {
    actor: ManagementActor,
    repository_id: RepositoryId,
    attempt_id: AttemptId,
    decision: EnvironmentReviewDecision,
}

impl ProtectedEnvironmentReviewApiRequest {
    pub(crate) const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    pub(crate) const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    pub(crate) const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    pub(crate) const fn decision(&self) -> EnvironmentReviewDecision {
        self.decision
    }
}

impl fmt::Debug for ProtectedEnvironmentReviewApiRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedEnvironmentReviewApiRequest")
            .field("repository_id", &self.repository_id)
            .field("attempt_id", &self.attempt_id)
            .field("decision", &self.decision)
            .finish_non_exhaustive()
    }
}

/// Closed, sanitized product failures exposed by the HTTP boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedEnvironmentReviewApiBackendError {
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Invariant,
}

/// Product composition boundary behind the CLI HTTP adapter.
#[async_trait]
pub(crate) trait ProtectedEnvironmentReviewApiBackend: fmt::Debug + Send + Sync {
    async fn review(
        &self,
        request: ProtectedEnvironmentReviewApiRequest,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentReviewApiBackendError>;
}

#[derive(Clone)]
struct ProtectedEnvironmentReviewApiState {
    backend: Arc<dyn ProtectedEnvironmentReviewApiBackend>,
    clock: Arc<dyn Clock>,
}

/// Builds the isolated CLI-authenticated environment-review route.
pub(crate) fn protected_environment_review_api_router(
    backend: Arc<dyn ProtectedEnvironmentReviewApiBackend>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(PROTECTED_ENVIRONMENT_REVIEW_PATH, post(review_environment))
        .with_state(ProtectedEnvironmentReviewApiState { backend, clock })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn review_environment(
    State(state): State<ProtectedEnvironmentReviewApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let review = match prepare_request(&state, path, request).await {
        Ok(review) => review,
        Err(error) => return error.into_response(),
    };
    match state.backend.review(review).await {
        Ok(state) => success_response(state),
        Err(error) => ApiError::from(error).into_response(),
    }
}

async fn prepare_request(
    state: &ProtectedEnvironmentReviewApiState,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Result<ProtectedEnvironmentReviewApiRequest, ApiError> {
    if request.uri().query().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let Path((repository_id, attempt_id)) = path.map_err(|_| ApiError::InvalidRequest)?;
    let repository_id = RepositoryId::from_uuid(canonical_uuid(&repository_id)?);
    let attempt_id = AttemptId::from_uuid(canonical_uuid(&attempt_id)?);
    let actor = actor_from_request(state, &request)?;
    let document = json_document(request).await?;
    Ok(ProtectedEnvironmentReviewApiRequest {
        actor,
        repository_id,
        attempt_id,
        decision: document.decision.into(),
    })
}

fn canonical_uuid(value: &str) -> Result<Uuid, ApiError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(ApiError::InvalidRequest);
    }
    Ok(parsed)
}

fn actor_from_request(
    state: &ProtectedEnvironmentReviewApiState,
    request: &Request,
) -> Result<ManagementActor, ApiError> {
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .ok_or(ApiError::Unauthorized)?;
    let identity = snapshot.session().identity();
    if identity.kind() != SessionKind::Cli {
        return Err(ApiError::Unauthorized);
    }
    let authorization_revision =
        ManagementRevision::new(snapshot.session().authorization_revision())
            .map_err(|_| ApiError::Unauthorized)?;
    Ok(ManagementActor::new(
        identity.tenant_id().clone(),
        identity.principal_id().clone(),
        identity.session_id().clone(),
        authorization_revision,
        None,
        state.clock.now(),
    ))
}

async fn json_document(request: Request) -> Result<ReviewDocument, ApiError> {
    if request.headers().contains_key(header::CONTENT_ENCODING) {
        return Err(ApiError::UnsupportedMediaType);
    }
    if !is_json_content_type(request.headers()) {
        return Err(ApiError::UnsupportedMediaType);
    }
    let body = to_bytes(request.into_body(), MAX_REQUEST_BYTES)
        .await
        .map_err(|_| ApiError::TooLarge)?;
    serde_json::from_slice(&body).map_err(|_| ApiError::InvalidRequest)
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|value| {
        let mut parts = value.split(';');
        if !parts
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
        {
            return false;
        }
        let Some(parameter) = parts.next() else {
            return true;
        };
        parts.next().is_none()
            && parameter
                .trim()
                .split_once('=')
                .is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("charset")
                        && value.trim().eq_ignore_ascii_case("utf-8")
                })
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewDocument {
    decision: ReviewDecisionDocument,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReviewDecisionDocument {
    Approve,
    Reject,
}

impl From<ReviewDecisionDocument> for EnvironmentReviewDecision {
    fn from(value: ReviewDecisionDocument) -> Self {
        match value {
            ReviewDecisionDocument::Approve => Self::Approve,
            ReviewDecisionDocument::Reject => Self::Reject,
        }
    }
}

fn success_response(state: JobEnvironmentGateState) -> Response {
    json_response(
        StatusCode::OK,
        &ReviewResponseDocument {
            state: state_name(state),
        },
    )
}

const fn state_name(state: JobEnvironmentGateState) -> &'static str {
    match state {
        JobEnvironmentGateState::Waiting => "waiting",
        JobEnvironmentGateState::Resolving => "resolving",
        JobEnvironmentGateState::Ready => "ready",
        JobEnvironmentGateState::Rejected => "rejected",
        JobEnvironmentGateState::Expired => "expired",
        JobEnvironmentGateState::Cancelled => "cancelled",
    }
}

#[derive(Debug, Serialize)]
struct ReviewResponseDocument {
    state: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorDocument {
    error: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    InvalidRequest,
    UnsupportedMediaType,
    TooLarge,
    Conflict,
    Unavailable,
    Internal,
}

impl From<ProtectedEnvironmentReviewApiBackendError> for ApiError {
    fn from(value: ProtectedEnvironmentReviewApiBackendError) -> Self {
        match value {
            ProtectedEnvironmentReviewApiBackendError::Forbidden => Self::Forbidden,
            ProtectedEnvironmentReviewApiBackendError::NotFound => Self::NotFound,
            ProtectedEnvironmentReviewApiBackendError::Conflict => Self::Conflict,
            ProtectedEnvironmentReviewApiBackendError::Unavailable => Self::Unavailable,
            ProtectedEnvironmentReviewApiBackendError::Invariant => Self::Internal,
        }
    }
}

impl ApiError {
    const fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::TooLarge => "request_too_large",
            Self::Conflict => "conflict",
            Self::Unavailable => "dependency_unavailable",
            Self::Internal => "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = json_response(self.status(), &ErrorDocument { error: self.code() });
        if self == Self::Unauthorized {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"automata\""),
            );
        }
        if self == Self::Unavailable {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

fn json_response<T: Serialize>(status: StatusCode, document: &T) -> Response {
    match serde_json::to_vec(document) {
        Ok(body) => (
            status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            br#"{"error":"internal_error"}"#.as_slice(),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Mutex};

    use automata_ci_auth::{
        authorization::AuthorizationContext,
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
        request_auth::ViewerDisplayMetadata,
        session::{DurableSession, DurableSessionIdentity, SessionId},
        time::UnixTimestamp,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, header},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::*;

    const REPOSITORY_ID: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const ATTEMPT_ID: &str = "22222222-2222-4222-8222-222222222222";
    const PATH: &str = "/api/v1/repositories/aaaaaaaa-1111-4111-8111-111111111111/attempts/22222222-2222-4222-8222-222222222222/environment/reviews";

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(777)
        }
    }

    #[derive(Debug)]
    struct RecordingBackend {
        result: Result<JobEnvironmentGateState, ProtectedEnvironmentReviewApiBackendError>,
        requests: Mutex<Vec<ProtectedEnvironmentReviewApiRequest>>,
    }

    #[async_trait]
    impl ProtectedEnvironmentReviewApiBackend for RecordingBackend {
        async fn review(
            &self,
            request: ProtectedEnvironmentReviewApiRequest,
        ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentReviewApiBackendError> {
            self.requests.lock().expect("request lock").push(request);
            self.result
        }
    }

    #[tokio::test]
    async fn cli_review_binds_exact_target_and_returns_typed_state() {
        let backend = Arc::new(RecordingBackend {
            result: Ok(JobEnvironmentGateState::Ready),
            requests: Mutex::new(Vec::new()),
        });
        let response = app(backend.clone())
            .oneshot(request(
                PATH,
                Some(SessionKind::Cli),
                r#"{"decision":"approve"}"#,
            ))
            .await
            .expect("review response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response_json(response).await, json!({"state": "ready"}));
        let requests = backend.requests.lock().expect("request lock");
        let [captured] = requests.as_slice() else {
            panic!("one request expected");
        };
        assert_eq!(
            captured.repository_id().as_uuid().to_string(),
            REPOSITORY_ID
        );
        assert_eq!(captured.attempt_id().as_uuid().to_string(), ATTEMPT_ID);
        assert_eq!(captured.decision(), EnvironmentReviewDecision::Approve);
        assert_eq!(captured.actor().tenant_id().as_str(), "tenant-review-api");
        assert_eq!(
            captured.actor().principal_id().as_str(),
            "55555555-5555-4555-8555-555555555555"
        );
        assert_eq!(
            captured.actor().session_id().as_str(),
            "66666666-6666-4666-8666-666666666666"
        );
        assert_eq!(captured.actor().authorization_revision().value(), 7);
        assert_eq!(captured.actor().now(), UnixTimestamp::from_seconds(777));
    }

    #[tokio::test]
    async fn browser_or_absent_session_never_reaches_backend() {
        for kind in [None, Some(SessionKind::Browser)] {
            let backend = Arc::new(RecordingBackend {
                result: Ok(JobEnvironmentGateState::Waiting),
                requests: Mutex::new(Vec::new()),
            });
            let response = app(backend.clone())
                .oneshot(request(PATH, kind, r#"{"decision":"reject"}"#))
                .await
                .expect("review response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(backend.requests.lock().expect("request lock").is_empty());
        }
    }

    #[tokio::test]
    async fn malformed_targets_documents_and_encodings_are_bounded() {
        let query_path = format!("{PATH}?decision=approve");
        for (uri, content_type, encoding, body, expected) in [
            (
                query_path.as_str(),
                "application/json",
                None,
                r#"{"decision":"approve"}"#.to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH,
                "text/plain",
                None,
                r#"{"decision":"approve"}"#.to_owned(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                PATH,
                "application/json",
                Some("gzip"),
                r#"{"decision":"approve"}"#.to_owned(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                PATH,
                "application/json",
                None,
                r#"{"decision":"approve","extra":true}"#.to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH,
                "application/json",
                None,
                "x".repeat(MAX_REQUEST_BYTES + 1),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let backend = Arc::new(RecordingBackend {
                result: Ok(JobEnvironmentGateState::Waiting),
                requests: Mutex::new(Vec::new()),
            });
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, content_type)
                .extension(snapshot(SessionKind::Cli));
            if let Some(encoding) = encoding {
                builder = builder.header(header::CONTENT_ENCODING, encoding);
            }
            let response = app(backend.clone())
                .oneshot(builder.body(Body::from(body)).expect("request"))
                .await
                .expect("review response");
            assert_eq!(response.status(), expected);
            assert!(backend.requests.lock().expect("request lock").is_empty());
        }
    }

    #[tokio::test]
    async fn backend_failures_have_closed_sanitized_codes() {
        for (error, status, code) in [
            (
                ProtectedEnvironmentReviewApiBackendError::Forbidden,
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                ProtectedEnvironmentReviewApiBackendError::NotFound,
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                ProtectedEnvironmentReviewApiBackendError::Conflict,
                StatusCode::CONFLICT,
                "conflict",
            ),
            (
                ProtectedEnvironmentReviewApiBackendError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
            ),
            (
                ProtectedEnvironmentReviewApiBackendError::Invariant,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ] {
            let backend = Arc::new(RecordingBackend {
                result: Err(error),
                requests: Mutex::new(Vec::new()),
            });
            let response = app(backend)
                .oneshot(request(
                    PATH,
                    Some(SessionKind::Cli),
                    r#"{"decision":"approve"}"#,
                ))
                .await
                .expect("review response");
            assert_eq!(response.status(), status);
            assert_eq!(response_json(response).await, json!({"error": code}));
        }
    }

    fn app(backend: Arc<RecordingBackend>) -> Router {
        protected_environment_review_api_router(backend, Arc::new(FixedClock))
    }

    fn request(uri: &str, kind: Option<SessionKind>, body: &str) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(kind) = kind {
            builder = builder.extension(snapshot(kind));
        }
        builder.body(Body::from(body.to_owned())).expect("request")
    }

    fn snapshot(kind: SessionKind) -> AuthenticatedRequestSnapshot {
        let tenant = TenantId::new("tenant-review-api").expect("tenant");
        let principal =
            PrincipalId::new("55555555-5555-4555-8555-555555555555").expect("principal");
        let provider = ProviderId::new("neutral-provider").expect("provider");
        let subject = ProviderSubject::new("neutral-subject").expect("subject");
        let identity = DurableSessionIdentity::new(
            SessionId::new("66666666-6666-4666-8666-666666666666").expect("session"),
            tenant.clone(),
            principal.clone(),
            provider.clone(),
            subject.clone(),
            kind,
        )
        .expect("identity");
        let session = DurableSession::new(
            identity,
            7,
            UnixTimestamp::from_seconds(1),
            UnixTimestamp::from_seconds(2),
            UnixTimestamp::from_seconds(900),
            UnixTimestamp::from_seconds(1_000),
            None,
        )
        .expect("session");
        let human = AuthenticatedHuman::new(
            principal.clone(),
            provider,
            subject,
            "neutral-user",
            Some("Neutral User".to_owned()),
            UnixTimestamp::from_seconds(1),
        )
        .expect("human");
        let authorization =
            AuthorizationContext::authenticated_at_revision(tenant, principal, BTreeSet::new(), 7)
                .expect("authorization");
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("Neutral User").expect("viewer"),
            authorization,
        )
        .expect("snapshot")
    }

    async fn response_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), 16 * 1_024)
            .await
            .expect("response body");
        serde_json::from_slice(&body).expect("response JSON")
    }
}
