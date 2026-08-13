//! Authenticated HTTP boundary for durable CLI and browser workflow reruns.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::{
    management::{ManagementActor, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::Clock,
};
use automata_ci_core::{OperationId, RunId};
use automata_ci_store::{LogicalWorkflowJobId, WorkflowRerunSelection};
use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, Visitor},
};
use uuid::Uuid;

const MAX_REQUEST_BYTES: usize = 8 * 1_024;
const MAX_REPOSITORY_SEGMENT_BYTES: usize = 100;

// foundation-governance: derived-contract owner=workflow kind=wire-discriminator
pub(crate) const WORKFLOW_RERUN_PATH: &str =
    "/api/v1/repositories/{owner}/{repository}/runs/{source_run_id}/reruns";
pub(crate) const WORKFLOW_BROWSER_RERUN_PATH: &str =
    "/{owner}/{repository}/actions/runs/{source_run_id}/reruns";

/// Exact authority-bearing rerun request passed to product composition.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WorkflowRerunApiRequest {
    actor: ManagementActor,
    repository_owner: String,
    repository_name: String,
    source_run_id: RunId,
    selection: WorkflowRerunSelection,
    operation_id: OperationId,
}

impl fmt::Debug for WorkflowRerunApiRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowRerunApiRequest")
            .field("repository_owner", &self.repository_owner)
            .field("repository_name", &self.repository_name)
            .field("source_run_id", &self.source_run_id)
            .field("selection", &self.selection)
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

impl WorkflowRerunApiRequest {
    pub(crate) const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    pub(crate) fn repository_owner(&self) -> &str {
        &self.repository_owner
    }

    pub(crate) fn repository_name(&self) -> &str {
        &self.repository_name
    }

    pub(crate) const fn source_run_id(&self) -> RunId {
        self.source_run_id
    }

    pub(crate) const fn selection(&self) -> WorkflowRerunSelection {
        self.selection
    }

    pub(crate) const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

/// Validated successful product outcome rendered by the HTTP adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowRerunApiOutcome {
    source_run_id: RunId,
    run_id: RunId,
    public_run_id: u64,
    run_number: u64,
    run_attempt: u32,
    replay: bool,
}

impl WorkflowRerunApiOutcome {
    pub(crate) fn new(
        source_run_id: RunId,
        run_id: RunId,
        public_run_id: u64,
        run_number: u64,
        run_attempt: u32,
        replay: bool,
    ) -> Result<Self, WorkflowRerunApiBackendError> {
        if source_run_id.as_uuid().is_nil()
            || run_id.as_uuid().is_nil()
            || public_run_id == 0
            || run_number == 0
            || run_attempt == 0
        {
            return Err(WorkflowRerunApiBackendError::Invariant);
        }
        Ok(Self {
            source_run_id,
            run_id,
            public_run_id,
            run_number,
            run_attempt,
            replay,
        })
    }

    pub(crate) const fn source_run_id(self) -> RunId {
        self.source_run_id
    }

    pub(crate) const fn run_id(self) -> RunId {
        self.run_id
    }

    pub(crate) const fn public_run_id(self) -> u64 {
        self.public_run_id
    }

    pub(crate) const fn run_number(self) -> u64 {
        self.run_number
    }

    pub(crate) const fn run_attempt(self) -> u32 {
        self.run_attempt
    }

    pub(crate) const fn is_replay(self) -> bool {
        self.replay
    }
}

/// Closed, sanitized workflow-rerun failures exposed by product composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowRerunApiBackendError {
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Invariant,
}

/// Product composition boundary behind the CLI HTTP adapter.
#[async_trait]
pub(crate) trait WorkflowRerunApiBackend: fmt::Debug + Send + Sync {
    async fn rerun(
        &self,
        request: WorkflowRerunApiRequest,
    ) -> Result<WorkflowRerunApiOutcome, WorkflowRerunApiBackendError>;
}

#[derive(Clone)]
struct WorkflowRerunApiState {
    backend: Arc<dyn WorkflowRerunApiBackend>,
    clock: Arc<dyn Clock>,
}

/// Builds the isolated CLI-authenticated workflow-rerun route.
pub(crate) fn workflow_rerun_api_router(
    backend: Arc<dyn WorkflowRerunApiBackend>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(WORKFLOW_RERUN_PATH, post(rerun_workflow))
        .route(WORKFLOW_BROWSER_RERUN_PATH, post(rerun_workflow))
        .with_state(WorkflowRerunApiState { backend, clock })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn rerun_workflow(
    State(state): State<WorkflowRerunApiState>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let rerun = match prepare_request(&state, path, request).await {
        Ok(rerun) => rerun,
        Err(error) => return error.into_response(),
    };
    match state.backend.rerun(rerun).await {
        Ok(outcome) => success_response(outcome),
        Err(error) => ApiError::from(error).into_response(),
    }
}

async fn prepare_request(
    state: &WorkflowRerunApiState,
    path: Result<Path<(String, String, String)>, PathRejection>,
    request: Request,
) -> Result<WorkflowRerunApiRequest, ApiError> {
    if request.uri().query().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let (repository_owner, repository_name, source_run_id) = exact_target(path)?;
    let actor = actor_from_request(state, &request)?;
    let document = json_document(request).await?;
    let operation_id = OperationId::from_uuid(document.operation_id);
    if operation_id.as_uuid().is_nil() {
        return Err(ApiError::InvalidRequest);
    }
    Ok(WorkflowRerunApiRequest {
        actor,
        repository_owner,
        repository_name,
        source_run_id,
        selection: document.selection.0,
        operation_id,
    })
}

fn exact_target(
    path: Result<Path<(String, String, String)>, PathRejection>,
) -> Result<(String, String, RunId), ApiError> {
    let Path((owner, repository, source_run_id)) = path.map_err(|_| ApiError::InvalidRequest)?;
    Ok((
        repository_segment(owner)?,
        repository_segment(repository)?,
        RunId::from_uuid(canonical_uuid(&source_run_id)?),
    ))
}

fn repository_segment(value: String) -> Result<String, ApiError> {
    if value.is_empty()
        || matches!(value.as_str(), "." | "..")
        || value.len() > MAX_REPOSITORY_SEGMENT_BYTES
        || value.contains('/')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(value)
}

fn canonical_uuid(value: &str) -> Result<Uuid, ApiError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(ApiError::InvalidRequest);
    }
    Ok(parsed)
}

fn actor_from_request(
    state: &WorkflowRerunApiState,
    request: &Request,
) -> Result<ManagementActor, ApiError> {
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .ok_or(ApiError::Unauthorized)?;
    let identity = snapshot.session().identity();
    let route_kind_is_exact = match identity.kind() {
        SessionKind::Cli => request.uri().path().starts_with("/api/v1/"),
        SessionKind::Browser => request.uri().path().contains("/actions/runs/"),
    };
    if !route_kind_is_exact {
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

async fn json_document(request: Request) -> Result<RerunDocument, ApiError> {
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
struct RerunDocument {
    #[serde(deserialize_with = "deserialize_canonical_uuid")]
    operation_id: Uuid,
    selection: SelectionDocument,
}

fn deserialize_canonical_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let parsed = Uuid::parse_str(&value).map_err(|_| D::Error::custom("invalid canonical UUID"))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(D::Error::custom("invalid canonical UUID"));
    }
    Ok(parsed)
}

#[derive(Debug)]
struct SelectionDocument(WorkflowRerunSelection);

impl<'de> Deserialize<'de> for SelectionDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SelectionVisitor;

        impl<'de> Visitor<'de> for SelectionVisitor {
            type Value = SelectionDocument;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an exact workflow rerun selection")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut mode: Option<String> = None;
                let mut logical_job_id: Option<Uuid> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "mode" if mode.is_none() => mode = Some(map.next_value()?),
                        "logical_job_id" if logical_job_id.is_none() => {
                            logical_job_id = Some(map.next_value::<CanonicalUuid>()?.0);
                        }
                        "mode" => return Err(M::Error::duplicate_field("mode")),
                        "logical_job_id" => {
                            return Err(M::Error::duplicate_field("logical_job_id"));
                        }
                        _ => {
                            return Err(M::Error::unknown_field(&key, &["mode", "logical_job_id"]));
                        }
                    }
                }
                let mode = mode.ok_or_else(|| M::Error::missing_field("mode"))?;
                let selection = match (mode.as_str(), logical_job_id) {
                    ("entire_workflow", None) => WorkflowRerunSelection::EntireWorkflow,
                    ("failed_jobs_and_dependents", None) => {
                        WorkflowRerunSelection::FailedJobsAndDependents
                    }
                    ("job_and_dependents", Some(job_id)) => {
                        WorkflowRerunSelection::JobAndDependents(
                            LogicalWorkflowJobId::from_uuid(job_id)
                                .map_err(|_| M::Error::custom("invalid logical job ID"))?,
                        )
                    }
                    _ => return Err(M::Error::custom("invalid workflow rerun selection")),
                };
                Ok(SelectionDocument(selection))
            }
        }

        deserializer.deserialize_map(SelectionVisitor)
    }
}

struct CanonicalUuid(Uuid);

impl<'de> Deserialize<'de> for CanonicalUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_canonical_uuid(deserializer).map(Self)
    }
}

fn success_response(outcome: WorkflowRerunApiOutcome) -> Response {
    json_response(
        if outcome.is_replay() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        &RerunResponseDocument {
            source_run_id: outcome.source_run_id().as_uuid(),
            run_id: outcome.run_id().as_uuid(),
            public_run_id: outcome.public_run_id(),
            run_number: outcome.run_number(),
            run_attempt: outcome.run_attempt(),
            replay: outcome.is_replay(),
        },
    )
}

#[derive(Debug, Serialize)]
struct RerunResponseDocument {
    source_run_id: Uuid,
    run_id: Uuid,
    public_run_id: u64,
    run_number: u64,
    run_attempt: u32,
    replay: bool,
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

impl From<WorkflowRerunApiBackendError> for ApiError {
    fn from(value: WorkflowRerunApiBackendError) -> Self {
        match value {
            WorkflowRerunApiBackendError::Forbidden => Self::Forbidden,
            WorkflowRerunApiBackendError::NotFound => Self::NotFound,
            WorkflowRerunApiBackendError::Conflict => Self::Conflict,
            WorkflowRerunApiBackendError::Unavailable => Self::Unavailable,
            WorkflowRerunApiBackendError::Invariant => Self::Internal,
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
        http::{Method, Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;

    use super::*;

    const REPOSITORY_OWNER: &str = "automata-ci";
    const REPOSITORY_NAME: &str = "automata";
    const SOURCE_RUN_ID: &str = "22222222-2222-4222-8222-222222222222";
    const OPERATION_ID: &str = "33333333-3333-4333-8333-333333333333";
    const RUN_ID: &str = "44444444-4444-4444-8444-444444444444";
    const LOGICAL_JOB_ID: &str = "77777777-7777-4777-8777-777777777777";
    const PATH: &str = "/api/v1/repositories/automata-ci/automata/runs/22222222-2222-4222-8222-222222222222/reruns";
    const BROWSER_PATH: &str =
        "/automata-ci/automata/actions/runs/22222222-2222-4222-8222-222222222222/reruns";

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(777)
        }
    }

    #[derive(Debug)]
    struct RecordingBackend {
        result: Result<WorkflowRerunApiOutcome, WorkflowRerunApiBackendError>,
        requests: Mutex<Vec<WorkflowRerunApiRequest>>,
    }

    impl RecordingBackend {
        fn success(replay: bool) -> Arc<Self> {
            Arc::new(Self {
                result: WorkflowRerunApiOutcome::new(
                    RunId::from_uuid(Uuid::parse_str(SOURCE_RUN_ID).expect("source run")),
                    RunId::from_uuid(Uuid::parse_str(RUN_ID).expect("run")),
                    41,
                    17,
                    2,
                    replay,
                ),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn failure(error: WorkflowRerunApiBackendError) -> Arc<Self> {
            Arc::new(Self {
                result: Err(error),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl WorkflowRerunApiBackend for RecordingBackend {
        async fn rerun(
            &self,
            request: WorkflowRerunApiRequest,
        ) -> Result<WorkflowRerunApiOutcome, WorkflowRerunApiBackendError> {
            self.requests.lock().expect("request lock").push(request);
            self.result
        }
    }

    #[tokio::test]
    async fn cli_request_admits_exact_selection_and_returns_created() {
        let backend = RecordingBackend::success(false);
        let response = app(backend.clone())
            .oneshot(request(PATH, Some(SessionKind::Cli), valid_body()))
            .await
            .expect("rerun response");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response_json(response).await,
            json!({
                "source_run_id": SOURCE_RUN_ID, "run_id": RUN_ID,
                "public_run_id": 41, "run_number": 17, "run_attempt": 2,
                "replay": false
            })
        );
        let requests = backend.requests.lock().expect("request lock");
        let [captured] = requests.as_slice() else {
            panic!("one request expected");
        };
        assert_eq!(captured.repository_owner(), REPOSITORY_OWNER);
        assert_eq!(captured.repository_name(), REPOSITORY_NAME);
        assert_eq!(
            captured.source_run_id().as_uuid().to_string(),
            SOURCE_RUN_ID
        );
        assert_eq!(captured.operation_id().to_string(), OPERATION_ID);
        assert_eq!(captured.selection(), WorkflowRerunSelection::EntireWorkflow);
        assert_eq!(captured.actor().now(), UnixTimestamp::from_seconds(777));
        let debug = format!("{captured:?}");
        assert!(!debug.contains("tenant-rerun-api"));
    }

    #[tokio::test]
    async fn exact_replay_returns_ok() {
        let response = app(RecordingBackend::success(true))
            .oneshot(request(PATH, Some(SessionKind::Cli), valid_body()))
            .await
            .expect("replay response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["replay"], true);
    }

    #[tokio::test]
    async fn browser_route_uses_the_same_durable_backend() {
        let backend = RecordingBackend::success(false);
        let response = app(backend.clone())
            .oneshot(request(
                BROWSER_PATH,
                Some(SessionKind::Browser),
                valid_body(),
            ))
            .await
            .expect("browser rerun response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(backend.requests.lock().expect("request lock").len(), 1);
    }

    #[tokio::test]
    async fn missing_and_browser_sessions_are_rejected() {
        for kind in [None, Some(SessionKind::Browser)] {
            let backend = RecordingBackend::success(false);
            let response = app(backend.clone())
                .oneshot(request(PATH, kind, valid_body()))
                .await
                .expect("auth response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                "Bearer realm=\"automata\""
            );
            assert!(backend.requests.lock().expect("request lock").is_empty());
        }
    }

    #[tokio::test]
    async fn strict_selection_rejects_unknown_duplicate_and_inconsistent_fields() {
        let invalid = [
            format!(
                r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"entire_workflow","mode":"failed_jobs_and_dependents"}}}}"#
            ),
            format!(
                r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"job_and_dependents","logical_job_id":"{LOGICAL_JOB_ID}","logical_job_id":"{LOGICAL_JOB_ID}"}}}}"#
            ),
            format!(
                r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"entire_workflow","logical_job_id":"{LOGICAL_JOB_ID}"}}}}"#
            ),
            format!(
                r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"job_and_dependents"}}}}"#
            ),
            format!(r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"unknown"}}}}"#),
            r#"{"operation_id":"AAAAAAAA-1111-4111-8111-111111111111","selection":{"mode":"entire_workflow"}}"#
                .to_owned(),
            format!(
                r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"job_and_dependents","logical_job_id":"{}"}}}}"#,
                LOGICAL_JOB_ID.replace('-', "")
            ),
            format!(
                r#"{{"operation_id":"{{{OPERATION_ID}}}","selection":{{"mode":"entire_workflow"}}}}"#
            ),
            format!(
                r#"{{"operation_id":"{OPERATION_ID}","selection":{{"mode":"entire_workflow"}},"actor":"forged"}}"#
            ),
        ];
        for body in invalid {
            let backend = RecordingBackend::success(false);
            let response = app(backend.clone())
                .oneshot(request(PATH, Some(SessionKind::Cli), Body::from(body)))
                .await
                .expect("validation response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(backend.requests.lock().expect("request lock").is_empty());
        }
    }

    #[tokio::test]
    async fn every_supported_selection_reaches_the_backend() {
        for (selection, expected) in [
            (
                json!({"mode": "failed_jobs_and_dependents"}),
                WorkflowRerunSelection::FailedJobsAndDependents,
            ),
            (
                json!({"mode": "job_and_dependents", "logical_job_id": LOGICAL_JOB_ID}),
                WorkflowRerunSelection::JobAndDependents(
                    LogicalWorkflowJobId::from_uuid(Uuid::parse_str(LOGICAL_JOB_ID).expect("job"))
                        .expect("logical job"),
                ),
            ),
        ] {
            let backend = RecordingBackend::success(false);
            let body = Body::from(
                json!({"operation_id": OPERATION_ID, "selection": selection}).to_string(),
            );
            let response = app(backend.clone())
                .oneshot(request(PATH, Some(SessionKind::Cli), body))
                .await
                .expect("selection response");
            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(
                backend.requests.lock().expect("request lock")[0].selection(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn transport_and_target_bounds_fail_closed() {
        let encoded_slash = PATH.replace("/automata-ci/", "/automata%2Fci/");
        let encoded_control = PATH.replace("/automata/", "/auto%0Amata/");
        let oversized = PATH.replace(
            "/automata-ci/",
            &format!("/{}/", "a".repeat(MAX_REPOSITORY_SEGMENT_BYTES + 1)),
        );
        let cases = [
            (
                format!("{PATH}?selection=forged"),
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                encoded_slash,
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                encoded_control,
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                oversized,
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH.replace(SOURCE_RUN_ID, "not-a-run"),
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH.to_owned(),
                "text/plain",
                valid_body(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                PATH.to_owned(),
                "application/json",
                Body::from(vec![b'x'; MAX_REQUEST_BYTES + 1]),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ];
        for (uri, content_type, body, expected) in cases {
            let backend = RecordingBackend::success(false);
            let response = app_with_content_type(
                backend.clone(),
                &uri,
                Some(SessionKind::Cli),
                content_type,
                body,
            )
            .oneshot_request()
            .await;
            assert_eq!(response.status(), expected);
            assert!(backend.requests.lock().expect("request lock").is_empty());
        }
    }

    #[tokio::test]
    async fn content_encoding_is_rejected_before_body_parsing() {
        let backend = RecordingBackend::success(false);
        let mut encoded = request(PATH, Some(SessionKind::Cli), valid_body());
        encoded.headers_mut().insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );

        let response = app(backend.clone())
            .oneshot(encoded)
            .await
            .expect("encoded request response");

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(backend.requests.lock().expect("request lock").is_empty());
    }

    #[tokio::test]
    async fn valid_authenticated_backend_failures_are_closed_and_only_unavailable_retries() {
        for (error, status, code) in [
            (
                WorkflowRerunApiBackendError::Forbidden,
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                WorkflowRerunApiBackendError::NotFound,
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                WorkflowRerunApiBackendError::Conflict,
                StatusCode::CONFLICT,
                "conflict",
            ),
            (
                WorkflowRerunApiBackendError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
            ),
            (
                WorkflowRerunApiBackendError::Invariant,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ] {
            let backend = RecordingBackend::failure(error);
            let response = app(backend.clone())
                .oneshot(request(PATH, Some(SessionKind::Cli), valid_body()))
                .await
                .expect("backend response");
            assert_eq!(response.status(), status);
            assert_eq!(backend.requests.lock().expect("request lock").len(), 1);
            if error == WorkflowRerunApiBackendError::Unavailable {
                assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            } else {
                assert!(!response.headers().contains_key(header::RETRY_AFTER));
            }
            assert_eq!(response_json(response).await, json!({"error": code}));
        }
    }

    fn app(backend: Arc<RecordingBackend>) -> Router {
        workflow_rerun_api_router(backend, Arc::new(FixedClock))
    }

    fn request(uri: &str, kind: Option<SessionKind>, body: Body) -> Request<Body> {
        raw_request(uri, kind, "application/json", body)
    }

    fn raw_request(
        uri: &str,
        kind: Option<SessionKind>,
        content_type: &str,
        body: Body,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type);
        if let Some(kind) = kind {
            request = request.extension(snapshot(kind));
        }
        request.body(body).expect("HTTP request")
    }

    struct PendingRequest {
        app: Router,
        request: Request<Body>,
    }

    impl PendingRequest {
        async fn oneshot_request(self) -> Response {
            self.app.oneshot(self.request).await.expect("HTTP response")
        }
    }

    fn app_with_content_type(
        backend: Arc<RecordingBackend>,
        uri: &str,
        kind: Option<SessionKind>,
        content_type: &str,
        body: Body,
    ) -> PendingRequest {
        PendingRequest {
            app: app(backend),
            request: raw_request(uri, kind, content_type, body),
        }
    }

    fn valid_body() -> Body {
        Body::from(
            json!({
                "operation_id": OPERATION_ID,
                "selection": {"mode": "entire_workflow"}
            })
            .to_string(),
        )
    }

    fn snapshot(kind: SessionKind) -> AuthenticatedRequestSnapshot {
        let tenant = TenantId::new("tenant-rerun-api").expect("tenant");
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
