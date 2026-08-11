//! CLI-authenticated HTTP boundary for exact manual workflow dispatch.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::{
    management::{ManagementActor, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::Clock,
};
use automata_ci_core::{OperationId, RunId, WorkflowId, WorkflowInputKey};
use automata_ci_store::RepositoryId;
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

const MAX_REQUEST_BYTES: usize = 128 * 1_024;
const MAX_TARGET_TEXT_BYTES: usize = 1_024;
const MAX_INPUTS: usize = 25;
const MAX_INPUT_CHARACTERS: usize = 65_535;

pub(crate) const WORKFLOW_DISPATCH_PATH: &str =
    "/api/v1/repositories/{repository_id}/workflows/{workflow_id}/dispatches";

/// Exact, authority-bearing request passed from HTTP to product composition.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WorkflowDispatchApiRequest {
    actor: ManagementActor,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
    git_ref: String,
    commit_sha: String,
    operation_id: OperationId,
    inputs: BTreeMap<WorkflowInputKey, WorkflowDispatchApiInputValue>,
}

impl fmt::Debug for WorkflowDispatchApiRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowDispatchApiRequest")
            .field("actor", &self.actor)
            .field("repository_id", &self.repository_id)
            .field("workflow_id", &self.workflow_id)
            .field("git_ref", &self.git_ref)
            .field("commit_sha", &self.commit_sha)
            .field("operation_id", &self.operation_id)
            .field("input_count", &self.inputs.len())
            .finish()
    }
}

/// One type-preserving manual-dispatch input admitted from JSON.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum WorkflowDispatchApiInputValue {
    Boolean(bool),
    String(String),
}

impl fmt::Debug for WorkflowDispatchApiInputValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(_) => formatter.write_str("Boolean([REDACTED])"),
            Self::String(value) => formatter
                .debug_tuple("String")
                .field(&format_args!("{} chars [REDACTED]", value.chars().count()))
                .finish(),
        }
    }
}

impl WorkflowDispatchApiInputValue {
    fn character_count(&self) -> usize {
        match self {
            Self::Boolean(true) => "true".len(),
            Self::Boolean(false) => "false".len(),
            Self::String(value) => value.chars().count(),
        }
    }
}

impl WorkflowDispatchApiRequest {
    pub(crate) const fn actor(&self) -> &ManagementActor {
        &self.actor
    }

    pub(crate) const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    pub(crate) const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    pub(crate) fn git_ref(&self) -> &str {
        &self.git_ref
    }

    pub(crate) fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    pub(crate) const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub(crate) const fn inputs(
        &self,
    ) -> &BTreeMap<WorkflowInputKey, WorkflowDispatchApiInputValue> {
        &self.inputs
    }
}

/// Validated successful product outcome rendered by the HTTP adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowDispatchApiOutcome {
    run_id: RunId,
    run_number: u64,
    replay: bool,
}

impl WorkflowDispatchApiOutcome {
    pub(crate) fn new(
        run_id: RunId,
        run_number: u64,
        replay: bool,
    ) -> Result<Self, WorkflowDispatchApiBackendError> {
        if run_id.as_uuid().is_nil() || run_number == 0 {
            return Err(WorkflowDispatchApiBackendError::Invariant);
        }
        Ok(Self {
            run_id,
            run_number,
            replay,
        })
    }

    pub(crate) const fn run_id(self) -> RunId {
        self.run_id
    }

    pub(crate) const fn run_number(self) -> u64 {
        self.run_number
    }

    pub(crate) const fn is_replay(self) -> bool {
        self.replay
    }
}

/// Closed, sanitized dispatch failures exposed by product composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowDispatchApiBackendError {
    InvalidRequest,
    NotFound,
    Forbidden,
    Conflict,
    Unavailable,
    Invariant,
}

/// Product composition boundary behind the CLI HTTP adapter.
#[async_trait]
pub(crate) trait WorkflowDispatchApiBackend: fmt::Debug + Send + Sync {
    async fn dispatch(
        &self,
        request: WorkflowDispatchApiRequest,
    ) -> Result<WorkflowDispatchApiOutcome, WorkflowDispatchApiBackendError>;
}

#[derive(Clone)]
struct WorkflowDispatchApiState {
    backend: Arc<dyn WorkflowDispatchApiBackend>,
    clock: Arc<dyn Clock>,
}

/// Builds the isolated CLI-authenticated manual-dispatch route.
pub(crate) fn workflow_dispatch_api_router(
    backend: Arc<dyn WorkflowDispatchApiBackend>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(WORKFLOW_DISPATCH_PATH, post(dispatch_workflow))
        .with_state(WorkflowDispatchApiState { backend, clock })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn dispatch_workflow(
    State(state): State<WorkflowDispatchApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let result = prepare_request(&state, path, request).await;
    let dispatch = match result {
        Ok(dispatch) => dispatch,
        Err(error) => return error.into_response(),
    };
    match state.backend.dispatch(dispatch).await {
        Ok(outcome) => success_response(outcome),
        Err(error) => ApiError::from(error).into_response(),
    }
}

async fn prepare_request(
    state: &WorkflowDispatchApiState,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Result<WorkflowDispatchApiRequest, ApiError> {
    if request.uri().query().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let (repository_id, workflow_id) = exact_target(path)?;
    let actor = actor_from_request(state, &request)?;
    let document = json_document(request).await?;
    let operation_id = OperationId::from_uuid(document.operation_id);
    if operation_id.as_uuid().is_nil()
        || !valid_git_ref(&document.git_ref)
        || !valid_commit_sha(&document.commit_sha)
    {
        return Err(ApiError::InvalidRequest);
    }
    let inputs = validated_inputs(document.inputs)?;
    Ok(WorkflowDispatchApiRequest {
        actor,
        repository_id,
        workflow_id,
        git_ref: document.git_ref,
        commit_sha: document.commit_sha,
        operation_id,
        inputs,
    })
}

fn validated_inputs(
    inputs: DispatchInputsDocument,
) -> Result<BTreeMap<WorkflowInputKey, WorkflowDispatchApiInputValue>, ApiError> {
    let inputs = inputs.0;
    if inputs.len() > MAX_INPUTS {
        return Err(ApiError::InvalidRequest);
    }
    let mut characters = 0_usize;
    inputs
        .into_iter()
        .map(|(key, value)| {
            let key = WorkflowInputKey::new(key).map_err(|_| ApiError::InvalidRequest)?;
            let value = value.into_dispatch_value();
            characters = characters
                .checked_add(key.as_str().chars().count())
                .and_then(|count| count.checked_add(value.character_count()))
                .filter(|count| *count <= MAX_INPUT_CHARACTERS)
                .ok_or(ApiError::InvalidRequest)?;
            Ok((key, value))
        })
        .collect()
}

fn exact_target(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(RepositoryId, WorkflowId), ApiError> {
    let Path((repository_id, workflow_id)) = path.map_err(|_| ApiError::InvalidRequest)?;
    let repository_id = canonical_uuid(&repository_id)?;
    let workflow_id = canonical_uuid(&workflow_id)?;
    Ok((
        RepositoryId::from_uuid(repository_id),
        WorkflowId::from_uuid(workflow_id),
    ))
}

fn canonical_uuid(value: &str) -> Result<Uuid, ApiError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(ApiError::InvalidRequest);
    }
    Ok(parsed)
}

fn actor_from_request(
    state: &WorkflowDispatchApiState,
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

async fn json_document(request: Request) -> Result<DispatchDocument, ApiError> {
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

fn valid_git_ref(value: &str) -> bool {
    valid_text(value)
        && value
            .strip_prefix("refs/")
            .is_some_and(|suffix| !suffix.is_empty())
}

fn valid_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TARGET_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn success_response(outcome: WorkflowDispatchApiOutcome) -> Response {
    json_response(
        if outcome.is_replay() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        &DispatchResponseDocument {
            run_id: outcome.run_id().as_uuid(),
            run_number: outcome.run_number(),
            replay: outcome.is_replay(),
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchDocument {
    git_ref: String,
    commit_sha: String,
    operation_id: Uuid,
    inputs: DispatchInputsDocument,
}

#[derive(Debug)]
struct DispatchInputsDocument(BTreeMap<String, DispatchInputDocument>);

impl<'de> Deserialize<'de> for DispatchInputsDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InputsVisitor;

        impl<'de> Visitor<'de> for InputsVisitor {
            type Value = DispatchInputsDocument;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded map of boolean or string workflow inputs")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut inputs = BTreeMap::new();
                while let Some((key, value)) = map.next_entry()? {
                    if inputs.len() == MAX_INPUTS {
                        return Err(M::Error::custom("too many workflow inputs"));
                    }
                    if inputs.insert(key, value).is_some() {
                        return Err(M::Error::custom("duplicate workflow input"));
                    }
                }
                Ok(DispatchInputsDocument(inputs))
            }
        }

        deserializer.deserialize_map(InputsVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DispatchInputDocument {
    Boolean(bool),
    String(String),
}

impl DispatchInputDocument {
    fn into_dispatch_value(self) -> WorkflowDispatchApiInputValue {
        match self {
            Self::Boolean(value) => WorkflowDispatchApiInputValue::Boolean(value),
            Self::String(value) => WorkflowDispatchApiInputValue::String(value),
        }
    }
}

#[derive(Debug, Serialize)]
struct DispatchResponseDocument {
    run_id: Uuid,
    run_number: u64,
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

impl From<WorkflowDispatchApiBackendError> for ApiError {
    fn from(value: WorkflowDispatchApiBackendError) -> Self {
        match value {
            WorkflowDispatchApiBackendError::InvalidRequest => Self::InvalidRequest,
            WorkflowDispatchApiBackendError::NotFound => Self::NotFound,
            WorkflowDispatchApiBackendError::Forbidden => Self::Forbidden,
            WorkflowDispatchApiBackendError::Conflict => Self::Conflict,
            WorkflowDispatchApiBackendError::Unavailable => Self::Unavailable,
            WorkflowDispatchApiBackendError::Invariant => Self::Internal,
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

    const REPOSITORY_ID: &str = "11111111-1111-4111-8111-111111111111";
    const WORKFLOW_ID: &str = "22222222-2222-4222-8222-222222222222";
    const OPERATION_ID: &str = "33333333-3333-4333-8333-333333333333";
    const RUN_ID: &str = "44444444-4444-4444-8444-444444444444";
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const PATH: &str = "/api/v1/repositories/11111111-1111-4111-8111-111111111111/workflows/22222222-2222-4222-8222-222222222222/dispatches";

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(777)
        }
    }

    #[derive(Debug)]
    struct RecordingBackend {
        result: Result<WorkflowDispatchApiOutcome, WorkflowDispatchApiBackendError>,
        requests: Mutex<Vec<WorkflowDispatchApiRequest>>,
    }

    impl RecordingBackend {
        fn success(replay: bool) -> Arc<Self> {
            Arc::new(Self {
                result: WorkflowDispatchApiOutcome::new(
                    RunId::from_uuid(Uuid::parse_str(RUN_ID).expect("run ID")),
                    17,
                    replay,
                ),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn failure(error: WorkflowDispatchApiBackendError) -> Arc<Self> {
            Arc::new(Self {
                result: Err(error),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<WorkflowDispatchApiRequest> {
            self.requests.lock().expect("request lock").clone()
        }
    }

    #[async_trait]
    impl WorkflowDispatchApiBackend for RecordingBackend {
        async fn dispatch(
            &self,
            request: WorkflowDispatchApiRequest,
        ) -> Result<WorkflowDispatchApiOutcome, WorkflowDispatchApiBackendError> {
            self.requests.lock().expect("request lock").push(request);
            self.result
        }
    }

    #[tokio::test]
    async fn cli_request_admits_only_exact_typed_fields() {
        let backend = RecordingBackend::success(false);
        let response = app(backend.clone())
            .oneshot(request(
                PATH,
                Some(SessionKind::Cli),
                "application/json; charset=utf-8",
                valid_body(),
            ))
            .await
            .expect("dispatch response");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response_json(response).await,
            json!({"run_id": RUN_ID, "run_number": 17, "replay": false})
        );
        let requests = backend.requests();
        let [captured] = requests.as_slice() else {
            panic!("one captured dispatch request expected");
        };
        assert_eq!(
            captured.repository_id().as_uuid().to_string(),
            REPOSITORY_ID
        );
        assert_eq!(captured.workflow_id().as_uuid().to_string(), WORKFLOW_ID);
        assert_eq!(captured.git_ref(), "refs/heads/release");
        assert_eq!(captured.commit_sha(), SHA);
        assert_eq!(captured.operation_id().to_string(), OPERATION_ID);
        assert_eq!(captured.actor().tenant_id().as_str(), "tenant-dispatch-api");
        assert_eq!(captured.actor().now(), UnixTimestamp::from_seconds(777));
        assert!(captured.actor().request_id().is_none());
        let inputs = captured.inputs();
        assert_eq!(
            input(inputs, "target"),
            &WorkflowDispatchApiInputValue::String("live".to_owned())
        );
        assert_eq!(
            input(inputs, "dry_run"),
            &WorkflowDispatchApiInputValue::Boolean(true)
        );
        assert_eq!(
            input(inputs, "note"),
            &WorkflowDispatchApiInputValue::String("neutral fixture".to_owned())
        );
    }

    #[tokio::test]
    async fn replay_is_an_exact_success_document() {
        let backend = RecordingBackend::success(true);
        let response = app(backend)
            .oneshot(request(
                PATH,
                Some(SessionKind::Cli),
                "application/json",
                valid_body(),
            ))
            .await
            .expect("replay response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(response).await,
            json!({"run_id": RUN_ID, "run_number": 17, "replay": true})
        );
    }

    #[tokio::test]
    async fn missing_or_browser_authentication_never_reaches_the_backend() {
        for kind in [None, Some(SessionKind::Browser)] {
            let backend = RecordingBackend::success(false);
            let response = app(backend.clone())
                .oneshot(request(PATH, kind, "application/json", valid_body()))
                .await
                .expect("authentication response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()[header::WWW_AUTHENTICATE],
                "Bearer realm=\"automata\""
            );
            assert!(backend.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn strict_bounded_json_rejects_source_authority_and_untyped_values() {
        let mut invalid_bodies = vec![
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA,
                "operation_id": OPERATION_ID, "inputs": {}, "source": "on: push"
            })
            .to_string(),
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA,
                "operation_id": OPERATION_ID, "inputs": {}, "actor": "forged"
            })
            .to_string(),
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA,
                "operation_id": OPERATION_ID, "inputs": {"count": 3}
            })
            .to_string(),
            json!({
                "git_ref": "release", "commit_sha": SHA,
                "operation_id": OPERATION_ID, "inputs": {}
            })
            .to_string(),
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA.to_uppercase(),
                "operation_id": OPERATION_ID, "inputs": {}
            })
            .to_string(),
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA,
                "operation_id": Uuid::nil(), "inputs": {}
            })
            .to_string(),
            format!(
                "{{\"git_ref\":\"refs/heads/release\",\"commit_sha\":\"{SHA}\",\"operation_id\":\"{OPERATION_ID}\",\"inputs\":{{\"same\":true,\"same\":false}}}}"
            ),
        ];
        let excessive_inputs = (0..=MAX_INPUTS)
            .map(|index| (format!("input_{index}"), json!("value")))
            .collect::<serde_json::Map<_, _>>();
        invalid_bodies.push(
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA,
                "operation_id": OPERATION_ID, "inputs": excessive_inputs
            })
            .to_string(),
        );
        invalid_bodies.push(
            json!({
                "git_ref": "refs/heads/release", "commit_sha": SHA,
                "operation_id": OPERATION_ID,
                "inputs": {"oversized": "x".repeat(MAX_INPUT_CHARACTERS)}
            })
            .to_string(),
        );

        for body in invalid_bodies {
            let backend = RecordingBackend::success(false);
            let response = app(backend.clone())
                .oneshot(request(
                    PATH,
                    Some(SessionKind::Cli),
                    "application/json",
                    Body::from(body),
                ))
                .await
                .expect("validation response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(backend.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn transport_and_target_bounds_fail_closed() {
        let cases = [
            (
                PATH.to_owned(),
                "text/plain",
                valid_body(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                format!("{PATH}?ref=forged"),
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH.replace(REPOSITORY_ID, &Uuid::nil().to_string()),
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH.replace(WORKFLOW_ID, "not-a-workflow-id"),
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
            ),
            (
                PATH.replace(REPOSITORY_ID, &REPOSITORY_ID.to_uppercase()),
                "application/json",
                valid_body(),
                StatusCode::BAD_REQUEST,
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
            let response = app(backend.clone())
                .oneshot(request(&uri, Some(SessionKind::Cli), content_type, body))
                .await
                .expect("bounded response");
            assert_eq!(response.status(), expected, "URI {uri}");
            assert!(backend.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn backend_failures_have_closed_sanitized_statuses() {
        for (error, status, code) in [
            (
                WorkflowDispatchApiBackendError::InvalidRequest,
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                WorkflowDispatchApiBackendError::NotFound,
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                WorkflowDispatchApiBackendError::Forbidden,
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                WorkflowDispatchApiBackendError::Conflict,
                StatusCode::CONFLICT,
                "conflict",
            ),
            (
                WorkflowDispatchApiBackendError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "dependency_unavailable",
            ),
            (
                WorkflowDispatchApiBackendError::Invariant,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ] {
            let backend = RecordingBackend::failure(error);
            let response = app(backend.clone())
                .oneshot(request(
                    PATH,
                    Some(SessionKind::Cli),
                    "application/json",
                    valid_body(),
                ))
                .await
                .expect("backend failure response");
            assert_eq!(response.status(), status);
            if error == WorkflowDispatchApiBackendError::Unavailable {
                assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            }
            assert_eq!(response_json(response).await, json!({"error": code}));
            assert_eq!(backend.requests().len(), 1);
        }
    }

    #[test]
    fn outcomes_reject_impossible_receipts() {
        assert_eq!(
            WorkflowDispatchApiOutcome::new(RunId::from_uuid(Uuid::nil()), 1, false),
            Err(WorkflowDispatchApiBackendError::Invariant)
        );
        assert_eq!(
            WorkflowDispatchApiOutcome::new(
                RunId::from_uuid(Uuid::parse_str(RUN_ID).expect("run ID")),
                0,
                false,
            ),
            Err(WorkflowDispatchApiBackendError::Invariant)
        );
    }

    fn app(backend: Arc<RecordingBackend>) -> Router {
        workflow_dispatch_api_router(backend, Arc::new(FixedClock))
    }

    fn request(
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

    fn valid_body() -> Body {
        Body::from(
            serde_json::to_vec(&json!({
                "git_ref": "refs/heads/release",
                "commit_sha": SHA,
                "operation_id": OPERATION_ID,
                "inputs": {
                    "target": "live",
                    "dry_run": true,
                    "note": "neutral fixture"
                }
            }))
            .expect("request JSON"),
        )
    }

    fn snapshot(kind: SessionKind) -> AuthenticatedRequestSnapshot {
        let tenant = TenantId::new("tenant-dispatch-api").expect("tenant");
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
        .expect("session identity");
        let session = DurableSession::new(
            identity,
            7,
            UnixTimestamp::from_seconds(1),
            UnixTimestamp::from_seconds(2),
            UnixTimestamp::from_seconds(900),
            UnixTimestamp::from_seconds(1_000),
            None,
        )
        .expect("durable session");
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
                .expect("authorization context");
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("Neutral User").expect("viewer"),
            authorization,
        )
        .expect("authenticated snapshot")
    }

    fn input<'a>(
        inputs: &'a BTreeMap<WorkflowInputKey, WorkflowDispatchApiInputValue>,
        key: &str,
    ) -> &'a WorkflowDispatchApiInputValue {
        inputs
            .iter()
            .find_map(|(candidate, value)| (candidate.as_str() == key).then_some(value))
            .expect("input")
    }

    async fn response_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), 16 * 1_024)
            .await
            .expect("response body");
        serde_json::from_slice(&body).expect("response JSON")
    }
}
