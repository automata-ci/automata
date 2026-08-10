//! Explicitly opt-in local workflow admission HTTP boundary.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_core::WorkflowEventProvenance;
use automata_ci_store::{
    LogicalWorkflowAdmissionStoreError, TenantScope, WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_ci_workflow_service::{
    AdmissionRepositoryCoordinates, WorkflowAdmissionError, WorkflowAdmissionRequest,
    WorkflowAdmissionService,
};
use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) const LOCAL_WORKFLOW_ADMISSION_PATH: &str = "/api/v1/local/workflow-runs";
const MAX_WORKFLOW_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 1_024;
const TEXT_FIELD_COUNT: usize = 9;
// JSON may encode one source byte as a six-byte `\u00xx` escape. A valid JSON
// event and every control-free text field expand by at most two bytes per input
// byte when nested as JSON strings. The fixed allowance covers field names,
// quotes, separators, and braces with room to keep the proof independent of
// field-name spelling.
const MAX_REQUEST_BYTES: usize = MAX_WORKFLOW_SOURCE_BYTES * 6
    + MAX_EVENT_BYTES * 2
    + MAX_TEXT_BYTES * TEXT_FIELD_COUNT * 2
    + 1_024;
const MAX_DIAGNOSTIC_CODES: usize = 256;
const MAX_DIAGNOSTIC_CODE_BYTES: usize = 128;
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");

/// Exact local workflow-admission document sent by the administration CLI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWorkflowAdmissionRequest {
    provider_repository_id: String,
    repository_owner: String,
    repository_name: String,
    workflow_path: String,
    workflow_source: String,
    event_json: String,
    event_name: String,
    delivery_id: String,
    commit_sha: String,
    git_ref: String,
    workflow_name: String,
}

impl LocalWorkflowAdmissionRequest {
    /// Creates an exact request. Provider-specific validation remains server-owned.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        provider_repository_id: impl Into<String>,
        repository_owner: impl Into<String>,
        repository_name: impl Into<String>,
        workflow_path: impl Into<String>,
        workflow_source: impl Into<String>,
        event_json: impl Into<String>,
        event_name: impl Into<String>,
        delivery_id: impl Into<String>,
        commit_sha: impl Into<String>,
        git_ref: impl Into<String>,
        workflow_name: impl Into<String>,
    ) -> Self {
        Self {
            provider_repository_id: provider_repository_id.into(),
            repository_owner: repository_owner.into(),
            repository_name: repository_name.into(),
            workflow_path: workflow_path.into(),
            workflow_source: workflow_source.into(),
            event_json: event_json.into(),
            event_name: event_name.into(),
            delivery_id: delivery_id.into(),
            commit_sha: commit_sha.into(),
            git_ref: git_ref.into(),
            workflow_name: workflow_name.into(),
        }
    }

    fn validate(&self) -> Result<(), LocalWorkflowAdmissionError> {
        if self.workflow_source.is_empty() || self.workflow_source.len() > MAX_WORKFLOW_SOURCE_BYTES
        {
            return Err(LocalWorkflowAdmissionError::InvalidRequest);
        }
        if self.event_json.is_empty() || self.event_json.len() > MAX_EVENT_BYTES {
            return Err(LocalWorkflowAdmissionError::InvalidRequest);
        }
        for value in [
            &self.provider_repository_id,
            &self.repository_owner,
            &self.repository_name,
            &self.workflow_path,
            &self.event_name,
            &self.delivery_id,
            &self.commit_sha,
            &self.git_ref,
            &self.workflow_name,
        ] {
            if value.is_empty()
                || value.len() > MAX_TEXT_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(LocalWorkflowAdmissionError::InvalidRequest);
            }
        }
        if !safe_repository_segment(&self.repository_owner)
            || !safe_repository_segment(&self.repository_name)
        {
            return Err(LocalWorkflowAdmissionError::InvalidRequest);
        }
        if serde_json::from_str::<serde_json::Value>(&self.event_json).is_err()
            || !canonical_commit_sha(&self.commit_sha)
            || self.git_ref.strip_prefix("refs/").is_none_or(str::is_empty)
            || AdmissionRepositoryCoordinates::new(
                "github",
                self.provider_repository_id.as_str(),
                self.repository_owner.as_str(),
                self.repository_name.as_str(),
            )
            .is_err()
            || WorkflowAdmissionIdempotency::provider_delivery(self.delivery_id.as_str()).is_err()
        {
            return Err(LocalWorkflowAdmissionError::InvalidRequest);
        }
        Ok(())
    }
}

/// Stable local-admission response suitable for table or JSON CLI output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWorkflowAdmissionResponse {
    run_id: String,
    run_number: u64,
    replayed: bool,
}

impl LocalWorkflowAdmissionResponse {
    /// Constructs a validated response for an admission adapter.
    ///
    /// # Errors
    ///
    /// Rejects a non-UUID run identity or a zero run number.
    pub fn new(
        run_id: impl Into<String>,
        run_number: u64,
        replayed: bool,
    ) -> Result<Self, LocalWorkflowAdmissionResponseError> {
        let run_id = run_id.into();
        let parsed = run_id
            .parse::<automata_ci_core::RunId>()
            .map_err(|_| LocalWorkflowAdmissionResponseError)?;
        if run_number == 0 || parsed.as_uuid().is_nil() || parsed.to_string() != run_id {
            return Err(LocalWorkflowAdmissionResponseError);
        }
        Ok(Self {
            run_id,
            run_number,
            replayed,
        })
    }

    /// Returns the exact durable run identifier.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the positive repository-scoped run number.
    #[must_use]
    pub const fn run_number(&self) -> u64 {
        self.run_number
    }

    /// Reports whether this receipt is an exact replay of prior admission.
    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalWorkflowAdmissionResponseWire {
    run_id: String,
    run_number: u64,
    replayed: bool,
}

impl<'de> Deserialize<'de> for LocalWorkflowAdmissionResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LocalWorkflowAdmissionResponseWire::deserialize(deserializer)?;
        Self::new(wire.run_id, wire.run_number, wire.replayed).map_err(serde::de::Error::custom)
    }
}

/// An admission adapter returned a malformed durable receipt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("local workflow admission response is invalid")]
pub struct LocalWorkflowAdmissionResponseError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Exact sanitized error document returned by the local admission HTTP boundary.
pub struct LocalWorkflowAdmissionErrorDocument {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<Vec<String>>,
}

impl LocalWorkflowAdmissionErrorDocument {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub fn error(&self) -> &str {
        &self.error
    }

    /// Returns at most 256 sorted unique machine codes of at most 128 ASCII bytes each.
    #[must_use]
    pub fn diagnostics(&self) -> &[String] {
        self.diagnostics.as_deref().unwrap_or_default()
    }

    /// Reports whether this is the exact sanitized document for `status`.
    #[must_use]
    pub fn is_current_for_status(&self, status: StatusCode) -> bool {
        self.has_current_shape()
            && matches!(
                (status, self.error.as_str()),
                (StatusCode::BAD_REQUEST, "invalid_request")
                    | (StatusCode::UNAUTHORIZED, "unauthorized")
                    | (StatusCode::CONFLICT, "admission_conflict")
                    | (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed")
                    | (StatusCode::PAYLOAD_TOO_LARGE, "request_too_large")
                    | (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
                    | (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "frontend_rejected" | "compilation_rejected",
                    )
                    | (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                    | (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable")
                    | (StatusCode::GATEWAY_TIMEOUT, "request_timeout")
            )
    }

    fn has_current_shape(&self) -> bool {
        if matches!(
            self.error.as_str(),
            "invalid_request"
                | "unauthorized"
                | "admission_conflict"
                | "method_not_allowed"
                | "request_too_large"
                | "unsupported_media_type"
                | "internal_error"
                | "dependency_unavailable"
                | "request_timeout"
        ) {
            return self.diagnostics.is_none();
        }
        if !matches!(
            self.error.as_str(),
            "frontend_rejected" | "compilation_rejected"
        ) {
            return false;
        }
        let Some(diagnostics) = self.diagnostics.as_deref() else {
            return false;
        };
        !diagnostics.is_empty()
            && diagnostics.len() <= MAX_DIAGNOSTIC_CODES
            && diagnostics
                .iter()
                .all(|code| safe_machine_code(code, MAX_DIAGNOSTIC_CODE_BYTES))
            && diagnostics.windows(2).all(|pair| pair[0] < pair[1])
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalWorkflowAdmissionErrorWire {
    error: String,
    #[serde(default)]
    diagnostics: LocalWorkflowAdmissionDiagnosticsWire,
}

#[derive(Default)]
enum LocalWorkflowAdmissionDiagnosticsWire {
    #[default]
    Missing,
    Present(Vec<String>),
}

impl<'de> Deserialize<'de> for LocalWorkflowAdmissionDiagnosticsWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer
            .deserialize_seq(LocalWorkflowAdmissionDiagnosticsVisitor)
            .map(Self::Present)
    }
}

struct LocalWorkflowAdmissionDiagnosticsVisitor;

impl<'de> serde::de::Visitor<'de> for LocalWorkflowAdmissionDiagnosticsVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a nonempty sorted array of bounded diagnostic codes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > MAX_DIAGNOSTIC_CODES)
        {
            return Err(<A::Error as serde::de::Error>::custom(
                "too many workflow admission diagnostic codes",
            ));
        }
        let mut diagnostics = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or_default()
                .min(MAX_DIAGNOSTIC_CODES),
        );
        while let Some(code) = sequence.next_element::<String>()? {
            if diagnostics.len() == MAX_DIAGNOSTIC_CODES
                || !safe_machine_code(&code, MAX_DIAGNOSTIC_CODE_BYTES)
                || diagnostics.last().is_some_and(|prior| prior >= &code)
            {
                return Err(<A::Error as serde::de::Error>::custom(
                    "invalid workflow admission diagnostic codes",
                ));
            }
            diagnostics.push(code);
        }
        if diagnostics.is_empty() {
            return Err(<A::Error as serde::de::Error>::custom(
                "workflow admission diagnostics cannot be empty",
            ));
        }
        Ok(diagnostics)
    }
}

impl<'de> Deserialize<'de> for LocalWorkflowAdmissionErrorDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = LocalWorkflowAdmissionErrorWire::deserialize(deserializer)?;
        let document = Self {
            error: wire.error,
            diagnostics: match wire.diagnostics {
                LocalWorkflowAdmissionDiagnosticsWire::Missing => None,
                LocalWorkflowAdmissionDiagnosticsWire::Present(diagnostics) => Some(diagnostics),
            },
        };
        if document.has_current_shape() {
            Ok(document)
        } else {
            Err(<D::Error as serde::de::Error>::custom(
                "invalid local workflow admission error document",
            ))
        }
    }
}

/// Secret bearer token protecting the loopback-only bootstrap ingress.
pub struct LocalAdmissionToken(Zeroizing<Vec<u8>>);

impl LocalAdmissionToken {
    /// Validates a bounded visible-ASCII bearer token.
    ///
    /// # Errors
    ///
    /// Rejects values outside the byte bounds or containing non-visible ASCII.
    pub fn new(value: &str) -> Result<Self, LocalAdmissionTokenError> {
        if value.len() < MIN_TOKEN_BYTES
            || value.len() > MAX_TOKEN_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(LocalAdmissionTokenError);
        }
        Ok(Self(Zeroizing::new(value.as_bytes().to_vec())))
    }

    fn authorizes(&self, header_value: Option<&HeaderValue>) -> bool {
        let Some(header_value) = header_value else {
            return false;
        };
        let actual = header_value.as_bytes();
        let Some(token) = actual.strip_prefix(b"Bearer ") else {
            return false;
        };
        token.len() == self.0.len() && bool::from(token.ct_eq(self.0.as_slice()))
    }
}

impl fmt::Debug for LocalAdmissionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalAdmissionToken([redacted])")
    }
}

/// Invalid local-admission bearer token configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("local workflow admission token must contain 32-512 visible ASCII bytes")]
pub struct LocalAdmissionTokenError;

/// Application port kept independent of HTTP extraction and authentication.
#[async_trait]
pub trait LocalWorkflowAdmission: fmt::Debug + Send + Sync {
    /// Validates, compiles, and durably admits one exact workflow request.
    ///
    /// Implementations preserve provider delivery idempotency: an exact retry
    /// returns the prior receipt, while conflicting evidence fails closed.
    async fn admit(
        &self,
        request: LocalWorkflowAdmissionRequest,
    ) -> Result<LocalWorkflowAdmissionResponse, LocalWorkflowAdmissionError>;
}

/// GitHub implementation over the provider-neutral durable admission service.
#[derive(Clone, Debug)]
pub struct GithubLocalWorkflowAdmission {
    tenant: TenantScope,
    service: WorkflowAdmissionService,
}

impl GithubLocalWorkflowAdmission {
    /// Binds the GitHub admission service to one authenticated tenant.
    #[must_use]
    pub const fn new(tenant: TenantScope, service: WorkflowAdmissionService) -> Self {
        Self { tenant, service }
    }
}

#[async_trait]
impl LocalWorkflowAdmission for GithubLocalWorkflowAdmission {
    async fn admit(
        &self,
        request: LocalWorkflowAdmissionRequest,
    ) -> Result<LocalWorkflowAdmissionResponse, LocalWorkflowAdmissionError> {
        request.validate()?;
        let projection = github_run_projection(&request.event_json, &request.workflow_name)?;
        let repository = format!("{}/{}", request.repository_owner, request.repository_name);
        let provenance = SourceProvenance::new(
            SourceId::new(request.workflow_path.as_str()),
            SourceOrigin::Repository {
                repository: Arc::from(repository.as_str()),
                revision: Arc::from(request.commit_sha.as_str()),
                path: Arc::from(request.workflow_path.as_str()),
            },
        );
        let parsed = GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(
            provenance,
            &request.workflow_source,
        ));
        if !parsed.is_accepted() {
            return Err(LocalWorkflowAdmissionError::FrontendRejected(
                diagnostic_codes(parsed.diagnostics()),
            ));
        }
        let event = WorkflowEventProvenance::new("github", &request.event_name)
            .with_delivery_id(&request.delivery_id)
            .with_commit_sha(&request.commit_sha)
            .with_git_ref(&request.git_ref);
        let compiled = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
            parsed
                .plan()
                .ok_or(LocalWorkflowAdmissionError::InvalidRequest)?,
            event,
        ));
        if !compiled.is_accepted() {
            return Err(LocalWorkflowAdmissionError::CompilationRejected(
                diagnostic_codes(compiled.diagnostics()),
            ));
        }
        let plan = compiled
            .into_parts()
            .0
            .ok_or(LocalWorkflowAdmissionError::InvalidRequest)?;
        let coordinates = AdmissionRepositoryCoordinates::new(
            "github",
            &request.provider_repository_id,
            &request.repository_owner,
            &request.repository_name,
        )
        .map_err(|_| LocalWorkflowAdmissionError::InvalidRequest)?;
        let idempotency = WorkflowAdmissionIdempotency::provider_delivery(&request.delivery_id)
            .map_err(|_| LocalWorkflowAdmissionError::InvalidRequest)?;
        let mut admission = WorkflowAdmissionRequest::builder(
            self.tenant.clone(),
            coordinates,
            request.workflow_path,
            Bytes::from(request.workflow_source),
            Bytes::from(request.event_json),
            plan,
            idempotency,
        )
        .commit_sha(request.commit_sha)
        .git_ref(request.git_ref)
        .workflow_name(request.workflow_name)
        .display_title(projection.display_title)
        .run_attempt(1);
        if let Some(commit_subject) = projection.commit_subject {
            admission = admission.commit_subject(commit_subject);
        }
        let admission = admission
            .build()
            .map_err(|_| LocalWorkflowAdmissionError::InvalidRequest)?;
        let receipt = self
            .service
            .admit(admission)
            .await
            .map_err(LocalWorkflowAdmissionError::from)?
            .receipt();
        LocalWorkflowAdmissionResponse::new(
            receipt.run_id().to_string(),
            receipt.run_number(),
            receipt.is_replay(),
        )
        .map_err(|_| LocalWorkflowAdmissionError::Internal)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GithubRunProjection {
    display_title: String,
    commit_subject: Option<String>,
}

fn github_run_projection(
    event_json: &str,
    workflow_name: &str,
) -> Result<GithubRunProjection, LocalWorkflowAdmissionError> {
    let event: serde_json::Value = serde_json::from_str(event_json)
        .map_err(|_| LocalWorkflowAdmissionError::InvalidRequest)?;
    let workflow_name = bounded_projection_text(workflow_name)
        .ok_or(LocalWorkflowAdmissionError::InvalidRequest)?;
    let commit_subject = event
        .pointer("/head_commit/message")
        .and_then(serde_json::Value::as_str)
        .and_then(|message| message.lines().next())
        .and_then(bounded_projection_text)
        .map(str::to_owned);
    let display_title = event
        .pointer("/pull_request/title")
        .and_then(serde_json::Value::as_str)
        .and_then(bounded_projection_text)
        .map(str::to_owned)
        .or_else(|| commit_subject.clone())
        .unwrap_or_else(|| workflow_name.to_owned());
    Ok(GithubRunProjection {
        display_title,
        commit_subject,
    })
}

fn bounded_projection_text(value: &str) -> Option<&str> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_TEXT_BYTES).then_some(value)
}

/// Sanitized local workflow admission failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LocalWorkflowAdmissionError {
    /// Request shape, bounds, identifiers, or event JSON were invalid.
    #[error("local workflow admission request is invalid")]
    InvalidRequest,
    /// The GitHub workflow frontend rejected the source with stable diagnostic codes.
    #[error("workflow frontend rejected the source")]
    FrontendRejected(Vec<String>),
    /// Event-specific compilation rejected the workflow with stable diagnostic codes.
    #[error("workflow compiler rejected the source")]
    CompilationRejected(Vec<String>),
    /// The idempotency key or immutable admission identity conflicts with durable state.
    #[error("workflow admission conflicts with durable state")]
    Conflict,
    /// A required durable store or immutable blob dependency is unavailable.
    ///
    /// The HTTP boundary returns `503` with `Retry-After: 1`. A client may retry
    /// the same immutable request and delivery ID; it must not rewrite evidence.
    #[error("workflow admission dependencies are unavailable")]
    Unavailable,
    /// Admission failed without a safe client-visible detail.
    #[error("workflow admission failed")]
    Internal,
}

impl From<WorkflowAdmissionError> for LocalWorkflowAdmissionError {
    fn from(error: WorkflowAdmissionError) -> Self {
        match error {
            WorkflowAdmissionError::Verification(_)
            | WorkflowAdmissionError::AdmissionValue(_)
            | WorkflowAdmissionError::LogicalValue(_)
            | WorkflowAdmissionError::Store(
                LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource,
            ) => Self::InvalidRequest,
            WorkflowAdmissionError::Store(
                LogicalWorkflowAdmissionStoreError::IdempotencyConflict
                | LogicalWorkflowAdmissionStoreError::IdentityConflict(_),
            ) => Self::Conflict,
            WorkflowAdmissionError::Blob(_)
            | WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::Store(_)) => {
                Self::Unavailable
            }
            WorkflowAdmissionError::Store(
                LogicalWorkflowAdmissionStoreError::RunNumberExhausted,
            )
            | WorkflowAdmissionError::Serialization
            | WorkflowAdmissionError::Internal => Self::Internal,
        }
    }
}

/// Creates the local bootstrap route. Callers must opt in with a configured token.
pub fn local_workflow_admission_router(
    service: Arc<dyn LocalWorkflowAdmission>,
    token: Arc<LocalAdmissionToken>,
) -> Router {
    Router::new()
        .route(
            LOCAL_WORKFLOW_ADMISSION_PATH,
            post(move |request: Request| {
                handle_local_admission(request, Arc::clone(&service), Arc::clone(&token))
            })
            .fallback(method_not_allowed),
        )
        .layer(middleware::from_fn(harden_local_admission_response))
}

async fn method_not_allowed() -> Response {
    let mut response = error_response(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("POST"));
    response
}

async fn handle_local_admission(
    request: Request,
    service: Arc<dyn LocalWorkflowAdmission>,
    token: Arc<LocalAdmissionToken>,
) -> Response {
    let Ok(authorization) = optional_single_header(request.headers(), &header::AUTHORIZATION)
    else {
        return unauthorized_response();
    };
    if !token.authorizes(authorization) {
        return unauthorized_response();
    }
    if request.uri().query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if optional_single_header(request.headers(), &header::CONTENT_TYPE)
        .ok()
        .flatten()
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
    {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_REQUEST_BYTES).await else {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
    };
    let Ok(document) = serde_json::from_slice::<LocalWorkflowAdmissionRequest>(&body) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if document.validate().is_err() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    match service.admit(document).await {
        Ok(response) => {
            let status = if response.is_replay() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            json_response(status, &response)
        }
        Err(LocalWorkflowAdmissionError::InvalidRequest) => {
            error_response(StatusCode::BAD_REQUEST, "invalid_request")
        }
        Err(LocalWorkflowAdmissionError::FrontendRejected(codes)) => {
            diagnostic_response(StatusCode::UNPROCESSABLE_ENTITY, "frontend_rejected", codes)
        }
        Err(LocalWorkflowAdmissionError::CompilationRejected(codes)) => diagnostic_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "compilation_rejected",
            codes,
        ),
        Err(LocalWorkflowAdmissionError::Conflict) => {
            error_response(StatusCode::CONFLICT, "admission_conflict")
        }
        Err(LocalWorkflowAdmissionError::Unavailable) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable")
        }
        Err(LocalWorkflowAdmissionError::Internal) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

fn optional_single_header<'headers>(
    headers: &'headers HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'headers HeaderValue>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    Ok(Some(value))
}

fn unauthorized_response() -> Response {
    let mut response = error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"automata-local-admission\""),
    );
    response
}

async fn harden_local_admission_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
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

fn error_response(status: StatusCode, error: &str) -> Response {
    let document = LocalWorkflowAdmissionErrorDocument {
        error: error.to_owned(),
        diagnostics: None,
    };
    if !document.is_current_for_status(status) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &LocalWorkflowAdmissionErrorDocument {
                error: "internal_error".to_owned(),
                diagnostics: None,
            },
        );
    }
    let mut response = json_response(status, &document);
    if status == StatusCode::SERVICE_UNAVAILABLE && error == "dependency_unavailable" {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

fn diagnostic_response(status: StatusCode, error: &str, mut diagnostics: Vec<String>) -> Response {
    if diagnostics
        .iter()
        .any(|code| !safe_machine_code(code, MAX_DIAGNOSTIC_CODE_BYTES))
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    diagnostics.sort();
    diagnostics.dedup();
    diagnostics.truncate(MAX_DIAGNOSTIC_CODES);
    let document = LocalWorkflowAdmissionErrorDocument {
        error: error.to_owned(),
        diagnostics: Some(diagnostics),
    };
    if !document.is_current_for_status(status) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    }
    json_response(status, &document)
}

fn diagnostic_codes(diagnostics: &[automata_ci_workflow_github::Diagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code().to_owned())
        .collect()
}

fn safe_repository_segment(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn canonical_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_machine_code(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use automata_ci_store::LogicalWorkflowAdmissionStoreError;
    use automata_ci_workflow_service::WorkflowAdmissionError;

    use super::{
        GithubRunProjection, LocalWorkflowAdmissionError, LocalWorkflowAdmissionRequest,
        LocalWorkflowAdmissionResponse, MAX_EVENT_BYTES, MAX_REQUEST_BYTES, MAX_TEXT_BYTES,
        MAX_WORKFLOW_SOURCE_BYTES, github_run_projection,
    };

    const RUN_ID: &str = "45e8cc88-5075-40c5-a6cb-9f1dad46c3b1";

    fn request() -> LocalWorkflowAdmissionRequest {
        LocalWorkflowAdmissionRequest::new(
            "repository-1",
            "automata-ci",
            "automata",
            ".github/workflows/ci.yml",
            "name: CI\non: workflow_dispatch\njobs: {}\n",
            "{}",
            "workflow_dispatch",
            "delivery-1",
            "0123456789abcdef0123456789abcdef01234567",
            "refs/heads/main",
            "CI",
        )
    }

    #[test]
    fn unsupported_local_source_is_a_sanitized_invalid_request() {
        let error = LocalWorkflowAdmissionError::from(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource,
        ));

        assert_eq!(error, LocalWorkflowAdmissionError::InvalidRequest);
    }

    #[test]
    fn public_receipt_constructor_and_deserializer_require_one_canonical_durable_shape() {
        let receipt =
            LocalWorkflowAdmissionResponse::new(RUN_ID, 7, false).expect("canonical receipt");
        let encoded = serde_json::to_vec(&receipt).expect("receipt JSON");
        assert_eq!(
            serde_json::from_slice::<LocalWorkflowAdmissionResponse>(&encoded)
                .expect("canonical receipt JSON"),
            receipt
        );

        for run_id in [
            RUN_ID.to_ascii_uppercase(),
            RUN_ID.replace('-', ""),
            format!("{{{RUN_ID}}}"),
            "00000000-0000-0000-0000-000000000000".to_owned(),
        ] {
            assert!(LocalWorkflowAdmissionResponse::new(&run_id, 7, false).is_err());
            let wire = serde_json::json!({
                "run_id": run_id,
                "run_number": 7,
                "replayed": false,
            });
            assert!(serde_json::from_value::<LocalWorkflowAdmissionResponse>(wire).is_err());
        }
        assert!(LocalWorkflowAdmissionResponse::new(RUN_ID, 0, false).is_err());
        assert!(
            serde_json::from_value::<LocalWorkflowAdmissionResponse>(serde_json::json!({
                "run_id": RUN_ID,
                "run_number": 0,
                "replayed": false,
            }))
            .is_err()
        );
    }

    #[test]
    fn request_semantics_are_validated_independently_of_the_adapter() {
        assert!(request().validate().is_ok());

        let mut invalid_event = request();
        invalid_event.event_json = "{".to_owned();
        assert_eq!(
            invalid_event.validate(),
            Err(LocalWorkflowAdmissionError::InvalidRequest)
        );

        let mut noncanonical_commit = request();
        noncanonical_commit.commit_sha = "A".repeat(40);
        assert_eq!(
            noncanonical_commit.validate(),
            Err(LocalWorkflowAdmissionError::InvalidRequest)
        );

        let mut abbreviated_ref = request();
        abbreviated_ref.git_ref = "main".to_owned();
        assert_eq!(
            abbreviated_ref.validate(),
            Err(LocalWorkflowAdmissionError::InvalidRequest)
        );
    }

    #[test]
    fn request_ceiling_covers_worst_case_json_escaping_of_valid_inputs() {
        let source = "\u{1}".repeat(MAX_WORKFLOW_SOURCE_BYTES);
        let event = format!("{}{{}}", "\t".repeat(MAX_EVENT_BYTES - 2));
        let request = LocalWorkflowAdmissionRequest::new(
            "\\".repeat(MAX_TEXT_BYTES),
            "a".repeat(MAX_TEXT_BYTES),
            "b".repeat(MAX_TEXT_BYTES),
            "\\".repeat(MAX_TEXT_BYTES),
            source,
            event,
            "\"".repeat(MAX_TEXT_BYTES),
            "\\".repeat(MAX_TEXT_BYTES),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            format!("refs/{}", "\\".repeat(MAX_TEXT_BYTES - 5)),
            "\"".repeat(MAX_TEXT_BYTES),
        );
        request
            .validate()
            .expect("maximum request remains semantic");
        let encoded = serde_json::to_vec(&request).expect("maximum request JSON");
        assert!(encoded.len() > 20 * 1024 * 1024);
        assert!(encoded.len() <= MAX_REQUEST_BYTES);
    }

    #[test]
    fn github_projection_prefers_pull_request_title_and_keeps_commit_subject() {
        let projection = github_run_projection(
            r#"{
                "pull_request":{"title":" Tighten release validation "},
                "head_commit":{"message":"Preserve exact metadata\nLong body"}
            }"#,
            "CI",
        )
        .expect("valid event projection");
        assert_eq!(
            projection,
            GithubRunProjection {
                display_title: "Tighten release validation".into(),
                commit_subject: Some("Preserve exact metadata".into()),
            }
        );
    }

    #[test]
    fn github_projection_uses_commit_subject_then_workflow_fallback() {
        let push = github_run_projection(
            r#"{"head_commit":{"message":"Ship projection\nDetails"}}"#,
            "CI",
        )
        .expect("valid push projection");
        assert_eq!(push.display_title, "Ship projection");
        assert_eq!(push.commit_subject.as_deref(), Some("Ship projection"));

        let fallback =
            github_run_projection("{}", "Nightly validation").expect("valid fallback projection");
        assert_eq!(fallback.display_title, "Nightly validation");
        assert_eq!(fallback.commit_subject, None);
    }

    #[test]
    fn github_projection_rejects_unbounded_or_control_bearing_event_text() {
        let event = serde_json::json!({
            "pull_request": {"title": "unsafe\tlabel"},
            "head_commit": {"message": "x".repeat(1_025)},
        })
        .to_string();
        let projection = github_run_projection(&event, "CI").expect("safe fallback");
        assert_eq!(
            projection,
            GithubRunProjection {
                display_title: "CI".into(),
                commit_subject: None,
            }
        );
    }
}
