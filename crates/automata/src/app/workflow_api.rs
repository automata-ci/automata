//! Explicitly opt-in local workflow admission HTTP boundary.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_core::WorkflowEventProvenance;
use automata_store::{TenantScope, WorkflowAdmissionIdempotency, WorkflowAdmissionStoreError};
use automata_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};
use automata_workflow_service::{
    AdmissionRepositoryCoordinates, WorkflowAdmissionError, WorkflowAdmissionRequest,
    WorkflowAdmissionService,
};
use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

const LOCAL_ADMISSION_PATH: &str = "/api/v1/local/workflow-runs";
const MAX_REQUEST_BYTES: usize = 20 * 1024 * 1024;
const MAX_WORKFLOW_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 1_024;

/// Exact local workflow-dispatch document sent by the administration CLI.
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
        Ok(())
    }
}

/// Stable local-admission response suitable for table or JSON CLI output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
        if run_number == 0 || run_id.parse::<automata_core::RunId>().is_err() {
            return Err(LocalWorkflowAdmissionResponseError);
        }
        Ok(Self {
            run_id,
            run_number,
            replayed,
        })
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub const fn run_number(&self) -> u64 {
        self.run_number
    }

    #[must_use]
    pub const fn is_replay(&self) -> bool {
        self.replayed
    }
}

/// An admission adapter returned a malformed durable receipt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("local workflow admission response is invalid")]
pub struct LocalWorkflowAdmissionResponseError;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWorkflowAdmissionErrorDocument {
    code: String,
}

impl LocalWorkflowAdmissionErrorDocument {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
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
        let workspace = format!("/__w/{name}/{name}", name = request.repository_name);
        let admission = WorkflowAdmissionRequest::builder(
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
        .workspace(workspace)
        .actor("automata-local-bootstrap")
        .run_attempt(1)
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

/// Sanitized local workflow admission failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LocalWorkflowAdmissionError {
    #[error("local workflow admission request is invalid")]
    InvalidRequest,
    #[error("workflow frontend rejected the source")]
    FrontendRejected(Vec<String>),
    #[error("workflow compiler rejected the source")]
    CompilationRejected(Vec<String>),
    #[error("workflow admission conflicts with durable state")]
    Conflict,
    #[error("workflow admission dependencies are unavailable")]
    Unavailable,
    #[error("workflow admission failed")]
    Internal,
}

impl From<WorkflowAdmissionError> for LocalWorkflowAdmissionError {
    fn from(error: WorkflowAdmissionError) -> Self {
        match error {
            WorkflowAdmissionError::Materialization(_)
            | WorkflowAdmissionError::AdmissionValue(_) => Self::InvalidRequest,
            WorkflowAdmissionError::Store(
                WorkflowAdmissionStoreError::IdempotencyConflict
                | WorkflowAdmissionStoreError::IdentityConflict(_),
            ) => Self::Conflict,
            WorkflowAdmissionError::Blob(_)
            | WorkflowAdmissionError::Store(WorkflowAdmissionStoreError::Store(_)) => {
                Self::Unavailable
            }
            WorkflowAdmissionError::Store(WorkflowAdmissionStoreError::RunNumberExhausted)
            | WorkflowAdmissionError::Serialization
            | WorkflowAdmissionError::JobIrEncoding
            | WorkflowAdmissionError::MaterializedInvariant
            | WorkflowAdmissionError::Internal => Self::Internal,
        }
    }
}

/// Creates the local bootstrap route. Callers must opt in with a configured token.
pub fn local_workflow_admission_router(
    service: Arc<dyn LocalWorkflowAdmission>,
    token: Arc<LocalAdmissionToken>,
) -> Router {
    Router::new().route(
        LOCAL_ADMISSION_PATH,
        post(move |request: Request| {
            handle_local_admission(request, Arc::clone(&service), Arc::clone(&token))
        }),
    )
}

async fn handle_local_admission(
    request: Request,
    service: Arc<dyn LocalWorkflowAdmission>,
    token: Arc<LocalAdmissionToken>,
) -> Response {
    if !token.authorizes(request.headers().get(header::AUTHORIZATION)) {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
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
            br#"{"code":"internal_error"}"#.as_slice(),
        )
            .into_response(),
    }
}

fn error_response(status: StatusCode, code: &str) -> Response {
    json_response(
        status,
        &LocalWorkflowAdmissionErrorDocument {
            code: code.to_owned(),
        },
    )
}

fn diagnostic_response(status: StatusCode, code: &str, mut diagnostics: Vec<String>) -> Response {
    diagnostics.sort();
    diagnostics.dedup();
    json_response(status, &DiagnosticDocument { code, diagnostics })
}

#[derive(Serialize)]
struct DiagnosticDocument<'code> {
    code: &'code str,
    diagnostics: Vec<String>,
}

fn diagnostic_codes(diagnostics: &[automata_workflow_github::Diagnostic]) -> Vec<String> {
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
