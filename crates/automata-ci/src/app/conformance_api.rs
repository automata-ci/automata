//! CLI-authenticated, versioned export of provider delivery and run evidence.

use std::sync::Arc;

use automata_ci_auth::{
    authorization::{
        AuthorizationRequest, AuthorizationScope, Permission, RepositoryResource,
        RepositoryResourceId,
    },
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
};
use automata_ci_blob::{
    BlobDescriptor, BlobKey, BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore, MediaType,
};
#[cfg(test)]
use automata_ci_core::JobConclusion;
use automata_ci_core::{
    ContextValue, JobIrEnvelope, JobLifecycle, JobResult, RunId, StrategyContext, WorkflowId,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    ConformanceDelivery, ConformanceDeliveryQuery, ConformanceDeliveryState,
    ConformanceReadRepository, ConformanceWorkflowOutcome, HumanAuthorizationTarget,
    HumanJobAttempt, HumanRunConclusion, HumanRunDetail, HumanRunScope,
    HumanWorkflowReadRepository, JobIrMetadata, LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE,
    LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE, RepositoryId, StoreError, TenantScope,
    WorkflowRunStatus,
};
use axum::{
    Router,
    body::Body,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use uuid::Uuid;

const CONFORMANCE_READ_PERMISSION: &str = "conformance:read";
const MAX_CONFORMANCE_EXPORT_BLOB_BYTES: u64 = 128 * 1_048_576;

pub(crate) const GITHUB_DELIVERY_EXPORT_PATH: &str =
    "/api/v1/conformance/repositories/{repository_id}/github-deliveries/{delivery_id}";

#[derive(Clone)]
struct ConformanceApiState {
    reads: Arc<dyn HumanWorkflowReadRepository>,
    deliveries: Arc<dyn ConformanceReadRepository>,
    blobs: Arc<dyn ImmutableBlobStore>,
}

/// Builds the private conformance-export route.
///
/// The surrounding human-auth middleware must provide a current CLI
/// [`AuthenticatedRequestSnapshot`]. Browser sessions and public repository
/// publication policy never grant this surface.
pub(crate) fn conformance_api_router(
    reads: Arc<dyn HumanWorkflowReadRepository>,
    deliveries: Arc<dyn ConformanceReadRepository>,
    blobs: Arc<dyn ImmutableBlobStore>,
) -> Router {
    Router::new()
        .route(GITHUB_DELIVERY_EXPORT_PATH, get(export_github_delivery))
        .with_state(ConformanceApiState {
            reads,
            deliveries,
            blobs,
        })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn export_github_delivery(
    State(state): State<ConformanceApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let (repository_id, delivery_id) = match delivery_target(path) {
        Ok(target) => target,
        Err(error) => return error.into_response(),
    };
    if request.uri().query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let snapshot = match cli_snapshot(&request) {
        Ok(snapshot) => snapshot,
        Err(error) => return error.into_response(),
    };
    let Ok(tenant) = TenantScope::from_authenticated_tenant_id(
        snapshot.session().identity().tenant_id().as_str(),
    ) else {
        return ApiError::Internal.into_response();
    };
    let Ok(query) =
        ConformanceDeliveryQuery::new(tenant.clone(), repository_id, "github", delivery_id)
    else {
        return ApiError::InvalidRequest.into_response();
    };
    match authorize(&state, snapshot, &tenant, repository_id).await {
        Ok(true) => {}
        Ok(false) => return ApiError::Forbidden.into_response(),
        Err(error) => return error.into_response(),
    }

    let delivery = match state.deliveries.get_conformance_delivery(&query).await {
        Ok(Some(delivery)) => delivery,
        Ok(None) => return ApiError::NotFound.into_response(),
        Err(error) => return store_error(&error).into_response(),
    };
    match export_document(&state, tenant, repository_id, delivery).await {
        Ok(document) => json_response(StatusCode::OK, &document),
        Err(error) => error.into_response(),
    }
}

async fn authorize(
    state: &ConformanceApiState,
    snapshot: &AuthenticatedRequestSnapshot,
    tenant: &TenantScope,
    repository_id: RepositoryId,
) -> Result<bool, ApiError> {
    let resource_id =
        RepositoryResourceId::from_uuid(repository_id.as_uuid()).map_err(|_| ApiError::Internal)?;
    let resource = RepositoryResource::new(
        snapshot.session().identity().tenant_id().clone(),
        resource_id,
    );
    let permission =
        Permission::new(CONFORMANCE_READ_PERMISSION).map_err(|_| ApiError::Internal)?;
    let target = HumanAuthorizationTarget::current_policy(AuthorizationRequest::new(
        AuthorizationScope::repository(resource),
        permission,
    ));
    state
        .reads
        .is_repository_request_allowed(tenant, repository_id, snapshot.authorization(), &target)
        .await
        .map_err(|error| store_error(&error))
}

async fn export_document(
    state: &ConformanceApiState,
    tenant: TenantScope,
    repository_id: RepositoryId,
    delivery: ConformanceDelivery,
) -> Result<ConformanceExportDocument, ApiError> {
    let mut run_ids = Vec::new();
    for workflow in delivery.workflows() {
        if let ConformanceWorkflowOutcome::Admitted { run_id } = workflow.outcome()
            && !run_ids.contains(run_id)
        {
            run_ids.push(*run_id);
        }
    }
    let mut runs = Vec::with_capacity(run_ids.len());
    for run_id in run_ids {
        let scope = HumanRunScope::new(tenant.clone(), repository_id, run_id);
        let detail = state
            .reads
            .get_run(&scope)
            .await
            .map_err(|error| store_error(&error))?
            .ok_or(ApiError::Internal)?;
        runs.push(export_run(state, detail).await?);
    }
    Ok(ConformanceExportDocument {
        schema_version: 1,
        delivery: DeliveryDocument::from_delivery(&delivery),
        runs,
    })
}

async fn export_run(
    state: &ConformanceApiState,
    detail: HumanRunDetail,
) -> Result<RunDocument, ApiError> {
    let mut blob_budget = 0_u64;
    for job in &detail.jobs {
        if let Some(metadata) = &job.job_ir {
            blob_budget = add_blob_budget(blob_budget, metadata.encoded_size())?;
        }
        if let Some(result) = job
            .latest_attempt
            .as_ref()
            .and_then(|attempt| attempt.terminal_result.as_ref())
        {
            blob_budget = add_blob_budget(blob_budget, result.descriptor.size())?;
        }
    }

    let run_id = detail.run.id;
    let workflow_id = detail.run.workflow_id;
    let workflow_path = detail.run.workflow_path.clone();
    let mut jobs = Vec::with_capacity(detail.jobs.len());
    for job in detail.jobs {
        let (job_ir, runtime_context) = match &job.job_ir {
            Some(metadata) => {
                let (job_ir, runtime_context) = load_job_ir(
                    state.blobs.as_ref(),
                    metadata,
                    run_id,
                    workflow_id,
                    &workflow_path,
                    job.id,
                    &mut blob_budget,
                )
                .await?;
                (Some(job_ir), Some(runtime_context))
            }
            None => (None, None),
        };
        let latest_attempt = match job.latest_attempt.as_ref() {
            Some(attempt) => Some(load_attempt(state.blobs.as_ref(), attempt).await?),
            None => None,
        };
        jobs.push(JobDocument {
            id: job.id.as_uuid().to_string(),
            logical_key: job.key,
            display_name: job.display_name,
            created_at_ms: job.created_at.get(),
            job_ir,
            runtime_context,
            latest_attempt,
        });
    }
    let artifacts = detail
        .artifacts
        .into_iter()
        .map(|artifact| ArtifactDocument {
            name: artifact.name,
            mime_type: artifact.mime_type,
            size: artifact.content_size,
            sha256: artifact.content_digest.to_string(),
            expires_at_seconds: artifact.expires_at_seconds,
            finalized_at_seconds: artifact.finalized_at_seconds,
        })
        .collect();
    Ok(RunDocument {
        id: run_id.as_uuid().to_string(),
        workflow_id: workflow_id.as_uuid().to_string(),
        workflow_path: detail.run.workflow_path,
        workflow_name: detail.run.workflow_name,
        run_number: detail.run.run_number,
        run_attempt: detail.run.run_attempt,
        event_name: detail.run.event_name,
        head_commit: hex_bytes(detail.run.head_commit.as_bytes()),
        git_ref: detail.run.git_ref,
        status: run_status(detail.run.status),
        conclusion: detail.run.conclusion.map(run_conclusion),
        created_at_ms: detail.run.created_at.get(),
        updated_at_ms: detail.run.updated_at.get(),
        finished_at_ms: detail
            .run
            .finished_at
            .map(automata_ci_core::UnixMillis::get),
        jobs,
        artifacts,
    })
}

fn add_blob_budget(current: u64, size: u64) -> Result<u64, ApiError> {
    current
        .checked_add(size)
        .filter(|total| *total <= MAX_CONFORMANCE_EXPORT_BLOB_BYTES)
        .ok_or(ApiError::TooLarge)
}

async fn load_job_ir(
    blobs: &dyn ImmutableBlobStore,
    metadata: &JobIrMetadata,
    run_id: RunId,
    workflow_id: WorkflowId,
    workflow_path: &str,
    job_id: automata_ci_core::JobId,
    blob_budget: &mut u64,
) -> Result<(JobIrEnvelope, RuntimeContextDocument), ApiError> {
    let descriptor = BlobDescriptor::new(
        BlobKey::new(metadata.object_key().as_str()).map_err(|_| ApiError::Internal)?,
        metadata.digest(),
        metadata.encoded_size(),
        MediaType::new(LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE).map_err(|_| ApiError::Internal)?,
    );
    let encoded = blobs
        .get_verified(&descriptor, metadata.encoded_size())
        .await
        .map_err(blob_error)?;
    let envelope =
        automata_ci_protocol_protobuf::decode_job_ir(encoded.bytes(), &ProtocolLimits::default())
            .map_err(|_| ApiError::Internal)?;
    if envelope.version() != metadata.version()
        || envelope.workflow_id() != workflow_id
        || envelope.source().workflow_path() != workflow_path
        || envelope.job().run_id() != run_id
        || envelope.job().job_id() != job_id
        || metadata.run_id() != run_id
        || metadata.job_id() != job_id
    {
        return Err(ApiError::Internal);
    }
    envelope.validate().map_err(|_| ApiError::Internal)?;
    let runtime_reference = envelope.execution().runtime_context();
    if runtime_reference.media_type() != LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE {
        return Err(ApiError::Internal);
    }
    *blob_budget = add_blob_budget(*blob_budget, runtime_reference.encoded_size())?;
    let runtime_descriptor = BlobDescriptor::new(
        BlobKey::new(runtime_reference.object_key()).map_err(|_| ApiError::Internal)?,
        runtime_reference.digest(),
        runtime_reference.encoded_size(),
        MediaType::new(runtime_reference.media_type()).map_err(|_| ApiError::Internal)?,
    );
    let encoded_runtime = blobs
        .get_verified(&runtime_descriptor, runtime_reference.encoded_size())
        .await
        .map_err(blob_error)?;
    let runtime = automata_ci_protocol_protobuf::decode_job_runtime_context(
        encoded_runtime.bytes(),
        &ProtocolLimits::default(),
    )
    .map_err(|_| ApiError::Internal)?;
    runtime.validate().map_err(|_| ApiError::Internal)?;
    let instance = envelope.job().instance_identity();
    let strategy = runtime.strategy();
    if instance.matrix_index() != strategy.job_index()
        || instance.matrix_total() != strategy.job_total()
    {
        return Err(ApiError::Internal);
    }
    let runtime_document = RuntimeContextDocument {
        matrix: runtime.matrix().clone(),
        strategy,
    };
    Ok((envelope, runtime_document))
}

async fn load_attempt(
    blobs: &dyn ImmutableBlobStore,
    attempt: &HumanJobAttempt,
) -> Result<AttemptDocument, ApiError> {
    let result = match &attempt.terminal_result {
        Some(terminal) => {
            let encoded = blobs
                .get_verified(&terminal.descriptor, terminal.descriptor.size())
                .await
                .map_err(blob_error)?;
            let result: JobResult =
                serde_json::from_slice(encoded.bytes()).map_err(|_| ApiError::Internal)?;
            result.validate().map_err(|_| ApiError::Internal)?;
            if result.attempt_id() != attempt.id
                || result.attempt_id() != terminal.attempt_id
                || result.conclusion() != terminal.conclusion
                || result.completed_at() != terminal.completed_at
            {
                return Err(ApiError::Internal);
            }
            Some(result)
        }
        None => None,
    };
    Ok(AttemptDocument {
        id: attempt.id.as_uuid().to_string(),
        number: attempt.number.get(),
        lifecycle: job_lifecycle(attempt.lifecycle),
        queued_at_ms: attempt.queued_at.get(),
        started_at_ms: attempt.started_at.map(automata_ci_core::UnixMillis::get),
        finished_at_ms: attempt.finished_at.map(automata_ci_core::UnixMillis::get),
        runner: attempt.runner.as_ref().map(|runner| RunnerDocument {
            id: runner.id.as_uuid().to_string(),
            name: runner.name.clone(),
        }),
        result,
    })
}

fn delivery_target(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(RepositoryId, String), ApiError> {
    let Path((repository_id, delivery_id)) = path.map_err(|_| ApiError::InvalidRequest)?;
    let repository_id = canonical_uuid(&repository_id)?;
    if delivery_id.is_empty() {
        return Err(ApiError::InvalidRequest);
    }
    Ok((RepositoryId::from_uuid(repository_id), delivery_id))
}

fn canonical_uuid(value: &str) -> Result<Uuid, ApiError> {
    let parsed = Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(ApiError::InvalidRequest);
    }
    Ok(parsed)
}

fn cli_snapshot(request: &Request) -> Result<&AuthenticatedRequestSnapshot, ApiError> {
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .ok_or(ApiError::Unauthorized)?;
    if snapshot.session().identity().kind() != SessionKind::Cli {
        return Err(ApiError::Unauthorized);
    }
    Ok(snapshot)
}

fn store_error(error: &StoreError) -> ApiError {
    if matches!(error, StoreError::CorruptData(_)) {
        ApiError::Internal
    } else {
        ApiError::Unavailable
    }
}

const fn blob_error(error: BlobStoreError) -> ApiError {
    match error.kind() {
        BlobStoreErrorKind::Unauthorized | BlobStoreErrorKind::Unavailable => ApiError::Unavailable,
        BlobStoreErrorKind::NotFound
        | BlobStoreErrorKind::Conflict
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::TooLarge
        | BlobStoreErrorKind::InvalidResponse => ApiError::Internal,
    }
}

fn json_response(status: StatusCode, document: &impl Serialize) -> Response {
    let Ok(body) = serde_json::to_vec(document) else {
        return ApiError::Internal.into_response();
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiError {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    TooLarge,
    Unavailable,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, r#"{"error":"invalid_request"}"#),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            Self::Forbidden => (StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#),
            Self::NotFound => (StatusCode::NOT_FOUND, r#"{"error":"not_found"}"#),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, r#"{"error":"too_large"}"#),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"temporarily_unavailable"}"#,
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"internal_error"}"#,
            ),
        };
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        response
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConformanceExportDocument {
    schema_version: u16,
    delivery: DeliveryDocument,
    runs: Vec<RunDocument>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryDocument {
    id: String,
    external_id: String,
    state: &'static str,
    attempts: u16,
    accepted_at_ms: i64,
    completed_at_ms: Option<i64>,
    workflows: Vec<WorkflowDeliveryDocument>,
}

impl DeliveryDocument {
    fn from_delivery(delivery: &ConformanceDelivery) -> Self {
        Self {
            id: delivery.id().as_uuid().to_string(),
            external_id: delivery.external_delivery_id().to_owned(),
            state: delivery_state(delivery.state()),
            attempts: delivery.attempts(),
            accepted_at_ms: delivery.accepted_at().get(),
            completed_at_ms: delivery
                .completed_at()
                .map(automata_ci_core::UnixMillis::get),
            workflows: delivery
                .workflows()
                .iter()
                .map(WorkflowDeliveryDocument::from_result)
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowDeliveryDocument {
    path: String,
    outcome: WorkflowDeliveryOutcomeDocument,
}

impl WorkflowDeliveryDocument {
    fn from_result(result: &automata_ci_store::ConformanceWorkflowResult) -> Self {
        let outcome = match result.outcome() {
            ConformanceWorkflowOutcome::Admitted { run_id } => {
                WorkflowDeliveryOutcomeDocument::Admitted {
                    run_id: run_id.as_uuid().to_string(),
                }
            }
            ConformanceWorkflowOutcome::Skipped { reason } => {
                WorkflowDeliveryOutcomeDocument::Skipped {
                    reason: reason.clone(),
                }
            }
            ConformanceWorkflowOutcome::Failed { failure_kind } => {
                WorkflowDeliveryOutcomeDocument::Failed {
                    failure_kind: failure_kind.clone(),
                }
            }
        };
        Self {
            path: result.workflow_path().to_owned(),
            outcome,
        }
    }
}

#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum WorkflowDeliveryOutcomeDocument {
    Admitted { run_id: String },
    Skipped { reason: String },
    Failed { failure_kind: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDocument {
    id: String,
    workflow_id: String,
    workflow_path: String,
    workflow_name: Option<String>,
    run_number: u64,
    run_attempt: u32,
    event_name: String,
    head_commit: String,
    git_ref: Option<String>,
    status: &'static str,
    conclusion: Option<&'static str>,
    created_at_ms: i64,
    updated_at_ms: i64,
    finished_at_ms: Option<i64>,
    jobs: Vec<JobDocument>,
    artifacts: Vec<ArtifactDocument>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobDocument {
    id: String,
    logical_key: String,
    display_name: String,
    created_at_ms: i64,
    job_ir: Option<JobIrEnvelope>,
    runtime_context: Option<RuntimeContextDocument>,
    latest_attempt: Option<AttemptDocument>,
}

/// Safe subset of the independently verified runtime context. Inputs, needs,
/// variables, and secret locators are deliberately excluded from this API.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeContextDocument {
    matrix: ContextValue,
    strategy: StrategyContext,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttemptDocument {
    id: String,
    number: u32,
    lifecycle: &'static str,
    queued_at_ms: i64,
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
    runner: Option<RunnerDocument>,
    result: Option<JobResult>,
}

#[derive(Serialize)]
struct RunnerDocument {
    id: String,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactDocument {
    name: String,
    mime_type: String,
    size: u64,
    sha256: String,
    expires_at_seconds: Option<i64>,
    finalized_at_seconds: i64,
}

const fn delivery_state(state: ConformanceDeliveryState) -> &'static str {
    match state {
        ConformanceDeliveryState::Pending => "pending",
        ConformanceDeliveryState::Claimed => "claimed",
        ConformanceDeliveryState::RetryPending => "retry_pending",
        ConformanceDeliveryState::Completed => "completed",
        ConformanceDeliveryState::Rejected => "rejected",
    }
}

const fn run_status(status: WorkflowRunStatus) -> &'static str {
    match status {
        WorkflowRunStatus::Queued => "queued",
        WorkflowRunStatus::InProgress => "in_progress",
        WorkflowRunStatus::Completed => "completed",
        WorkflowRunStatus::Cancelled => "cancelled",
    }
}

const fn run_conclusion(conclusion: HumanRunConclusion) -> &'static str {
    match conclusion {
        HumanRunConclusion::Success => "success",
        HumanRunConclusion::Failure => "failure",
        HumanRunConclusion::Cancelled => "cancelled",
        HumanRunConclusion::TimedOut => "timed_out",
        HumanRunConclusion::Skipped => "skipped",
        HumanRunConclusion::Lost => "lost",
    }
}

const fn job_lifecycle(lifecycle: JobLifecycle) -> &'static str {
    match lifecycle {
        JobLifecycle::Queued => "queued",
        JobLifecycle::Leased => "leased",
        JobLifecycle::Preparing => "preparing",
        JobLifecycle::Running => "running",
        JobLifecycle::Cancelling => "cancelling",
        JobLifecycle::Finalizing => "finalizing",
        JobLifecycle::Succeeded => "succeeded",
        JobLifecycle::Failed => "failed",
        JobLifecycle::Cancelled => "cancelled",
        JobLifecycle::TimedOut => "timed_out",
        JobLifecycle::Skipped => "skipped",
        JobLifecycle::Lost => "lost",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_ids_are_canonical_and_non_nil() {
        let canonical = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert_eq!(
            canonical_uuid(canonical).expect("UUID").to_string(),
            canonical
        );
        assert!(canonical_uuid("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").is_err());
        assert!(canonical_uuid("00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn export_blob_budget_is_closed() {
        assert_eq!(add_blob_budget(1, 2), Ok(3));
        assert_eq!(
            add_blob_budget(MAX_CONFORMANCE_EXPORT_BLOB_BYTES, 1),
            Err(ApiError::TooLarge)
        );
    }

    #[test]
    fn all_job_conclusions_have_stable_json_names() {
        for (conclusion, expected) in [
            (JobConclusion::Success, "\"success\""),
            (JobConclusion::Failure, "\"failure\""),
            (JobConclusion::Cancelled, "\"cancelled\""),
            (JobConclusion::TimedOut, "\"timed_out\""),
            (JobConclusion::Skipped, "\"skipped\""),
        ] {
            assert_eq!(serde_json::to_string(&conclusion).expect("JSON"), expected);
        }
    }
}
