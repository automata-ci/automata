//! CLI-authenticated, versioned export of provider delivery and run evidence.

use std::{collections::BTreeMap, sync::Arc};

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
use automata_ci_conformance::{AvailabilityReason, EvidenceAvailability};
#[cfg(test)]
use automata_ci_core::JobConclusion;
use automata_ci_core::{
    ContextValue, JobIrEnvelope, JobLifecycle, JobResult, RunId, StrategyContext, WorkflowId,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_store::{
    ConformanceDelivery, ConformanceDeliveryQuery, ConformanceDeliveryState,
    ConformanceReadRepository, ConformanceWorkflowOutcome, HumanAuthorizationTarget,
    HumanJobAttempt, HumanJobScope, HumanLogSegmentCursor, HumanLogSegmentPageSize,
    HumanLogSegmentQuery, HumanLogStream, HumanOutputPublication, HumanRunConclusion,
    HumanRunDetail, HumanRunScope, HumanWorkflowReadRepository, JobIrMetadata,
    LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE, LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    ProviderRepositoryId, RepositoryId, StoreError, TenantScope, WorkflowRunStatus,
    github_provider_repository_id,
};
use axum::{
    Router,
    body::Body,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::web::{
    codec::{LogSegmentExpectation, decode_log_segment},
    log_stream_safety_is_valid,
};

const CONFORMANCE_READ_PERMISSION: &str = "conformance:read";
// foundation-governance: operational-limit
const MAX_CONFORMANCE_EXPORT_BLOB_BYTES: u64 = 128 * 1_048_576;
// foundation-governance: operational-limit
const MAX_CONFORMANCE_LOG_SEGMENTS: usize = 4_096;
// foundation-governance: operational-limit
const MAX_CONFORMANCE_LOG_PAGES: usize = MAX_CONFORMANCE_LOG_SEGMENTS + 1;
const CONFORMANCE_EXPORT_V1_SCHEMA_VERSION: u16 = 1;
const CONFORMANCE_EXPORT_V2_SCHEMA_VERSION: u16 = 2;

/// Opt-in media type for the presence-aware complete export contract.
pub(crate) const CONFORMANCE_EXPORT_V2_MEDIA_TYPE: &str =
    "application/vnd.automata.conformance.v2+json";

// foundation-governance: derived-contract owner=conformance kind=wire-discriminator
pub(crate) const GITHUB_DELIVERY_EXPORT_PATH: &str =
    "/api/v1/conformance/github/repositories/{provider_repository_id}/deliveries/{delivery_id}";

#[derive(Clone)]
struct ConformanceApiState {
    reads: Arc<dyn HumanWorkflowReadRepository>,
    deliveries: Arc<dyn ConformanceReadRepository>,
    blobs: Arc<dyn ImmutableBlobStore>,
    authorization: ConformanceAuthorization,
}

#[derive(Clone)]
enum ConformanceAuthorization {
    HumanSession,
    DeploymentToken {
        tenant: TenantScope,
        token_sha256: [u8; 32],
    },
}

enum PresentedAuthorization {
    HumanSession(Box<AuthenticatedRequestSnapshot>),
    DeploymentToken(String),
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
    conformance_router(
        reads,
        deliveries,
        blobs,
        ConformanceAuthorization::HumanSession,
    )
}

/// Builds the loopback deployment-token conformance route.
pub(crate) fn deployment_conformance_api_router(
    reads: Arc<dyn HumanWorkflowReadRepository>,
    deliveries: Arc<dyn ConformanceReadRepository>,
    blobs: Arc<dyn ImmutableBlobStore>,
    tenant: TenantScope,
    token: &str,
) -> Router {
    conformance_router(
        reads,
        deliveries,
        blobs,
        ConformanceAuthorization::DeploymentToken {
            tenant,
            token_sha256: Sha256::digest(token.as_bytes()).into(),
        },
    )
}

fn conformance_router(
    reads: Arc<dyn HumanWorkflowReadRepository>,
    deliveries: Arc<dyn ConformanceReadRepository>,
    blobs: Arc<dyn ImmutableBlobStore>,
    authorization: ConformanceAuthorization,
) -> Router {
    Router::new()
        .route(GITHUB_DELIVERY_EXPORT_PATH, get(export_github_delivery))
        .with_state(ConformanceApiState {
            reads,
            deliveries,
            blobs,
            authorization,
        })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn export_github_delivery(
    State(state): State<ConformanceApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let export_version = match requested_export_version(request.headers()) {
        Ok(version) => version,
        Err(error) => return error.into_response(),
    };
    let (provider_repository_id, delivery_id) = match delivery_target(path) {
        Ok(target) => target,
        Err(error) => return error.into_response(),
    };
    if request.uri().query().is_some() {
        return ApiError::InvalidRequest.into_response();
    }
    let presented = match presented_authorization(&state, &request) {
        Ok(presented) => presented,
        Err(error) => return error.into_response(),
    };
    let (tenant, repository_id) =
        match authorized_scope(&state, presented, provider_repository_id).await {
            Ok(scope) => scope,
            Err(error) => return error.into_response(),
        };
    let Ok(query) =
        ConformanceDeliveryQuery::new(tenant.clone(), repository_id, "github", delivery_id)
    else {
        return ApiError::InvalidRequest.into_response();
    };

    let delivery = match state.deliveries.get_conformance_delivery(&query).await {
        Ok(Some(delivery)) => delivery,
        Ok(None) => return ApiError::NotFound.into_response(),
        Err(error) => return store_error(&error).into_response(),
    };
    match export_version {
        ExportVersion::V1 => match export_document(&state, tenant, repository_id, delivery).await {
            Ok(document) => json_response(StatusCode::OK, "application/json", &document),
            Err(error) => error.into_response(),
        },
        ExportVersion::V2 => {
            match export_document_v2(&state, tenant, repository_id, delivery).await {
                Ok(document) => {
                    json_response(StatusCode::OK, CONFORMANCE_EXPORT_V2_MEDIA_TYPE, &document)
                }
                Err(error) => error.into_response(),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportVersion {
    V1,
    V2,
}

fn requested_export_version(headers: &HeaderMap) -> Result<ExportVersion, ApiError> {
    let mut values = headers.get_all(header::ACCEPT).iter();
    let Some(value) = values.next() else {
        return Ok(ExportVersion::V1);
    };
    if values.next().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    match value.to_str().map_err(|_| ApiError::InvalidRequest)? {
        "application/json" | "*/*" => Ok(ExportVersion::V1),
        CONFORMANCE_EXPORT_V2_MEDIA_TYPE => Ok(ExportVersion::V2),
        _ => Err(ApiError::InvalidRequest),
    }
}

async fn authorized_scope(
    state: &ConformanceApiState,
    presented: PresentedAuthorization,
    provider_repository_id: ProviderRepositoryId,
) -> Result<(TenantScope, RepositoryId), ApiError> {
    match (&state.authorization, presented) {
        (
            ConformanceAuthorization::HumanSession,
            PresentedAuthorization::HumanSession(snapshot),
        ) => {
            let tenant = TenantScope::from_authenticated_tenant_id(
                snapshot.session().identity().tenant_id().as_str(),
            )
            .map_err(|_| ApiError::Internal)?;
            let repository_id = github_provider_repository_id(&tenant, provider_repository_id);
            if !authorize(state, &snapshot, &tenant, repository_id).await? {
                return Err(ApiError::Forbidden);
            }
            Ok((tenant, repository_id))
        }
        (
            ConformanceAuthorization::DeploymentToken {
                tenant,
                token_sha256,
            },
            PresentedAuthorization::DeploymentToken(token),
        ) => {
            let candidate: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            if !bool::from(token_sha256.ct_eq(&candidate)) {
                return Err(ApiError::Unauthorized);
            }
            let repository_id = github_provider_repository_id(tenant, provider_repository_id);
            Ok((tenant.clone(), repository_id))
        }
        _ => Err(ApiError::Unauthorized),
    }
}

fn presented_authorization(
    state: &ConformanceApiState,
    request: &Request,
) -> Result<PresentedAuthorization, ApiError> {
    match &state.authorization {
        ConformanceAuthorization::HumanSession => Ok(PresentedAuthorization::HumanSession(
            Box::new(cli_snapshot(request)?),
        )),
        ConformanceAuthorization::DeploymentToken { .. } => Ok(
            PresentedAuthorization::DeploymentToken(exact_bearer(request.headers())?.to_owned()),
        ),
    }
}

fn exact_bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(ApiError::Unauthorized)?;
    if values.next().is_some() {
        return Err(ApiError::Unauthorized);
    }
    let value = value.to_str().map_err(|_| ApiError::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(ApiError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(token)
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
    export_document_internal(state, tenant, repository_id, delivery, false).await
}

async fn export_document_v2(
    state: &ConformanceApiState,
    tenant: TenantScope,
    repository_id: RepositoryId,
    delivery: ConformanceDelivery,
) -> Result<ConformanceExportDocumentV2, ApiError> {
    export_document_internal(state, tenant, repository_id, delivery, true)
        .await
        .map(ConformanceExportDocumentV2::from_v1)
}

async fn export_document_internal(
    state: &ConformanceApiState,
    tenant: TenantScope,
    repository_id: RepositoryId,
    delivery: ConformanceDelivery,
    include_logs: bool,
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
        runs.push(export_run(state, &tenant, repository_id, detail, include_logs).await?);
    }
    Ok(ConformanceExportDocument {
        schema_version: CONFORMANCE_EXPORT_V1_SCHEMA_VERSION,
        delivery: DeliveryDocument::from_delivery(&delivery),
        runs,
    })
}

async fn export_run(
    state: &ConformanceApiState,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    detail: HumanRunDetail,
    include_logs: bool,
) -> Result<RunDocument, ApiError> {
    let mut blob_budget = 0_u64;
    for job in &detail.jobs {
        blob_budget = add_blob_budget(blob_budget, job.job_ir.encoded_size())?;
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
        let logs = if include_logs {
            load_log_evidence(
                state,
                tenant,
                repository_id,
                run_id,
                job.id,
                job.latest_attempt.as_ref(),
                &mut blob_budget,
            )
            .await?
        } else {
            EvidenceAvailability::unavailable(AvailabilityReason::UnsupportedForEvidenceClass)
        };
        let (job_ir, runtime_context) = load_job_ir(
            state.blobs.as_ref(),
            &job.job_ir,
            run_id,
            workflow_id,
            &workflow_path,
            job.id,
            &mut blob_budget,
        )
        .await?;
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
            logs,
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

async fn load_log_evidence(
    state: &ConformanceApiState,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: automata_ci_core::JobId,
    attempt: Option<&HumanJobAttempt>,
    blob_budget: &mut u64,
) -> Result<EvidenceAvailability<LogDocument>, ApiError> {
    let Some(attempt) = attempt else {
        return Ok(EvidenceAvailability::unavailable(
            AvailabilityReason::NotProduced,
        ));
    };
    let scope = HumanJobScope::new(tenant.clone(), repository_id, run_id, job_id);
    let detail = state
        .reads
        .get_job(&scope)
        .await
        .map_err(|error| store_error(&error))?
        .ok_or(ApiError::Internal)?;
    if detail.job.id != job_id
        || detail
            .job
            .latest_attempt
            .as_ref()
            .is_none_or(|current| current.id != attempt.id)
    {
        return Err(ApiError::Internal);
    }
    let Some(stream) = detail.log_stream else {
        return Ok(EvidenceAvailability::unavailable(
            AvailabilityReason::NotProduced,
        ));
    };
    if !conformance_log_stream_is_valid(detail.job.log_publication.as_ref(), attempt.id, &stream) {
        return Err(ApiError::Internal);
    }
    let segments = load_log_segments(state, &scope, &stream, blob_budget).await?;
    Ok(EvidenceAvailability::present(LogDocument {
        stream_id: stream.id.as_uuid().to_string(),
        attempt_id: stream.attempt_id.as_uuid().to_string(),
        schema_version: stream.schema.get(),
        opened_at_ms: stream.opened_at.get(),
        closed_at_ms: availability(stream.closed_at.map(automata_ci_core::UnixMillis::get)),
        segments,
    }))
}

fn conformance_log_stream_is_valid(
    job_publication: Option<&HumanOutputPublication>,
    attempt_id: automata_ci_core::AttemptId,
    stream: &HumanLogStream,
) -> bool {
    stream.attempt_id == attempt_id
        && job_publication == Some(&stream.publication)
        && log_stream_safety_is_valid(stream)
}

async fn load_log_segments(
    state: &ConformanceApiState,
    scope: &HumanJobScope,
    stream: &HumanLogStream,
    blob_budget: &mut u64,
) -> Result<Vec<LogSegmentDocument>, ApiError> {
    let mut cursor: Option<HumanLogSegmentCursor> = None;
    let mut observed_cursors = Vec::new();
    let mut segments = Vec::new();
    let mut expected_first_sequence = 0_u64;
    let mut end_of_stream_observed = false;
    let mut page_count = 0_usize;
    loop {
        page_count = page_count.checked_add(1).ok_or(ApiError::TooLarge)?;
        if page_count > MAX_CONFORMANCE_LOG_PAGES {
            return Err(ApiError::TooLarge);
        }
        let page = state
            .reads
            .list_log_segments(&HumanLogSegmentQuery {
                scope: scope.clone(),
                stream_id: stream.id,
                cursor,
                limit: HumanLogSegmentPageSize::default(),
            })
            .await
            .map_err(|error| store_error(&error))?
            .ok_or(ApiError::Internal)?;
        if page.stream != *stream {
            return Err(ApiError::Internal);
        }
        if segments.len().saturating_add(page.segments.len()) > MAX_CONFORMANCE_LOG_SEGMENTS {
            return Err(ApiError::TooLarge);
        }
        for segment in page.segments {
            validate_log_segment_order(
                &mut expected_first_sequence,
                &mut end_of_stream_observed,
                segment.first_sequence.get(),
                segment.last_sequence.get(),
                segment.end_of_stream,
            )?;
            *blob_budget = add_blob_budget(*blob_budget, segment.uncompressed_size)?;
            let blob = state
                .blobs
                .get_verified(&segment.descriptor, segment.descriptor.size())
                .await
                .map_err(blob_error)?;
            let expectation = LogSegmentExpectation::new(
                stream.attempt_id,
                stream.id,
                segment.first_sequence,
                segment.last_sequence,
                segment.uncompressed_size,
                segment.end_of_stream,
            );
            let frames =
                tokio::task::spawn_blocking(move || decode_log_segment(&blob, expectation))
                    .await
                    .map_err(|_| ApiError::Unavailable)?
                    .map_err(|_| ApiError::Internal)?;
            let descriptor = segment.descriptor;
            segments.push(LogSegmentDocument {
                first_sequence: segment.first_sequence.get(),
                last_sequence: segment.last_sequence.get(),
                object_key: descriptor.key().as_str().to_owned(),
                sha256: descriptor.digest().to_string(),
                encoded_size: descriptor.size(),
                uncompressed_size: segment.uncompressed_size,
                media_type: descriptor.media_type().as_str().to_owned(),
                stored_at_ms: segment.stored_at.get(),
                end_of_stream: segment.end_of_stream,
                frames,
            });
        }
        let Some(next) = page.newer_cursor else {
            break;
        };
        advance_log_cursor(&mut cursor, &mut observed_cursors, next)?;
    }
    validate_log_terminal_state(stream.closed_at.is_some(), end_of_stream_observed)?;
    Ok(segments)
}

fn advance_log_cursor(
    cursor: &mut Option<HumanLogSegmentCursor>,
    observed: &mut Vec<HumanLogSegmentCursor>,
    next: HumanLogSegmentCursor,
) -> Result<(), ApiError> {
    if *cursor == Some(next) || observed.contains(&next) {
        return Err(ApiError::Internal);
    }
    observed.push(next);
    *cursor = Some(next);
    Ok(())
}

fn validate_log_segment_order(
    expected_first_sequence: &mut u64,
    end_of_stream_observed: &mut bool,
    first_sequence: u64,
    last_sequence: u64,
    end_of_stream: bool,
) -> Result<(), ApiError> {
    if *end_of_stream_observed
        || first_sequence != *expected_first_sequence
        || last_sequence < first_sequence
    {
        return Err(ApiError::Internal);
    }
    *expected_first_sequence = last_sequence.checked_add(1).ok_or(ApiError::Internal)?;
    *end_of_stream_observed = end_of_stream;
    Ok(())
}

fn validate_log_terminal_state(
    stream_is_closed: bool,
    end_of_stream_observed: bool,
) -> Result<(), ApiError> {
    if stream_is_closed && !end_of_stream_observed {
        return Err(ApiError::Internal);
    }
    Ok(())
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
) -> Result<(ProviderRepositoryId, String), ApiError> {
    let Path((provider_repository_id, delivery_id)) = path.map_err(|_| ApiError::InvalidRequest)?;
    let parsed = provider_repository_id
        .parse::<u64>()
        .map_err(|_| ApiError::InvalidRequest)?;
    if parsed.to_string() != provider_repository_id {
        return Err(ApiError::InvalidRequest);
    }
    let repository_id = ProviderRepositoryId::new(parsed).map_err(|_| ApiError::InvalidRequest)?;
    if delivery_id.is_empty() {
        return Err(ApiError::InvalidRequest);
    }
    Ok((repository_id, delivery_id))
}

fn cli_snapshot(request: &Request) -> Result<AuthenticatedRequestSnapshot, ApiError> {
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .ok_or(ApiError::Unauthorized)?;
    if snapshot.session().identity().kind() != SessionKind::Cli {
        return Err(ApiError::Unauthorized);
    }
    Ok(snapshot.clone())
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

fn json_response(
    status: StatusCode,
    media_type: &'static str,
    document: &impl Serialize,
) -> Response {
    let Ok(body) = serde_json::to_vec(document) else {
        return ApiError::Internal.into_response();
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
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
    workflow_name: String,
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
    job_ir: JobIrEnvelope,
    runtime_context: RuntimeContextDocument,
    latest_attempt: Option<AttemptDocument>,
    #[serde(skip)]
    logs: EvidenceAvailability<LogDocument>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConformanceExportDocumentV2 {
    schema_version: u16,
    delivery: DeliveryDocumentV2,
    runs: Vec<RunDocumentV2>,
}

impl ConformanceExportDocumentV2 {
    fn from_v1(document: ConformanceExportDocument) -> Self {
        Self {
            schema_version: CONFORMANCE_EXPORT_V2_SCHEMA_VERSION,
            delivery: DeliveryDocumentV2::from_v1(document.delivery),
            runs: document
                .runs
                .into_iter()
                .map(RunDocumentV2::from_v1)
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryDocumentV2 {
    id: String,
    external_id: String,
    state: &'static str,
    attempts: u16,
    accepted_at_ms: i64,
    completed_at_ms: EvidenceAvailability<i64>,
    workflows: Vec<WorkflowDeliveryDocument>,
}

impl DeliveryDocumentV2 {
    fn from_v1(delivery: DeliveryDocument) -> Self {
        Self {
            id: delivery.id,
            external_id: delivery.external_id,
            state: delivery.state,
            attempts: delivery.attempts,
            accepted_at_ms: delivery.accepted_at_ms,
            completed_at_ms: availability(delivery.completed_at_ms),
            workflows: delivery.workflows,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDocumentV2 {
    id: String,
    workflow_id: String,
    workflow_path: String,
    workflow_name: String,
    run_number: u64,
    run_attempt: u32,
    event_name: String,
    head_commit: String,
    git_ref: EvidenceAvailability<String>,
    status: &'static str,
    conclusion: EvidenceAvailability<&'static str>,
    created_at_ms: i64,
    updated_at_ms: i64,
    finished_at_ms: EvidenceAvailability<i64>,
    jobs: Vec<JobDocumentV2>,
    artifacts: Vec<ArtifactDocumentV2>,
    services: EvidenceAvailability<Vec<serde_json::Value>>,
    caches: EvidenceAvailability<Vec<serde_json::Value>>,
    effective_authority: EvidenceAvailability<serde_json::Value>,
    cleanup: EvidenceAvailability<serde_json::Value>,
}

impl RunDocumentV2 {
    fn from_v1(run: RunDocument) -> Self {
        Self {
            id: run.id,
            workflow_id: run.workflow_id,
            workflow_path: run.workflow_path,
            workflow_name: run.workflow_name,
            run_number: run.run_number,
            run_attempt: run.run_attempt,
            event_name: run.event_name,
            head_commit: run.head_commit,
            git_ref: availability(run.git_ref),
            status: run.status,
            conclusion: availability(run.conclusion),
            created_at_ms: run.created_at_ms,
            updated_at_ms: run.updated_at_ms,
            finished_at_ms: availability(run.finished_at_ms),
            jobs: run.jobs.into_iter().map(JobDocumentV2::from_v1).collect(),
            artifacts: run
                .artifacts
                .into_iter()
                .map(ArtifactDocumentV2::from_v1)
                .collect(),
            services: EvidenceAvailability::unavailable(AvailabilityReason::NotRetainedBySchema),
            caches: EvidenceAvailability::unavailable(AvailabilityReason::NotRetainedBySchema),
            effective_authority: EvidenceAvailability::unavailable(
                AvailabilityReason::NotRetainedBySchema,
            ),
            cleanup: EvidenceAvailability::unavailable(AvailabilityReason::NotRetainedBySchema),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactDocumentV2 {
    name: String,
    mime_type: String,
    size: u64,
    sha256: String,
    expires_at_seconds: EvidenceAvailability<i64>,
    finalized_at_seconds: i64,
}

impl ArtifactDocumentV2 {
    fn from_v1(artifact: ArtifactDocument) -> Self {
        Self {
            name: artifact.name,
            mime_type: artifact.mime_type,
            size: artifact.size,
            sha256: artifact.sha256,
            expires_at_seconds: availability(artifact.expires_at_seconds),
            finalized_at_seconds: artifact.finalized_at_seconds,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobDocumentV2 {
    id: String,
    logical_key: String,
    display_name: String,
    created_at_ms: i64,
    job_ir: EvidenceAvailability<JobIrEnvelope>,
    runtime_context: EvidenceAvailability<RuntimeContextDocument>,
    latest_attempt: EvidenceAvailability<AttemptDocumentV2>,
    logs: EvidenceAvailability<LogDocument>,
}

impl JobDocumentV2 {
    fn from_v1(job: JobDocument) -> Self {
        Self {
            id: job.id,
            logical_key: job.logical_key,
            display_name: job.display_name,
            created_at_ms: job.created_at_ms,
            job_ir: EvidenceAvailability::present(job.job_ir),
            runtime_context: EvidenceAvailability::present(job.runtime_context),
            latest_attempt: match job.latest_attempt {
                Some(attempt) => EvidenceAvailability::present(AttemptDocumentV2::from_v1(attempt)),
                None => EvidenceAvailability::unavailable(AvailabilityReason::NotProduced),
            },
            logs: job.logs,
        }
    }
}

fn availability<T>(value: Option<T>) -> EvidenceAvailability<T> {
    match value {
        Some(value) => EvidenceAvailability::present(value),
        None => EvidenceAvailability::unavailable(AvailabilityReason::NotProduced),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttemptDocumentV2 {
    id: String,
    number: u32,
    lifecycle: &'static str,
    queued_at_ms: i64,
    started_at_ms: EvidenceAvailability<i64>,
    finished_at_ms: EvidenceAvailability<i64>,
    runner: EvidenceAvailability<RunnerDocument>,
    result: EvidenceAvailability<JobResultDocumentV2>,
}

impl AttemptDocumentV2 {
    fn from_v1(attempt: AttemptDocument) -> Self {
        Self {
            id: attempt.id,
            number: attempt.number,
            lifecycle: attempt.lifecycle,
            queued_at_ms: attempt.queued_at_ms,
            started_at_ms: availability(attempt.started_at_ms),
            finished_at_ms: availability(attempt.finished_at_ms),
            runner: availability(attempt.runner),
            result: match attempt.result {
                Some(result) => {
                    EvidenceAvailability::present(JobResultDocumentV2::from_result(&result))
                }
                None => EvidenceAvailability::unavailable(AvailabilityReason::NotProduced),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobResultDocumentV2 {
    schema_version: u16,
    attempt_id: String,
    conclusion: automata_ci_core::JobConclusion,
    secret_exposure: automata_ci_core::JobSecretExposure,
    outputs: BTreeMap<String, automata_ci_core::JobResultOutput>,
    steps: Vec<StepResultDocumentV2>,
    completed_at_ms: i64,
}

impl JobResultDocumentV2 {
    fn from_result(result: &JobResult) -> Self {
        Self {
            schema_version: result.schema_version(),
            attempt_id: result.attempt_id().as_uuid().to_string(),
            conclusion: result.conclusion(),
            secret_exposure: result.secret_exposure(),
            outputs: result.outputs().clone(),
            steps: result
                .steps()
                .iter()
                .map(StepResultDocumentV2::from_result)
                .collect(),
            completed_at_ms: result.completed_at().get(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StepResultDocumentV2 {
    id: String,
    outcome: automata_ci_core::JobConclusion,
    conclusion: automata_ci_core::JobConclusion,
    started_at_ms: i64,
    completed_at_ms: i64,
    outputs: EvidenceAvailability<BTreeMap<String, automata_ci_core::JobResultOutput>>,
    summary_markdown: EvidenceAvailability<String>,
    annotations: Vec<automata_ci_core::StepAnnotation>,
}

impl StepResultDocumentV2 {
    fn from_result(result: &automata_ci_core::StepResult) -> Self {
        Self {
            id: result.step_id().as_str().to_owned(),
            outcome: result.outcome(),
            conclusion: result.conclusion(),
            started_at_ms: result.started_at().get(),
            completed_at_ms: result.completed_at().get(),
            outputs: EvidenceAvailability::unavailable(AvailabilityReason::NotRetainedBySchema),
            summary_markdown: result.summary_markdown().map_or_else(
                || EvidenceAvailability::unavailable(AvailabilityReason::NotProduced),
                |summary| EvidenceAvailability::present(summary.to_owned()),
            ),
            annotations: result.annotations().to_vec(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogDocument {
    stream_id: String,
    attempt_id: String,
    schema_version: u16,
    opened_at_ms: i64,
    closed_at_ms: EvidenceAvailability<i64>,
    segments: Vec<LogSegmentDocument>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogSegmentDocument {
    first_sequence: u64,
    last_sequence: u64,
    object_key: String,
    sha256: String,
    encoded_size: u64,
    uncompressed_size: u64,
    media_type: String,
    stored_at_ms: i64,
    end_of_stream: bool,
    frames: Vec<automata_ci_core::LogFrame>,
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

    fn valid_log_stream(
        attempt_id: automata_ci_core::AttemptId,
    ) -> (HumanOutputPublication, HumanLogStream) {
        let publication = HumanOutputPublication {
            secret_exposure: automata_ci_auth::authorization::SecretExposureClass::Secretless,
            requested_visibility: automata_ci_auth::authorization::OutputVisibility::Private,
            effective_visibility: automata_ci_auth::authorization::OutputVisibility::Private,
            safety_reason: "fixture".to_owned(),
            safety_schema: u16::try_from(automata_ci_store::HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA)
                .expect("publication safety schema fits u16"),
        };
        let stream = HumanLogStream {
            id: automata_ci_core::LogStreamId::new(),
            attempt_id,
            schema: automata_ci_store::DocumentSchema::new(1).expect("log schema"),
            opened_at: automata_ci_core::UnixMillis::new(1),
            closed_at: None,
            raw_log_disposition: automata_ci_store::HumanRawLogDisposition::Persist,
            publication: publication.clone(),
        };
        (publication, stream)
    }

    #[test]
    fn conformance_logs_require_current_matching_publication_safety() {
        let attempt_id = automata_ci_core::AttemptId::new();
        let (publication, mut stream) = valid_log_stream(attempt_id);
        assert!(conformance_log_stream_is_valid(
            Some(&publication),
            attempt_id,
            &stream
        ));
        assert!(!conformance_log_stream_is_valid(
            Some(&publication),
            automata_ci_core::AttemptId::new(),
            &stream
        ));

        stream.publication.safety_schema += 1;
        let noncurrent = stream.publication.clone();
        assert!(!conformance_log_stream_is_valid(
            Some(&noncurrent),
            attempt_id,
            &stream
        ));

        let (mut mismatched, stream) = valid_log_stream(attempt_id);
        mismatched.safety_reason = "different-fixture".to_owned();
        assert!(!conformance_log_stream_is_valid(
            Some(&mismatched),
            attempt_id,
            &stream
        ));

        let (_, mut stream) = valid_log_stream(attempt_id);
        stream.publication.secret_exposure =
            automata_ci_auth::authorization::SecretExposureClass::ReadableSecret;
        stream.publication.effective_visibility =
            automata_ci_auth::authorization::OutputVisibility::Authenticated;
        let nonprivate = stream.publication.clone();
        assert!(!conformance_log_stream_is_valid(
            Some(&nonprivate),
            attempt_id,
            &stream
        ));

        stream.publication.effective_visibility =
            automata_ci_auth::authorization::OutputVisibility::Private;
        let private = stream.publication.clone();
        assert!(conformance_log_stream_is_valid(
            Some(&private),
            attempt_id,
            &stream
        ));
    }

    fn representative_job_result(attempt_id: automata_ci_core::AttemptId) -> JobResult {
        let step = automata_ci_core::StepResult::new(
            automata_ci_core::StepId::new("build").expect("step ID"),
            JobConclusion::Success,
            JobConclusion::Success,
            automata_ci_core::UnixMillis::new(12),
            automata_ci_core::UnixMillis::new(20),
        )
        .with_summary_markdown("# summary")
        .with_annotations(vec![automata_ci_core::StepAnnotation::new(
            automata_ci_core::StepAnnotationLevel::Notice,
            "compiled",
            vec![automata_ci_core::StepAnnotationProperty::new(
                "file",
                "src/main.rs",
            )],
        )]);
        JobResult::new(
            attempt_id,
            JobConclusion::Success,
            automata_ci_core::JobSecretExposure::Secretless,
            automata_ci_core::UnixMillis::new(20),
        )
        .with_outputs(BTreeMap::from([(
            "answer".to_owned(),
            automata_ci_core::JobResultOutput::public("42").expect("public output"),
        )]))
        .with_steps(vec![step])
    }

    fn representative_log_document(attempt_id: automata_ci_core::AttemptId) -> LogDocument {
        let stream_id = automata_ci_core::LogStreamId::from_uuid(uuid::Uuid::from_u128(8));
        let frame = automata_ci_core::LogFrame::new(
            stream_id,
            attempt_id,
            automata_ci_core::LogSequence::new(0),
            automata_ci_core::UnixMillis::new(19),
            automata_ci_core::LogChannel::Stdout,
            b"ok\n".to_vec(),
            true,
        )
        .expect("log frame");
        LogDocument {
            stream_id: stream_id.as_uuid().to_string(),
            attempt_id: attempt_id.as_uuid().to_string(),
            schema_version: automata_ci_core::CORE_SCHEMA_VERSION,
            opened_at_ms: 12,
            closed_at_ms: EvidenceAvailability::present(20),
            segments: vec![LogSegmentDocument {
                first_sequence: 0,
                last_sequence: 0,
                object_key: "logs/segment-0".to_owned(),
                sha256: "b".repeat(64),
                encoded_size: 3,
                uncompressed_size: 3,
                media_type: "application/vnd.automata.log-segment.v1+jsonl".to_owned(),
                stored_at_ms: 20,
                end_of_stream: true,
                frames: vec![frame],
            }],
        }
    }

    fn representative_job_evidence() -> (JobIrEnvelope, RuntimeContextDocument) {
        let job_ir = JobIrEnvelope::new(
            WorkflowId::from_uuid(uuid::Uuid::from_u128(1)),
            automata_ci_core::JobSource::new(
                "github",
                "automata-ci/automata",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ".ci/workflows/ci.yml",
                "push",
            ),
            automata_ci_core::JobExecutionContext::new(
                "CI",
                "refs/heads/main",
                "/__w/automata/automata",
                automata_ci_core::JobContentReference::new(
                    "events/push.json",
                    automata_ci_core::Sha256Digest::from_bytes([0x11; 32]),
                    2,
                    "application/json",
                ),
                automata_ci_core::JobContentReference::new(
                    "contexts/build.pb",
                    automata_ci_core::Sha256Digest::from_bytes([0x22; 32]),
                    2,
                    automata_ci_core::JOB_RUNTIME_CONTEXT_MEDIA_TYPE,
                ),
            ),
            automata_ci_core::JobIr::new(
                automata_ci_core::JobId::from_uuid(uuid::Uuid::from_u128(3)),
                RunId::from_uuid(uuid::Uuid::from_u128(2)),
                "Build",
                automata_ci_core::RunnerRequirements::default(),
                automata_ci_core::JobInstanceIdentity::new(
                    "build",
                    0,
                    1,
                    automata_ci_core::Sha256Digest::from_bytes([0x33; 32]),
                )
                .expect("job instance"),
                false,
                Vec::new(),
            ),
        );
        job_ir.validate().expect("representative JobIR");
        let runtime_context = RuntimeContextDocument {
            matrix: ContextValue::empty_object(),
            strategy: StrategyContext::new(true, 0, 1, 1).expect("strategy"),
        };
        (job_ir, runtime_context)
    }

    fn representative_export_document() -> ConformanceExportDocument {
        let attempt_id = automata_ci_core::AttemptId::from_uuid(uuid::Uuid::from_u128(7));
        let result = representative_job_result(attempt_id);
        let logs = representative_log_document(attempt_id);
        let (job_ir, runtime_context) = representative_job_evidence();

        ConformanceExportDocument {
            schema_version: CONFORMANCE_EXPORT_V1_SCHEMA_VERSION,
            delivery: DeliveryDocument {
                id: "delivery".to_owned(),
                external_id: "external-delivery".to_owned(),
                state: "completed",
                attempts: 1,
                accepted_at_ms: 10,
                completed_at_ms: Some(20),
                workflows: vec![WorkflowDeliveryDocument {
                    path: ".ci/workflows/ci.yml".to_owned(),
                    outcome: WorkflowDeliveryOutcomeDocument::Admitted {
                        run_id: "run".to_owned(),
                    },
                }],
            },
            runs: vec![RunDocument {
                id: "run".to_owned(),
                workflow_id: "workflow".to_owned(),
                workflow_path: ".ci/workflows/ci.yml".to_owned(),
                workflow_name: "CI".to_owned(),
                run_number: 4,
                run_attempt: 1,
                event_name: "push".to_owned(),
                head_commit: "a".repeat(40),
                git_ref: Some("refs/heads/main".to_owned()),
                status: "completed",
                conclusion: Some("success"),
                created_at_ms: 10,
                updated_at_ms: 20,
                finished_at_ms: Some(20),
                jobs: vec![JobDocument {
                    id: "job".to_owned(),
                    logical_key: "build".to_owned(),
                    display_name: "Build".to_owned(),
                    created_at_ms: 10,
                    job_ir,
                    runtime_context,
                    latest_attempt: Some(AttemptDocument {
                        id: "attempt".to_owned(),
                        number: 1,
                        lifecycle: "succeeded",
                        queued_at_ms: 11,
                        started_at_ms: Some(12),
                        finished_at_ms: Some(20),
                        runner: Some(RunnerDocument {
                            id: "runner".to_owned(),
                            name: "linux".to_owned(),
                        }),
                        result: Some(result),
                    }),
                    logs: EvidenceAvailability::present(logs),
                }],
                artifacts: vec![ArtifactDocument {
                    name: "bundle".to_owned(),
                    mime_type: "application/zip".to_owned(),
                    size: 3,
                    sha256: "c".repeat(64),
                    expires_at_seconds: None,
                    finalized_at_seconds: 30,
                }],
            }],
        }
    }

    fn assert_export_golden(actual: impl Serialize, expected: &str) {
        let actual = serde_json::to_value(actual).expect("export JSON");
        let expected: serde_json::Value = serde_json::from_str(expected).expect("golden JSON");
        assert_eq!(actual, expected);
    }

    #[test]
    fn provider_repository_ids_are_canonical_and_positive() {
        assert_eq!(
            delivery_target(Ok(Path(("42".to_owned(), "delivery".to_owned()))))
                .expect("target")
                .0
                .get(),
            42
        );
        for invalid in ["0", "01", "+1", "-1", "not-a-number"] {
            assert!(
                delivery_target(Ok(Path((invalid.to_owned(), "delivery".to_owned())))).is_err()
            );
        }
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

    #[test]
    fn deployment_bearer_parser_accepts_one_exact_opaque_credential() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer deployment-secret"),
        );
        assert_eq!(exact_bearer(&headers), Ok("deployment-secret"));

        for malformed in [
            "Basic deployment-secret",
            "Bearer",
            "Bearer  deployment-secret",
            "Bearer deployment-secret extra",
        ] {
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(malformed).expect("header"),
            );
            assert_eq!(exact_bearer(&headers), Err(ApiError::Unauthorized));
        }
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second-secret"),
        );
        assert_eq!(exact_bearer(&headers), Err(ApiError::Unauthorized));
    }

    #[test]
    fn export_schema_is_selected_by_one_exact_accept_media_type() {
        let mut headers = HeaderMap::new();
        assert_eq!(requested_export_version(&headers), Ok(ExportVersion::V1));
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(requested_export_version(&headers), Ok(ExportVersion::V1));
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(CONFORMANCE_EXPORT_V2_MEDIA_TYPE),
        );
        assert_eq!(requested_export_version(&headers), Ok(ExportVersion::V2));
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.automata.conformance.v3+json"),
        );
        assert_eq!(
            requested_export_version(&headers),
            Err(ApiError::InvalidRequest)
        );
    }

    #[test]
    fn v1_export_remains_a_supported_prior_contract() {
        assert_eq!(CONFORMANCE_EXPORT_V1_SCHEMA_VERSION, 1);
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(requested_export_version(&headers), Ok(ExportVersion::V1));
    }

    #[test]
    fn v1_export_schema_is_the_exact_default_contract() {
        assert_eq!(CONFORMANCE_EXPORT_V1_SCHEMA_VERSION, 1);
        assert_eq!(
            requested_export_version(&HeaderMap::new()),
            Ok(ExportVersion::V1)
        );
    }

    #[test]
    fn v2_export_schema_is_selected_only_by_its_exact_media_type() {
        assert_eq!(CONFORMANCE_EXPORT_V2_SCHEMA_VERSION, 2);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(CONFORMANCE_EXPORT_V2_MEDIA_TYPE),
        );
        assert_eq!(requested_export_version(&headers), Ok(ExportVersion::V2));
    }

    #[test]
    fn v1_and_v2_exports_match_complete_wire_goldens() {
        assert_export_golden(
            representative_export_document(),
            include_str!("fixtures/conformance-export-v1.json"),
        );
        assert_export_golden(
            ConformanceExportDocumentV2::from_v1(representative_export_document()),
            include_str!("fixtures/conformance-export-v2.json"),
        );
    }

    #[test]
    fn v2_step_outputs_are_presence_aware_and_never_synthesized_empty() {
        let attempt_id = automata_ci_core::AttemptId::from_uuid(uuid::Uuid::from_u128(7));
        let step = automata_ci_core::StepResult::new(
            automata_ci_core::StepId::new("build").expect("step ID"),
            JobConclusion::Success,
            JobConclusion::Success,
            automata_ci_core::UnixMillis::new(10),
            automata_ci_core::UnixMillis::new(20),
        );
        let result = JobResult::new(
            attempt_id,
            JobConclusion::Success,
            automata_ci_core::JobSecretExposure::Secretless,
            automata_ci_core::UnixMillis::new(20),
        )
        .with_steps(vec![step]);
        let v2 = JobResultDocumentV2::from_result(&result);
        let json = serde_json::to_value(v2).expect("v2 JSON");
        assert_eq!(json["steps"][0]["outputs"]["state"], "unavailable");
        assert_eq!(
            json["steps"][0]["outputs"]["reason"],
            "not_retained_by_schema"
        );
        assert!(json["steps"][0]["outputs"].get("value").is_none());
    }

    #[test]
    fn every_optional_v2_field_has_an_explicit_availability_state() {
        let delivery = DeliveryDocumentV2::from_v1(DeliveryDocument {
            id: "delivery".to_owned(),
            external_id: "external".to_owned(),
            state: "pending",
            attempts: 0,
            accepted_at_ms: 1,
            completed_at_ms: None,
            workflows: Vec::new(),
        });
        let (job_ir, runtime_context) = representative_job_evidence();
        let v2 = RunDocumentV2::from_v1(RunDocument {
            id: "run".to_owned(),
            workflow_id: "workflow".to_owned(),
            workflow_path: ".ci/workflows/ci.yml".to_owned(),
            workflow_name: "CI".to_owned(),
            run_number: 1,
            run_attempt: 1,
            event_name: "push".to_owned(),
            head_commit: "a".repeat(40),
            git_ref: None,
            status: "queued",
            conclusion: None,
            created_at_ms: 1,
            updated_at_ms: 1,
            finished_at_ms: None,
            jobs: vec![JobDocument {
                id: "job".to_owned(),
                logical_key: "build".to_owned(),
                display_name: "build".to_owned(),
                created_at_ms: 1,
                job_ir,
                runtime_context,
                latest_attempt: Some(AttemptDocument {
                    id: "attempt".to_owned(),
                    number: 1,
                    lifecycle: "queued",
                    queued_at_ms: 1,
                    started_at_ms: None,
                    finished_at_ms: None,
                    runner: None,
                    result: None,
                }),
                logs: EvidenceAvailability::unavailable(AvailabilityReason::NotProduced),
            }],
            artifacts: vec![ArtifactDocument {
                name: "artifact".to_owned(),
                mime_type: "application/zip".to_owned(),
                size: 1,
                sha256: "b".repeat(64),
                expires_at_seconds: None,
                finalized_at_seconds: 1,
            }],
        });
        let delivery = serde_json::to_value(delivery).expect("delivery JSON");
        assert_eq!(delivery["completedAtMs"]["state"], "unavailable");
        let json = serde_json::to_value(v2).expect("v2 JSON");
        assert_eq!(json["workflowName"], "CI");
        assert_eq!(json["jobs"][0]["jobIr"]["state"], "present");
        assert_eq!(json["jobs"][0]["runtimeContext"]["state"], "present");
        for pointer in [
            "/gitRef",
            "/conclusion",
            "/finishedAtMs",
            "/jobs/0/latestAttempt/value/startedAtMs",
            "/jobs/0/latestAttempt/value/finishedAtMs",
            "/jobs/0/latestAttempt/value/runner",
            "/jobs/0/latestAttempt/value/result",
            "/artifacts/0/expiresAtSeconds",
            "/services",
            "/caches",
            "/effectiveAuthority",
            "/cleanup",
        ] {
            assert_eq!(
                json.pointer(pointer)
                    .and_then(|value| value.get("state"))
                    .and_then(serde_json::Value::as_str),
                Some("unavailable"),
                "missing explicit availability at {pointer}"
            );
        }
    }

    #[test]
    fn log_export_rejects_gaps_after_end_and_cursor_cycles() {
        let mut expected = 0;
        let mut ended = false;
        assert_eq!(
            validate_log_segment_order(&mut expected, &mut ended, 0, 2, false),
            Ok(())
        );
        assert_eq!(
            validate_log_segment_order(&mut expected, &mut ended, 3, 4, true),
            Ok(())
        );
        assert_eq!(
            validate_log_segment_order(&mut expected, &mut ended, 5, 5, false),
            Err(ApiError::Internal)
        );

        let cursor_a = HumanLogSegmentCursor {
            sequence: automata_ci_core::LogSequence::new(2),
            direction: automata_ci_store::HumanLogSegmentPageDirection::Newer,
        };
        let cursor_b = HumanLogSegmentCursor {
            sequence: automata_ci_core::LogSequence::new(4),
            direction: automata_ci_store::HumanLogSegmentPageDirection::Newer,
        };
        let mut cursor = None;
        let mut observed = Vec::new();
        assert_eq!(
            advance_log_cursor(&mut cursor, &mut observed, cursor_a),
            Ok(())
        );
        assert_eq!(
            advance_log_cursor(&mut cursor, &mut observed, cursor_b),
            Ok(())
        );
        assert_eq!(
            advance_log_cursor(&mut cursor, &mut observed, cursor_a),
            Err(ApiError::Internal)
        );

        let mut gap_expected = 0;
        let mut gap_ended = false;
        assert_eq!(
            validate_log_segment_order(&mut gap_expected, &mut gap_ended, 1, 1, false),
            Err(ApiError::Internal)
        );
    }

    #[test]
    fn closed_log_stream_requires_a_terminal_segment() {
        assert_eq!(validate_log_terminal_state(false, false), Ok(()));
        assert_eq!(validate_log_terminal_state(false, true), Ok(()));
        assert_eq!(validate_log_terminal_state(true, true), Ok(()));
        assert_eq!(
            validate_log_terminal_state(true, false),
            Err(ApiError::Internal)
        );
    }
}
