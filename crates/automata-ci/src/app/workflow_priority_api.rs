//! Authenticated HTTP boundary for workflow-run priority changes.

use std::{fmt, sync::Arc};

use automata_ci_auth::secret::SecretString;
use automata_ci_auth::{
    management::{ManagementActor, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::Clock,
};
use automata_ci_core::RunId;
use automata_ci_store::{
    HumanWorkflowReadRepository, RepositoryCoordinate, TenantScope, UpdateWorkflowRunPriority,
    UpdateWorkflowRunPriorityOutcome, WorkflowPriorityRepository, WorkflowPriorityRepositoryError,
    WorkflowRunPriority,
};
use axum::{
    Router,
    body::to_bytes,
    extract::{Path, Request, State, rejection::PathRejection},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::put,
};
use serde::{Deserialize, Serialize};

use super::api_support::{ApiError, canonical_uuid, is_json_content_type, json_response};

const MAX_REQUEST_BYTES: usize = 1_024;
const SCM_PROVIDER: &str = "github";

pub(crate) const WORKFLOW_PRIORITY_PATH: &str =
    "/api/v1/repositories/{owner}/{repository}/runs/{run_id}/priority";
pub(crate) const WORKFLOW_BROWSER_PRIORITY_PATH: &str =
    "/{owner}/{repository}/actions/runs/{run_id}/priority";
pub(crate) const MAX_PRIORITY_FORM_BYTES: usize = 1_024;

/// Business fields retained by browser-form authentication after CSRF verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedWorkflowPriorityForm {
    priority: u8,
}

impl VerifiedWorkflowPriorityForm {
    pub(crate) const fn priority(self) -> u8 {
        self.priority
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkflowPriorityFormSubmission {
    Valid(VerifiedWorkflowPriorityForm),
    Invalid,
}

pub(crate) fn is_workflow_priority_form(method: &axum::http::Method, path: &str) -> bool {
    *method == axum::http::Method::POST
        && path.starts_with('/')
        && path.contains("/actions/runs/")
        && path.ends_with("/priority")
}

pub(crate) fn workflow_priority_csrf_token(body: &[u8]) -> Result<SecretString, ()> {
    let (csrf_token, _) = parse_priority_form_fields(body)?;
    csrf_token.ok_or(())
}

pub(crate) fn parse_workflow_priority_form(body: &[u8]) -> WorkflowPriorityFormSubmission {
    let Ok((csrf_token, priority)) = parse_priority_form_fields(body) else {
        return WorkflowPriorityFormSubmission::Invalid;
    };
    if csrf_token.is_none() {
        return WorkflowPriorityFormSubmission::Invalid;
    }
    match priority.and_then(|value| value.parse::<u8>().ok()) {
        Some(priority) if priority <= 99 => {
            WorkflowPriorityFormSubmission::Valid(VerifiedWorkflowPriorityForm { priority })
        }
        _ => WorkflowPriorityFormSubmission::Invalid,
    }
}

fn parse_priority_form_fields(body: &[u8]) -> Result<(Option<SecretString>, Option<String>), ()> {
    if body.is_empty() || body.len() > MAX_PRIORITY_FORM_BYTES {
        return Err(());
    }
    let mut csrf_token = None;
    let mut priority = None;
    let mut fields = 0_usize;
    for pair in body.split(|byte| *byte == b'&') {
        fields = fields.checked_add(1).ok_or(())?;
        if fields > 2 {
            return Err(());
        }
        let Some(separator) = pair.iter().position(|byte| *byte == b'=') else {
            return Err(());
        };
        let name = decode_form_component(&pair[..separator])?;
        let value = decode_form_component(&pair[separator + 1..])?;
        match name.as_str() {
            "csrf_token" => {
                if csrf_token.is_some() {
                    return Err(());
                }
                csrf_token = Some(SecretString::new(value).map_err(|_| ())?);
            }
            "priority" => {
                if priority.replace(value).is_some() {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
    }
    Ok((csrf_token, priority))
}

fn decode_form_component(bytes: &[u8]) -> Result<String, ()> {
    super::form::decode_text(bytes, MAX_PRIORITY_FORM_BYTES).map_err(|_| ())
}

#[derive(Clone)]
struct WorkflowPriorityApiState {
    reads: Arc<dyn HumanWorkflowReadRepository>,
    priorities: Arc<dyn WorkflowPriorityRepository>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for WorkflowPriorityApiState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowPriorityApiState")
            .finish_non_exhaustive()
    }
}

pub(crate) fn workflow_priority_api_router(
    reads: Arc<dyn HumanWorkflowReadRepository>,
    priorities: Arc<dyn WorkflowPriorityRepository>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(WORKFLOW_PRIORITY_PATH, put(update_priority))
        .route(
            WORKFLOW_BROWSER_PRIORITY_PATH,
            put(update_priority).post(update_priority),
        )
        .with_state(WorkflowPriorityApiState {
            reads,
            priorities,
            clock,
        })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn update_priority(
    State(state): State<WorkflowPriorityApiState>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let browser_redirect = (request.method() == axum::http::Method::POST).then(|| {
        request
            .uri()
            .path()
            .strip_suffix("/priority")
            .unwrap_or(request.uri().path())
            .to_owned()
    });
    let update = match prepare_update(&state, path, request).await {
        Ok(update) => update,
        Err(error) => return error.into_response(),
    };
    match state.priorities.update_workflow_run_priority(update).await {
        Ok(UpdateWorkflowRunPriorityOutcome::Applied(priority)) => browser_redirect.map_or_else(
            || {
                json_response(
                    StatusCode::OK,
                    &PriorityResponse {
                        priority: priority.level(),
                    },
                )
            },
            |path| Redirect::to(&path).into_response(),
        ),
        Ok(UpdateWorkflowRunPriorityOutcome::AuthorityRejected) => {
            ApiError::Forbidden.into_response()
        }
        Ok(UpdateWorkflowRunPriorityOutcome::NotFound) => ApiError::NotFound.into_response(),
        Ok(
            UpdateWorkflowRunPriorityOutcome::RunNotQueued
            | UpdateWorkflowRunPriorityOutcome::MergeQueueManaged,
        ) => ApiError::Conflict.into_response(),
        Err(WorkflowPriorityRepositoryError::InvalidRequest) => {
            ApiError::InvalidRequest.into_response()
        }
        Err(WorkflowPriorityRepositoryError::Unavailable) => ApiError::Unavailable.into_response(),
        Err(WorkflowPriorityRepositoryError::CorruptData) => ApiError::Internal.into_response(),
    }
}

async fn prepare_update(
    state: &WorkflowPriorityApiState,
    path: Result<Path<(String, String, String)>, PathRejection>,
    request: Request,
) -> Result<UpdateWorkflowRunPriority, ApiError> {
    if request.uri().query().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let Path((owner, repository, run_id)) = path.map_err(|_| ApiError::InvalidRequest)?;
    let coordinate = RepositoryCoordinate::new(SCM_PROVIDER, owner, repository)
        .map_err(|_| ApiError::InvalidRequest)?;
    let run_id = RunId::from_uuid(canonical_uuid(&run_id)?);
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .cloned()
        .ok_or(ApiError::Unauthorized)?;
    let identity = snapshot.session().identity();
    let exact_route = match identity.kind() {
        SessionKind::Cli => request.uri().path().starts_with("/api/v1/"),
        SessionKind::Browser => request.uri().path().contains("/actions/runs/"),
    };
    if !exact_route {
        return Err(ApiError::Unauthorized);
    }
    let tenant = TenantScope::from_authenticated_tenant_id(identity.tenant_id().as_str())
        .map_err(|_| ApiError::Unauthorized)?;
    let resolved = state
        .reads
        .resolve_repository(&tenant, &coordinate)
        .await
        .map_err(|_| ApiError::Unavailable)?
        .ok_or(ApiError::NotFound)?;
    if resolved.scm_provider != SCM_PROVIDER
        || resolved.owner != coordinate.owner()
        || resolved.name != coordinate.name()
        || resolved.resource.tenant_id() != identity.tenant_id()
    {
        return Err(ApiError::Internal);
    }
    let document =
        if let Some(submission) = request.extensions().get::<WorkflowPriorityFormSubmission>() {
            match submission {
                WorkflowPriorityFormSubmission::Valid(form) => PriorityDocument {
                    priority: form.priority(),
                },
                WorkflowPriorityFormSubmission::Invalid => return Err(ApiError::InvalidRequest),
            }
        } else {
            json_document(request).await?
        };
    let priority =
        WorkflowRunPriority::user(document.priority).map_err(|_| ApiError::InvalidRequest)?;
    let revision = ManagementRevision::new(snapshot.session().authorization_revision())
        .map_err(|_| ApiError::Unauthorized)?;
    UpdateWorkflowRunPriority::new(
        ManagementActor::new(
            identity.tenant_id().clone(),
            identity.principal_id().clone(),
            identity.session_id().clone(),
            revision,
            None,
            state.clock.now(),
        ),
        resolved.id,
        run_id,
        priority,
    )
    .map_err(|_| ApiError::InvalidRequest)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorityDocument {
    priority: u8,
}

async fn json_document(request: Request) -> Result<PriorityDocument, ApiError> {
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

#[derive(Debug, Serialize)]
struct PriorityResponse {
    priority: u8,
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    use super::{
        VerifiedWorkflowPriorityForm, WorkflowPriorityFormSubmission, is_workflow_priority_form,
        parse_workflow_priority_form, workflow_priority_csrf_token,
    };

    #[test]
    fn browser_priority_form_is_strict_and_bounded() {
        assert_eq!(
            parse_workflow_priority_form(b"csrf_token=csrf&priority=99"),
            WorkflowPriorityFormSubmission::Valid(VerifiedWorkflowPriorityForm { priority: 99 })
        );
        assert_eq!(
            parse_workflow_priority_form(b"csrf_token=csrf&priority=100"),
            WorkflowPriorityFormSubmission::Invalid
        );
        assert_eq!(
            parse_workflow_priority_form(b"csrf_token=csrf&priority=1&extra=x"),
            WorkflowPriorityFormSubmission::Invalid
        );
        assert!(workflow_priority_csrf_token(b"csrf_token=csrf&priority=1").is_ok());
        assert!(workflow_priority_csrf_token(b"priority=1").is_err());
    }

    #[test]
    fn only_browser_post_priority_routes_are_native_forms() {
        assert!(is_workflow_priority_form(
            &Method::POST,
            "/automata-ci/automata/actions/runs/00000000-0000-4000-8000-000000000001/priority"
        ));
        assert!(!is_workflow_priority_form(
            &Method::PUT,
            "/automata-ci/automata/actions/runs/00000000-0000-4000-8000-000000000001/priority"
        ));
        assert!(!is_workflow_priority_form(
            &Method::POST,
            "/api/v1/repositories/automata-ci/automata/runs/00000000-0000-4000-8000-000000000001/priority"
        ));
    }
}
