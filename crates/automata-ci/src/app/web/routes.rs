use std::{fmt, fmt::Write as _, str::FromStr as _, sync::Arc};

use automata_ci_auth::{
    human::TenantId,
    management::{
        DirectBindingGrantOptionsState, ManagementMutationCapabilities, ManagementRevision,
    },
    request_auth::AuthenticatedRequestSnapshot,
    secret::CsrfToken,
};
use automata_ci_core::{JobId, RunId, WorkflowId};
use automata_ci_ui_renderer::{EmbeddedAsset, RenderError, Renderer, client_assets, find_asset};
use axum::Router;
use axum::body::Body;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Extension, OriginalUri, Path, Query, RawQuery, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH,
    RETRY_AFTER,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;
use tracing::error;

use super::data::{
    EmptyWebData, JobLogRequest, LOG_PAGE_DECODED_BYTES, LOG_PAGE_SIZE, REPOSITORY_PAGE_SIZE,
    RUN_JOB_PAGE_SIZE, RUN_PAGE_SIZE, RbacDirectBindingListRequest, RbacRoleDetailRequest,
    RbacRoleListRequest, RbacUserDetailRequest, RbacUserListRequest, RbacWebData, RbacWebDataError,
    RbacWebReadOutcome, RepositoryDirectoryRequest, RepositoryPath, RequestContext,
    RunDetailRequest, RunListRequest, SetupPageAvailability, SetupPageAvailabilityError,
    SetupPageAvailabilityState, StatusFilter, WebData, WebDataError,
};
use super::encoding::percent_encode;
use super::model;
use super::text::{forbidden_display_character, is_safe_display_text};
use crate::app::rbac_management::{
    RbacManagementFormSubmission, RbacMutationApplied, RbacWebMutationOutcome,
    VerifiedRbacManagementForm,
};
use crate::app::repository_secrets::{
    REPOSITORY_SECRETS_SETTINGS_PATH, RepositorySecretWebError, RepositorySecretsPageRequest,
    RepositorySecretsReadOutcome,
};

const MAX_FILTER_BYTES: usize = 1_024;
const MAX_GIT_REF_BYTES: usize = 1_024;
const GIT_HEAD_REF_PREFIX: &str = "refs/heads/";
const MAX_CURSOR_BYTES: usize = 512;
const MAX_QUERY_BYTES: usize = 4 * 1_024;
const PAGE_CACHE_CONTROL: &str = "no-store";
const GITHUB_AUTHORIZATION_ORIGIN: &str = "https://github.com";
const RBAC_USERS_RETURN_PATH: &str = "/settings/access/users";
const RBAC_ROLES_RETURN_PATH: &str = "/settings/access/roles";
const RBAC_DIRECT_BINDINGS_RETURN_PATH: &str = "/settings/access/direct-bindings";

#[derive(Clone)]
struct WebState {
    renderer: Arc<dyn Renderer>,
    data: Arc<dyn WebData>,
    rbac_data: Option<Arc<dyn RbacWebData>>,
    rbac_mutations: bool,
    setup_page_availability: Option<Arc<dyn SetupPageAvailability>>,
    fallback_context: RequestContext,
    render_permits: Arc<Semaphore>,
}

impl fmt::Debug for WebState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("WebState").finish_non_exhaustive()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunListQuery {
    status: Option<String>,
    branch: Option<String>,
    cursor: Option<String>,
    workflow_cursor: Option<String>,
}

#[derive(Debug)]
struct ValidatedRunListQuery {
    status: StatusFilter,
    branch: Option<String>,
    cursor: Option<String>,
    workflow_cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunDetailQuery {
    job_cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobLogQuery {
    q: Option<String>,
    cursor: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RbacListQuery {
    cursor: Option<String>,
    notice: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RbacDetailQuery {
    notice: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositorySecretsQuery {
    after: Option<String>,
    notice: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryDirectoryQuery {
    cursor: Option<String>,
}

pub fn router(renderer: Arc<dyn Renderer>, max_concurrent_renders: usize) -> Router {
    let tenant = TenantId::new("preview")
        .expect("the built-in dependency-free web tenant must remain valid");
    router_with_data(
        renderer,
        max_concurrent_renders,
        Arc::new(EmptyWebData),
        RequestContext::anonymous(tenant),
    )
}

pub(crate) fn router_with_data(
    renderer: Arc<dyn Renderer>,
    max_concurrent_renders: usize,
    data: Arc<dyn WebData>,
    fallback_context: RequestContext,
) -> Router {
    router_with_optional_rbac_data(
        renderer,
        max_concurrent_renders,
        data,
        None,
        false,
        None,
        fallback_context,
    )
}

/// Builds the ordinary web router plus the availability-guarded anonymous setup page.
///
/// `setup_page_availability` is invoked on every GET. Production composition
/// must inject a fresh durable state read, never a startup snapshot.
pub(crate) fn router_with_data_and_setup_availability(
    renderer: Arc<dyn Renderer>,
    max_concurrent_renders: usize,
    data: Arc<dyn WebData>,
    fallback_context: RequestContext,
    setup_page_availability: Arc<dyn SetupPageAvailability>,
) -> Router {
    router_with_optional_rbac_data(
        renderer,
        max_concurrent_renders,
        data,
        None,
        false,
        Some(setup_page_availability),
        fallback_context,
    )
}

#[cfg(test)]
pub(crate) fn router_with_data_and_rbac(
    renderer: Arc<dyn Renderer>,
    max_concurrent_renders: usize,
    data: Arc<dyn WebData>,
    rbac_data: Arc<dyn RbacWebData>,
    fallback_context: RequestContext,
) -> Router {
    router_with_optional_rbac_data(
        renderer,
        max_concurrent_renders,
        data,
        Some(rbac_data),
        false,
        None,
        fallback_context,
    )
}

pub(crate) fn router_with_data_rbac_and_management(
    renderer: Arc<dyn Renderer>,
    max_concurrent_renders: usize,
    data: Arc<dyn WebData>,
    rbac_data: Arc<dyn RbacWebData>,
    fallback_context: RequestContext,
) -> Router {
    router_with_optional_rbac_data(
        renderer,
        max_concurrent_renders,
        data,
        Some(rbac_data),
        true,
        None,
        fallback_context,
    )
}

/// Builds the full RBAC management router alongside the guarded setup page.
///
/// The setup availability remains a fresh per-GET read. RBAC handlers retain
/// their independent authenticated snapshot, capability, CSRF, and revision
/// checks, so composing both route families does not make either one authority
/// for the other.
pub(crate) fn router_with_data_rbac_management_and_setup_availability(
    renderer: Arc<dyn Renderer>,
    max_concurrent_renders: usize,
    data: Arc<dyn WebData>,
    rbac_data: Arc<dyn RbacWebData>,
    setup_page_availability: Arc<dyn SetupPageAvailability>,
    fallback_context: RequestContext,
) -> Router {
    router_with_optional_rbac_data(
        renderer,
        max_concurrent_renders,
        data,
        Some(rbac_data),
        true,
        Some(setup_page_availability),
        fallback_context,
    )
}

fn router_with_optional_rbac_data(
    renderer: Arc<dyn Renderer>,
    max_concurrent_renders: usize,
    data: Arc<dyn WebData>,
    rbac_data: Option<Arc<dyn RbacWebData>>,
    rbac_mutations: bool,
    setup_page_availability: Option<Arc<dyn SetupPageAvailability>>,
    fallback_context: RequestContext,
) -> Router {
    let router = Router::new()
        .route("/", get(root_redirect))
        .route("/repositories", get(repository_directory))
        .route("/{owner}/{repository}/actions", get(repository_runs))
        .route(
            "/{owner}/{repository}/actions/workflows/{workflow_id}",
            get(workflow_runs),
        )
        .route(
            "/{owner}/{repository}/actions/runs/{run_id}",
            get(run_detail),
        )
        .route(
            "/{owner}/{repository}/actions/runs/{run_id}/jobs/{job_id}",
            get(job_log),
        )
        .route(
            "/{owner}/{repository}/actions/runs/{run_id}/jobs/{job_id}/snapshot",
            get(job_log_snapshot),
        )
        .route(
            "/{owner}/{repository}/actions/runs/{run_id}/artifacts/{artifact_id}",
            get(artifact),
        )
        .route(
            "/{owner}/{repository}/settings/access",
            get(repository_settings),
        )
        .route(REPOSITORY_SECRETS_SETTINGS_PATH, get(repository_secrets))
        .route("/assets/{*asset_path}", get(asset))
        .fallback(fallback_not_found);
    let router = if setup_page_availability.is_some() {
        router.route("/setup", get(installation_setup))
    } else {
        router
    };
    let router = if rbac_data.is_some() && rbac_mutations {
        router
            .route("/settings/access/users", get(rbac_user_list))
            .route(
                "/settings/access/users/{principal_id}",
                get(rbac_user_detail),
            )
            .route(
                "/settings/access/users/{principal_id}/status",
                post(rbac_mutation),
            )
            .route(
                "/settings/access/roles",
                get(rbac_role_list).post(rbac_mutation),
            )
            .route(
                "/settings/access/roles/{role_id}",
                get(rbac_role_detail).post(rbac_mutation),
            )
            .route(
                "/settings/access/roles/{role_id}/delete",
                post(rbac_mutation),
            )
            .route(
                "/settings/access/roles/{role_id}/permissions/{permission}",
                post(rbac_mutation),
            )
            .route(
                "/settings/access/direct-bindings",
                get(rbac_direct_binding_list).post(rbac_mutation),
            )
            .route(
                "/settings/access/direct-bindings/{binding_id}/revoke",
                post(rbac_mutation),
            )
    } else if rbac_data.is_some() {
        router
            .route("/settings/access/users", get(rbac_user_list))
            .route(
                "/settings/access/users/{principal_id}",
                get(rbac_user_detail),
            )
            .route("/settings/access/roles", get(rbac_role_list))
            .route("/settings/access/roles/{role_id}", get(rbac_role_detail))
            .route(
                "/settings/access/direct-bindings",
                get(rbac_direct_binding_list),
            )
    } else {
        router
    };
    router.with_state(WebState {
        renderer,
        data,
        rbac_data,
        rbac_mutations,
        setup_page_availability,
        fallback_context,
        render_permits: Arc::new(Semaphore::new(max_concurrent_renders)),
    })
}

async fn rbac_user_list(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RbacListQuery>, QueryRejection>,
) -> Response<Body> {
    let Ok(Query(query)) = query else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Ok(notice) = rbac_notice(query.notice.as_deref()) else {
        return bad_request();
    };
    let Some(rbac_data) = state.rbac_data.as_ref() else {
        return not_found();
    };
    let Some(Extension(snapshot)) = snapshot else {
        return rbac_unauthorized(RBAC_USERS_RETURN_PATH);
    };
    let context = request_context(&state, context);
    if !rbac_request_context_matches(&context, &snapshot) {
        error!("authenticated RBAC web context did not match its request snapshot");
        return internal_server_error();
    }
    let request = match RbacUserListRequest::new(query.cursor.clone()) {
        Ok(request) => request,
        Err(RbacWebDataError::InvalidRequest) => return bad_request(),
        Err(
            RbacWebDataError::Unavailable
            | RbacWebDataError::Corrupt
            | RbacWebDataError::Unrepresentable,
        ) => {
            return internal_server_error();
        }
    };
    let data = match rbac_data.list_users(&snapshot, &request).await {
        Ok(RbacWebReadOutcome::Authorized(data)) => data,
        Ok(RbacWebReadOutcome::Forbidden) => return rbac_forbidden(),
        Ok(RbacWebReadOutcome::SessionStale) => {
            return rbac_unauthorized(RBAC_USERS_RETURN_PATH);
        }
        Ok(RbacWebReadOutcome::NotFound) => return rbac_not_found(),
        Err(error) => return rbac_data_error_response(error),
    };
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::rbac_user_list(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        query.cursor.as_deref(),
        notice,
        &data,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble RBAC user-list page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn rbac_user_detail(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<String>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RbacDetailQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path(principal_id)), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Ok(notice) = rbac_notice(query.notice.as_deref()) else {
        return bad_request();
    };
    let Some(rbac_data) = state.rbac_data.as_ref() else {
        return not_found();
    };
    let Some(Extension(snapshot)) = snapshot else {
        return rbac_unauthorized(RBAC_USERS_RETURN_PATH);
    };
    let context = request_context(&state, context);
    if !rbac_request_context_matches(&context, &snapshot) {
        error!("authenticated RBAC web context did not match its request snapshot");
        return internal_server_error();
    }
    let request = match RbacUserDetailRequest::new(&principal_id) {
        Ok(request) => request,
        Err(RbacWebDataError::InvalidRequest) => return bad_request(),
        Err(error) => return rbac_data_error_response(error),
    };
    let data = match rbac_data.user_detail(&snapshot, &request).await {
        Ok(RbacWebReadOutcome::Authorized(data)) => data,
        Ok(RbacWebReadOutcome::Forbidden) => return rbac_forbidden(),
        Ok(RbacWebReadOutcome::SessionStale) => {
            return rbac_unauthorized(RBAC_USERS_RETURN_PATH);
        }
        Ok(RbacWebReadOutcome::NotFound) => return rbac_not_found(),
        Err(error) => return rbac_data_error_response(error),
    };
    let Some(page_revision) = authenticated_revision(&snapshot) else {
        return internal_server_error();
    };
    let capabilities = match rbac_mutation_capabilities(
        &state,
        rbac_data,
        &snapshot,
        page_revision,
        RBAC_USERS_RETURN_PATH,
    )
    .await
    {
        Ok(capabilities) => capabilities,
        Err(response) => return response,
    };
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::rbac_user_detail(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        request.principal_id,
        &data,
        notice,
        page_revision,
        capabilities.as_ref(),
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble RBAC user-detail page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn rbac_role_list(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RbacListQuery>, QueryRejection>,
) -> Response<Body> {
    let Ok(Query(query)) = query else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Ok(notice) = rbac_notice(query.notice.as_deref()) else {
        return bad_request();
    };
    let Some(rbac_data) = state.rbac_data.as_ref() else {
        return not_found();
    };
    let Some(Extension(snapshot)) = snapshot else {
        return rbac_unauthorized(RBAC_ROLES_RETURN_PATH);
    };
    let context = request_context(&state, context);
    if !rbac_request_context_matches(&context, &snapshot) {
        error!("authenticated RBAC web context did not match its request snapshot");
        return internal_server_error();
    }
    let request = match RbacRoleListRequest::new(query.cursor.clone()) {
        Ok(request) => request,
        Err(RbacWebDataError::InvalidRequest) => return bad_request(),
        Err(error) => return rbac_data_error_response(error),
    };
    let data = match rbac_data.list_roles(&snapshot, &request).await {
        Ok(RbacWebReadOutcome::Authorized(data)) => data,
        Ok(RbacWebReadOutcome::Forbidden) => return rbac_forbidden(),
        Ok(RbacWebReadOutcome::SessionStale) => {
            return rbac_unauthorized(RBAC_ROLES_RETURN_PATH);
        }
        Ok(RbacWebReadOutcome::NotFound) => return rbac_not_found(),
        Err(error) => return rbac_data_error_response(error),
    };
    let capabilities = match rbac_mutation_capabilities(
        &state,
        rbac_data,
        &snapshot,
        data.mutation_authorization_revision,
        RBAC_ROLES_RETURN_PATH,
    )
    .await
    {
        Ok(capabilities) => capabilities,
        Err(response) => return response,
    };
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::rbac_role_list(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        query.cursor.as_deref(),
        notice,
        &data,
        capabilities.as_ref(),
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble RBAC role-list page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn rbac_role_detail(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<String>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RbacDetailQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path(role_id)), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Ok(notice) = rbac_notice(query.notice.as_deref()) else {
        return bad_request();
    };
    let Some(rbac_data) = state.rbac_data.as_ref() else {
        return not_found();
    };
    let Some(Extension(snapshot)) = snapshot else {
        return rbac_unauthorized(RBAC_ROLES_RETURN_PATH);
    };
    let context = request_context(&state, context);
    if !rbac_request_context_matches(&context, &snapshot) {
        error!("authenticated RBAC web context did not match its request snapshot");
        return internal_server_error();
    }
    let request = match RbacRoleDetailRequest::new(&role_id) {
        Ok(request) => request,
        Err(RbacWebDataError::InvalidRequest) => return bad_request(),
        Err(error) => return rbac_data_error_response(error),
    };
    let data = match rbac_data.role_detail(&snapshot, &request).await {
        Ok(RbacWebReadOutcome::Authorized(data)) => data,
        Ok(RbacWebReadOutcome::Forbidden) => return rbac_forbidden(),
        Ok(RbacWebReadOutcome::SessionStale) => {
            return rbac_unauthorized(RBAC_ROLES_RETURN_PATH);
        }
        Ok(RbacWebReadOutcome::NotFound) => return rbac_not_found(),
        Err(error) => return rbac_data_error_response(error),
    };
    let Some(page_revision) = authenticated_revision(&snapshot) else {
        return internal_server_error();
    };
    let capabilities = match rbac_mutation_capabilities(
        &state,
        rbac_data,
        &snapshot,
        page_revision,
        RBAC_ROLES_RETURN_PATH,
    )
    .await
    {
        Ok(capabilities) => capabilities,
        Err(response) => return response,
    };
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::rbac_role_detail(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        request.role_id,
        &data,
        notice,
        page_revision,
        capabilities.as_ref(),
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble RBAC role-detail page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn rbac_direct_binding_list(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RbacListQuery>, QueryRejection>,
) -> Response<Body> {
    let Ok(Query(query)) = query else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Ok(notice) = rbac_notice(query.notice.as_deref()) else {
        return bad_request();
    };
    let Some(rbac_data) = state.rbac_data.as_ref() else {
        return not_found();
    };
    let Some(Extension(snapshot)) = snapshot else {
        return rbac_unauthorized(RBAC_DIRECT_BINDINGS_RETURN_PATH);
    };
    let context = request_context(&state, context);
    if !rbac_request_context_matches(&context, &snapshot) {
        error!("authenticated RBAC web context did not match its request snapshot");
        return internal_server_error();
    }
    let request = match RbacDirectBindingListRequest::new(query.cursor.clone()) {
        Ok(request) => request,
        Err(RbacWebDataError::InvalidRequest) => return bad_request(),
        Err(error) => return rbac_data_error_response(error),
    };
    let data = match rbac_data.list_direct_bindings(&snapshot, &request).await {
        Ok(RbacWebReadOutcome::Authorized(data)) => data,
        Ok(RbacWebReadOutcome::Forbidden) => return rbac_forbidden(),
        Ok(RbacWebReadOutcome::SessionStale) => {
            return rbac_unauthorized(RBAC_DIRECT_BINDINGS_RETURN_PATH);
        }
        Ok(RbacWebReadOutcome::NotFound) => return rbac_not_found(),
        Err(error) => return rbac_data_error_response(error),
    };
    let capabilities = match rbac_mutation_capabilities(
        &state,
        rbac_data,
        &snapshot,
        data.mutation_authorization_revision,
        RBAC_DIRECT_BINDINGS_RETURN_PATH,
    )
    .await
    {
        Ok(capabilities) => capabilities,
        Err(response) => return response,
    };
    let grant_options =
        if capabilities.is_some_and(ManagementMutationCapabilities::role_bindings_manage) {
            match rbac_direct_binding_grant_options(
                &state,
                rbac_data,
                &snapshot,
                data.mutation_authorization_revision,
                RBAC_DIRECT_BINDINGS_RETURN_PATH,
            )
            .await
            {
                Ok(options) => options,
                Err(response) => return response,
            }
        } else {
            None
        };
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::rbac_direct_binding_list(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        query.cursor.as_deref(),
        notice,
        &data,
        capabilities.as_ref(),
        grant_options.as_ref(),
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble RBAC direct-binding-list page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn rbac_mutation(
    State(state): State<WebState>,
    OriginalUri(original_uri): OriginalUri,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    form: Option<Extension<RbacManagementFormSubmission>>,
) -> Response<Body> {
    if !state.rbac_mutations || original_uri.query().is_some() {
        return not_found();
    }
    let Some(rbac_data) = state.rbac_data.as_ref() else {
        return not_found();
    };
    let return_path = rbac_return_path_for_mutation(original_uri.path());
    let Some(Extension(snapshot)) = snapshot else {
        return rbac_unauthorized(return_path);
    };
    let Some(Extension(submission)) = form else {
        return rbac_forbidden();
    };
    let RbacManagementFormSubmission::Valid(form) = submission else {
        return bad_request();
    };
    if form.canonical_path() != original_uri.path() {
        return bad_request();
    }
    let destination_form = form.clone();
    match rbac_data.mutate(&snapshot, form).await {
        Ok(RbacWebMutationOutcome::Applied(applied)) => {
            let Some(location) = rbac_applied_location(&destination_form, applied) else {
                error!("RBAC mutation adapter returned a mismatched applied identity");
                return internal_server_error();
            };
            rbac_see_other(&location, "saved")
        }
        Ok(RbacWebMutationOutcome::Conflict) => {
            rbac_see_other(&rbac_form_location(&destination_form), "conflict")
        }
        Ok(RbacWebMutationOutcome::Forbidden) => {
            rbac_see_other(&rbac_form_location(&destination_form), "forbidden")
        }
        Ok(RbacWebMutationOutcome::NotFound) => {
            rbac_see_other(rbac_collection_location(&destination_form), "conflict")
        }
        Ok(RbacWebMutationOutcome::SessionStale) => rbac_unauthorized(return_path),
        Err(error) => rbac_data_error_response(error),
    }
}

fn rbac_return_path_for_mutation(path: &str) -> &'static str {
    if path.starts_with("/settings/access/users/") {
        RBAC_USERS_RETURN_PATH
    } else if path.starts_with("/settings/access/roles") {
        RBAC_ROLES_RETURN_PATH
    } else {
        RBAC_DIRECT_BINDINGS_RETURN_PATH
    }
}

fn rbac_form_location(form: &VerifiedRbacManagementForm) -> String {
    match form {
        VerifiedRbacManagementForm::ChangeMemberStatus { principal_id, .. } => {
            format!("{RBAC_USERS_RETURN_PATH}/{principal_id}")
        }
        VerifiedRbacManagementForm::CreateRole { .. } => RBAC_ROLES_RETURN_PATH.to_owned(),
        VerifiedRbacManagementForm::UpdateRole { role_id, .. }
        | VerifiedRbacManagementForm::DeleteRole { role_id, .. }
        | VerifiedRbacManagementForm::SetRolePermission { role_id, .. } => {
            format!("{RBAC_ROLES_RETURN_PATH}/{role_id}")
        }
        VerifiedRbacManagementForm::GrantRole { .. }
        | VerifiedRbacManagementForm::RevokeRole { .. } => {
            RBAC_DIRECT_BINDINGS_RETURN_PATH.to_owned()
        }
    }
}

const fn rbac_collection_location(form: &VerifiedRbacManagementForm) -> &'static str {
    match form {
        VerifiedRbacManagementForm::ChangeMemberStatus { .. } => RBAC_USERS_RETURN_PATH,
        VerifiedRbacManagementForm::CreateRole { .. }
        | VerifiedRbacManagementForm::UpdateRole { .. }
        | VerifiedRbacManagementForm::DeleteRole { .. }
        | VerifiedRbacManagementForm::SetRolePermission { .. } => RBAC_ROLES_RETURN_PATH,
        VerifiedRbacManagementForm::GrantRole { .. }
        | VerifiedRbacManagementForm::RevokeRole { .. } => RBAC_DIRECT_BINDINGS_RETURN_PATH,
    }
}

fn rbac_applied_location(
    form: &VerifiedRbacManagementForm,
    applied: RbacMutationApplied,
) -> Option<String> {
    match (form, applied) {
        (
            VerifiedRbacManagementForm::ChangeMemberStatus { principal_id, .. },
            RbacMutationApplied::MemberStatus {
                principal_id: applied,
            },
        ) if *principal_id == applied => Some(format!("{RBAC_USERS_RETURN_PATH}/{applied}")),
        (
            VerifiedRbacManagementForm::CreateRole { .. },
            RbacMutationApplied::RoleCreated { role_id },
        ) => Some(format!("{RBAC_ROLES_RETURN_PATH}/{role_id}")),
        (
            VerifiedRbacManagementForm::UpdateRole { role_id, .. },
            RbacMutationApplied::RoleUpdated { role_id: applied },
        ) if *role_id == applied => Some(format!("{RBAC_ROLES_RETURN_PATH}/{applied}")),
        (VerifiedRbacManagementForm::DeleteRole { .. }, RbacMutationApplied::RoleDeleted) => {
            Some(RBAC_ROLES_RETURN_PATH.to_owned())
        }
        (
            VerifiedRbacManagementForm::SetRolePermission { role_id, .. },
            RbacMutationApplied::RolePermission { role_id: applied },
        ) if *role_id == applied => Some(format!("{RBAC_ROLES_RETURN_PATH}/{applied}")),
        (
            VerifiedRbacManagementForm::GrantRole { .. },
            RbacMutationApplied::BindingGranted { .. },
        )
        | (VerifiedRbacManagementForm::RevokeRole { .. }, RbacMutationApplied::BindingRevoked) => {
            Some(RBAC_DIRECT_BINDINGS_RETURN_PATH.to_owned())
        }
        _ => None,
    }
}

fn rbac_see_other(location: &str, notice: &'static str) -> Response<Body> {
    let location = format!("{location}?notice={notice}");
    let mut response = Redirect::to(&location).into_response();
    apply_static_page_headers(response.headers_mut());
    response
}

async fn rbac_mutation_capabilities(
    state: &WebState,
    rbac_data: &Arc<dyn RbacWebData>,
    snapshot: &AuthenticatedRequestSnapshot,
    page_revision: ManagementRevision,
    return_path: &'static str,
) -> Result<Option<ManagementMutationCapabilities>, Response<Body>> {
    if !state.rbac_mutations {
        return Ok(None);
    }
    match rbac_data.mutation_capabilities(snapshot).await {
        Ok(RbacWebReadOutcome::Authorized(capabilities)) => {
            if capabilities.authorization_revision() == page_revision {
                Ok(Some(capabilities))
            } else {
                error!("RBAC mutation capabilities did not match the page-read revision");
                Err(internal_server_error())
            }
        }
        Ok(RbacWebReadOutcome::Forbidden) | Err(RbacWebDataError::Unavailable) => Ok(None),
        Ok(RbacWebReadOutcome::SessionStale) => Err(rbac_unauthorized(return_path)),
        Ok(RbacWebReadOutcome::NotFound)
        | Err(
            RbacWebDataError::InvalidRequest
            | RbacWebDataError::Corrupt
            | RbacWebDataError::Unrepresentable,
        ) => {
            error!("RBAC mutation-capability read failed closed");
            Err(internal_server_error())
        }
    }
}

async fn rbac_direct_binding_grant_options(
    state: &WebState,
    rbac_data: &Arc<dyn RbacWebData>,
    snapshot: &AuthenticatedRequestSnapshot,
    page_revision: ManagementRevision,
    return_path: &'static str,
) -> Result<Option<DirectBindingGrantOptionsState>, Response<Body>> {
    if !state.rbac_mutations {
        return Ok(None);
    }
    match rbac_data.direct_binding_grant_options(snapshot).await {
        Ok(RbacWebReadOutcome::Authorized(options)) => {
            let options_revision = match &options {
                DirectBindingGrantOptionsState::Available(options) => {
                    options.authorization_revision()
                }
                DirectBindingGrantOptionsState::Overflow {
                    authorization_revision,
                    ..
                } => *authorization_revision,
            };
            if options_revision == page_revision {
                Ok(Some(options))
            } else {
                error!("RBAC direct-grant options did not match the page-read revision");
                Err(internal_server_error())
            }
        }
        Ok(RbacWebReadOutcome::Forbidden) | Err(RbacWebDataError::Unavailable) => Ok(None),
        Ok(RbacWebReadOutcome::SessionStale) => Err(rbac_unauthorized(return_path)),
        Ok(RbacWebReadOutcome::NotFound)
        | Err(
            RbacWebDataError::InvalidRequest
            | RbacWebDataError::Corrupt
            | RbacWebDataError::Unrepresentable,
        ) => {
            error!("RBAC direct-grant option read failed closed");
            Err(internal_server_error())
        }
    }
}

fn authenticated_revision(snapshot: &AuthenticatedRequestSnapshot) -> Option<ManagementRevision> {
    ManagementRevision::new(snapshot.session().authorization_revision())
        .inspect_err(|_| {
            error!("authenticated RBAC session carried an invalid authorization revision");
        })
        .ok()
}

fn rbac_notice(value: Option<&str>) -> Result<Option<&'static str>, ()> {
    match value {
        None => Ok(None),
        Some("saved") => Ok(Some("saved")),
        Some("conflict") => Ok(Some("conflict")),
        Some("forbidden") => Ok(Some("forbidden")),
        Some(_) => Err(()),
    }
}

async fn installation_setup(
    State(state): State<WebState>,
    RawQuery(raw_query): RawQuery,
) -> Response<Body> {
    if raw_query.is_some() {
        return bad_request();
    }
    let Some(availability) = state.setup_page_availability.as_ref() else {
        return setup_not_found();
    };
    match availability.current().await {
        Ok(SetupPageAvailabilityState::Armed) => {}
        Ok(SetupPageAvailabilityState::Absent) => return setup_not_found(),
        Err(SetupPageAvailabilityError::Unavailable) => return setup_page_unavailable(),
        Err(SetupPageAvailabilityError::Corrupt) => {
            error!("setup-page availability failed integrity validation");
            return internal_server_error();
        }
    }
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a setup-page CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::installation_setup(client_assets(), csp_nonce.clone()) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble installation setup page");
            return internal_server_error();
        }
    };
    let setup_csp = format!(
        "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src data:; \
         form-action 'self' {GITHUB_AUTHORIZATION_ORIGIN}; frame-ancestors 'none'; \
         img-src 'self' data:; script-src 'self' 'nonce-{csp_nonce}'; style-src 'self'"
    );
    let Ok(setup_csp) = HeaderValue::from_str(&setup_csp) else {
        error!("failed to construct the setup-page content security policy");
        return internal_server_error();
    };
    let mut response = render(state, request_json, csp_nonce).await;
    if response.status() == StatusCode::OK {
        // Browsers apply `form-action` across the POST redirect chain. Permit
        // only the fixed GitHub authorization origin in addition to the local
        // setup receiver; every other rendered form remains same-origin only.
        response.headers_mut().insert(
            HeaderName::from_static("content-security-policy"),
            setup_csp,
        );
        // A form POST uses the document's referrer policy when serializing its
        // Origin header. `no-referrer` therefore produces `Origin: null`, which
        // cannot satisfy the setup route's exact same-origin admission check.
        response.headers_mut().insert(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("same-origin"),
        );
    }
    response
}

async fn root_redirect(RawQuery(raw_query): RawQuery) -> Response<Body> {
    if raw_query.is_some() {
        return bad_request();
    }
    permanent_redirect("/repositories")
}

async fn repository_directory(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RepositoryDirectoryQuery>, QueryRejection>,
) -> Response<Body> {
    let Ok(Query(query)) = query else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref())
        || !valid_cursor(query.cursor.as_deref())
        || !canonical_repository_directory_query(raw_query.as_deref(), query.cursor.as_deref())
    {
        return bad_request();
    }
    let context = request_context(&state, context);
    let request = RepositoryDirectoryRequest {
        cursor: query.cursor,
        limit: REPOSITORY_PAGE_SIZE,
    };
    let page = match state.data.repository_page(&context, &request).await {
        Ok(page) => page,
        Err(error) => return data_error_response(error),
    };
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a repository-directory CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::repository_directory(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        &request,
        &page,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble repository directory");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn repository_runs(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RunListQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path((owner, repository))), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    render_run_list(state, context, csrf, owner, repository, None, query).await
}

async fn workflow_runs(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RunListQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path((owner, repository, workflow_id))), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Some(workflow_id) = parse_workflow_id(&workflow_id) else {
        return bad_request();
    };
    render_run_list(
        state,
        context,
        csrf,
        owner,
        repository,
        Some(workflow_id),
        query,
    )
    .await
}

async fn render_run_list(
    state: WebState,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    owner: String,
    repository: String,
    workflow_id: Option<WorkflowId>,
    query: RunListQuery,
) -> Response<Body> {
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let Some(query) = validate_run_query(query) else {
        return bad_request();
    };
    let context = request_context(&state, context);
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let request = RunListRequest {
        workflow_id,
        workflow_cursor: query.workflow_cursor,
        status: query.status,
        git_ref: query.branch,
        cursor: query.cursor,
        limit: RUN_PAGE_SIZE,
    };
    let data = match state
        .data
        .list_runs(&context, &repository_path, &request)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => return not_found(),
        Err(error) => return data_error_response(error),
    };
    if !repository_matches(&data.repository, &repository_path)
        || data.selected_workflow.as_ref().map(|workflow| workflow.id) != workflow_id
    {
        error!("workflow run-list data did not preserve the requested workflow scope");
        return internal_server_error();
    }
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::run_list(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        &request,
        &data,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble workflow run-list page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn run_detail(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RunDetailQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path((owner, repository, run_id))), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) || !valid_cursor(query.job_cursor.as_deref())
    {
        return bad_request();
    }
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let Some(run_id) = parse_run_id(&run_id) else {
        return bad_request();
    };
    let context = request_context(&state, context);
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let request = RunDetailRequest {
        job_cursor: query.job_cursor,
        limit: RUN_JOB_PAGE_SIZE,
    };
    let data = match state
        .data
        .run_detail(&context, &repository_path, run_id, &request)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) if context.viewer().is_none() && context.sign_in_action().is_some() => {
            let mut return_path = format!(
                "/{}/{}/actions/runs/{run_id}",
                repository_path.owner, repository_path.name
            );
            if let Some(query) = raw_query.as_deref().filter(|query| !query.is_empty()) {
                return_path.push('?');
                return_path.push_str(query);
            }
            return deep_link_sign_in(state, &context, return_path).await;
        }
        Ok(None) => return not_found(),
        Err(error) => return data_error_response(error),
    };
    if !repository_matches(&data.repository, &repository_path) || data.run.id != run_id {
        error!("workflow run detail data did not preserve its requested scope");
        return internal_server_error();
    }
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::run_detail(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        &request,
        &data,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble workflow run detail page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn job_log(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String, String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<JobLogQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path((owner, repository, run_id, job_id))), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let Some(run_id) = parse_run_id(&run_id) else {
        return bad_request();
    };
    let Some(job_id) = parse_job_id(&job_id) else {
        return bad_request();
    };
    let Some((search, cursor)) = validate_log_query(query) else {
        return bad_request();
    };
    let context = request_context(&state, context);
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let request = JobLogRequest {
        cursor,
        limit: LOG_PAGE_SIZE,
        maximum_decoded_bytes: LOG_PAGE_DECODED_BYTES,
    };
    let data = match state
        .data
        .job_log(&context, &repository_path, run_id, job_id, &request)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) if context.viewer().is_none() && context.sign_in_action().is_some() => {
            let mut return_path = format!(
                "/{}/{}/actions/runs/{run_id}/jobs/{job_id}",
                repository_path.owner, repository_path.name
            );
            if let Some(query) = raw_query.as_deref().filter(|query| !query.is_empty()) {
                return_path.push('?');
                return_path.push_str(query);
            }
            return deep_link_sign_in(state, &context, return_path).await;
        }
        Ok(None) => return not_found(),
        Err(error) => return data_error_response(error),
    };
    if !repository_matches(&data.repository, &repository_path)
        || data.run.id != run_id
        || data.job.id != job_id
    {
        error!("job log data did not preserve its requested scope");
        return internal_server_error();
    }
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::job_log(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        &search,
        request.cursor.as_deref(),
        data,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble job log page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn deep_link_sign_in(
    state: WebState,
    context: &RequestContext,
    return_path: String,
) -> Response<Body> {
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json =
        match model::deep_link_sign_in(client_assets(), csp_nonce.clone(), context, return_path) {
            Ok(request) => request,
            Err(error) => {
                error!(%error, "failed to assemble deep-link sign-in page");
                return internal_server_error();
            }
        };
    render(state, request_json, csp_nonce).await
}

async fn job_log_snapshot(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String, String, String)>, PathRejection>,
    request_headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<JobLogQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path((owner, repository, run_id, job_id))), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let Some(run_id) = parse_run_id(&run_id) else {
        return bad_request();
    };
    let Some(job_id) = parse_job_id(&job_id) else {
        return bad_request();
    };
    let Some((search, cursor)) = validate_log_query(query) else {
        return bad_request();
    };
    let context = request_context(&state, context);
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let request = JobLogRequest {
        cursor,
        limit: LOG_PAGE_SIZE,
        maximum_decoded_bytes: LOG_PAGE_DECODED_BYTES,
    };
    let data = match state
        .data
        .job_log(&context, &repository_path, run_id, job_id, &request)
        .await
    {
        Ok(Some(data)) => data,
        // This endpoint is consumed only after the viewer has loaded the HTML
        // page. A generic 404 on expired/changed authority preserves the same
        // non-enumerating boundary without returning login HTML to `fetch`.
        Ok(None) => return not_found(),
        Err(error) => return data_error_response(error),
    };
    if !repository_matches(&data.repository, &repository_path)
        || data.run.id != run_id
        || data.job.id != job_id
    {
        error!("job snapshot data did not preserve its requested scope");
        return internal_server_error();
    }
    let request_json = match model::job_log(
        client_assets(),
        // The snapshot is JSON rather than executable HTML, but using the same
        // validated model builder keeps its shape and limits identical.
        "snapshot".to_owned(),
        &context,
        mutation,
        &search,
        request.cursor.as_deref(),
        data,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble job snapshot");
            return internal_server_error();
        }
    };
    json_snapshot_response(request_json, &request_headers)
}

async fn artifact(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    path: Result<Path<(String, String, String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
) -> Response<Body> {
    let Ok(Path((owner, repository, run_id, artifact_id))) = path else {
        return bad_request();
    };
    if raw_query.is_some_and(|query| !query.is_empty()) {
        return bad_request();
    }
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let Some(run_id) = parse_run_id(&run_id) else {
        return bad_request();
    };
    let Some(artifact_id) = parse_artifact_id(&artifact_id) else {
        return bad_request();
    };
    let context = request_context(&state, context);
    match state
        .data
        .artifact(&context, &repository_path, run_id, artifact_id)
        .await
    {
        Ok(Some(download)) => artifact_response(download),
        Ok(None) => not_found(),
        Err(error) => data_error_response(error),
    }
}

async fn repository_settings(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
) -> Response<Body> {
    let Ok(Path((owner, repository))) = path else {
        return bad_request();
    };
    if raw_query.is_some() {
        return bad_request();
    }
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let context = request_context(&state, context);
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let ShellMutationResolution::Valid(mutation) = shell_mutation(&context, csrf.as_deref()) else {
        return internal_server_error();
    };
    let data = match state
        .data
        .repository_settings(&context, &repository_path)
        .await
    {
        Ok(Some(data)) => data,
        Ok(None) => return not_found(),
        Err(error) => return data_error_response(error),
    };
    if !repository_matches(&data.repository, &repository_path) {
        error!("repository settings data did not preserve its requested scope");
        return internal_server_error();
    }
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::repository_settings(
        client_assets(),
        csp_nonce.clone(),
        &context,
        data,
        mutation,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble repository settings page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

async fn repository_secrets(
    State(state): State<WebState>,
    context: Option<Extension<RequestContext>>,
    snapshot: Option<Extension<AuthenticatedRequestSnapshot>>,
    csrf: Option<Extension<Arc<CsrfToken>>>,
    path: Result<Path<(String, String)>, PathRejection>,
    RawQuery(raw_query): RawQuery,
    query: Result<Query<RepositorySecretsQuery>, QueryRejection>,
) -> Response<Body> {
    let (Ok(Path((owner, repository))), Ok(Query(query))) = (path, query) else {
        return bad_request();
    };
    if !valid_raw_query_encoding(raw_query.as_deref()) {
        return bad_request();
    }
    let Ok(notice) = repository_secrets_notice(query.notice.as_deref()) else {
        return bad_request();
    };
    let Some(repository_path) = repository_path(owner, repository) else {
        return bad_request();
    };
    let Some(Extension(snapshot)) = snapshot else {
        return not_found();
    };
    let context = request_context(&state, context);
    if !rbac_request_context_matches(&context, &snapshot) {
        error!("authenticated repository-secret context did not match its request snapshot");
        return internal_server_error();
    }
    let request = match RepositorySecretsPageRequest::new(query.after.as_deref()) {
        Ok(request) => request,
        Err(RepositorySecretWebError::InvalidRequest) => return bad_request(),
        Err(RepositorySecretWebError::Unavailable | RepositorySecretWebError::Corrupt) => {
            return internal_server_error();
        }
    };
    let data = match state
        .data
        .repository_secrets(&snapshot, &repository_path, request)
        .await
    {
        Ok(RepositorySecretsReadOutcome::Found(data)) => data,
        Ok(RepositorySecretsReadOutcome::SessionStale) => {
            return repository_secrets_unauthorized(&repository_path);
        }
        Ok(RepositorySecretsReadOutcome::NotFound) => return not_found(),
        Err(error) => return data_error_response(error),
    };
    if data.owner != repository_path.owner || data.repository != repository_path.name {
        error!("repository-secret data did not preserve its requested scope");
        return internal_server_error();
    }
    let csrf = csrf.map(|Extension(csrf)| csrf);
    let Some(csrf) = csrf.as_deref() else {
        return internal_server_error();
    };
    let mutation = model::ShellMutation::new(csrf);
    let csp_nonce = match new_csp_nonce() {
        Ok(nonce) => nonce,
        Err(error) => {
            error!(%error, "failed to generate a CSP nonce");
            return internal_server_error();
        }
    };
    let request_json = match model::repository_secrets(
        client_assets(),
        csp_nonce.clone(),
        &context,
        mutation,
        request.after,
        notice,
        &data,
    ) {
        Ok(request) => request,
        Err(error) => {
            error!(%error, "failed to assemble repository Secrets page");
            return internal_server_error();
        }
    };
    render(state, request_json, csp_nonce).await
}

fn repository_secrets_notice(value: Option<&str>) -> Result<Option<&'static str>, ()> {
    match value {
        None => Ok(None),
        Some("created") => Ok(Some("created")),
        Some("replaced") => Ok(Some("replaced")),
        Some("deleted") => Ok(Some("deleted")),
        Some("provider-activated") => Ok(Some("provider-activated")),
        Some("conflict") => Ok(Some("conflict")),
        Some(_) => Err(()),
    }
}

fn repository_secrets_unauthorized(repository: &RepositoryPath) -> Response<Body> {
    let href = format!("/{}/{}/settings/secrets", repository.owner, repository.name);
    error_page_response_with_action(
        StatusCode::UNAUTHORIZED,
        "Sign in required",
        "Your session is no longer current. Sign in again to review repository secrets.",
        &href,
        "Reload repository secrets",
    )
}

enum ShellMutationResolution<'a> {
    Valid(Option<model::ShellMutation<'a>>),
    Invalid,
}

fn shell_mutation<'a>(
    context: &RequestContext,
    csrf: Option<&'a CsrfToken>,
) -> ShellMutationResolution<'a> {
    match (context.viewer().is_some(), csrf) {
        (true, Some(csrf)) => ShellMutationResolution::Valid(Some(model::ShellMutation::new(csrf))),
        (false, None) => ShellMutationResolution::Valid(None),
        _ => {
            error!("browser UI context and its session-bound mutation capability diverged");
            ShellMutationResolution::Invalid
        }
    }
}

async fn render(state: WebState, request_json: String, csp_nonce: String) -> Response<Body> {
    let Ok(permit) = Arc::clone(&state.render_permits).try_acquire_owned() else {
        return renderer_unavailable();
    };
    let renderer = Arc::clone(&state.renderer);
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        renderer.render(&request_json)
    })
    .await
    {
        Ok(Ok(page)) => html_response(page.into_string(), &csp_nonce),
        Ok(Err(RenderError::AtCapacity | RenderError::ResourceExhausted(_))) => {
            renderer_unavailable()
        }
        Ok(Err(error)) => {
            error!(%error, "isolated UI renderer rejected a page model");
            internal_server_error()
        }
        Err(error) => {
            error!(%error, "isolated UI renderer task failed");
            internal_server_error()
        }
    }
}

async fn asset(Path(asset_path): Path<String>, request_headers: HeaderMap) -> Response<Body> {
    let requested_path = format!("/assets/{asset_path}");
    let Some(asset) = find_asset(&requested_path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let etag = format!("\"{}\"", asset.sha256);
    if request_headers
        .get(IF_NONE_MATCH)
        .is_some_and(|value| if_none_match_matches(value, &etag))
    {
        return asset_response(StatusCode::NOT_MODIFIED, asset, &etag, Body::empty());
    }

    asset_response(StatusCode::OK, asset, &etag, Body::from(asset.bytes))
}

async fn fallback_not_found() -> Response<Body> {
    not_found()
}

fn request_context(state: &WebState, context: Option<Extension<RequestContext>>) -> RequestContext {
    context
        .map_or_else(
            || state.fallback_context.clone(),
            |Extension(context)| context,
        )
        .with_access_management_available(state.rbac_data.is_some())
}

fn repository_path(owner: String, name: String) -> Option<RepositoryPath> {
    if valid_route_segment(&owner) && valid_route_segment(&name) {
        Some(RepositoryPath { owner, name })
    } else {
        None
    }
}

fn valid_route_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !matches!(value, "." | "..")
        && !value.chars().any(char::is_control)
}

fn repository_matches(repository: &super::data::Repository, path: &RepositoryPath) -> bool {
    repository.owner == path.owner && repository.name == path.name
}

fn valid_raw_query_encoding(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    if query.len() > MAX_QUERY_BYTES {
        return false;
    }
    let bytes = query.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                else {
                    return false;
                };
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'%' => return false,
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_run_query(query: RunListQuery) -> Option<ValidatedRunListQuery> {
    let status = match query.status.as_deref() {
        None | Some("all") => StatusFilter::All,
        Some("queued") => StatusFilter::Queued,
        Some("in_progress") => StatusFilter::InProgress,
        Some("completed") => StatusFilter::Completed,
        Some(_) => return None,
    };
    let branch = match query.branch {
        Some(value) => {
            if value.chars().any(forbidden_display_character) {
                return None;
            }
            let value = value.trim();
            if value.is_empty() {
                None
            } else if !is_safe_display_text(value, MAX_FILTER_BYTES)
                || canonical_git_ref_length(value) > MAX_GIT_REF_BYTES
            {
                return None;
            } else {
                Some(value.to_owned())
            }
        }
        None => None,
    };
    if !valid_cursor(query.cursor.as_deref()) || !valid_cursor(query.workflow_cursor.as_deref()) {
        return None;
    }
    Some(ValidatedRunListQuery {
        status,
        branch,
        cursor: query.cursor,
        workflow_cursor: query.workflow_cursor,
    })
}

fn validate_log_query(query: JobLogQuery) -> Option<(String, Option<String>)> {
    let search = query.q.unwrap_or_default();
    let trimmed = search.trim();
    if search.len() > MAX_FILTER_BYTES
        || search.chars().any(forbidden_display_character)
        || (!trimmed.is_empty() && !is_safe_display_text(trimmed, MAX_FILTER_BYTES))
    {
        return None;
    }
    if !valid_cursor(query.cursor.as_deref()) {
        return None;
    }
    Some((trimmed.to_owned(), query.cursor))
}

fn canonical_git_ref_length(value: &str) -> usize {
    if value.starts_with("refs/") {
        value.len()
    } else {
        GIT_HEAD_REF_PREFIX.len().saturating_add(value.len())
    }
}

fn valid_cursor(cursor: Option<&str>) -> bool {
    cursor.is_none_or(|value| {
        !value.is_empty()
            && value.len() <= MAX_CURSOR_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

fn canonical_repository_directory_query(raw_query: Option<&str>, cursor: Option<&str>) -> bool {
    match (raw_query, cursor) {
        (None, None) => true,
        (Some(raw_query), Some(cursor)) => raw_query == format!("cursor={cursor}"),
        _ => false,
    }
}

fn parse_workflow_id(value: &str) -> Option<WorkflowId> {
    let id = WorkflowId::from_str(value).ok()?;
    (!id.as_uuid().is_nil() && id.to_string() == value).then_some(id)
}

fn parse_run_id(value: &str) -> Option<RunId> {
    let id = RunId::from_str(value).ok()?;
    (!id.as_uuid().is_nil() && id.to_string() == value).then_some(id)
}

fn parse_job_id(value: &str) -> Option<JobId> {
    let id = JobId::from_str(value).ok()?;
    (!id.as_uuid().is_nil() && id.to_string() == value).then_some(id)
}

fn parse_artifact_id(value: &str) -> Option<i64> {
    let id = value.parse::<i64>().ok()?;
    (id > 0 && id.to_string() == value).then_some(id)
}

fn if_none_match_matches(value: &HeaderValue, etag: &str) -> bool {
    value.to_str().ok().is_some_and(|value| {
        value.split(',').any(|candidate| {
            let candidate = candidate.trim();
            candidate == "*"
                || candidate == etag
                || candidate
                    .strip_prefix("W/")
                    .is_some_and(|candidate| candidate == etag)
        })
    })
}

fn json_snapshot_response(body: String, request_headers: &HeaderMap) -> Response<Body> {
    let digest = Sha256::digest(body.as_bytes());
    let mut etag = String::with_capacity(2 + "sha256-".len() + digest.len() * 2);
    etag.push('"');
    etag.push_str("sha256-");
    for byte in digest {
        write!(&mut etag, "{byte:02x}").expect("writing to a String cannot fail");
    }
    etag.push('"');

    let not_modified = request_headers
        .get(IF_NONE_MATCH)
        .is_some_and(|value| if_none_match_matches(value, &etag));
    let mut response = if not_modified {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        response
    } else {
        Response::new(Body::from(body))
    };
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(PAGE_CACHE_CONTROL));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    let Ok(etag) = HeaderValue::from_str(&etag) else {
        return internal_server_error();
    };
    headers.insert(ETAG, etag);
    response
}

fn artifact_response(download: super::data::ArtifactDownload) -> Response<Body> {
    if download.size > i64::MAX as u64
        || download.digest.len() != 64
        || !download
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        error!("artifact download metadata failed validation");
        return internal_server_error();
    }
    let Ok(content_type) = HeaderValue::from_str(&download.media_type) else {
        error!("artifact media type failed HTTP header validation");
        return internal_server_error();
    };
    let disposition = format!(
        "attachment; filename=\"artifact\"; filename*=UTF-8''{}",
        percent_encode(download.file_name.as_bytes())
    );
    let Ok(disposition) = HeaderValue::from_str(&disposition) else {
        error!("artifact filename failed HTTP header validation");
        return internal_server_error();
    };
    let Ok(content_length) = HeaderValue::from_str(&download.size.to_string()) else {
        return internal_server_error();
    };
    let Ok(etag) = HeaderValue::from_str(&format!("\"sha256-{}\"", download.digest)) else {
        return internal_server_error();
    };

    let mut response = Response::new(Body::from_stream(download.body));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, content_length);
    headers.insert(CONTENT_DISPOSITION, disposition);
    headers.insert(ETAG, etag);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(PAGE_CACHE_CONTROL));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn new_csp_nonce() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn html_response(html: String, csp_nonce: &str) -> Response<Body> {
    let mut response = Html(html).into_response();
    let csp = format!(
        "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src data:; \
         form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; \
         script-src 'self' 'nonce-{csp_nonce}'; style-src 'self'"
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        error!("failed to construct the page content security policy");
        return internal_server_error();
    };
    apply_page_headers(response.headers_mut(), csp);
    response
}

fn apply_page_headers(headers: &mut HeaderMap, csp: HeaderValue) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(PAGE_CACHE_CONTROL));
    headers.insert(HeaderName::from_static("content-security-policy"), csp);
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
}

fn asset_response(
    status: StatusCode,
    asset: EmbeddedAsset,
    etag: &str,
    body: Body,
) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type.as_str()),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static(EmbeddedAsset::CACHE_CONTROL),
    );
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(ETAG, value);
    }
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn bad_request() -> Response<Body> {
    error_page_response(
        StatusCode::BAD_REQUEST,
        "Invalid request",
        "Check the address or filters and try again.",
    )
}

fn rbac_request_context_matches(
    context: &RequestContext,
    snapshot: &AuthenticatedRequestSnapshot,
) -> bool {
    let identity = snapshot.session().identity();
    context.viewer().is_some()
        && context.tenant_id() == identity.tenant_id()
        && context.authorization().tenant_id() == Some(identity.tenant_id())
        && context.authorization().principal_id() == Some(identity.principal_id())
        && context.authorization().authorization_revision()
            == Some(snapshot.session().authorization_revision())
}

fn rbac_unauthorized(return_path: &'static str) -> Response<Body> {
    error_page_response_with_post_action(
        StatusCode::UNAUTHORIZED,
        "Sign in required",
        "Sign in with a current browser session to manage access.",
        "/auth/github/login",
        return_path,
        "Sign in with GitHub",
    )
}

fn rbac_forbidden() -> Response<Body> {
    error_page_response(
        StatusCode::FORBIDDEN,
        "Access denied",
        "Your current role grants do not allow this management view.",
    )
}

fn rbac_not_found() -> Response<Body> {
    error_page_response(
        StatusCode::NOT_FOUND,
        "Page not found",
        "The requested access-management resource could not be found or is not available.",
    )
}

fn permanent_redirect(location: &'static str) -> Response<Body> {
    let mut response = Redirect::permanent(location).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(PAGE_CACHE_CONTROL));
    response
}

fn not_found() -> Response<Body> {
    error_page_response(
        StatusCode::NOT_FOUND,
        "Page not found",
        "The requested workflow resource could not be found or is not available.",
    )
}

fn setup_not_found() -> Response<Body> {
    error_page_response(
        StatusCode::NOT_FOUND,
        "Page not found",
        "The requested page could not be found or is not available.",
    )
}

fn setup_page_unavailable() -> Response<Body> {
    let mut response = error_page_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "Page temporarily unavailable",
        "The requested page is temporarily unavailable. Try again in a moment.",
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn internal_server_error() -> Response<Body> {
    error_page_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to load this page",
        "An unexpected error prevented this page from loading.",
    )
}

fn renderer_unavailable() -> Response<Body> {
    let mut response = error_page_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "Page temporarily unavailable",
        "The interface is busy. Try again in a moment.",
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn data_error_response(error: WebDataError) -> Response<Body> {
    match error {
        WebDataError::InvalidRequest => bad_request(),
        WebDataError::Unavailable => {
            let mut response = error_page_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Page temporarily unavailable",
                "Workflow data is temporarily unavailable. Try again in a moment.",
            );
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
        WebDataError::Corrupt => {
            error!("workflow data failed integrity validation");
            internal_server_error()
        }
    }
}

fn rbac_data_error_response(error: RbacWebDataError) -> Response<Body> {
    match error {
        RbacWebDataError::InvalidRequest => bad_request(),
        RbacWebDataError::Unavailable => {
            let mut response = error_page_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Page temporarily unavailable",
                "Access-management data is temporarily unavailable. Try again in a moment.",
            );
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
        RbacWebDataError::Corrupt => {
            error!("RBAC management data failed integrity validation");
            internal_server_error()
        }
        RbacWebDataError::Unrepresentable => {
            error!("RBAC management data exceeded the released page contract");
            internal_server_error()
        }
    }
}

pub(crate) fn error_page_response(
    status: StatusCode,
    heading: &'static str,
    description: &'static str,
) -> Response<Body> {
    error_page_response_with_action(
        status,
        heading,
        description,
        "/repositories",
        "Back to repositories",
    )
}

pub(crate) fn error_page_response_with_action(
    status: StatusCode,
    heading: &'static str,
    description: &'static str,
    action_href: &str,
    action_label: &'static str,
) -> Response<Body> {
    let action = format!("<a class=\"button\" href=\"{action_href}\">{action_label}</a>");
    error_page_response_with_action_markup(status, heading, description, &action)
}

fn error_page_response_with_post_action(
    status: StatusCode,
    heading: &'static str,
    description: &'static str,
    action: &'static str,
    return_path: &'static str,
    action_label: &'static str,
) -> Response<Body> {
    let action = format!(
        "<form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"return_path\" value=\"{return_path}\">\
         <button class=\"button\" type=\"submit\">{action_label}</button></form>"
    );
    error_page_response_with_action_markup(status, heading, description, &action)
}

fn error_page_response_with_action_markup(
    status: StatusCode,
    heading: &'static str,
    description: &'static str,
    action: &str,
) -> Response<Body> {
    let mut stylesheet_links = String::new();
    for href in client_assets().stylesheet_paths {
        let _ = write!(
            stylesheet_links,
            "<link rel=\"stylesheet\" href=\"{href}\">"
        );
    }
    let document_title = format!("{} · {heading} · Automata", status.as_u16());
    let document = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"description\" content=\"{description}\">\
         <meta name=\"color-scheme\" content=\"light dark\">\
         <title>{document_title}</title>{stylesheet_links}</head>\
         <body><a class=\"skip-link\" href=\"#main-content\">Skip to content</a>\
         <header class=\"site-header\"><div class=\"site-header__inner\">\
         <a class=\"wordmark\" href=\"/repositories\" aria-label=\"Automata home\">\
         <span class=\"wordmark__mark\" aria-hidden=\"true\">\
         <i class=\"ph ph-path icon icon--18\" aria-hidden=\"true\"></i></span>\
         <span class=\"wordmark__label\">Automata</span></a>\
         <nav class=\"primary-nav\" aria-label=\"Primary navigation\">\
         <a href=\"/repositories\">Repositories</a></nav>\
         <div class=\"site-header__tools\"></div></div></header>\
         <main class=\"layout-width page\" id=\"main-content\" tabindex=\"-1\">\
         <div class=\"panel\"><div class=\"empty-state\">\
         <span class=\"empty-state__icon\" aria-hidden=\"true\">\
         <i class=\"ph ph-warning-circle icon icon--24\" aria-hidden=\"true\"></i></span>\
         <h1>{heading}</h1><p>{description}</p>{action}\
         </div></div></main><footer class=\"site-footer\">\
         <div class=\"layout-width\"><span>Automata</span></div></footer></body></html>"
    );
    let mut response = Html(document).into_response();
    *response.status_mut() = status;
    apply_static_page_headers(response.headers_mut());
    response
}

pub(crate) fn apply_static_page_headers(headers: &mut HeaderMap) {
    apply_page_headers(
        headers,
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src data:; \
             form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; \
             script-src 'none'; style-src 'self'",
        ),
    );
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr as _, sync::Mutex};

    use async_trait::async_trait;
    use automata_ci_auth::{
        authorization::{
            AuthorizationContext, AuthorizationScope, OutputVisibility, Permission,
            RepositoryPublicationPolicy, RepositoryResource, RepositoryResourceId, RoleName,
        },
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject},
        management::{
            DirectBindingGrantOptionCollection, DirectBindingGrantOptions,
            DirectBindingPrincipalOption, DirectBindingRoleOption, DirectRoleBindingSource,
            ManagedPrincipalId, ManagementBindingRole, ManagementRevision,
            ManagementRoleBindingRecord, ManagementRoleBindingSource, ManagementScopeRecord,
            MemberRecord, MemberStatus, ProviderRoleMappingId, RoleBindingId, RoleBindingStatus,
            RoleDetailRecord, RoleId, RoleKind, RolePermissionRecord, RoleRecord,
        },
        request_auth::ViewerDisplayMetadata,
        secret::{CsrfToken, SecretString},
        session::{DurableSession, DurableSessionIdentity, SessionId, SessionKind},
        time::UnixTimestamp,
    };
    use automata_ci_core::UnixMillis;
    use automata_ci_ui_renderer::{RenderPolicy, RenderedPage, WasmtimeRenderer};
    use axum::body::to_bytes;
    use axum::http::Request as HttpRequest;
    use bytes::Bytes;
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::*;
    use crate::app::web::data::{
        ArtifactDownload, ArtifactSummary, CollectionVisibility, JobLogLive, JobLogPage,
        JobNavigationItem, JobSummary, LogChannel, LogLine, RBAC_BINDING_PAGE_SIZE,
        RBAC_ROLE_PAGE_SIZE, RBAC_USER_DETAIL_BINDING_LIMIT, RBAC_USER_PAGE_SIZE,
        RbacDirectBindingListPage, RbacRoleListPage, RbacUserDetailPage, RbacUserListPage,
        Repository as DataRepository, RepositoryDirectoryItem, RepositoryDirectoryPage,
        RepositorySettingsDestination, RepositorySettingsPage, RunDetailPage, RunListPage,
        RunSummary, Status, Viewer, VisibleCollection, Workflow, WorkflowDefinition,
    };

    const WORKFLOW_ID: &str = "11111111-1111-4111-8111-11111111111a";
    const RUN_ID: &str = "22222222-2222-4222-8222-22222222222b";
    const JOB_ID: &str = "33333333-3333-4333-8333-33333333333c";
    const OTHER_JOB_ID: &str = "44444444-4444-4444-8444-44444444444d";
    const RENDERED_HTML: &str = "<!doctype html><html><body>route contract</body></html>";
    const MAX_ERROR_PAGE_BYTES: usize = 64 * 1_024;
    const ARTIFACT_PREFIX: &[u8] = b"PK\x03\x04";
    const ARTIFACT_PAYLOAD: &[u8] = b"verified release bundle\n";
    const CSRF_TOKEN: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const SETUP_BOOTSTRAP_SENTINEL: &str = "setup-bootstrap-sentinel-0123456789abcdef";

    #[derive(Debug, Default)]
    struct RecordingRenderer {
        requests: Mutex<Vec<String>>,
    }

    impl RecordingRenderer {
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("recording renderer mutex must remain available")
                .clone()
        }

        fn page(&self) -> Value {
            let requests = self.requests();
            assert_eq!(requests.len(), 1, "one page should be rendered");
            serde_json::from_str(&requests[0]).expect("render request must be valid JSON")
        }
    }

    impl Renderer for RecordingRenderer {
        fn render(&self, request_json: &str) -> Result<RenderedPage, RenderError> {
            self.requests
                .lock()
                .expect("recording renderer mutex must remain available")
                .push(request_json.to_owned());
            Ok(RenderedPage::from_complete_html(RENDERED_HTML.to_owned()))
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeOutcome {
        Found,
        ReadOnly,
        SecretsOnly,
        Missing,
        Unauthorized,
        Unavailable,
        Corrupt,
        ScopeMismatch,
        InvalidModel,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RecordedCall {
        RepositoryDirectory {
            cursor: Option<String>,
            limit: usize,
        },
        RunList {
            repository: RepositoryPath,
            workflow_id: Option<WorkflowId>,
            workflow_cursor: Option<String>,
            status: StatusFilter,
            git_ref: Option<String>,
            cursor: Option<String>,
            limit: usize,
        },
        RunDetail {
            repository: RepositoryPath,
            run_id: RunId,
            job_cursor: Option<String>,
            limit: usize,
        },
        RepositorySettings {
            repository: RepositoryPath,
        },
        JobLog {
            repository: RepositoryPath,
            run_id: RunId,
            job_id: JobId,
            cursor: Option<String>,
            limit: usize,
            maximum_decoded_bytes: usize,
        },
        Artifact {
            repository: RepositoryPath,
            run_id: RunId,
            artifact_id: i64,
        },
    }

    #[derive(Debug)]
    struct FakeWebData {
        outcome: FakeOutcome,
        calls: Mutex<Vec<RecordedCall>>,
    }

    impl FakeWebData {
        fn new(outcome: FakeOutcome) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, call: RecordedCall) {
            self.calls
                .lock()
                .expect("fake web data mutex must remain available")
                .push(call);
        }

        fn calls(&self) -> Vec<RecordedCall> {
            self.calls
                .lock()
                .expect("fake web data mutex must remain available")
                .clone()
        }

        fn result<T>(&self, value: T) -> Result<Option<T>, WebDataError> {
            match self.outcome {
                FakeOutcome::Missing | FakeOutcome::Unauthorized => Ok(None),
                FakeOutcome::Unavailable => Err(WebDataError::Unavailable),
                FakeOutcome::Corrupt => Err(WebDataError::Corrupt),
                FakeOutcome::Found
                | FakeOutcome::ReadOnly
                | FakeOutcome::SecretsOnly
                | FakeOutcome::ScopeMismatch
                | FakeOutcome::InvalidModel => Ok(Some(value)),
            }
        }
    }

    #[async_trait]
    impl WebData for FakeWebData {
        async fn repository_page(
            &self,
            _context: &RequestContext,
            request: &RepositoryDirectoryRequest,
        ) -> Result<RepositoryDirectoryPage, WebDataError> {
            self.record(RecordedCall::RepositoryDirectory {
                cursor: request.cursor.clone(),
                limit: request.limit,
            });
            match self.outcome {
                FakeOutcome::Unavailable => Err(WebDataError::Unavailable),
                FakeOutcome::Corrupt => Err(WebDataError::Corrupt),
                FakeOutcome::Missing | FakeOutcome::Unauthorized => Ok(RepositoryDirectoryPage {
                    repositories: Vec::new(),
                    next_cursor: None,
                }),
                FakeOutcome::Found => Ok(repository_directory_page()),
                FakeOutcome::ReadOnly => {
                    let mut page = repository_directory_page();
                    page.repositories[0].actions_visible = false;
                    page.repositories[0].repository.settings_visible = true;
                    page.repositories[0].settings_destination =
                        Some(RepositorySettingsDestination::Access);
                    Ok(page)
                }
                FakeOutcome::SecretsOnly => {
                    let mut page = repository_directory_page();
                    page.repositories[0].actions_visible = false;
                    page.repositories[0].settings_destination =
                        Some(RepositorySettingsDestination::Secrets);
                    Ok(page)
                }
                FakeOutcome::ScopeMismatch => {
                    let mut page = repository_directory_page();
                    page.repositories[0].repository.name = "different/repository".to_owned();
                    Ok(page)
                }
                FakeOutcome::InvalidModel => {
                    let mut page = repository_directory_page();
                    page.repositories[0].repository.scm_provider = "gitlab".to_owned();
                    Ok(page)
                }
            }
        }

        async fn list_runs(
            &self,
            _context: &RequestContext,
            repository: &RepositoryPath,
            request: &RunListRequest,
        ) -> Result<Option<RunListPage>, WebDataError> {
            self.record(RecordedCall::RunList {
                repository: repository.clone(),
                workflow_id: request.workflow_id,
                workflow_cursor: request.workflow_cursor.clone(),
                status: request.status,
                git_ref: request.git_ref.clone(),
                cursor: request.cursor.clone(),
                limit: request.limit,
            });
            let mut page = run_list_page(request.workflow_id);
            if self.outcome == FakeOutcome::ScopeMismatch {
                page.selected_workflow = Some(WorkflowDefinition {
                    id: workflow_id(),
                    name: "Different workflow".to_owned(),
                    enabled: true,
                });
            } else if self.outcome == FakeOutcome::InvalidModel {
                page.runs[0].head_sha = "not-a-canonical-sha".to_owned();
            }
            self.result(page)
        }

        async fn run_detail(
            &self,
            _context: &RequestContext,
            repository: &RepositoryPath,
            run_id: RunId,
            request: &RunDetailRequest,
        ) -> Result<Option<RunDetailPage>, WebDataError> {
            self.record(RecordedCall::RunDetail {
                repository: repository.clone(),
                run_id,
                job_cursor: request.job_cursor.clone(),
                limit: request.limit,
            });
            let mut page = run_detail_page();
            if self.outcome == FakeOutcome::ScopeMismatch {
                page.run.id = RunId::new();
            }
            self.result(page)
        }

        async fn repository_settings(
            &self,
            context: &RequestContext,
            repository: &RepositoryPath,
        ) -> Result<Option<RepositorySettingsPage>, WebDataError> {
            self.record(RecordedCall::RepositorySettings {
                repository: repository.clone(),
            });
            let mut page = repository_settings_page();
            page.editable = context.viewer().is_some() && self.outcome != FakeOutcome::ReadOnly;
            if self.outcome == FakeOutcome::ScopeMismatch {
                page.repository.name = "different-repository".to_owned();
            } else if self.outcome == FakeOutcome::InvalidModel {
                page.revision = 0;
            }
            self.result(page)
        }

        async fn job_log(
            &self,
            _context: &RequestContext,
            repository: &RepositoryPath,
            run_id: RunId,
            job_id: JobId,
            request: &JobLogRequest,
        ) -> Result<Option<JobLogPage>, WebDataError> {
            self.record(RecordedCall::JobLog {
                repository: repository.clone(),
                run_id,
                job_id,
                cursor: request.cursor.clone(),
                limit: request.limit,
                maximum_decoded_bytes: request.maximum_decoded_bytes,
            });
            let mut page = job_log_page();
            if self.outcome == FakeOutcome::ScopeMismatch {
                page.job.id = JobId::new();
            }
            self.result(page)
        }

        async fn artifact(
            &self,
            _context: &RequestContext,
            repository: &RepositoryPath,
            run_id: RunId,
            artifact_id: i64,
        ) -> Result<Option<ArtifactDownload>, WebDataError> {
            self.record(RecordedCall::Artifact {
                repository: repository.clone(),
                run_id,
                artifact_id,
            });
            self.result(artifact_download())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeRbacOutcome {
        Found,
        Forbidden,
        SessionStale,
        NotFound,
        Unavailable,
        Corrupt,
        Unrepresentable,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum RecordedRbacCall {
        UserList(RbacUserListRequest),
        UserDetail(RbacUserDetailRequest),
        RoleList(RbacRoleListRequest),
        RoleDetail(RbacRoleDetailRequest),
        DirectBindingList(RbacDirectBindingListRequest),
    }

    #[derive(Debug)]
    struct FakeRbacData {
        outcome: FakeRbacOutcome,
        calls: Mutex<Vec<RecordedRbacCall>>,
    }

    impl FakeRbacData {
        fn new(outcome: FakeRbacOutcome) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<RecordedRbacCall> {
            self.calls
                .lock()
                .expect("fake RBAC data mutex must remain available")
                .clone()
        }

        fn result<T>(&self, value: T) -> Result<RbacWebReadOutcome<T>, RbacWebDataError> {
            match self.outcome {
                FakeRbacOutcome::Found => Ok(RbacWebReadOutcome::Authorized(value)),
                FakeRbacOutcome::Forbidden => Ok(RbacWebReadOutcome::Forbidden),
                FakeRbacOutcome::SessionStale => Ok(RbacWebReadOutcome::SessionStale),
                FakeRbacOutcome::NotFound => Ok(RbacWebReadOutcome::NotFound),
                FakeRbacOutcome::Unavailable => Err(RbacWebDataError::Unavailable),
                FakeRbacOutcome::Corrupt => Err(RbacWebDataError::Corrupt),
                FakeRbacOutcome::Unrepresentable => Err(RbacWebDataError::Unrepresentable),
            }
        }
    }

    #[async_trait]
    impl RbacWebData for FakeRbacData {
        async fn list_users(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacUserListRequest,
        ) -> Result<RbacWebReadOutcome<RbacUserListPage>, RbacWebDataError> {
            self.calls
                .lock()
                .expect("fake RBAC data mutex must remain available")
                .push(RecordedRbacCall::UserList(request.clone()));
            self.result(RbacUserListPage {
                users: vec![rbac_member()],
                next_cursor: Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned()),
            })
        }

        async fn user_detail(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacUserDetailRequest,
        ) -> Result<RbacWebReadOutcome<RbacUserDetailPage>, RbacWebDataError> {
            self.calls
                .lock()
                .expect("fake RBAC data mutex must remain available")
                .push(RecordedRbacCall::UserDetail(request.clone()));
            let user = rbac_member();
            self.result(RbacUserDetailPage {
                assignments: vec![rbac_direct_binding(user.clone())],
                user,
            })
        }

        async fn list_roles(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacRoleListRequest,
        ) -> Result<RbacWebReadOutcome<RbacRoleListPage>, RbacWebDataError> {
            self.calls
                .lock()
                .expect("fake RBAC data mutex must remain available")
                .push(RecordedRbacCall::RoleList(request.clone()));
            self.result(RbacRoleListPage {
                roles: vec![rbac_role()],
                next_cursor: Some("dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_owned()),
                mutation_authorization_revision: ManagementRevision::new(4)
                    .expect("authorization revision"),
            })
        }

        async fn role_detail(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacRoleDetailRequest,
        ) -> Result<RbacWebReadOutcome<RoleDetailRecord>, RbacWebDataError> {
            self.calls
                .lock()
                .expect("fake RBAC data mutex must remain available")
                .push(RecordedRbacCall::RoleDetail(*request));
            self.result(rbac_role_detail_record())
        }

        async fn list_direct_bindings(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacDirectBindingListRequest,
        ) -> Result<RbacWebReadOutcome<RbacDirectBindingListPage>, RbacWebDataError> {
            self.calls
                .lock()
                .expect("fake RBAC data mutex must remain available")
                .push(RecordedRbacCall::DirectBindingList(request.clone()));
            let user = rbac_member();
            self.result(RbacDirectBindingListPage {
                bindings: vec![
                    rbac_direct_binding(user.clone()),
                    rbac_provider_binding(user),
                ],
                next_cursor: Some("d:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".to_owned()),
                mutation_authorization_revision: ManagementRevision::new(4)
                    .expect("authorization revision"),
            })
        }
    }

    #[derive(Debug)]
    struct FakeMutationRbacData {
        reads: FakeRbacData,
        capabilities: Option<ManagementMutationCapabilities>,
        grant_options: Option<DirectBindingGrantOptionsState>,
        mutation_outcome: RbacWebMutationOutcome,
        mutations: Mutex<Vec<VerifiedRbacManagementForm>>,
    }

    impl FakeMutationRbacData {
        fn new(
            capabilities: Option<ManagementMutationCapabilities>,
            grant_options: Option<DirectBindingGrantOptionsState>,
            mutation_outcome: RbacWebMutationOutcome,
        ) -> Self {
            Self {
                reads: FakeRbacData::new(FakeRbacOutcome::Found),
                capabilities,
                grant_options,
                mutation_outcome,
                mutations: Mutex::new(Vec::new()),
            }
        }

        fn mutations(&self) -> Vec<VerifiedRbacManagementForm> {
            self.mutations
                .lock()
                .expect("fake mutation mutex must remain available")
                .clone()
        }
    }

    #[async_trait]
    impl RbacWebData for FakeMutationRbacData {
        async fn mutation_capabilities(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
        ) -> Result<RbacWebReadOutcome<ManagementMutationCapabilities>, RbacWebDataError> {
            self.capabilities.map_or_else(
                || Err(RbacWebDataError::Unavailable),
                |capabilities| Ok(RbacWebReadOutcome::Authorized(capabilities)),
            )
        }

        async fn direct_binding_grant_options(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
        ) -> Result<RbacWebReadOutcome<DirectBindingGrantOptionsState>, RbacWebDataError> {
            self.grant_options.clone().map_or_else(
                || Err(RbacWebDataError::Unavailable),
                |options| Ok(RbacWebReadOutcome::Authorized(options)),
            )
        }

        async fn mutate(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            form: VerifiedRbacManagementForm,
        ) -> Result<RbacWebMutationOutcome, RbacWebDataError> {
            self.mutations
                .lock()
                .expect("fake mutation mutex must remain available")
                .push(form);
            Ok(self.mutation_outcome)
        }

        async fn list_users(
            &self,
            snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacUserListRequest,
        ) -> Result<RbacWebReadOutcome<RbacUserListPage>, RbacWebDataError> {
            self.reads.list_users(snapshot, request).await
        }

        async fn user_detail(
            &self,
            snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacUserDetailRequest,
        ) -> Result<RbacWebReadOutcome<RbacUserDetailPage>, RbacWebDataError> {
            self.reads.user_detail(snapshot, request).await
        }

        async fn list_roles(
            &self,
            snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacRoleListRequest,
        ) -> Result<RbacWebReadOutcome<RbacRoleListPage>, RbacWebDataError> {
            self.reads.list_roles(snapshot, request).await
        }

        async fn role_detail(
            &self,
            snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacRoleDetailRequest,
        ) -> Result<RbacWebReadOutcome<RoleDetailRecord>, RbacWebDataError> {
            self.reads.role_detail(snapshot, request).await
        }

        async fn list_direct_bindings(
            &self,
            snapshot: &AuthenticatedRequestSnapshot,
            request: &RbacDirectBindingListRequest,
        ) -> Result<RbacWebReadOutcome<RbacDirectBindingListPage>, RbacWebDataError> {
            self.reads.list_direct_bindings(snapshot, request).await
        }
    }

    fn workflow_id() -> WorkflowId {
        WorkflowId::from_str(WORKFLOW_ID).expect("workflow fixture ID must be valid")
    }

    fn run_id() -> RunId {
        RunId::from_str(RUN_ID).expect("run fixture ID must be valid")
    }

    fn job_id() -> JobId {
        JobId::from_str(JOB_ID).expect("job fixture ID must be valid")
    }

    fn other_job_id() -> JobId {
        JobId::from_str(OTHER_JOB_ID).expect("alternate job fixture ID must be valid")
    }

    fn repository_path() -> RepositoryPath {
        RepositoryPath {
            owner: "acme-labs".to_owned(),
            name: "payments-api".to_owned(),
        }
    }

    fn repository() -> DataRepository {
        DataRepository {
            id: "repo-acme-payments".to_owned(),
            scm_provider: "github".to_owned(),
            owner: "acme-labs".to_owned(),
            name: "payments-api".to_owned(),
            settings_visible: false,
        }
    }

    fn repository_directory_page() -> RepositoryDirectoryPage {
        RepositoryDirectoryPage {
            repositories: vec![RepositoryDirectoryItem {
                repository: repository(),
                actions_visible: true,
                settings_destination: None,
            }],
            next_cursor: Some("next_repositories".to_owned()),
        }
    }

    fn workflow() -> Workflow {
        Workflow {
            id: workflow_id(),
            name: "Pull request checks".to_owned(),
            path: ".ci/workflows/verify.yml".to_owned(),
        }
    }

    fn workflow_definition() -> WorkflowDefinition {
        WorkflowDefinition {
            id: workflow_id(),
            name: "Pull request checks".to_owned(),
            enabled: false,
        }
    }

    fn run_summary() -> RunSummary {
        RunSummary {
            id: run_id(),
            number: 1_842,
            attempt: 2,
            title: Some("Validate checkout and release metadata".to_owned()),
            workflow: workflow(),
            status: Status::Succeeded,
            git_ref: None,
            event: "pull_request".to_owned(),
            actor: None,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            commit_subject: None,
            created_at: UnixMillis::new(1_777_890_000_000),
            finished_at: Some(UnixMillis::new(1_777_890_125_000)),
        }
    }

    fn job_summary() -> JobSummary {
        JobSummary {
            id: job_id(),
            name: "Test on Ubuntu".to_owned(),
            attempt: Some(3),
            runner_label: None,
            status: Status::Succeeded,
            started_at: Some(UnixMillis::new(1_777_890_005_000)),
            finished_at: Some(UnixMillis::new(1_777_890_120_000)),
            logs_available: true,
        }
    }

    fn run_list_page(selected_workflow_id: Option<WorkflowId>) -> RunListPage {
        let workflow = workflow_definition();
        let selected_workflow = selected_workflow_id.map(|id| {
            if id == workflow.id {
                workflow.clone()
            } else {
                WorkflowDefinition {
                    id,
                    name: "Selected workflow".to_owned(),
                    enabled: true,
                }
            }
        });
        RunListPage {
            repository: repository(),
            workflows: vec![workflow],
            selected_workflow,
            workflow_previous_cursor: None,
            workflow_next_cursor: Some("workflow_next".to_owned()),
            runs: vec![run_summary()],
            previous_cursor: Some("previous_1".to_owned()),
            next_cursor: Some("next_2".to_owned()),
        }
    }

    fn run_detail_page() -> RunDetailPage {
        RunDetailPage {
            repository: repository(),
            run: run_summary(),
            jobs: VisibleCollection {
                visibility: CollectionVisibility::Full,
                items: vec![job_summary()],
            },
            job_previous_cursor: None,
            job_next_cursor: Some("job_next".to_owned()),
            artifacts: VisibleCollection {
                visibility: CollectionVisibility::Full,
                items: vec![ArtifactSummary {
                    id: 73,
                    name: "test-results".to_owned(),
                    size: 2_048,
                    digest: "a".repeat(64),
                    expires_at_seconds: None,
                    downloadable: true,
                }],
            },
        }
    }

    fn repository_settings_page() -> RepositorySettingsPage {
        let mut repository = repository();
        repository.settings_visible = true;
        RepositorySettingsPage {
            repository,
            policy: RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Authenticated,
                OutputVisibility::Private,
            ),
            revision: 7,
            editable: true,
            secrets_visible: false,
        }
    }

    fn job_log_page() -> JobLogPage {
        let mut run = run_summary();
        run.status = Status::InProgress;
        run.finished_at = None;
        let mut job = job_summary();
        job.status = Status::InProgress;
        job.finished_at = None;
        JobLogPage {
            repository: repository(),
            run,
            jobs: vec![
                JobNavigationItem {
                    id: job_id(),
                    name: "Test on Ubuntu".to_owned(),
                    status: Status::InProgress,
                    logs_available: true,
                },
                JobNavigationItem {
                    id: other_job_id(),
                    name: "Lint source".to_owned(),
                    status: Status::Succeeded,
                    logs_available: false,
                },
            ],
            previous_navigation_job_id: None,
            next_navigation_job_id: None,
            job,
            log_visibility: CollectionVisibility::Full,
            lines: vec![
                LogLine {
                    sequence: 38,
                    fragment: None,
                    emitted_at: UnixMillis::new(1_777_890_010_000),
                    channel: LogChannel::System,
                    text: "Runner image is ready.".to_owned(),
                },
                LogLine {
                    sequence: 39,
                    fragment: Some(1),
                    emitted_at: UnixMillis::new(1_777_890_115_000),
                    channel: LogChannel::Stdout,
                    text: "All 128 tests passed.".to_owned(),
                },
            ],
            previous_cursor: None,
            next_cursor: Some("log_40".to_owned()),
            live: Some(JobLogLive {
                checkpoint: Some("log_39".to_owned()),
                stream_closed: false,
                more_available: true,
            }),
        }
    }

    fn artifact_download() -> ArtifactDownload {
        let size = u64::try_from(ARTIFACT_PREFIX.len() + ARTIFACT_PAYLOAD.len())
            .expect("artifact fixture length must fit u64");
        ArtifactDownload {
            file_name: "release bundle.zip".to_owned(),
            media_type: "application/zip".to_owned(),
            size,
            digest: "b".repeat(64),
            body: Box::pin(futures::stream::iter([
                Ok(Bytes::from_static(ARTIFACT_PREFIX)),
                Ok(Bytes::from_static(ARTIFACT_PAYLOAD)),
            ])),
        }
    }

    fn rbac_member() -> MemberRecord {
        MemberRecord::new(
            ManagedPrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .expect("managed principal"),
            ProviderId::new("github").expect("provider"),
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            MemberStatus::Active,
            ManagementRevision::new(11).expect("authorization revision"),
            ManagementRevision::new(7).expect("member revision"),
        )
        .expect("RBAC member fixture")
    }

    fn rbac_role() -> RoleRecord {
        RoleRecord::new(
            RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID"),
            RoleName::new("release-reviewer").expect("role name"),
            "Release reviewer",
            RoleKind::Custom,
            false,
            ManagementRevision::new(9).expect("role revision"),
            BTreeSet::from([Permission::new("runs:read").expect("permission")]),
        )
        .expect("RBAC role fixture")
    }

    fn rbac_role_detail_record() -> RoleDetailRecord {
        RoleDetailRecord::new(
            rbac_role(),
            vec![
                RolePermissionRecord::new(
                    Permission::new("artifacts:download").expect("permission"),
                    "Download authorized finalized artifacts.",
                    true,
                    false,
                )
                .expect("permission catalog entry"),
                RolePermissionRecord::new(
                    Permission::new("runs:read").expect("permission"),
                    "Read authorized workflow-run metadata.",
                    false,
                    true,
                )
                .expect("permission catalog entry"),
            ],
        )
        .expect("RBAC role detail fixture")
    }

    fn rbac_immutable_role_detail_record() -> RoleDetailRecord {
        let role = RoleRecord::new(
            RoleId::new("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("role ID"),
            RoleName::new("tenant-viewer").expect("role name"),
            "Tenant viewer",
            RoleKind::BuiltIn,
            true,
            ManagementRevision::new(9).expect("role revision"),
            BTreeSet::from([Permission::new("runs:read").expect("permission")]),
        )
        .expect("immutable role fixture");
        RoleDetailRecord::new(
            role,
            vec![
                RolePermissionRecord::new(
                    Permission::new("runs:read").expect("permission"),
                    "Read authorized workflow-run metadata.",
                    false,
                    true,
                )
                .expect("permission catalog entry"),
            ],
        )
        .expect("immutable role detail fixture")
    }

    fn rbac_direct_binding(principal: MemberRecord) -> ManagementRoleBindingRecord {
        let repository = RepositoryResource::new(
            TenantId::new("acme-production").expect("tenant"),
            RepositoryResourceId::new("12121212-1212-4212-8212-121212121212")
                .expect("repository ID"),
        );
        ManagementRoleBindingRecord::new(
            RoleBindingId::new("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").expect("binding ID"),
            principal,
            ManagementBindingRole::new(
                RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID"),
                RoleName::new("release-reviewer").expect("role name"),
                "Release reviewer",
            )
            .expect("binding role"),
            ManagementScopeRecord::new(
                AuthorizationScope::repository(repository),
                "acme-labs/payments-api",
            )
            .expect("binding scope"),
            ManagementRoleBindingSource::Direct(DirectRoleBindingSource::Manual),
            RoleBindingStatus::Active,
            Some(UnixTimestamp::from_seconds(1_788_220_800)),
            ManagementRevision::new(5).expect("binding revision"),
        )
        .expect("direct binding fixture")
    }

    fn rbac_provider_binding(principal: MemberRecord) -> ManagementRoleBindingRecord {
        let mapping_id =
            ProviderRoleMappingId::new("ffffffff-ffff-4fff-8fff-ffffffffffff").expect("mapping ID");
        let binding_id =
            RoleBindingId::for_provider_observation(principal.principal_id(), mapping_id);
        ManagementRoleBindingRecord::new(
            binding_id,
            principal,
            ManagementBindingRole::new(
                RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID"),
                RoleName::new("release-reviewer").expect("role name"),
                "Release reviewer",
            )
            .expect("binding role"),
            ManagementScopeRecord::new(
                AuthorizationScope::tenant(TenantId::new("acme-production").expect("tenant")),
                "Acme production",
            )
            .expect("binding scope"),
            ManagementRoleBindingSource::ProviderObserved { mapping_id },
            RoleBindingStatus::Active,
            None,
            ManagementRevision::new(2).expect("mapping revision"),
        )
        .expect("provider binding fixture")
    }

    fn rbac_snapshot() -> AuthenticatedRequestSnapshot {
        let tenant_id = TenantId::new("acme-production").expect("tenant");
        let principal_id =
            PrincipalId::new("11111111-1111-4111-8111-111111111111").expect("principal");
        let provider_id = ProviderId::new("github").expect("provider");
        let provider_subject = ProviderSubject::new("123").expect("provider subject");
        let identity = DurableSessionIdentity::new(
            SessionId::new("22222222-2222-4222-8222-222222222222").expect("session"),
            tenant_id.clone(),
            principal_id.clone(),
            provider_id.clone(),
            provider_subject.clone(),
            SessionKind::Browser,
        )
        .expect("session identity");
        let session = DurableSession::new(
            identity,
            4,
            UnixTimestamp::from_seconds(1),
            UnixTimestamp::from_seconds(2),
            UnixTimestamp::from_seconds(900),
            UnixTimestamp::from_seconds(1_000),
            None,
        )
        .expect("session");
        let human = AuthenticatedHuman::new(
            principal_id.clone(),
            provider_id,
            provider_subject,
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            UnixTimestamp::from_seconds(1),
        )
        .expect("human");
        let authorization = AuthorizationContext::authenticated_at_revision(
            tenant_id,
            principal_id,
            BTreeSet::new(),
            4,
        )
        .expect("authorization");
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("Ada Lovelace").expect("viewer"),
            authorization,
        )
        .expect("request snapshot")
    }

    fn rbac_context(snapshot: &AuthenticatedRequestSnapshot) -> RequestContext {
        RequestContext::new(
            snapshot.session().identity().tenant_id().clone(),
            snapshot.authorization().clone(),
            Some(Viewer {
                display_name: snapshot.viewer().display_name().to_owned(),
            }),
            None,
        )
        .expect("RBAC request context")
    }

    fn rbac_test_router(
        outcome: FakeRbacOutcome,
    ) -> (Router, Arc<RecordingRenderer>, Arc<FakeRbacData>) {
        let renderer = Arc::new(RecordingRenderer::default());
        let data: Arc<dyn WebData> = Arc::new(FakeWebData::new(FakeOutcome::Found));
        let rbac_data = Arc::new(FakeRbacData::new(outcome));
        let tenant = TenantId::new("acme-production").expect("test tenant must be valid");
        let app = router_with_data_and_rbac(
            renderer.clone(),
            4,
            data,
            rbac_data.clone(),
            RequestContext::anonymous(tenant),
        );
        (app, renderer, rbac_data)
    }

    fn rbac_mutation_test_router(
        capabilities: Option<ManagementMutationCapabilities>,
        grant_options: Option<DirectBindingGrantOptionsState>,
        mutation_outcome: RbacWebMutationOutcome,
    ) -> (Router, Arc<RecordingRenderer>, Arc<FakeMutationRbacData>) {
        let renderer = Arc::new(RecordingRenderer::default());
        let data: Arc<dyn WebData> = Arc::new(FakeWebData::new(FakeOutcome::Found));
        let rbac_data = Arc::new(FakeMutationRbacData::new(
            capabilities,
            grant_options,
            mutation_outcome,
        ));
        let tenant = TenantId::new("acme-production").expect("test tenant must be valid");
        let app = router_with_data_rbac_and_management(
            renderer.clone(),
            4,
            data,
            rbac_data.clone(),
            RequestContext::anonymous(tenant),
        );
        (app, renderer, rbac_data)
    }

    fn rbac_role_permission_form() -> VerifiedRbacManagementForm {
        VerifiedRbacManagementForm::SetRolePermission {
            role_id: RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID"),
            permission: Permission::new("runs:read").expect("permission"),
            expected_authorization_revision: ManagementRevision::new(4)
                .expect("authorization revision"),
            expected_revision: ManagementRevision::new(9).expect("role revision"),
            present: false,
        }
    }

    fn rbac_grant_options() -> DirectBindingGrantOptionsState {
        DirectBindingGrantOptionsState::Available(
            DirectBindingGrantOptions::new(
                ManagementRevision::new(4).expect("authorization revision"),
                vec![
                    DirectBindingPrincipalOption::new(
                        ManagedPrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                            .expect("principal ID"),
                        "Ada Lovelace",
                    )
                    .expect("principal option"),
                ],
                vec![
                    DirectBindingRoleOption::new(
                        RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID"),
                        RoleName::new("release-reviewer").expect("role name"),
                        "Release reviewer",
                        RoleKind::Custom,
                        false,
                    )
                    .expect("role option"),
                ],
                Vec::new(),
                Vec::new(),
            )
            .expect("bounded coherent grant options"),
        )
    }

    fn test_router(outcome: FakeOutcome) -> (Router, Arc<RecordingRenderer>, Arc<FakeWebData>) {
        let renderer = Arc::new(RecordingRenderer::default());
        let data = Arc::new(FakeWebData::new(outcome));
        let tenant = TenantId::new("acme-production").expect("test tenant must be valid");
        let app = router_with_data(
            renderer.clone(),
            4,
            data.clone(),
            RequestContext::anonymous(tenant),
        );
        (app, renderer, data)
    }

    #[derive(Debug)]
    struct FakeSetupPageAvailability {
        outcome: Mutex<Result<SetupPageAvailabilityState, SetupPageAvailabilityError>>,
        calls: Mutex<usize>,
    }

    impl FakeSetupPageAvailability {
        fn new(outcome: Result<SetupPageAvailabilityState, SetupPageAvailabilityError>) -> Self {
            Self {
                outcome: Mutex::new(outcome),
                calls: Mutex::new(0),
            }
        }

        fn set(&self, outcome: Result<SetupPageAvailabilityState, SetupPageAvailabilityError>) {
            *self
                .outcome
                .lock()
                .expect("setup availability mutex must remain available") = outcome;
        }

        fn calls(&self) -> usize {
            *self
                .calls
                .lock()
                .expect("setup call-count mutex must remain available")
        }
    }

    #[async_trait]
    impl SetupPageAvailability for FakeSetupPageAvailability {
        async fn current(&self) -> Result<SetupPageAvailabilityState, SetupPageAvailabilityError> {
            *self
                .calls
                .lock()
                .expect("setup call-count mutex must remain available") += 1;
            *self
                .outcome
                .lock()
                .expect("setup availability mutex must remain available")
        }
    }

    fn setup_test_router(
        outcome: Result<SetupPageAvailabilityState, SetupPageAvailabilityError>,
    ) -> (
        Router,
        Arc<RecordingRenderer>,
        Arc<FakeSetupPageAvailability>,
    ) {
        let renderer = Arc::new(RecordingRenderer::default());
        let tenant = TenantId::new("acme-production").expect("test tenant must be valid");
        let data = Arc::new(EmptyWebData);
        let context = RequestContext::anonymous(tenant);
        let availability = Arc::new(FakeSetupPageAvailability::new(outcome));
        let availability_port: Arc<dyn SetupPageAvailability> = availability.clone();
        let app = router_with_data_and_setup_availability(
            renderer.clone(),
            4,
            data,
            context,
            availability_port,
        );
        (app, renderer, availability)
    }

    #[tokio::test]
    async fn armed_setup_get_is_queryless_uncached_and_value_free() {
        let (app, renderer, availability) =
            setup_test_router(Ok(SetupPageAvailabilityState::Armed));
        let response = get(&app, "/setup").await;
        let page = renderer.page();

        assert_page_headers_with_referrer(&response, &page, "same-origin");
        assert_eq!(page["page"]["kind"], "setup");
        assert_eq!(page["page"]["form"]["action"], "/setup/auth/github");
        assert_eq!(page["page"]["form"]["returnPath"], "/");
        assert_eq!(page["page"]["shell"]["signIn"], Value::Null);
        assert_eq!(page["page"]["shell"]["viewer"], Value::Null);
        assert!(!renderer.requests()[0].contains("bootstrap_token"));
        assert!(!renderer.requests()[0].contains(SETUP_BOOTSTRAP_SENTINEL));
        assert_eq!(availability.calls(), 1);

        for uri in ["/setup?unexpected=value", "/setup?"] {
            let (app, renderer, availability) =
                setup_test_router(Ok(SetupPageAvailabilityState::Armed));
            let response = get(&app, uri).await;
            assert_error_page_headers(&response, StatusCode::BAD_REQUEST);
            assert!(renderer.requests().is_empty());
            assert_eq!(availability.calls(), 0);
        }

        let (app, renderer, availability) =
            setup_test_router(Ok(SetupPageAvailabilityState::Armed));
        let response = post_request(&app, "/setup").await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(renderer.requests().is_empty());
        assert_eq!(availability.calls(), 0);
    }

    #[tokio::test]
    async fn setup_get_freshly_closes_after_the_armed_state_transitions() {
        let (app, renderer, availability) =
            setup_test_router(Ok(SetupPageAvailabilityState::Armed));
        let response = get(&app, "/setup").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(renderer.requests().len(), 1);

        availability.set(Ok(SetupPageAvailabilityState::Absent));
        let response = get(&app, "/setup").await;
        assert_error_page_headers(&response, StatusCode::NOT_FOUND);
        assert_eq!(renderer.requests().len(), 1);
        assert_eq!(availability.calls(), 2);
        let body = error_page_body(response).await;
        assert!(!body.contains(SETUP_BOOTSTRAP_SENTINEL));
        assert!(!body.contains("bootstrap_token"));
    }

    #[tokio::test]
    async fn setup_route_is_absent_without_the_fresh_availability_port() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let response = get(&app, "/setup").await;
        assert_error_page_headers(&response, StatusCode::NOT_FOUND);
        assert!(renderer.requests().is_empty());
        assert!(data.calls().is_empty());
    }

    #[tokio::test]
    async fn setup_availability_failures_close_before_rendering() {
        for (error, status) in [
            (
                SetupPageAvailabilityError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                SetupPageAvailabilityError::Corrupt,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let (app, renderer, availability) = setup_test_router(Err(error));
            let response = get(&app, "/setup").await;
            assert_error_page_headers(&response, status);
            assert!(renderer.requests().is_empty());
            assert_eq!(availability.calls(), 1);
            let body = error_page_body(response).await;
            assert!(!body.contains(SETUP_BOOTSTRAP_SENTINEL));
            assert!(!body.contains("bootstrap_token"));
        }
    }

    async fn get(app: &Router, uri: &str) -> Response<Body> {
        app.clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("test request URI must be valid"),
            )
            .await
            .expect("route must produce a response")
    }

    async fn post_request(app: &Router, uri: &str) -> Response<Body> {
        app.clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::empty())
                    .expect("test request URI must be valid"),
            )
            .await
            .expect("route must produce a response")
    }

    fn assert_page_headers(response: &Response<Body>, page: &Value) {
        assert_page_headers_with_referrer(response, page, "no-referrer");
    }

    fn assert_page_headers_with_referrer(
        response: &Response<Body>,
        page: &Value,
        expected_referrer_policy: &str,
    ) {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(response.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["referrer-policy"],
            expected_referrer_policy
        );
        let nonce = page["host"]["cspNonce"]
            .as_str()
            .expect("page model must contain its CSP nonce");
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .expect("CSP must be valid text");
        assert!(csp.contains(&format!("'nonce-{nonce}'")));
        assert!(csp.contains("frame-ancestors 'none'"));
        if page["page"]["kind"] == "setup" {
            assert!(csp.contains("form-action 'self' https://github.com"));
            assert!(!csp.contains("form-action *"));
        } else {
            assert!(csp.contains("form-action 'self';"));
            assert!(!csp.contains(GITHUB_AUTHORIZATION_ORIGIN));
        }
    }

    fn assert_error_page_headers(response: &Response<Body>, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(response.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(
            response.headers()["cross-origin-opener-policy"],
            "same-origin"
        );
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .expect("error-page CSP must be valid text");
        assert!(csp.contains("script-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("nonce-"));
    }

    async fn error_page_body(response: Response<Body>) -> String {
        let body = to_bytes(response.into_body(), MAX_ERROR_PAGE_BYTES)
            .await
            .expect("error-page HTML must be readable");
        String::from_utf8(body.to_vec()).expect("error-page HTML must be UTF-8")
    }

    fn authenticated_rbac_router(app: Router) -> Router {
        let snapshot = rbac_snapshot();
        let context = rbac_context(&snapshot);
        let csrf = CsrfToken::from_generated_secret(
            SecretString::new(CSRF_TOKEN).expect("CSRF fixture must be bounded"),
        )
        .expect("CSRF fixture must be canonical");
        app.layer(Extension(context))
            .layer(Extension(snapshot))
            .layer(Extension(Arc::new(csrf)))
    }

    #[tokio::test]
    async fn rbac_user_list_reauthorizes_and_renders_only_the_truthful_read() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let cursor = "99999999-9999-4999-8999-999999999999";
        let response = get(
            &authenticated_rbac_router(app),
            &format!("/settings/access/users?cursor={cursor}"),
        )
        .await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "user-list");
        assert_eq!(page["page"]["users"][0]["providerLogin"], "ada-lovelace");
        assert!(page["page"]["users"][0].get("revision").is_none());
        assert_eq!(
            page["page"]["pagination"]["nextHref"],
            "/settings/access/users?cursor=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        );
        assert_eq!(
            rbac_data.calls(),
            vec![RecordedRbacCall::UserList(RbacUserListRequest {
                cursor: Some(cursor.to_owned()),
                limit: automata_ci_auth::management::ManagementPageSize::new(RBAC_USER_PAGE_SIZE,)
                    .expect("page size"),
            })]
        );

        let body = to_bytes(response.into_body(), RENDERED_HTML.len())
            .await
            .expect("rendered RBAC page must be readable");
        assert_eq!(&body[..], RENDERED_HTML.as_bytes());
    }

    #[tokio::test]
    async fn rbac_user_list_requires_matching_authentication_and_a_canonical_cursor() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let response = get(&app, "/settings/access/users").await;
        assert_error_page_headers(&response, StatusCode::UNAUTHORIZED);
        let body = error_page_body(response).await;
        assert!(body.contains("<form method=\"post\" action=\"/auth/github/login\">"));
        assert!(body.contains(
            "<input type=\"hidden\" name=\"return_path\" value=\"/settings/access/users\">"
        ));
        assert!(
            body.contains("<button class=\"button\" type=\"submit\">Sign in with GitHub</button>")
        );
        assert!(!body.contains("href=\"/auth/github/login\""));
        assert!(renderer.requests().is_empty());
        assert!(rbac_data.calls().is_empty());

        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/users?cursor=not-a-canonical-uuid",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(renderer.requests().is_empty());
        assert!(rbac_data.calls().is_empty());
    }

    #[tokio::test]
    async fn rbac_user_list_preserves_closed_read_outcomes() {
        for (outcome, status) in [
            (FakeRbacOutcome::Forbidden, StatusCode::FORBIDDEN),
            (FakeRbacOutcome::SessionStale, StatusCode::UNAUTHORIZED),
            (FakeRbacOutcome::NotFound, StatusCode::NOT_FOUND),
            (
                FakeRbacOutcome::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (FakeRbacOutcome::Corrupt, StatusCode::INTERNAL_SERVER_ERROR),
            (
                FakeRbacOutcome::Unrepresentable,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let (app, renderer, rbac_data) = rbac_test_router(outcome);
            let response = get(&authenticated_rbac_router(app), "/settings/access/users").await;
            assert_eq!(response.status(), status, "outcome {outcome:?}");
            if outcome == FakeRbacOutcome::Unavailable {
                assert_eq!(response.headers()[RETRY_AFTER], "1");
            }
            assert!(renderer.requests().is_empty());
            assert_eq!(rbac_data.calls().len(), 1);
        }
    }

    #[tokio::test]
    async fn rbac_user_detail_uses_the_exact_member_and_read_only_joined_assignments() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let principal_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let response = get(
            &authenticated_rbac_router(app),
            &format!("/settings/access/users/{principal_id}"),
        )
        .await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "user-detail");
        assert_eq!(page["page"]["user"]["id"], principal_id);
        assert_eq!(page["page"]["heading"], "Ada Lovelace");
        assert_eq!(page["page"]["roleAssignments"][0]["source"], "direct");
        assert_eq!(
            page["page"]["roleAssignments"][0]["scope"]["label"],
            "acme-labs/payments-api"
        );
        assert_eq!(
            page["page"]["roleAssignments"][0]["validUntil"]["iso"],
            "2026-09-01T00:00:00Z"
        );
        assert!(page["page"].get("sessionsHref").is_none());
        assert!(page["page"].get("statusOperation").is_none());
        assert_eq!(
            rbac_data.calls(),
            vec![RecordedRbacCall::UserDetail(RbacUserDetailRequest {
                principal_id: ManagedPrincipalId::new(principal_id).expect("principal ID"),
                binding_limit: automata_ci_auth::management::ManagementPageSize::new(
                    RBAC_USER_DETAIL_BINDING_LIMIT,
                )
                .expect("binding limit"),
            })]
        );
    }

    #[tokio::test]
    async fn rbac_role_list_projects_only_current_readable_roles() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let cursor = "99999999-9999-4999-8999-999999999999";
        let response = get(
            &authenticated_rbac_router(app),
            &format!("/settings/access/roles?cursor={cursor}"),
        )
        .await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "role-list");
        assert!(page["page"].get("revision").is_none());
        assert_eq!(page["page"]["roles"][0]["name"], "release-reviewer");
        assert_eq!(page["page"]["roles"][0]["permissionCount"], 1);
        assert!(page["page"].get("createRole").is_none());
        assert_eq!(
            page["page"]["pagination"]["nextHref"],
            "/settings/access/roles?cursor=dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        );
        assert_eq!(
            rbac_data.calls(),
            vec![RecordedRbacCall::RoleList(RbacRoleListRequest {
                cursor: Some(cursor.to_owned()),
                limit: automata_ci_auth::management::ManagementPageSize::new(RBAC_ROLE_PAGE_SIZE,)
                    .expect("role page size"),
            })]
        );
    }

    #[tokio::test]
    async fn rbac_role_detail_projects_the_complete_catalog_without_mutation_capabilities() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let role_id = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let response = get(
            &authenticated_rbac_router(app),
            &format!("/settings/access/roles/{role_id}"),
        )
        .await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "role-detail");
        assert_eq!(page["page"]["role"]["id"], role_id);
        assert_eq!(
            page["page"]["permissions"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(page["page"]["permissions"][0]["name"], "artifacts:download");
        assert!(
            !page["page"]["permissions"][0]["granted"]
                .as_bool()
                .expect("grant state")
        );
        assert!(page["page"]["permissions"][0].get("operation").is_none());
        assert!(page["page"]["permissions"][1].get("operation").is_none());
        assert!(page["page"].get("updateRole").is_none());
        assert!(page["page"].get("deleteRole").is_none());
        assert_eq!(
            rbac_data.calls(),
            vec![RecordedRbacCall::RoleDetail(RbacRoleDetailRequest {
                role_id: RoleId::new(role_id).expect("role ID"),
            })]
        );
    }

    #[tokio::test]
    async fn rbac_binding_list_preserves_sources_and_never_mutates_provider_observations() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let cursor = "d:99999999-9999-4999-8999-999999999999";
        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/direct-bindings?cursor=d%3A99999999-9999-4999-8999-999999999999",
        )
        .await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "direct-binding-list");
        assert!(page["page"].get("revision").is_none());
        assert_eq!(page["page"]["bindings"][0]["source"], "direct");
        assert_eq!(page["page"]["bindings"][1]["source"], "provider-observed");
        assert!(page["page"]["bindings"][0]["revoke"].is_null());
        assert!(page["page"]["bindings"][1]["revoke"].is_null());
        assert!(page["page"].get("grantBinding").is_none());
        assert_eq!(
            page["page"]["pagination"]["nextHref"],
            "/settings/access/direct-bindings?cursor=d%3Aeeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        );
        assert_eq!(
            rbac_data.calls(),
            vec![RecordedRbacCall::DirectBindingList(
                RbacDirectBindingListRequest {
                    cursor: Some(cursor.to_owned()),
                    limit: automata_ci_auth::management::ManagementPageSize::new(
                        RBAC_BINDING_PAGE_SIZE,
                    )
                    .expect("binding page size"),
                },
            )]
        );
    }

    #[tokio::test]
    async fn rbac_mutation_forms_require_the_exact_page_read_revision_and_capability() {
        let exact_capabilities = ManagementMutationCapabilities::new(
            ManagementRevision::new(4).expect("authorization revision"),
            false,
            true,
            false,
        );
        let (app, renderer, rbac_data) = rbac_mutation_test_router(
            Some(exact_capabilities),
            None,
            RbacWebMutationOutcome::Conflict,
        );
        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
        .await;
        let page = renderer.page();
        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["update"]["expectedAuthorizationRevision"], "4");
        assert_eq!(page["page"]["delete"]["expectedRevision"], "9");
        assert_eq!(page["page"]["permissions"][0]["update"]["operation"], "add");
        assert_eq!(
            page["page"]["permissions"][1]["update"]["operation"],
            "remove"
        );
        assert!(rbac_data.mutations().is_empty(), "GET must never mutate");

        let (app, renderer, _) = rbac_mutation_test_router(
            Some(ManagementMutationCapabilities::new(
                ManagementRevision::new(5).expect("mismatched revision"),
                false,
                true,
                false,
            )),
            None,
            RbacWebMutationOutcome::Conflict,
        );
        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(renderer.requests().is_empty());

        let (app, renderer, _) =
            rbac_mutation_test_router(None, None, RbacWebMutationOutcome::Conflict);
        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
        .await;
        let page = renderer.page();
        assert_page_headers(&response, &page);
        assert!(page["page"]["update"].is_null());
        assert!(page["page"]["delete"].is_null());
        assert!(
            page["page"]["permissions"]
                .as_array()
                .expect("permission rows")
                .iter()
                .all(|permission| permission["update"].is_null())
        );
    }

    #[test]
    fn immutable_roles_and_cross_tenant_binding_scopes_fail_closed_in_projection() {
        let snapshot = rbac_snapshot();
        let context = rbac_context(&snapshot);
        let csrf = CsrfToken::from_generated_secret(
            SecretString::new(CSRF_TOKEN).expect("CSRF fixture must be bounded"),
        )
        .expect("CSRF fixture must be canonical");
        let mutation = Some(model::ShellMutation::new(&csrf));
        let capabilities = ManagementMutationCapabilities::new(
            ManagementRevision::new(4).expect("authorization revision"),
            false,
            true,
            false,
        );
        let detail = rbac_immutable_role_detail_record();
        let json = model::rbac_role_detail(
            client_assets(),
            "nonce".to_owned(),
            &context,
            mutation,
            detail.role().id(),
            &detail,
            None,
            ManagementRevision::new(4).expect("page revision"),
            Some(&capabilities),
        )
        .expect("immutable role projection");
        let page: Value = serde_json::from_str(&json).expect("render request JSON");
        assert!(page["page"]["update"].is_null());
        assert!(page["page"]["delete"].is_null());
        assert!(page["page"]["permissions"][0]["update"].is_null());

        let cross_tenant_scope = ManagementScopeRecord::new(
            AuthorizationScope::tenant(
                TenantId::new("different-tenant").expect("cross-tenant fixture"),
            ),
            "Different tenant",
        )
        .expect("cross-tenant scope record");
        let binding = ManagementRoleBindingRecord::new(
            RoleBindingId::new("abababab-abab-4bab-8bab-abababababab").expect("binding ID"),
            rbac_member(),
            ManagementBindingRole::new(
                RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID"),
                RoleName::new("release-reviewer").expect("role name"),
                "Release reviewer",
            )
            .expect("binding role"),
            cross_tenant_scope,
            ManagementRoleBindingSource::Direct(DirectRoleBindingSource::Manual),
            RoleBindingStatus::Active,
            None,
            ManagementRevision::new(2).expect("binding revision"),
        )
        .expect("cross-tenant binding record");
        assert!(matches!(
            model::rbac_direct_binding_list(
                client_assets(),
                "nonce".to_owned(),
                &context,
                mutation,
                None,
                None,
                &RbacDirectBindingListPage {
                    bindings: vec![binding],
                    next_cursor: None,
                    mutation_authorization_revision: ManagementRevision::new(4)
                        .expect("page revision"),
                },
                None,
                None,
            ),
            Err(model::ModelError::InvalidData)
        ));
    }

    #[tokio::test]
    async fn direct_grant_overflow_and_unavailability_render_no_grant_form() {
        let capabilities = ManagementMutationCapabilities::new(
            ManagementRevision::new(4).expect("authorization revision"),
            false,
            false,
            true,
        );
        for (grant_options, expected_reason) in [
            (
                Some(DirectBindingGrantOptionsState::Overflow {
                    authorization_revision: ManagementRevision::new(4)
                        .expect("authorization revision"),
                    collection: DirectBindingGrantOptionCollection::Principals,
                }),
                "options-overflow",
            ),
            (None, "options-unavailable"),
        ] {
            let (app, renderer, rbac_data) = rbac_mutation_test_router(
                Some(capabilities),
                grant_options,
                RbacWebMutationOutcome::Conflict,
            );
            let response = get(
                &authenticated_rbac_router(app),
                "/settings/access/direct-bindings",
            )
            .await;
            let page = renderer.page();
            assert_page_headers(&response, &page);
            assert!(page["page"]["grant"].is_null());
            assert_eq!(page["page"]["readOnlyReason"], expected_reason);
            assert!(page["page"]["bindings"][0]["revoke"].is_object());
            assert!(page["page"]["bindings"][1]["revoke"].is_null());
            assert!(rbac_data.mutations().is_empty());
        }
    }

    #[tokio::test]
    async fn rbac_posts_are_exact_prg_surfaces_with_closed_notices() {
        let role_id = RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("role ID");
        let form = rbac_role_permission_form();
        let path =
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc/permissions/runs:read";
        let (app, _renderer, rbac_data) = rbac_mutation_test_router(
            None,
            None,
            RbacWebMutationOutcome::Applied(RbacMutationApplied::RolePermission { role_id }),
        );
        let app = authenticated_rbac_router(app)
            .layer(Extension(RbacManagementFormSubmission::Valid(form.clone())));

        let response = get(&app, path).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let response = post_request(&app, &format!("{path}?unexpected=1")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(rbac_data.mutations().is_empty());

        let response = post_request(&app, path).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()["location"],
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc?notice=saved"
        );
        assert_eq!(rbac_data.mutations(), vec![form.clone()]);

        let (mismatch_app, _, mismatch_data) =
            rbac_mutation_test_router(None, None, RbacWebMutationOutcome::Conflict);
        let mismatch_app = authenticated_rbac_router(mismatch_app)
            .layer(Extension(RbacManagementFormSubmission::Valid(form.clone())));
        let response = post_request(
            &mismatch_app,
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc/permissions/artifacts:download",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(mismatch_data.mutations().is_empty());

        for (outcome, notice) in [
            (RbacWebMutationOutcome::Conflict, "conflict"),
            (RbacWebMutationOutcome::Forbidden, "forbidden"),
        ] {
            let (app, _, data) = rbac_mutation_test_router(None, None, outcome);
            let app = authenticated_rbac_router(app)
                .layer(Extension(RbacManagementFormSubmission::Valid(form.clone())));
            let response = post_request(&app, path).await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                response.headers()["location"],
                format!(
                    "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc?notice={notice}"
                )
            );
            assert_eq!(data.mutations(), vec![form.clone()]);
        }
    }

    #[tokio::test]
    async fn rbac_detail_routes_reject_bad_ids_before_lookup_and_hide_absent_targets() {
        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::Found);
        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/users/not-a-principal",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(renderer.requests().is_empty());
        assert!(rbac_data.calls().is_empty());

        let (app, renderer, rbac_data) = rbac_test_router(FakeRbacOutcome::NotFound);
        let response = get(
            &authenticated_rbac_router(app),
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(renderer.requests().is_empty());
        assert_eq!(rbac_data.calls().len(), 1);
    }

    #[tokio::test]
    async fn rbac_management_routes_are_absent_without_the_authorized_data_port() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        for path in [
            "/settings/access/users",
            "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "/settings/access/roles",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "/settings/access/direct-bindings",
        ] {
            let response = get(&app, path).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
        }
        assert!(renderer.requests().is_empty());
        assert!(data.calls().is_empty());
    }

    #[tokio::test]
    async fn every_routed_rbac_page_satisfies_the_embedded_renderer_contract() {
        let (app, recording_renderer, _) = rbac_test_router(FakeRbacOutcome::Found);
        let app = authenticated_rbac_router(app);
        for path in [
            "/settings/access/users",
            "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "/settings/access/roles",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "/settings/access/direct-bindings",
        ] {
            let response = get(&app, path).await;
            assert_eq!(response.status(), StatusCode::OK, "path {path}");
        }

        let requests = recording_renderer.requests();
        assert_eq!(requests.len(), 5);
        let kinds = tokio::task::spawn_blocking(move || {
            let embedded = WasmtimeRenderer::new(RenderPolicy::default())
                .expect("the embedded RBAC renderer must initialize");
            let mut kinds = BTreeSet::new();
            for request in requests {
                let value: Value =
                    serde_json::from_str(&request).expect("RBAC render request JSON");
                let kind = value["page"]["kind"]
                    .as_str()
                    .expect("RBAC page kind")
                    .to_owned();
                let expected_copy = match kind.as_str() {
                    "user-list" => "Users",
                    "user-detail" => "Ada Lovelace",
                    "role-list" => "Roles",
                    "role-detail" => "Release reviewer",
                    "direct-binding-list" => "Direct bindings",
                    unexpected => panic!("unexpected routed RBAC page kind {unexpected}"),
                };
                let rendered = embedded
                    .render(&request)
                    .expect("the routed host model must satisfy the embedded RBAC contract");
                assert!(rendered.as_str().contains(expected_copy), "kind {kind}");
                assert!(kinds.insert(kind), "every routed kind must be unique");
            }
            kinds
        })
        .await
        .expect("embedded RBAC renderer task must complete");
        assert_eq!(
            kinds,
            BTreeSet::from([
                "direct-binding-list".to_owned(),
                "role-detail".to_owned(),
                "role-list".to_owned(),
                "user-detail".to_owned(),
                "user-list".to_owned(),
            ])
        );
    }

    #[tokio::test]
    async fn every_rbac_mutation_model_satisfies_the_pinned_embedded_renderer() {
        let capabilities = ManagementMutationCapabilities::new(
            ManagementRevision::new(4).expect("authorization revision"),
            true,
            true,
            true,
        );
        let (app, recording_renderer, _) = rbac_mutation_test_router(
            Some(capabilities),
            Some(rbac_grant_options()),
            RbacWebMutationOutcome::Conflict,
        );
        let app = authenticated_rbac_router(app);
        for path in [
            "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "/settings/access/roles",
            "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "/settings/access/direct-bindings",
        ] {
            let response = get(&app, path).await;
            assert_eq!(response.status(), StatusCode::OK, "path {path}");
        }

        let requests = recording_renderer.requests();
        assert_eq!(requests.len(), 4);
        tokio::task::spawn_blocking(move || {
            let embedded = WasmtimeRenderer::new(RenderPolicy::default())
                .expect("the pinned mutation-capable renderer must initialize");
            for request in requests {
                let value: Value =
                    serde_json::from_str(&request).expect("RBAC render request JSON");
                match value["page"]["kind"].as_str().expect("RBAC page kind") {
                    "user-detail" => assert!(value["page"]["statusUpdate"].is_object()),
                    "role-list" => assert!(value["page"]["create"].is_object()),
                    "role-detail" => {
                        assert!(value["page"]["update"].is_object());
                        assert!(value["page"]["delete"].is_object());
                        assert!(value["page"]["permissions"][0]["update"].is_object());
                    }
                    "direct-binding-list" => {
                        assert!(value["page"]["grant"].is_object());
                        assert!(value["page"]["bindings"][0]["revoke"].is_object());
                        assert!(value["page"]["bindings"][1]["revoke"].is_null());
                    }
                    unexpected => panic!("unexpected mutation page kind {unexpected}"),
                }
                let rendered = embedded
                    .render(&request)
                    .expect("the mutation host model must satisfy the pinned renderer contract");
                assert!(rendered.as_str().contains("<form"));
            }
        })
        .await
        .expect("embedded mutation renderer task must complete");
    }

    #[tokio::test]
    async fn root_redirects_only_the_exact_empty_query_to_the_repository_directory() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let response = get(&app, "/").await;

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
        assert_eq!(response.headers()["location"], "/repositories");
        assert!(renderer.requests().is_empty());
        assert!(data.calls().is_empty());

        let response = get(&app, "/?cursor=not-an-alias").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = get(&app, "/runs").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(data.calls().is_empty());
    }

    #[tokio::test]
    async fn empty_repository_directory_is_honest_and_repository_neutral() {
        let (app, renderer, data) = test_router(FakeOutcome::Missing);
        let response = get(&app, "/repositories").await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "repository-directory");
        assert_eq!(page["page"]["heading"], "Repositories");
        assert_eq!(page["page"]["shell"]["homeHref"], "/repositories");
        assert_eq!(page["page"]["shell"]["signIn"], Value::Null);
        assert_eq!(page["page"]["repositories"], serde_json::json!([]));
        assert!(page["page"].get("repository").is_none());
        assert!(!page.to_string().contains("github.com"));
        let body = to_bytes(response.into_body(), RENDERED_HTML.len())
            .await
            .expect("rendered repository-directory page must be readable");
        assert_eq!(&body[..], RENDERED_HTML.as_bytes());
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RepositoryDirectory {
                cursor: None,
                limit: REPOSITORY_PAGE_SIZE,
            }]
        );
    }

    #[tokio::test]
    async fn repository_directory_exposes_only_authorized_destinations_and_exact_next_page() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let response = get(&app, "/repositories?cursor=request_page").await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["repositories"][0],
            serde_json::json!({
                "owner": "acme-labs",
                "name": "payments-api",
                "sourceHref": "https://github.com/acme-labs/payments-api",
                "actionsHref": "/acme-labs/payments-api/actions",
                "settingsHref": null,
            })
        );
        assert_eq!(
            page["page"]["pagination"]["nextHref"],
            "/repositories?cursor=next_repositories"
        );
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RepositoryDirectory {
                cursor: Some("request_page".to_owned()),
                limit: REPOSITORY_PAGE_SIZE,
            }]
        );
    }

    #[tokio::test]
    async fn repository_directory_routes_secret_metadata_only_rows_to_secrets() {
        let (app, renderer, data) = test_router(FakeOutcome::SecretsOnly);
        let response = get(&authenticated_rbac_router(app), "/repositories").await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["repositories"][0],
            serde_json::json!({
                "owner": "acme-labs",
                "name": "payments-api",
                "sourceHref": "https://github.com/acme-labs/payments-api",
                "actionsHref": null,
                "settingsHref": "/acme-labs/payments-api/settings/secrets",
            })
        );
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RepositoryDirectory {
                cursor: None,
                limit: REPOSITORY_PAGE_SIZE,
            }]
        );
    }

    #[tokio::test]
    async fn repository_run_list_preserves_domain_identity_filters_and_nullable_data() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let response = get(
            &app,
            "/acme-labs/payments-api/actions?status=completed&branch=refs%2Fheads%2Fmain&cursor=request_9",
        )
        .await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "run-list");
        assert_eq!(page["page"]["repository"]["owner"], "acme-labs");
        assert_eq!(page["page"]["repository"]["name"], "payments-api");
        assert_eq!(
            page["page"]["repository"]["sourceHref"],
            "https://github.com/acme-labs/payments-api"
        );
        assert_eq!(
            page["page"]["repository"]["runsHref"],
            "/acme-labs/payments-api/actions"
        );
        assert!(page["page"]["repository"]["settingsHref"].is_null());
        assert!(page["page"]["repository"].get("href").is_none());
        assert_eq!(page["page"]["shell"]["homeHref"], "/repositories");
        assert_eq!(
            page["page"]["shell"]["navigation"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            page["page"]["shell"]["navigation"][0]["label"],
            "Repositories"
        );
        assert_eq!(page["page"]["shell"]["navigation"][1]["label"], "Actions");
        assert_eq!(page["page"]["runs"][0]["id"], RUN_ID);
        assert_eq!(page["page"]["runs"][0]["number"], "1842");
        assert_ne!(
            page["page"]["runs"][0]["id"],
            page["page"]["runs"][0]["number"]
        );
        assert_eq!(
            page["page"]["runs"][0]["href"],
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}")
        );
        assert_eq!(
            page["page"]["runs"][0]["workflowHref"],
            format!("/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}")
        );
        assert!(page["page"]["runs"][0]["actor"].is_null());
        assert!(page["page"]["runs"][0]["sourceRef"].is_null());
        assert!(page["page"]["runs"][0].get("branch").is_none());
        assert!(page["page"]["runs"][0]["commit"]["message"].is_null());
        assert_eq!(
            page["page"]["runs"][0]["commit"]["href"],
            "https://github.com/acme-labs/payments-api/commit/0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(page["page"]["runs"][0]["durationLabel"], "2m 5s");
        assert!(page["page"]["workflowNavigation"]["selectedWorkflowId"].is_null());
        assert_eq!(
            page["page"]["workflowNavigation"]["workflows"][0]["href"],
            format!("/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}")
        );
        assert_eq!(
            page["page"]["workflowNavigation"]["workflows"][0]["enabled"],
            false
        );
        assert_eq!(page["page"]["filters"]["status"], "completed");
        assert_eq!(page["page"]["filters"]["branch"], "refs/heads/main");
        assert_eq!(
            page["page"]["workflowNavigation"]["pagination"]["nextHref"],
            "/acme-labs/payments-api/actions?status=completed&branch=refs%2Fheads%2Fmain&cursor=request_9&workflow_cursor=workflow_next"
        );
        assert_eq!(
            page["page"]["pagination"]["previousHref"],
            "/acme-labs/payments-api/actions?status=completed&branch=refs%2Fheads%2Fmain&cursor=previous_1"
        );
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RunList {
                repository: repository_path(),
                workflow_id: None,
                workflow_cursor: None,
                status: StatusFilter::Completed,
                git_ref: Some("refs/heads/main".to_owned()),
                cursor: Some("request_9".to_owned()),
                limit: RUN_PAGE_SIZE,
            }]
        );

        let body = to_bytes(response.into_body(), RENDERED_HTML.len())
            .await
            .expect("rendered HTML must be readable");
        assert_eq!(&body[..], RENDERED_HTML.as_bytes());
    }

    #[tokio::test]
    async fn paginated_actions_sign_in_returns_to_the_exact_viewed_page() {
        let renderer = Arc::new(RecordingRenderer::default());
        let data = Arc::new(FakeWebData::new(FakeOutcome::Found));
        let tenant = TenantId::new("acme-production").expect("test tenant must be valid");
        let context = RequestContext::new(
            tenant,
            AuthorizationContext::anonymous(),
            None,
            Some("/auth/github/login".to_owned()),
        )
        .expect("canonical anonymous sign-in context");
        let app = router_with_data(renderer.clone(), 4, data, context);

        let run_list_path = "/acme-labs/payments-api/actions?status=completed&branch=refs%2Fheads%2Fmain&cursor=request_9";
        let response = get(&app, run_list_path).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            renderer.page()["page"]["shell"]["signIn"]["returnPath"],
            run_list_path
        );

        let job_path = format!(
            "/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=retry%20warning&cursor=log_20"
        );
        let response = get(&app, &job_path).await;
        assert_eq!(response.status(), StatusCode::OK);
        let requests = renderer.requests();
        let page: Value = serde_json::from_str(
            requests
                .last()
                .expect("the job-log page must be the latest render request"),
        )
        .expect("job-log render request JSON");
        assert_eq!(page["page"]["shell"]["signIn"]["returnPath"], job_path);
        assert_eq!(page["page"]["pagination"]["currentCursor"], "log_20");
    }

    #[tokio::test]
    async fn access_navigation_requires_a_viewer_and_the_composed_management_surface() {
        let (anonymous_app, anonymous_renderer, _) = rbac_test_router(FakeRbacOutcome::Found);
        let response = get(&anonymous_app, "/acme-labs/payments-api/actions").await;
        assert_eq!(response.status(), StatusCode::OK);
        let page = anonymous_renderer.page();
        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["shell"]["navigation"].as_array().map(Vec::len),
            Some(2)
        );

        let (composed_app, composed_renderer, _) = rbac_test_router(FakeRbacOutcome::Found);
        let response = get(
            &authenticated_rbac_router(composed_app),
            "/acme-labs/payments-api/actions",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let page = composed_renderer.page();
        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["shell"]["navigation"][0]["label"],
            "Repositories"
        );
        assert_eq!(page["page"]["shell"]["navigation"][1]["label"], "Actions");
        assert_eq!(page["page"]["shell"]["navigation"][2]["label"], "Access");
        assert_eq!(
            page["page"]["shell"]["navigation"][2]["href"],
            RBAC_USERS_RETURN_PATH
        );

        let (uncomposed_app, uncomposed_renderer, _) = test_router(FakeOutcome::Found);
        let response = get(
            &authenticated_rbac_router(uncomposed_app),
            "/acme-labs/payments-api/actions",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let page = uncomposed_renderer.page();
        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["shell"]["navigation"].as_array().map(Vec::len),
            Some(2)
        );
    }

    #[tokio::test]
    async fn anonymous_repository_settings_data_fails_closed() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let response = get(&app, "/acme-labs/payments-api/settings/access").await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(renderer.requests().is_empty());
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RepositorySettings {
                repository: repository_path(),
            }]
        );
    }

    #[tokio::test]
    async fn repository_settings_reject_untrusted_notice_queries() {
        for notice in ["saved", "conflict"] {
            let (app, renderer, data) = test_router(FakeOutcome::Found);
            let uri = format!("/acme-labs/payments-api/settings/access?notice={notice}");
            let response = get(&app, &uri).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "notice={notice}"
            );
            assert!(renderer.requests().is_empty());
            assert!(data.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn editable_repository_settings_fail_closed_without_csrf_capability() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let context = RequestContext::new(
            TenantId::new("acme-production").expect("test tenant must be valid"),
            AuthorizationContext::anonymous(),
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("test context must be internally consistent");

        let response = get(
            &app.layer(Extension(context)),
            "/acme-labs/payments-api/settings/access",
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(renderer.requests().is_empty());
        assert!(data.calls().is_empty());
    }

    #[tokio::test]
    async fn repository_settings_token_cannot_bypass_denied_update_authority() {
        let (app, renderer, data) = test_router(FakeOutcome::ReadOnly);
        let context = RequestContext::new(
            TenantId::new("acme-production").expect("test tenant must be valid"),
            AuthorizationContext::anonymous(),
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("test context must be internally consistent");
        let csrf = CsrfToken::from_generated_secret(
            SecretString::new(CSRF_TOKEN).expect("CSRF fixture must be bounded"),
        )
        .expect("CSRF fixture must be canonical");
        let app = app
            .layer(Extension(context))
            .layer(Extension(Arc::new(csrf)));

        let response = get(&app, "/acme-labs/payments-api/settings/access").await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert!(page["page"]["update"].is_null());
        assert!(page["page"].get("readOnlyReason").is_none());
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RepositorySettings {
                repository: repository_path(),
            }]
        );
    }

    #[tokio::test]
    async fn repository_settings_expose_one_exact_verified_mutation_capability() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let tenant = TenantId::new("acme-production").expect("test tenant must be valid");
        let context = RequestContext::new(
            tenant,
            AuthorizationContext::anonymous(),
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("test context must be internally consistent");
        let csrf = CsrfToken::from_generated_secret(
            SecretString::new(CSRF_TOKEN).expect("CSRF fixture must be bounded"),
        )
        .expect("CSRF fixture must be canonical");
        let app = app
            .layer(Extension(context))
            .layer(Extension(Arc::new(csrf)));

        let response = get(&app, "/acme-labs/payments-api/settings/access").await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["shell"]["viewer"]["displayName"],
            "Ada Lovelace"
        );
        assert_eq!(
            page["page"]["update"]["action"],
            "/acme-labs/payments-api/settings/access"
        );
        assert!(page["page"].get("readOnlyReason").is_none());
        assert_eq!(page["page"]["update"]["csrfToken"], CSRF_TOKEN);
        assert_eq!(
            page["page"]["shell"]["signOut"]["action"],
            crate::app::github_auth::GITHUB_WEB_LOGOUT_PATH
        );
        assert_eq!(page["page"]["shell"]["signOut"]["csrfToken"], CSRF_TOKEN);
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RepositorySettings {
                repository: repository_path(),
            }]
        );
    }

    #[tokio::test]
    async fn workflow_route_scopes_the_query_and_uses_canonical_navigation() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let uri =
            format!("/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}?status=in_progress");
        let response = get(&app, &uri).await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(
            page["page"]["workflowNavigation"]["selectedWorkflow"]["id"],
            WORKFLOW_ID
        );
        assert_eq!(
            page["page"]["filters"]["action"],
            format!("/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}")
        );
        assert_eq!(
            page["page"]["workflowNavigation"]["workflows"][0]["enabled"],
            false
        );
        assert_eq!(
            page["page"]["pagination"]["nextHref"],
            format!(
                "/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}?status=in_progress&cursor=next_2"
            )
        );
        assert_eq!(
            page["page"]["workflowNavigation"]["pagination"]["nextHref"],
            format!(
                "/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}?status=in_progress&workflow_cursor=workflow_next"
            )
        );
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RunList {
                repository: repository_path(),
                workflow_id: Some(workflow_id()),
                workflow_cursor: None,
                status: StatusFilter::InProgress,
                git_ref: None,
                cursor: None,
                limit: RUN_PAGE_SIZE,
            }]
        );
    }

    #[tokio::test]
    async fn run_detail_exposes_canonical_child_links_and_honest_nulls() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let uri = format!("/acme-labs/payments-api/actions/runs/{RUN_ID}?job_cursor=request_job");
        let response = get(&app, &uri).await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "run-detail");
        assert!(page["page"]["run"].get("id").is_none());
        assert_eq!(page["page"]["run"]["number"], "1842");
        assert_eq!(page["page"]["run"]["durationLabel"], "2m 5s");
        assert_eq!(
            page["page"]["run"]["workflowHref"],
            format!("/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}")
        );
        assert!(page["page"]["run"]["actor"].is_null());
        assert!(page["page"]["run"]["sourceRef"].is_null());
        assert!(page["page"]["run"].get("branch").is_none());
        assert!(page["page"]["run"].get("branchHref").is_none());
        assert!(page["page"]["run"]["commit"]["message"].is_null());
        assert_eq!(
            page["page"]["run"]["commit"]["href"],
            "https://github.com/acme-labs/payments-api/commit/0123456789abcdef0123456789abcdef01234567"
        );
        assert!(page["page"].get("csrfToken").is_none());
        assert!(page["page"].get("operations").is_none());
        assert_eq!(page["page"]["jobs"]["visibility"], "full");
        assert_eq!(
            page["page"]["jobPagination"]["nextHref"],
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}?job_cursor=job_next")
        );
        assert_eq!(
            page["page"]["jobs"]["items"][0]["href"],
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}")
        );
        assert!(page["page"]["jobs"]["items"][0]["runnerLabel"].is_null());
        assert_eq!(page["page"]["jobs"]["items"][0]["durationLabel"], "1m 55s");
        assert!(page["page"]["jobs"]["items"][0].get("steps").is_none());
        assert_eq!(page["page"]["artifacts"]["visibility"], "full");
        assert!(page["page"]["artifacts"]["items"][0]["expiresAt"].is_null());
        assert_eq!(
            page["page"]["artifacts"]["items"][0]["downloadHref"],
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/artifacts/73")
        );
        assert_eq!(
            data.calls(),
            vec![RecordedCall::RunDetail {
                repository: repository_path(),
                run_id: run_id(),
                job_cursor: Some("request_job".to_owned()),
                limit: RUN_JOB_PAGE_SIZE,
            }]
        );
    }

    #[tokio::test]
    async fn job_log_preserves_search_pagination_and_job_navigation() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let path = format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}");
        let response = get(&app, &format!("{path}?q=retry%20warning&cursor=log_20")).await;
        let page = renderer.page();

        assert_page_headers(&response, &page);
        assert_eq!(page["page"]["kind"], "job-log");
        assert!(page["page"]["run"].get("id").is_none());
        assert!(page["page"]["run"].get("status").is_none());
        assert_eq!(page["page"]["run"]["number"], "1842");
        assert_eq!(page["page"]["run"]["workflowName"], "Pull request checks");
        assert_eq!(
            page["page"]["run"]["workflowHref"],
            format!("/acme-labs/payments-api/actions/workflows/{WORKFLOW_ID}")
        );
        assert_eq!(
            page["page"]["run"]["href"],
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}")
        );
        assert_eq!(page["page"]["job"]["id"], JOB_ID);
        assert_eq!(page["page"]["job"]["href"], path);
        assert_eq!(page["page"]["job"]["attempt"], 3);
        assert!(page["page"]["job"]["runnerLabel"].is_null());
        assert!(page["page"]["job"]["durationLabel"].is_null());
        assert!(page["page"]["jobs"][1]["href"].is_null());
        assert_eq!(page["page"]["search"]["query"], "retry warning");
        assert_eq!(page["page"]["search"]["action"], path);
        assert!(page["page"]["search"].get("refreshHref").is_none());
        assert_eq!(page["page"]["lines"][1]["id"], format!("log-{JOB_ID}-39.1"));
        assert_eq!(page["page"]["lines"][1]["channel"], "stdout");
        assert_eq!(page["page"]["pagination"]["nextCursor"], "log_40");
        assert_eq!(page["page"]["pagination"]["currentCursor"], "log_20");
        assert!(page["page"]["pagination"].get("nextHref").is_none());
        assert!(
            page["page"]["notice"]
                .as_str()
                .expect("incomplete job must have a notice")
                .contains("still running")
        );
        assert_eq!(
            data.calls(),
            vec![RecordedCall::JobLog {
                repository: repository_path(),
                run_id: run_id(),
                job_id: job_id(),
                cursor: Some("log_20".to_owned()),
                limit: LOG_PAGE_SIZE,
                maximum_decoded_bytes: LOG_PAGE_DECODED_BYTES,
            }]
        );
    }

    #[tokio::test]
    async fn job_snapshot_is_bounded_no_store_json_with_conditional_revalidation() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let uri = format!(
            "/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}/snapshot?q=retry%20warning&cursor=log_20"
        );
        let response = get(&app, &uri).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(response.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let etag = response.headers()[ETAG]
            .to_str()
            .expect("snapshot ETag")
            .to_owned();
        assert!(etag.starts_with("\"sha256-"));
        let body = to_bytes(response.into_body(), 8 * 1_024 * 1_024)
            .await
            .expect("snapshot body");
        let snapshot: serde_json::Value =
            serde_json::from_slice(&body).expect("snapshot render request");
        assert_eq!(snapshot["page"]["kind"], "job-log");
        assert_eq!(snapshot["page"]["job"]["id"], JOB_ID);
        assert_eq!(snapshot["page"]["search"]["query"], "retry warning");
        assert_eq!(snapshot["page"]["pagination"]["currentCursor"], "log_20");
        assert!(renderer.requests().is_empty());

        let not_modified = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(&uri)
                    .header(IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .expect("conditional snapshot request"),
            )
            .await
            .expect("snapshot route");
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers()[ETAG], etag);
        assert_eq!(not_modified.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
        assert!(
            to_bytes(not_modified.into_body(), 1)
                .await
                .expect("empty 304 body")
                .is_empty()
        );
        assert_eq!(data.calls().len(), 2);
    }

    #[tokio::test]
    async fn anonymous_missing_and_denied_run_links_share_an_exact_sign_in_handoff() {
        for outcome in [FakeOutcome::Missing, FakeOutcome::Unauthorized] {
            let (app, renderer, data) = test_router(outcome);
            let context = RequestContext::new(
                TenantId::new("acme-production").expect("tenant"),
                AuthorizationContext::anonymous(),
                None,
                Some(crate::app::github_auth::GITHUB_WEB_BEGIN_PATH.to_owned()),
            )
            .expect("anonymous sign-in context");
            let app = app.layer(Extension(context));
            let uri =
                format!("/acme-labs/payments-api/actions/runs/{RUN_ID}?job_cursor=request_job");

            let response = get(&app, &uri).await;
            let page = renderer.page();

            assert_page_headers(&response, &page);
            assert_eq!(page["page"]["kind"], "deep-link-sign-in");
            assert_eq!(
                page["page"]["shell"]["signIn"]["action"],
                crate::app::github_auth::GITHUB_WEB_BEGIN_PATH
            );
            assert_eq!(page["page"]["shell"]["signIn"]["returnPath"], uri);
            assert_eq!(
                data.calls(),
                vec![RecordedCall::RunDetail {
                    repository: repository_path(),
                    run_id: run_id(),
                    job_cursor: Some("request_job".to_owned()),
                    limit: RUN_JOB_PAGE_SIZE,
                }]
            );
        }
    }

    #[tokio::test]
    async fn anonymous_missing_and_denied_job_links_share_an_exact_sign_in_handoff() {
        for outcome in [FakeOutcome::Missing, FakeOutcome::Unauthorized] {
            let (app, renderer, data) = test_router(outcome);
            let context = RequestContext::new(
                TenantId::new("acme-production").expect("tenant"),
                AuthorizationContext::anonymous(),
                None,
                Some(crate::app::github_auth::GITHUB_WEB_BEGIN_PATH.to_owned()),
            )
            .expect("anonymous sign-in context");
            let app = app.layer(Extension(context));
            let uri = format!(
                "/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=retry%20warning"
            );

            let response = get(&app, &uri).await;
            let page = renderer.page();

            assert_page_headers(&response, &page);
            assert_eq!(page["page"]["kind"], "deep-link-sign-in");
            assert_eq!(
                page["page"]["shell"]["signIn"]["action"],
                crate::app::github_auth::GITHUB_WEB_BEGIN_PATH
            );
            assert_eq!(page["page"]["shell"]["signIn"]["returnPath"], uri);
            assert_eq!(
                data.calls(),
                vec![RecordedCall::JobLog {
                    repository: repository_path(),
                    run_id: run_id(),
                    job_id: job_id(),
                    cursor: None,
                    limit: LOG_PAGE_SIZE,
                    maximum_decoded_bytes: LOG_PAGE_DECODED_BYTES,
                }]
            );
        }
    }

    #[tokio::test]
    async fn artifact_download_streams_exact_bytes_with_safe_content_headers() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let uri = format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/artifacts/73");
        let response = get(&app, &uri).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/zip");
        assert_eq!(
            response.headers()[CONTENT_LENGTH],
            (ARTIFACT_PREFIX.len() + ARTIFACT_PAYLOAD.len()).to_string()
        );
        assert_eq!(
            response.headers()[CONTENT_DISPOSITION],
            "attachment; filename=\"artifact\"; filename*=UTF-8''release%20bundle.zip"
        );
        assert_eq!(
            response.headers()[ETAG],
            format!("\"sha256-{}\"", "b".repeat(64))
        );
        assert_eq!(response.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(response.headers().get("content-security-policy").is_none());
        assert!(renderer.requests().is_empty());
        assert_eq!(
            data.calls(),
            vec![RecordedCall::Artifact {
                repository: repository_path(),
                run_id: run_id(),
                artifact_id: 73,
            }]
        );

        let body = to_bytes(
            response.into_body(),
            ARTIFACT_PREFIX.len() + ARTIFACT_PAYLOAD.len(),
        )
        .await
        .expect("artifact stream must be readable");
        assert_eq!(&body[..ARTIFACT_PREFIX.len()], ARTIFACT_PREFIX);
        assert_eq!(&body[ARTIFACT_PREFIX.len()..], ARTIFACT_PAYLOAD);
    }

    #[tokio::test]
    async fn invalid_identifiers_and_queries_fail_before_data_access() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let invalid_uris = vec![
            "/repositories?".to_owned(),
            "/repositories?cursor=".to_owned(),
            "/repositories?unexpected=x".to_owned(),
            "/repositories?cursor=one&cursor=two".to_owned(),
            "/repositories?%63ursor=encoded-key".to_owned(),
            "/repositories?cursor=encoded%2Dvalue".to_owned(),
            "/acme-labs/payments-api/actions?status=unknown".to_owned(),
            "/acme-labs/payments-api/actions?status=all&unexpected=x".to_owned(),
            "/acme-labs/payments-api/actions?status=queued&status=completed".to_owned(),
            "/acme-labs/payments-api/actions?cursor=".to_owned(),
            "/acme-labs/payments-api/actions?branch=bad%0Aref".to_owned(),
            "/acme-labs/payments-api/actions?branch=%E2%80%8B".to_owned(),
            "/acme-labs/payments-api/actions?branch=main%E2%80%AE".to_owned(),
            format!(
                "/acme-labs/payments-api/actions?branch={}",
                "x".repeat(1_014)
            ),
            "/acme-labs/payments-api/actions?branch=%FF".to_owned(),
            "/acme-labs/%FF/actions".to_owned(),
            format!(
                "/acme-labs/payments-api/actions/workflows/{}",
                WORKFLOW_ID.to_ascii_uppercase()
            ),
            "/acme-labs/payments-api/actions/runs/not-a-uuid".to_owned(),
            "/acme-labs/payments-api/actions/runs/00000000-0000-0000-0000-000000000000".to_owned(),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}?q=x"),
            format!(
                "/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{}",
                JOB_ID.to_ascii_uppercase()
            ),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/artifacts/01"),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/artifacts/73?download=1"),
            "/acme-labs/payments-api/settings/access?unexpected=1".to_owned(),
            "/acme-labs/payments-api/settings/access?".to_owned(),
            "/acme-labs/payments-api/settings/access?notice=".to_owned(),
            "/acme-labs/payments-api/settings/access?notice=complete".to_owned(),
            "/acme-labs/payments-api/settings/access?notice=saved&notice=conflict".to_owned(),
            "/acme-labs/payments-api/settings/access?notice=%73aved".to_owned(),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=bad%0Aquery"),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=%E2%80%8B"),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=build%E2%80%AE"),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=one&q=two"),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}?q=x&unexpected=x"),
        ];

        for uri in invalid_uris {
            let response = get(&app, &uri).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "URI: {uri}");
            assert_error_page_headers(&response, StatusCode::BAD_REQUEST);
            let body = error_page_body(response).await;
            assert!(body.contains("<h1>Invalid request</h1>"), "URI: {uri}");
            assert!(body.contains("href=\"/repositories\">Back to repositories</a>"));
        }
        assert!(data.calls().is_empty());
        assert!(renderer.requests().is_empty());
    }

    #[tokio::test]
    async fn unmatched_pages_use_the_accessible_branded_not_found_document() {
        let (app, renderer, data) = test_router(FakeOutcome::Found);
        let response = get(&app, "/this/path/does/not/exist").await;

        assert_error_page_headers(&response, StatusCode::NOT_FOUND);
        let body = error_page_body(response).await;
        assert!(body.starts_with("<!doctype html><html lang=\"en\">"));
        assert!(body.contains("<title>404 · Page not found · Automata</title>"));
        assert!(body.contains("class=\"skip-link\" href=\"#main-content\""));
        assert!(
            body.contains("<main class=\"layout-width page\" id=\"main-content\" tabindex=\"-1\">")
        );
        assert!(body.contains("<h1>Page not found</h1>"));
        assert!(body.contains("href=\"/repositories\">Back to repositories</a>"));
        assert!(!body.contains("<script"));
        assert!(renderer.requests().is_empty());
        assert!(data.calls().is_empty());
    }

    #[tokio::test]
    async fn missing_and_unauthorized_resources_have_identical_not_found_responses() {
        for uri in [
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}"),
            "/acme-labs/payments-api/settings/access".to_owned(),
        ] {
            let (missing_app, missing_renderer, _) = test_router(FakeOutcome::Missing);
            let (unauthorized_app, unauthorized_renderer, _) =
                test_router(FakeOutcome::Unauthorized);
            let missing = get(&missing_app, &uri).await;
            let unauthorized = get(&unauthorized_app, &uri).await;

            assert_error_page_headers(&missing, StatusCode::NOT_FOUND);
            assert_error_page_headers(&unauthorized, StatusCode::NOT_FOUND);
            assert_eq!(missing.headers(), unauthorized.headers());
            let missing_body = to_bytes(missing.into_body(), MAX_ERROR_PAGE_BYTES)
                .await
                .expect("missing error document must be readable");
            let unauthorized_body = to_bytes(unauthorized.into_body(), MAX_ERROR_PAGE_BYTES)
                .await
                .expect("unauthorized error document must be readable");
            assert_eq!(missing_body, unauthorized_body);
            assert!(
                missing_body
                    .windows(b"<h1>Page not found</h1>".len())
                    .any(|window| { window == b"<h1>Page not found</h1>" })
            );
            assert!(missing_renderer.requests().is_empty());
            assert!(unauthorized_renderer.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn unavailable_data_is_retryable_without_invoking_the_renderer() {
        let (app, renderer, _) = test_router(FakeOutcome::Unavailable);
        let response = get(&app, "/acme-labs/payments-api/actions").await;

        assert_error_page_headers(&response, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        let body = error_page_body(response).await;
        assert!(body.contains("<h1>Page temporarily unavailable</h1>"));
        assert!(body.contains("Workflow data is temporarily unavailable."));
        assert!(renderer.requests().is_empty());
    }

    #[tokio::test]
    async fn corrupt_scope_and_invalid_model_data_fail_closed() {
        for outcome in [
            FakeOutcome::Corrupt,
            FakeOutcome::ScopeMismatch,
            FakeOutcome::InvalidModel,
        ] {
            let (app, renderer, _) = test_router(outcome);
            let response = get(&app, "/acme-labs/payments-api/actions").await;
            assert_error_page_headers(&response, StatusCode::INTERNAL_SERVER_ERROR);
            let body = error_page_body(response).await;
            assert!(
                body.contains("<h1>Unable to load this page</h1>"),
                "outcome: {outcome:?}"
            );
            assert!(renderer.requests().is_empty());
        }

        for outcome in [
            FakeOutcome::Corrupt,
            FakeOutcome::ScopeMismatch,
            FakeOutcome::InvalidModel,
        ] {
            let (app, renderer, _) = test_router(outcome);
            let response = get(&app, "/acme-labs/payments-api/settings/access").await;
            assert_error_page_headers(&response, StatusCode::INTERNAL_SERVER_ERROR);
            let body = error_page_body(response).await;
            assert!(
                body.contains("<h1>Unable to load this page</h1>"),
                "settings outcome: {outcome:?}"
            );
            assert!(renderer.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn nested_pages_reject_data_from_a_different_parent_scope() {
        for uri in [
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}"),
            format!("/acme-labs/payments-api/actions/runs/{RUN_ID}/jobs/{JOB_ID}"),
        ] {
            let (app, renderer, _) = test_router(FakeOutcome::ScopeMismatch);
            let response = get(&app, &uri).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(response.headers()[CACHE_CONTROL], PAGE_CACHE_CONTROL);
            assert!(renderer.requests().is_empty());
        }
    }

    #[test]
    fn identifiers_require_one_canonical_non_nil_representation() {
        assert!(parse_run_id("00000000-0000-0000-0000-000000000000").is_none());
        assert!(parse_run_id("550E8400-E29B-41D4-A716-446655440000").is_none());
        assert!(parse_run_id("550e8400-e29b-41d4-a716-446655440000").is_some());
        assert_eq!(parse_artifact_id("01"), None);
        assert_eq!(parse_artifact_id("1"), Some(1));
    }

    #[test]
    fn cursors_use_one_bounded_alias_free_alphabet() {
        assert!(valid_cursor(None));
        assert!(valid_cursor(Some("eyJpZCI6IjEifQ")));
        assert!(!valid_cursor(Some("")));
        assert!(!valid_cursor(Some("cursor=")));
    }

    #[test]
    fn artifact_names_are_header_encoded() {
        assert_eq!(
            percent_encode("release build.zip".as_bytes()),
            "release%20build.zip"
        );
        assert_eq!(percent_encode("bad\r\nname".as_bytes()), "bad%0D%0Aname");
    }

    #[test]
    fn route_segments_reject_dot_aliases_and_conditional_assets_accept_weak_matches() {
        assert!(!valid_route_segment("."));
        assert!(!valid_route_segment(".."));
        assert!(valid_route_segment("payments-api"));

        let etag = "\"abc123\"";
        assert!(if_none_match_matches(
            &HeaderValue::from_static("W/\"abc123\""),
            etag
        ));
        assert!(if_none_match_matches(&HeaderValue::from_static("*"), etag));
        assert!(!if_none_match_matches(
            &HeaderValue::from_static("\"different\""),
            etag
        ));
    }
}
