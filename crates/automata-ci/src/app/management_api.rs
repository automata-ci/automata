//! Typed JSON boundary for revision-safe human and RBAC administration.
//!
//! Authentication middleware supplies the only actor evidence accepted here.
//! Role names, permissions, tenant IDs, and session revisions in request bodies
//! are never treated as authority; the repository reauthorizes every operation
//! from current durable state.

use std::sync::Arc;

use automata_ci_auth::{
    authorization::{
        AuthorizationScope, Permission, RepositoryResource, RepositoryResourceId, RoleName,
        RunnerGroupResource, RunnerGroupResourceId,
    },
    management::{
        ChangeMemberStatus, CreateRole, DeleteRole, GrantRole, HumanRbacManagementRepository,
        ListManagementRecords, ListManagementRoleBindings, ManagedPrincipalId, ManagementActor,
        ManagementDetailOutcome, ManagementMutationOutcome, ManagementPage, ManagementPageSize,
        ManagementReadOutcome, ManagementRepositoryError, ManagementRequestId, ManagementRevision,
        ManagementRoleBindingCursor, ManagementRoleBindingRecord, ManagementRoleBindingSource,
        MemberRecord, MemberStatus, ReadMemberDetail, ReadRoleDetail, RevokeRole, RoleBindingId,
        RoleBindingRecord, RoleDetailRecord, RoleId, RoleRecord, SetRolePermission, UpdateRole,
    },
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::{Clock, UnixTimestamp},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, put},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_QUERY_BYTES: usize = 1_024;
const DEFAULT_PAGE_SIZE: u16 = 50;
const DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE: u16 = 50;
const REQUEST_ID_HEADER: &str = "x-request-id";

pub(crate) const USERS_PATH: &str = "/api/v1/users";
pub(crate) const USER_PATH: &str = "/api/v1/users/{principal_id}";
pub(crate) const ROLES_PATH: &str = "/api/v1/roles";
pub(crate) const ROLE_PATH: &str = "/api/v1/roles/{role_id}";
pub(crate) const ROLE_PERMISSION_PATH: &str = "/api/v1/roles/{role_id}/permissions/{permission}";
pub(crate) const DIRECT_BINDINGS_PATH: &str = "/api/v1/direct-bindings";
pub(crate) const DIRECT_BINDING_PATH: &str = "/api/v1/direct-bindings/{binding_id}";

/// Dependencies for the isolated RBAC management HTTP surface.
#[derive(Clone)]
struct ManagementApiState {
    repository: Arc<dyn HumanRbacManagementRepository>,
    clock: Arc<dyn Clock>,
}

/// Builds the authenticated JSON management routes.
///
/// The caller must place [`AuthenticatedRequestSnapshot`] in request extensions
/// before dispatch. Missing snapshots fail with a sanitized `401`.
pub(crate) fn management_api_router(
    repository: Arc<dyn HumanRbacManagementRepository>,
    clock: Arc<dyn Clock>,
) -> Router {
    let state = ManagementApiState { repository, clock };
    Router::new()
        .route(USERS_PATH, get(list_users))
        .route(USER_PATH, get(read_user).patch(change_user_status))
        .route(ROLES_PATH, get(list_roles).post(create_role))
        .route(
            ROLE_PATH,
            get(read_role).patch(update_role).delete(delete_role),
        )
        .route(
            ROLE_PERMISSION_PATH,
            put(add_role_permission).delete(remove_role_permission),
        )
        .route(
            DIRECT_BINDINGS_PATH,
            get(list_direct_bindings).post(grant_direct_binding),
        )
        .route(DIRECT_BINDING_PATH, delete(revoke_direct_binding))
        .with_state(state)
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn list_users(State(state): State<ManagementApiState>, request: Request) -> Response {
    let list = match list_request(&state, &request) {
        Ok(list) => list,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    match map_read(state.repository.list_members(&list).await) {
        Ok(page) => json_response(StatusCode::OK, &MemberPageDocument::from(&page)),
        Err(error) => error.into_response(),
    }
}

async fn list_roles(State(state): State<ManagementApiState>, request: Request) -> Response {
    let list = match list_request(&state, &request) {
        Ok(list) => list,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    match map_read(state.repository.list_roles(&list).await) {
        Ok(page) => json_response(StatusCode::OK, &RolePageDocument::from(&page)),
        Err(error) => error.into_response(),
    }
}

async fn list_direct_bindings(
    State(state): State<ManagementApiState>,
    request: Request,
) -> Response {
    let list = match list_request(&state, &request) {
        Ok(list) => list,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    match map_read(state.repository.list_role_bindings(&list).await) {
        Ok(page) => json_response(StatusCode::OK, &RoleBindingPageDocument::from(&page)),
        Err(error) => error.into_response(),
    }
}

async fn read_user(
    State(state): State<ManagementApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let principal_id = match one_path_id(path)
        .and_then(|value| ManagedPrincipalId::new(value).map_err(|_| ApiError::InvalidRequest))
    {
        Ok(principal_id) => principal_id,
        Err(error) => return error.into_response(),
    };
    let (cursor, limit) = match assignment_query(request.uri().query(), principal_id) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let actor = match actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }

    let authorization_revision = actor.authorization_revision();
    let tenant_id = actor.tenant_id().clone();
    let detail = ReadMemberDetail::new(actor.clone(), principal_id);
    let user = match map_detail(state.repository.read_member_detail(&detail).await) {
        Ok(user) if user.principal_id() == principal_id => user,
        Ok(_) => return ApiError::Internal.into_response(),
        Err(error) => return error.into_response(),
    };
    let Ok(bindings) =
        ListManagementRoleBindings::new(actor, cursor.as_deref(), limit, Some(principal_id))
    else {
        return ApiError::InvalidRequest.into_response();
    };
    let assignments = match map_assignment_read(
        state
            .repository
            .list_management_role_bindings(&bindings)
            .await,
    ) {
        Ok(assignments) => assignments,
        Err(error) => return error.into_response(),
    };
    let assignments = match assignment_page_document(
        &assignments,
        &user,
        &tenant_id,
        authorization_revision,
        cursor.as_deref(),
    ) {
        Ok(assignments) => assignments,
        Err(error) => return error.into_response(),
    };
    json_response(
        StatusCode::OK,
        &MemberDetailDocument {
            user: MemberDetailUserDocument::from(&user),
            role_assignments: assignments,
        },
    )
}

async fn read_role(
    State(state): State<ManagementApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let role_id = match one_path_id(path)
        .and_then(|value| RoleId::new(value).map_err(|_| ApiError::InvalidRequest))
    {
        Ok(role_id) => role_id,
        Err(error) => return error.into_response(),
    };
    let actor = match detail_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    let detail = ReadRoleDetail::new(actor, role_id);
    match map_detail(state.repository.read_role_detail(&detail).await) {
        Ok(detail) if detail.role().id() == role_id => {
            json_response(StatusCode::OK, &RoleDetailDocument::from(&detail))
        }
        Ok(_) => ApiError::Internal.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn create_role(State(state): State<ManagementApiState>, request: Request) -> Response {
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let document = match json_document::<CreateRoleDocument>(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let Ok(role_id) = RoleId::new(&document.role_id) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(name) = RoleName::new(document.name) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(command) = CreateRole::new(actor, role_id, name, document.display_name) else {
        return ApiError::InvalidRequest.into_response();
    };
    match map_mutation(state.repository.create_role(command).await) {
        Ok(record) => revisioned_json_response(
            StatusCode::CREATED,
            &RoleDocument::from(&record),
            record.revision(),
        ),
        Err(error) => error.into_response(),
    }
}

async fn update_role(
    State(state): State<ManagementApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let role_id = match one_path_id(path)
        .and_then(|value| RoleId::new(value).map_err(|_| ApiError::InvalidRequest))
    {
        Ok(role_id) => role_id,
        Err(error) => return error.into_response(),
    };
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match expected_revision(request.headers()) {
        Ok(revision) => revision,
        Err(error) => return error.into_response(),
    };
    let document = match json_document::<UpdateRoleDocument>(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let Ok(command) = UpdateRole::new(actor, role_id, expected_revision, document.display_name)
    else {
        return ApiError::InvalidRequest.into_response();
    };
    match map_mutation(state.repository.update_role(command).await) {
        Ok(record) => revisioned_json_response(
            StatusCode::OK,
            &RoleDocument::from(&record),
            record.revision(),
        ),
        Err(error) => error.into_response(),
    }
}

async fn delete_role(
    State(state): State<ManagementApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let role_id = match one_path_id(path)
        .and_then(|value| RoleId::new(value).map_err(|_| ApiError::InvalidRequest))
    {
        Ok(role_id) => role_id,
        Err(error) => return error.into_response(),
    };
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match expected_revision(request.headers()) {
        Ok(revision) => revision,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    let command = DeleteRole::new(actor, role_id, expected_revision);
    match map_mutation(state.repository.delete_role(command).await) {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(error) => error.into_response(),
    }
}

async fn add_role_permission(
    State(state): State<ManagementApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    set_role_permission(state, path, request, true).await
}

async fn remove_role_permission(
    State(state): State<ManagementApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    set_role_permission(state, path, request, false).await
}

async fn set_role_permission(
    state: ManagementApiState,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
    present: bool,
) -> Response {
    let (role_id, permission) = match two_path_ids(path) {
        Ok(values) => values,
        Err(error) => return error.into_response(),
    };
    let Ok(role_id) = RoleId::new(role_id) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(permission) = Permission::new(permission) else {
        return ApiError::InvalidRequest.into_response();
    };
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match expected_revision(request.headers()) {
        Ok(revision) => revision,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    let command = SetRolePermission::new(actor, role_id, expected_revision, permission, present);
    match map_mutation(state.repository.set_role_permission(command).await) {
        Ok(record) => revisioned_json_response(
            StatusCode::OK,
            &RoleDocument::from(&record),
            record.revision(),
        ),
        Err(error) => error.into_response(),
    }
}

async fn grant_direct_binding(
    State(state): State<ManagementApiState>,
    request: Request,
) -> Response {
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let document = match json_document::<GrantRoleDocument>(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let Ok(binding_id) = RoleBindingId::new(&document.binding_id) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(principal_id) = ManagedPrincipalId::new(&document.principal_id) else {
        return ApiError::InvalidRequest.into_response();
    };
    let Ok(role_id) = RoleId::new(&document.role_id) else {
        return ApiError::InvalidRequest.into_response();
    };
    let scope = match document.scope.into_scope(actor.tenant_id().clone()) {
        Ok(scope) => scope,
        Err(error) => return error.into_response(),
    };
    let valid_until = document
        .valid_until_seconds
        .map(UnixTimestamp::from_seconds);
    let Ok(command) = GrantRole::new(actor, binding_id, principal_id, role_id, scope, valid_until)
    else {
        return ApiError::InvalidRequest.into_response();
    };
    match map_mutation(state.repository.grant_role(command).await) {
        Ok(record) => revisioned_json_response(
            StatusCode::CREATED,
            &RoleBindingDocument::from(&record),
            record.revision(),
        ),
        Err(error) => error.into_response(),
    }
}

async fn revoke_direct_binding(
    State(state): State<ManagementApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let binding_id = match one_path_id(path)
        .and_then(|value| RoleBindingId::new(value).map_err(|_| ApiError::InvalidRequest))
    {
        Ok(binding_id) => binding_id,
        Err(error) => return error.into_response(),
    };
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match expected_revision(request.headers()) {
        Ok(revision) => revision,
        Err(error) => return error.into_response(),
    };
    let document = match json_document::<RevokeRoleDocument>(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let Ok(command) = RevokeRole::new(actor, binding_id, expected_revision, document.reason) else {
        return ApiError::InvalidRequest.into_response();
    };
    match map_mutation(state.repository.revoke_role(command).await) {
        Ok(record) => revisioned_json_response(
            StatusCode::OK,
            &RoleBindingDocument::from(&record),
            record.revision(),
        ),
        Err(error) => error.into_response(),
    }
}

async fn change_user_status(
    State(state): State<ManagementApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let principal_id = match one_path_id(path)
        .and_then(|value| ManagedPrincipalId::new(value).map_err(|_| ApiError::InvalidRequest))
    {
        Ok(principal_id) => principal_id,
        Err(error) => return error.into_response(),
    };
    let actor = match mutation_actor_from_request(&state, &request) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match expected_revision(request.headers()) {
        Ok(revision) => revision,
        Err(error) => return error.into_response(),
    };
    let document = match json_document::<ChangeMemberStatusDocument>(request).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let Ok(command) = ChangeMemberStatus::new(
        actor,
        principal_id,
        expected_revision,
        document.status,
        document.reason,
    ) else {
        return ApiError::InvalidRequest.into_response();
    };
    match map_mutation(state.repository.change_member_status(command).await) {
        Ok(record) => revisioned_json_response(
            StatusCode::OK,
            &MemberDocument::from(&record),
            record.revision(),
        ),
        Err(error) => error.into_response(),
    }
}

fn list_request(
    state: &ManagementApiState,
    request: &Request,
) -> Result<ListManagementRecords, ApiError> {
    let actor = actor_from_request(state, request)?;
    let (cursor, limit) = list_query(request.uri().query())?;
    ListManagementRecords::new(actor, cursor, limit).map_err(|_| ApiError::InvalidRequest)
}

fn actor_from_request(
    state: &ManagementApiState,
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
    let request_id = request_id(request.headers())?;
    Ok(ManagementActor::new(
        identity.tenant_id().clone(),
        identity.principal_id().clone(),
        identity.session_id().clone(),
        authorization_revision,
        request_id,
        state.clock.now(),
    ))
}

fn mutation_actor_from_request(
    state: &ManagementApiState,
    request: &Request,
) -> Result<ManagementActor, ApiError> {
    let actor = actor_from_request(state, request)?;
    require_no_query(request)?;
    Ok(actor)
}

fn detail_actor_from_request(
    state: &ManagementApiState,
    request: &Request,
) -> Result<ManagementActor, ApiError> {
    let actor = actor_from_request(state, request)?;
    require_no_query(request)?;
    Ok(actor)
}

fn require_no_query(request: &Request) -> Result<(), ApiError> {
    request
        .uri()
        .query()
        .is_none()
        .then_some(())
        .ok_or(ApiError::InvalidRequest)
}

fn request_id(headers: &HeaderMap) -> Result<Option<ManagementRequestId>, ApiError> {
    let mut values = headers.get_all(REQUEST_ID_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let value = value.to_str().map_err(|_| ApiError::InvalidRequest)?;
    ManagementRequestId::new(value.to_owned())
        .map(Some)
        .map_err(|_| ApiError::InvalidRequest)
}

fn expected_revision(headers: &HeaderMap) -> Result<ManagementRevision, ApiError> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let value = values.next().ok_or(ApiError::InvalidRequest)?;
    if values.next().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let value = value.to_str().map_err(|_| ApiError::InvalidRequest)?;
    let digits = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(ApiError::InvalidRequest)?;
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ApiError::InvalidRequest);
    }
    let revision = digits
        .parse::<u64>()
        .map_err(|_| ApiError::InvalidRequest)?;
    ManagementRevision::new(revision).map_err(|_| ApiError::InvalidRequest)
}

fn list_query(raw_query: Option<&str>) -> Result<(Option<String>, ManagementPageSize), ApiError> {
    let raw_query = raw_query.unwrap_or_default();
    if raw_query.len() > MAX_QUERY_BYTES {
        return Err(ApiError::InvalidRequest);
    }
    let mut cursor = None;
    let mut limit = None;
    for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if cursor.is_none() => cursor = Some(value.into_owned()),
            "limit" if limit.is_none() => limit = Some(value.into_owned()),
            _ => return Err(ApiError::InvalidRequest),
        }
    }
    if let Some(value) = cursor.as_deref() {
        ManagedPrincipalId::new(value).map_err(|_| ApiError::InvalidRequest)?;
    }
    let limit = match limit {
        Some(value)
            if !value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse::<u16>().map_err(|_| ApiError::InvalidRequest)?
        }
        Some(_) => return Err(ApiError::InvalidRequest),
        None => DEFAULT_PAGE_SIZE,
    };
    let limit = ManagementPageSize::new(limit).map_err(|_| ApiError::InvalidRequest)?;
    Ok((cursor, limit))
}

fn assignment_query(
    raw_query: Option<&str>,
    principal_id: ManagedPrincipalId,
) -> Result<(Option<String>, ManagementPageSize), ApiError> {
    let Some(raw_query) = raw_query else {
        return Ok((
            None,
            ManagementPageSize::new(DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE)
                .map_err(|_| ApiError::Internal)?,
        ));
    };
    if raw_query.is_empty() || raw_query.len() > MAX_QUERY_BYTES {
        return Err(ApiError::InvalidRequest);
    }
    let mut cursor = None;
    let mut limit = None;
    for (name, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if cursor.is_none() => cursor = Some(value.into_owned()),
            "limit" if limit.is_none() => limit = Some(value.into_owned()),
            _ => return Err(ApiError::InvalidRequest),
        }
    }
    if let Some(value) = cursor.as_deref() {
        let parsed =
            ManagementRoleBindingCursor::new(value).map_err(|_| ApiError::InvalidRequest)?;
        if matches!(
            parsed,
            ManagementRoleBindingCursor::ProviderObserved {
                principal_id: cursor_principal,
                ..
            } if cursor_principal != principal_id
        ) {
            return Err(ApiError::InvalidRequest);
        }
    }
    let limit = parse_page_size(limit, DEFAULT_DETAIL_ASSIGNMENT_PAGE_SIZE)?;
    Ok((cursor, limit))
}

fn parse_page_size(value: Option<String>, default: u16) -> Result<ManagementPageSize, ApiError> {
    let value = match value {
        Some(value)
            if !value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse::<u16>().map_err(|_| ApiError::InvalidRequest)?
        }
        Some(_) => return Err(ApiError::InvalidRequest),
        None => default,
    };
    ManagementPageSize::new(value).map_err(|_| ApiError::InvalidRequest)
}

async fn require_empty_body(request: Request) -> Result<(), ApiError> {
    if request.headers().contains_key(header::CONTENT_TYPE) {
        return Err(ApiError::UnsupportedMediaType);
    }
    let body = to_bytes(request.into_body(), 1)
        .await
        .map_err(|_| ApiError::TooLarge)?;
    body.is_empty()
        .then_some(())
        .ok_or(ApiError::InvalidRequest)
}

async fn json_document<T: DeserializeOwned>(request: Request) -> Result<T, ApiError> {
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

fn one_path_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    path.map(|Path(value)| value)
        .map_err(|_| ApiError::InvalidRequest)
}

fn two_path_ids(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(String, String), ApiError> {
    path.map(|Path(value)| value)
        .map_err(|_| ApiError::InvalidRequest)
}

fn map_read<T>(
    result: Result<ManagementReadOutcome<T>, ManagementRepositoryError>,
) -> Result<T, ApiError> {
    match result {
        Ok(ManagementReadOutcome::Authorized(value)) => Ok(value),
        Ok(ManagementReadOutcome::Forbidden) => Err(ApiError::Forbidden),
        Ok(ManagementReadOutcome::SessionStale) => Err(ApiError::Unauthorized),
        Err(ManagementRepositoryError::InvalidRequest) => Err(ApiError::InvalidRequest),
        Err(ManagementRepositoryError::Unavailable) => Err(ApiError::Unavailable),
        Err(ManagementRepositoryError::CorruptData) => Err(ApiError::Internal),
    }
}

fn map_detail<T>(
    result: Result<ManagementDetailOutcome<T>, ManagementRepositoryError>,
) -> Result<T, ApiError> {
    match result {
        Ok(ManagementDetailOutcome::Authorized(value)) => Ok(value),
        Ok(ManagementDetailOutcome::Forbidden | ManagementDetailOutcome::NotFound) => {
            Err(ApiError::NotFound)
        }
        Ok(ManagementDetailOutcome::SessionStale) => Err(ApiError::Unauthorized),
        Err(ManagementRepositoryError::InvalidRequest | ManagementRepositoryError::CorruptData) => {
            Err(ApiError::Internal)
        }
        Err(ManagementRepositoryError::Unavailable) => Err(ApiError::Unavailable),
    }
}

fn map_assignment_read<T>(
    result: Result<ManagementReadOutcome<T>, ManagementRepositoryError>,
) -> Result<T, ApiError> {
    match result {
        Ok(ManagementReadOutcome::Authorized(value)) => Ok(value),
        Ok(ManagementReadOutcome::Forbidden) => Err(ApiError::NotFound),
        Ok(ManagementReadOutcome::SessionStale) => Err(ApiError::Unauthorized),
        Err(ManagementRepositoryError::Unavailable) => Err(ApiError::Unavailable),
        Err(ManagementRepositoryError::InvalidRequest | ManagementRepositoryError::CorruptData) => {
            Err(ApiError::Internal)
        }
    }
}

fn map_mutation<T>(
    result: Result<ManagementMutationOutcome<T>, ManagementRepositoryError>,
) -> Result<T, ApiError> {
    match result {
        Ok(ManagementMutationOutcome::Applied(value)) => Ok(value),
        Ok(ManagementMutationOutcome::Forbidden) => Err(ApiError::Forbidden),
        Ok(ManagementMutationOutcome::SessionStale) => Err(ApiError::Unauthorized),
        Ok(ManagementMutationOutcome::NotFound) => Err(ApiError::NotFound),
        Ok(ManagementMutationOutcome::AlreadyExists) => Err(ApiError::AlreadyExists),
        Ok(ManagementMutationOutcome::RevisionConflict { current }) => {
            Err(ApiError::RevisionConflict(current))
        }
        Ok(ManagementMutationOutcome::Immutable) => Err(ApiError::Immutable),
        Ok(ManagementMutationOutcome::ResourceInUse) => Err(ApiError::ResourceInUse),
        Ok(ManagementMutationOutcome::SelfModificationForbidden) => {
            Err(ApiError::SelfModificationForbidden)
        }
        Ok(ManagementMutationOutcome::LastManager) => Err(ApiError::LastManager),
        Err(ManagementRepositoryError::InvalidRequest) => Err(ApiError::InvalidRequest),
        Err(ManagementRepositoryError::Unavailable) => Err(ApiError::Unavailable),
        Err(ManagementRepositoryError::CorruptData) => Err(ApiError::Internal),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    InvalidRequest,
    UnsupportedMediaType,
    TooLarge,
    AlreadyExists,
    RevisionConflict(ManagementRevision),
    Immutable,
    ResourceInUse,
    SelfModificationForbidden,
    LastManager,
    Unavailable,
    Internal,
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
            Self::AlreadyExists
            | Self::RevisionConflict(_)
            | Self::Immutable
            | Self::ResourceInUse
            | Self::SelfModificationForbidden
            | Self::LastManager => StatusCode::CONFLICT,
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
            Self::AlreadyExists => "already_exists",
            Self::RevisionConflict(_) => "revision_conflict",
            Self::Immutable => "immutable_role",
            Self::ResourceInUse => "resource_in_use",
            Self::SelfModificationForbidden => "self_modification_forbidden",
            Self::LastManager => "last_manager",
            Self::Unavailable => "dependency_unavailable",
            Self::Internal => "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let current_revision = match self {
            Self::RevisionConflict(current) => Some(current.value()),
            _ => None,
        };
        let mut response = json_response(
            self.status(),
            &ErrorDocument {
                error: self.code(),
                current_revision,
            },
        );
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

fn revisioned_json_response<T: Serialize>(
    status: StatusCode,
    document: &T,
    revision: ManagementRevision,
) -> Response {
    let mut response = json_response(status, document);
    let value = format!("\"{}\"", revision.value());
    match HeaderValue::from_str(&value) {
        Ok(value) => {
            response.headers_mut().insert(header::ETAG, value);
            response
        }
        Err(_) => ApiError::Unavailable.into_response(),
    }
}

fn empty_response(status: StatusCode) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Body::empty()).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoleDocument {
    role_id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRoleDocument {
    display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRoleDocument {
    binding_id: String,
    principal_id: String,
    role_id: String,
    scope: GrantScopeDocument,
    valid_until_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GrantScopeDocument {
    Tenant,
    Repository { repository_id: String },
    RunnerGroup { runner_group_id: String },
}

impl GrantScopeDocument {
    fn into_scope(
        self,
        tenant_id: automata_ci_auth::human::TenantId,
    ) -> Result<AuthorizationScope, ApiError> {
        match self {
            Self::Tenant => Ok(AuthorizationScope::tenant(tenant_id)),
            Self::Repository { repository_id } => {
                let repository_id = RepositoryResourceId::new(repository_id)
                    .map_err(|_| ApiError::InvalidRequest)?;
                Ok(AuthorizationScope::repository(RepositoryResource::new(
                    tenant_id,
                    repository_id,
                )))
            }
            Self::RunnerGroup { runner_group_id } => {
                let runner_group_id = RunnerGroupResourceId::new(runner_group_id)
                    .map_err(|_| ApiError::InvalidRequest)?;
                Ok(AuthorizationScope::runner_group(RunnerGroupResource::new(
                    tenant_id,
                    runner_group_id,
                )))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRoleDocument {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeMemberStatusDocument {
    status: MemberStatus,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorDocument {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_revision: Option<u64>,
}

#[derive(Debug, Serialize)]
struct MemberPageDocument {
    items: Vec<MemberDocument>,
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct MemberDetailDocument {
    user: MemberDetailUserDocument,
    role_assignments: ManagementRoleBindingPageDocument,
}

#[derive(Debug, Serialize)]
struct MemberDetailUserDocument {
    principal_id: String,
    provider_id: String,
    provider_login: String,
    display_name: Option<String>,
    status: MemberStatus,
    revision: u64,
}

impl From<&MemberRecord> for MemberDetailUserDocument {
    fn from(record: &MemberRecord) -> Self {
        Self {
            principal_id: record.principal_id().to_string(),
            provider_id: record.provider_id().as_str().to_owned(),
            provider_login: record.provider_login().to_owned(),
            display_name: record.display_name().map(str::to_owned),
            status: record.status(),
            revision: record.revision().value(),
        }
    }
}

impl From<&ManagementPage<MemberRecord>> for MemberPageDocument {
    fn from(page: &ManagementPage<MemberRecord>) -> Self {
        Self {
            items: page.items().iter().map(MemberDocument::from).collect(),
            next_cursor: page.next_cursor().map(str::to_owned),
        }
    }
}

#[derive(Debug, Serialize)]
struct MemberDocument {
    principal_id: String,
    provider_id: String,
    provider_login: String,
    display_name: Option<String>,
    status: MemberStatus,
    authorization_revision: u64,
    revision: u64,
}

impl From<&MemberRecord> for MemberDocument {
    fn from(record: &MemberRecord) -> Self {
        Self {
            principal_id: record.principal_id().to_string(),
            provider_id: record.provider_id().as_str().to_owned(),
            provider_login: record.provider_login().to_owned(),
            display_name: record.display_name().map(str::to_owned),
            status: record.status(),
            authorization_revision: record.authorization_revision().value(),
            revision: record.revision().value(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RolePageDocument {
    items: Vec<RoleDocument>,
    next_cursor: Option<String>,
}

impl From<&ManagementPage<RoleRecord>> for RolePageDocument {
    fn from(page: &ManagementPage<RoleRecord>) -> Self {
        Self {
            items: page.items().iter().map(RoleDocument::from).collect(),
            next_cursor: page.next_cursor().map(str::to_owned),
        }
    }
}

#[derive(Debug, Serialize)]
struct RoleDocument {
    id: String,
    name: String,
    display_name: String,
    kind: automata_ci_auth::management::RoleKind,
    immutable: bool,
    revision: u64,
    permissions: Vec<String>,
}

impl From<&RoleRecord> for RoleDocument {
    fn from(record: &RoleRecord) -> Self {
        Self {
            id: record.id().to_string(),
            name: record.name().as_str().to_owned(),
            display_name: record.display_name().to_owned(),
            kind: record.kind(),
            immutable: record.immutable(),
            revision: record.revision().value(),
            permissions: record
                .permissions()
                .iter()
                .map(|permission| permission.as_str().to_owned())
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RoleDetailDocument {
    role: RoleDetailRoleDocument,
    permission_catalog: Vec<RolePermissionDocument>,
}

impl From<&RoleDetailRecord> for RoleDetailDocument {
    fn from(detail: &RoleDetailRecord) -> Self {
        Self {
            role: RoleDetailRoleDocument::from(detail.role()),
            permission_catalog: detail
                .permission_catalog()
                .iter()
                .map(RolePermissionDocument::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RoleDetailRoleDocument {
    id: String,
    name: String,
    display_name: String,
    kind: automata_ci_auth::management::RoleKind,
    immutable: bool,
    revision: u64,
    permission_count: usize,
}

impl From<&RoleRecord> for RoleDetailRoleDocument {
    fn from(role: &RoleRecord) -> Self {
        Self {
            id: role.id().to_string(),
            name: role.name().as_str().to_owned(),
            display_name: role.display_name().to_owned(),
            kind: role.kind(),
            immutable: role.immutable(),
            revision: role.revision().value(),
            permission_count: role.permissions().len(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RolePermissionDocument {
    name: String,
    description: String,
    critical: bool,
    granted: bool,
}

impl From<&automata_ci_auth::management::RolePermissionRecord> for RolePermissionDocument {
    fn from(permission: &automata_ci_auth::management::RolePermissionRecord) -> Self {
        Self {
            name: permission.permission().as_str().to_owned(),
            description: permission.description().to_owned(),
            critical: permission.critical(),
            granted: permission.granted(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ManagementRoleBindingPageDocument {
    items: Vec<ManagementRoleBindingDocument>,
    next_cursor: Option<String>,
}

fn assignment_page_document(
    page: &ManagementPage<ManagementRoleBindingRecord>,
    user: &MemberRecord,
    tenant_id: &automata_ci_auth::human::TenantId,
    authorization_revision: ManagementRevision,
    request_cursor: Option<&str>,
) -> Result<ManagementRoleBindingPageDocument, ApiError> {
    if page.mutation_authorization_revision() != Some(authorization_revision)
        || page.items().iter().enumerate().any(|(index, assignment)| {
            assignment.principal() != user
                || assignment.scope().scope().tenant_id() != tenant_id
                || page.items()[..index]
                    .iter()
                    .any(|prior| prior.id() == assignment.id())
        })
    {
        return Err(ApiError::Internal);
    }
    let next_cursor = page
        .next_cursor()
        .map(ManagementRoleBindingCursor::new)
        .transpose()
        .map_err(|_| ApiError::Internal)?;
    if matches!(
        next_cursor,
        Some(ManagementRoleBindingCursor::ProviderObserved {
            principal_id,
            ..
        }) if principal_id != user.principal_id()
    ) {
        return Err(ApiError::Internal);
    }
    let next_cursor = next_cursor.map(ManagementRoleBindingCursor::encode);
    if request_cursor.is_some_and(|cursor| next_cursor.as_deref() == Some(cursor)) {
        return Err(ApiError::Internal);
    }
    Ok(ManagementRoleBindingPageDocument {
        items: page
            .items()
            .iter()
            .map(ManagementRoleBindingDocument::from)
            .collect(),
        next_cursor,
    })
}

#[derive(Debug, Serialize)]
struct ManagementRoleBindingDocument {
    id: String,
    role: ManagementBindingRoleDocument,
    scope: ManagementScopeDocument,
    source: &'static str,
    status: automata_ci_auth::management::RoleBindingStatus,
    valid_until_seconds: Option<u64>,
}

impl From<&ManagementRoleBindingRecord> for ManagementRoleBindingDocument {
    fn from(binding: &ManagementRoleBindingRecord) -> Self {
        Self {
            id: binding.id().to_string(),
            role: ManagementBindingRoleDocument {
                id: binding.role().id().to_string(),
                name: binding.role().name().as_str().to_owned(),
                display_name: binding.role().display_name().to_owned(),
            },
            scope: ManagementScopeDocument {
                scope: ScopeDocument::from(binding.scope().scope()),
                display_name: binding.scope().display_name().to_owned(),
            },
            source: match binding.source() {
                ManagementRoleBindingSource::Direct(_) => "direct",
                ManagementRoleBindingSource::ProviderObserved { .. } => "provider_observed",
            },
            status: binding.status(),
            valid_until_seconds: binding.valid_until().map(UnixTimestamp::as_seconds),
        }
    }
}

#[derive(Debug, Serialize)]
struct ManagementBindingRoleDocument {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct ManagementScopeDocument {
    #[serde(flatten)]
    scope: ScopeDocument,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct RoleBindingPageDocument {
    items: Vec<RoleBindingDocument>,
    next_cursor: Option<String>,
}

impl From<&ManagementPage<RoleBindingRecord>> for RoleBindingPageDocument {
    fn from(page: &ManagementPage<RoleBindingRecord>) -> Self {
        Self {
            items: page.items().iter().map(RoleBindingDocument::from).collect(),
            next_cursor: page.next_cursor().map(str::to_owned),
        }
    }
}

#[derive(Debug, Serialize)]
struct RoleBindingDocument {
    id: String,
    principal_id: String,
    role_id: String,
    scope: ScopeDocument,
    status: automata_ci_auth::management::RoleBindingStatus,
    valid_until_seconds: Option<u64>,
    revision: u64,
}

impl From<&RoleBindingRecord> for RoleBindingDocument {
    fn from(record: &RoleBindingRecord) -> Self {
        Self {
            id: record.id().to_string(),
            principal_id: record.principal_id().to_string(),
            role_id: record.role_id().to_string(),
            scope: ScopeDocument::from(record.scope()),
            status: record.status(),
            valid_until_seconds: record.valid_until().map(UnixTimestamp::as_seconds),
            revision: record.revision().value(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ScopeDocument {
    Tenant,
    Repository { repository_id: String },
    RunnerGroup { runner_group_id: String },
}

impl From<&AuthorizationScope> for ScopeDocument {
    fn from(scope: &AuthorizationScope) -> Self {
        if let Some(repository) = scope.repository_resource() {
            return Self::Repository {
                repository_id: repository.repository_id().to_string(),
            };
        }
        if let Some(runner_group) = scope.runner_group_resource() {
            return Self::RunnerGroup {
                runner_group_id: runner_group.runner_group_id().to_string(),
            };
        }
        Self::Tenant
    }
}

#[cfg(test)]
#[path = "management_api/route_tests.rs"]
mod route_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_preconditions_are_exact_and_positive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"42\""));
        assert_eq!(expected_revision(&headers).unwrap().value(), 42);

        for invalid in ["42", "W/\"42\"", "\"0\"", "\"01\"", "\"-1\""] {
            headers.insert(header::IF_MATCH, HeaderValue::from_str(invalid).unwrap());
            assert_eq!(expected_revision(&headers), Err(ApiError::InvalidRequest));
        }
        headers.clear();
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"1\""));
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"2\""));
        assert_eq!(expected_revision(&headers), Err(ApiError::InvalidRequest));
    }

    #[test]
    fn list_queries_are_bounded_alias_free_and_uuid_cursor_only() {
        let (cursor, limit) = list_query(Some(
            "cursor=20000000-0000-0000-0000-000000000001&limit=100",
        ))
        .unwrap();
        assert_eq!(
            cursor.as_deref(),
            Some("20000000-0000-0000-0000-000000000001")
        );
        assert_eq!(limit.value(), 100);

        for invalid in [
            "cursor=",
            "cursor=not-a-uuid",
            "limit=0",
            "limit=01",
            "limit=101",
            "limit=1&limit=2",
            "unexpected=1",
        ] {
            assert_eq!(list_query(Some(invalid)), Err(ApiError::InvalidRequest));
        }
    }

    #[test]
    fn mutation_routes_reject_every_query() {
        let queryless = Request::builder()
            .uri(ROLES_PATH)
            .body(Body::empty())
            .unwrap();
        assert_eq!(require_no_query(&queryless), Ok(()));

        for uri in [format!("{ROLES_PATH}?ignored=1"), format!("{ROLES_PATH}?")] {
            let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
            assert_eq!(require_no_query(&request), Err(ApiError::InvalidRequest));
        }
    }

    #[test]
    fn content_type_is_exact_and_unknown_parameters_are_rejected() {
        let mut headers = HeaderMap::new();
        for valid in ["application/json", "application/json; charset=utf-8"] {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(valid).unwrap());
            assert!(is_json_content_type(&headers));
        }
        for invalid in [
            "text/json",
            "application/json; profile=x",
            "application/json; charset=utf-8; charset=utf-8",
        ] {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(invalid).unwrap(),
            );
            assert!(!is_json_content_type(&headers));
        }
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_json_content_type(&headers));
    }

    #[test]
    fn closed_errors_have_sanitized_statuses_and_auth_headers() {
        assert_eq!(ApiError::InvalidRequest.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            ApiError::UnsupportedMediaType.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(ApiError::TooLarge.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let unauthorized = ApiError::Unauthorized.into_response();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=\"automata\""
        );
        assert_eq!(unauthorized.headers()[header::CACHE_CONTROL], "no-store");

        let unavailable = ApiError::Unavailable.into_response();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            map_read::<()>(Err(ManagementRepositoryError::CorruptData)),
            Err(ApiError::Internal)
        );
        assert_eq!(
            ApiError::Internal.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
