//! Bounded human API for repository-scoped secret management.
//!
//! Secret values cross this module only as one move-only, zeroizing byte owner.
//! Metadata, durable mutation intent, provider execution, and confirmation stay
//! behind a typed backend so generic JSON helpers never receive plaintext.

use std::{fmt, mem, sync::Arc};

use async_trait::async_trait;
use automata_ci_auth::{
    management::{ManagementActor, ManagementRequestId, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    session::SessionKind,
    time::Clock,
};
use automata_ci_core::RunId;
use automata_ci_store::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome, DeleteRepositorySecret,
    DeleteRepositorySecretOutcome, GetRepositorySecretMetadata, GetRepositorySecretMetadataOutcome,
    GithubRepositoryName, InspectBuiltinSecretProvider, InspectBuiltinSecretProviderOutcome,
    ListRepositorySecrets, ListRepositorySecretsOutcome, ManagedSecretProviderId, RepositoryId,
    RepositorySecretId, RepositorySecretManagementReadRepository, RepositorySecretMetadata,
    RepositorySecretMetadataPage, RepositorySecretMutationId, RepositorySecretName,
    RepositorySecretState, ReserveRepositorySecretVersionMutation,
    ResolveGithubRepositorySecretMetadata, ResolveGithubRepositorySecretMetadataOutcome,
    SecretManagementRepositoryError, SecretMetadataPageSize,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures::StreamExt as _;
use serde::Serialize;
use zeroize::{Zeroize as _, Zeroizing};

/// Maximum accepted plaintext bytes, matching the provider-neutral boundary.
pub(crate) const MAX_SECRET_INGRESS_BYTES: usize = automata_ci_secret::MAX_SECRET_VALUE_BYTES;
const MAX_QUERY_BYTES: usize = 1_024;
const DEFAULT_PAGE_SIZE: u16 = 50;
const REQUEST_ID_HEADER: &str = "x-request-id";
const MUTATION_ID_HEADER: &str = "x-automata-secret-mutation-id";
const SECRET_NAME_HEADER: &str = "x-automata-secret-name";
const SECRET_PROVIDER_HEADER: &str = "x-automata-secret-provider";

pub(crate) const REPOSITORY_SECRETS_PATH: &str = "/api/v1/repositories/{repository_id}/secrets";
pub(crate) const REPOSITORY_SECRET_PATH: &str =
    "/api/v1/repositories/{repository_id}/secrets/{secret_id}";
pub(crate) const GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH: &str =
    "/api/v1/repository-targets/github/{owner}/{repository}";
pub(crate) const REPOSITORY_SECRET_BY_NAME_PATH: &str =
    "/api/v1/repositories/{repository_id}/secrets/lookup";
pub(crate) const BUILTIN_SECRET_PROVIDER_PATH: &str = "/api/v1/secret-providers/builtin";
pub(crate) const BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH: &str =
    "/api/v1/secret-providers/builtin/activation";

/// Move-only plaintext accepted from one bounded HTTP body.
pub(crate) struct SecretIngressValue(Vec<u8>);

impl SecretIngressValue {
    pub(crate) fn new(value: Vec<u8>) -> Result<Self, SecretApiError> {
        if value.is_empty() || value.len() > MAX_SECRET_INGRESS_BYTES {
            let mut value = value;
            value.zeroize();
            return Err(SecretApiError::InvalidRequest);
        }
        Ok(Self(value))
    }

    /// Consumes the ingress owner for the one provider-bound conversion.
    #[must_use]
    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        mem::take(&mut self.0)
    }

    #[cfg(test)]
    fn expose_for_test(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretIngressValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretIngressValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretIngressValue([REDACTED])")
    }
}

/// Closed result of the reserve/provider/confirm orchestration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositorySecretMutationOutcome {
    Applied,
    AppliedThenSuperseded,
    AppliedThenDeleted,
    CasLost,
    Cancelled,
    Forbidden,
    SessionStale,
    NotFound,
    Conflict,
    RevisionConflict,
    ProviderUnavailable,
}

/// Sanitized backend failure with no provider response, handle, or value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretApiBackendError {
    InvalidRequest,
    Unavailable,
    CorruptData,
}

/// Product orchestration boundary used by the HTTP adapter.
#[async_trait]
pub(crate) trait RepositorySecretApiBackend: fmt::Debug + Send + Sync {
    async fn list(
        &self,
        request: ListRepositorySecrets,
    ) -> Result<ListRepositorySecretsOutcome, SecretApiBackendError>;

    async fn mutate(
        &self,
        request: ReserveRepositorySecretVersionMutation,
        value: SecretIngressValue,
    ) -> Result<RepositorySecretMutationOutcome, SecretApiBackendError>;

    async fn delete(
        &self,
        request: DeleteRepositorySecret,
    ) -> Result<DeleteRepositorySecretOutcome, SecretApiBackendError>;

    async fn activate_builtin(
        &self,
        request: ActivateBuiltinSecretProvider,
    ) -> Result<ActivateBuiltinSecretProviderOutcome, SecretApiBackendError>;
}

#[derive(Clone)]
struct SecretApiState {
    backend: Arc<dyn RepositorySecretApiBackend>,
    reads: Arc<dyn RepositorySecretManagementReadRepository>,
    clock: Arc<dyn Clock>,
}

/// Builds the authenticated repository-secret routes.
pub(crate) fn repository_secret_api_router(
    backend: Arc<dyn RepositorySecretApiBackend>,
    reads: Arc<dyn RepositorySecretManagementReadRepository>,
    clock: Arc<dyn Clock>,
) -> Router {
    Router::new()
        .route(
            GITHUB_REPOSITORY_SECRET_RESOLUTION_PATH,
            get(resolve_github_repository),
        )
        .route(
            REPOSITORY_SECRET_BY_NAME_PATH,
            get(get_repository_secret_by_name),
        )
        .route(REPOSITORY_SECRETS_PATH, get(list_repository_secrets))
        .route(
            REPOSITORY_SECRET_PATH,
            axum::routing::put(put_repository_secret).delete(delete_repository_secret),
        )
        .route(
            BUILTIN_SECRET_PROVIDER_PATH,
            get(inspect_builtin_secret_provider),
        )
        .route(
            BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH,
            post(activate_builtin_secret_provider),
        )
        .with_state(SecretApiState {
            backend,
            reads,
            clock,
        })
        .layer(middleware::from_fn(super::api_security::no_store))
}

async fn resolve_github_repository(
    State(state): State<SecretApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    if request.uri().query().is_some() {
        return SecretApiError::InvalidRequest.into_response();
    }
    let Ok(Path((owner, repository))) = path else {
        return SecretApiError::InvalidRequest.into_response();
    };
    let repository = match github_repository_name(&owner, &repository) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let actor = match actor_from_request(&state, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    match state
        .reads
        .resolve_github_repository_secret_metadata(ResolveGithubRepositorySecretMetadata::new(
            actor, repository,
        ))
        .await
    {
        Ok(ResolveGithubRepositorySecretMetadataOutcome::Found(repository_id)) => {
            if repository_id.as_uuid().is_nil() {
                SecretApiError::Internal.into_response()
            } else {
                json_response(
                    StatusCode::OK,
                    &RepositoryResolutionDocument {
                        repository_id: repository_id.as_uuid().hyphenated().to_string(),
                    },
                )
            }
        }
        Ok(ResolveGithubRepositorySecretMetadataOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(ResolveGithubRepositorySecretMetadataOutcome::NotFound) => {
            SecretApiError::NotFound.into_response()
        }
        Err(error) => repository_error(error).into_response(),
    }
}

async fn get_repository_secret_by_name(
    State(state): State<SecretApiState>,
    path: Result<Path<String>, PathRejection>,
    mut request: Request,
) -> Response {
    if request.uri().query().is_some() {
        return SecretApiError::InvalidRequest.into_response();
    }
    let repository_id = match one_uuid_path(path) {
        Ok(value) => RepositoryId::from_uuid(value.as_uuid()),
        Err(error) => return error.into_response(),
    };
    let name = match required_header(request.headers(), SECRET_NAME_HEADER) {
        Ok(value) if value.len() <= 255 => value.to_owned(),
        Ok(_) => return SecretApiError::InvalidRequest.into_response(),
        Err(error) => return error.into_response(),
    };
    request.headers_mut().remove(SECRET_NAME_HEADER);
    let Ok(name) = RepositorySecretName::new(name) else {
        return SecretApiError::InvalidRequest.into_response();
    };
    let actor = match actor_from_request(&state, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    let expected_name = name.clone();
    let Ok(request) = GetRepositorySecretMetadata::new(actor, repository_id, name) else {
        return SecretApiError::InvalidRequest.into_response();
    };
    match state.reads.get_repository_secret_metadata(request).await {
        Ok(GetRepositorySecretMetadataOutcome::Found(metadata))
            if valid_secret_metadata(&metadata, repository_id, Some(&expected_name)) =>
        {
            json_response(StatusCode::OK, &SecretMetadataDocument::from(&metadata))
        }
        Ok(GetRepositorySecretMetadataOutcome::Found(_)) => {
            SecretApiError::Internal.into_response()
        }
        Ok(GetRepositorySecretMetadataOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(GetRepositorySecretMetadataOutcome::NotFound) => {
            SecretApiError::NotFound.into_response()
        }
        Err(error) => repository_error(error).into_response(),
    }
}

async fn inspect_builtin_secret_provider(
    State(state): State<SecretApiState>,
    request: Request,
) -> Response {
    if request.uri().query().is_some() {
        return SecretApiError::InvalidRequest.into_response();
    }
    let actor = match actor_from_request(&state, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    match state
        .reads
        .inspect_builtin_secret_provider(InspectBuiltinSecretProvider::new(actor))
        .await
    {
        Ok(InspectBuiltinSecretProviderOutcome::Found(inspection)) => json_response(
            StatusCode::OK,
            &ProviderInspectionDocument::from(&inspection),
        ),
        Ok(InspectBuiltinSecretProviderOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(
            InspectBuiltinSecretProviderOutcome::Forbidden
            | InspectBuiltinSecretProviderOutcome::NotFound,
        ) => SecretApiError::NotFound.into_response(),
        Err(error) => repository_error(error).into_response(),
    }
}

async fn list_repository_secrets(
    State(state): State<SecretApiState>,
    path: Result<Path<String>, PathRejection>,
    request: Request,
) -> Response {
    let repository_id =
        match one_uuid_path(path).map(|value| RepositoryId::from_uuid(value.as_uuid())) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let actor = match actor_from_request(&state, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let (after, limit) = match list_query(request.uri().query()) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    let Ok(request) = ListRepositorySecrets::new(actor, repository_id, after, limit) else {
        return SecretApiError::InvalidRequest.into_response();
    };
    match state.backend.list(request).await {
        Ok(ListRepositorySecretsOutcome::Found(page))
            if valid_secret_page(&page, repository_id, after, limit) =>
        {
            json_response(StatusCode::OK, &SecretPageDocument::from(&page))
        }
        Ok(ListRepositorySecretsOutcome::Found(_)) => SecretApiError::Internal.into_response(),
        Ok(ListRepositorySecretsOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(ListRepositorySecretsOutcome::Forbidden | ListRepositorySecretsOutcome::NotFound) => {
            SecretApiError::NotFound.into_response()
        }
        Err(error) => backend_error(error).into_response(),
    }
}

async fn put_repository_secret(
    State(state): State<SecretApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    let reservation = match repository_secret_mutation_request(&state, path, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let value = match collect_secret_body(request).await {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    repository_secret_mutation_response(state.backend.mutate(reservation, value).await)
}

fn repository_secret_mutation_request(
    state: &SecretApiState,
    path: Result<Path<(String, String)>, PathRejection>,
    request: &Request,
) -> Result<ReserveRepositorySecretVersionMutation, SecretApiError> {
    if request.uri().query().is_some() {
        return Err(SecretApiError::InvalidRequest);
    }
    let (repository_id, secret_id) = two_uuid_path(path)?;
    let repository_id = RepositoryId::from_uuid(repository_id.as_uuid());
    let secret_id = RepositorySecretId::from_uuid(secret_id.as_uuid())
        .map_err(|_| SecretApiError::InvalidRequest)?;
    let actor = actor_from_request(state, request)?;
    let mutation_id =
        required_uuid_header(request.headers(), MUTATION_ID_HEADER).and_then(|value| {
            RepositorySecretMutationId::from_uuid(value.as_uuid(), secret_id)
                .map_err(|_| SecretApiError::InvalidRequest)
        })?;
    let name = required_header(request.headers(), SECRET_NAME_HEADER).and_then(|value| {
        RepositorySecretName::new(value).map_err(|_| SecretApiError::InvalidRequest)
    })?;
    let provider = optional_header(request.headers(), SECRET_PROVIDER_HEADER)?
        .map(|value| {
            ManagedSecretProviderId::new(value.to_owned())
                .map_err(|_| SecretApiError::InvalidRequest)
        })
        .transpose()?;
    let revision = optional_revision(request.headers())?;
    let reservation = match revision {
        None => ReserveRepositorySecretVersionMutation::create(
            actor,
            mutation_id,
            secret_id,
            repository_id,
            name,
            provider,
        ),
        Some(revision) if provider.is_none() => ReserveRepositorySecretVersionMutation::replace(
            actor,
            mutation_id,
            secret_id,
            repository_id,
            name,
            revision,
        ),
        Some(_) => return Err(SecretApiError::InvalidRequest),
    };
    reservation.map_err(|_| SecretApiError::InvalidRequest)
}

fn repository_secret_mutation_response(
    result: Result<RepositorySecretMutationOutcome, SecretApiBackendError>,
) -> Response {
    match result {
        Ok(RepositorySecretMutationOutcome::Applied) => empty_response(StatusCode::NO_CONTENT),
        Ok(RepositorySecretMutationOutcome::AppliedThenSuperseded) => {
            SecretApiError::Superseded.into_response()
        }
        Ok(RepositorySecretMutationOutcome::AppliedThenDeleted) => {
            SecretApiError::Deleted.into_response()
        }
        Ok(
            RepositorySecretMutationOutcome::CasLost
            | RepositorySecretMutationOutcome::Conflict
            | RepositorySecretMutationOutcome::RevisionConflict,
        ) => SecretApiError::Conflict.into_response(),
        Ok(RepositorySecretMutationOutcome::Cancelled) => SecretApiError::Deleted.into_response(),
        Ok(
            RepositorySecretMutationOutcome::Forbidden | RepositorySecretMutationOutcome::NotFound,
        ) => SecretApiError::NotFound.into_response(),
        Ok(RepositorySecretMutationOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(RepositorySecretMutationOutcome::ProviderUnavailable) => {
            SecretApiError::Unavailable.into_response()
        }
        Err(error) => backend_error(error).into_response(),
    }
}

async fn delete_repository_secret(
    State(state): State<SecretApiState>,
    path: Result<Path<(String, String)>, PathRejection>,
    request: Request,
) -> Response {
    if request.uri().query().is_some() {
        return SecretApiError::InvalidRequest.into_response();
    }
    let (repository_id, secret_id) = match two_uuid_path(path) {
        Ok((repository_id, secret_id)) => {
            (RepositoryId::from_uuid(repository_id.as_uuid()), secret_id)
        }
        Err(error) => return error.into_response(),
    };
    let Ok(secret_id) = RepositorySecretId::from_uuid(secret_id.as_uuid()) else {
        return SecretApiError::InvalidRequest.into_response();
    };
    let actor = match actor_from_request(&state, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match required_revision(request.headers()) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    let Ok(delete) =
        DeleteRepositorySecret::new(actor, repository_id, secret_id, expected_revision)
    else {
        return SecretApiError::InvalidRequest.into_response();
    };
    match state.backend.delete(delete).await {
        Ok(DeleteRepositorySecretOutcome::Deleted(receipt)) if receipt.secret_id() == secret_id => {
            empty_response(StatusCode::NO_CONTENT)
        }
        Ok(DeleteRepositorySecretOutcome::Deleted(_)) => SecretApiError::Internal.into_response(),
        Ok(DeleteRepositorySecretOutcome::AlreadyDeleted) => empty_response(StatusCode::NO_CONTENT),
        Ok(DeleteRepositorySecretOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(DeleteRepositorySecretOutcome::Forbidden | DeleteRepositorySecretOutcome::NotFound) => {
            SecretApiError::NotFound.into_response()
        }
        Ok(DeleteRepositorySecretOutcome::RevisionConflict { .. }) => {
            SecretApiError::Conflict.into_response()
        }
        Err(error) => backend_error(error).into_response(),
    }
}

async fn activate_builtin_secret_provider(
    State(state): State<SecretApiState>,
    request: Request,
) -> Response {
    if request.uri().query().is_some() {
        return SecretApiError::InvalidRequest.into_response();
    }
    let actor = match actor_from_request(&state, &request) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let expected_revision = match required_revision(request.headers()) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_empty_body(request).await {
        return error.into_response();
    }
    match state
        .backend
        .activate_builtin(ActivateBuiltinSecretProvider::new(actor, expected_revision))
        .await
    {
        Ok(ActivateBuiltinSecretProviderOutcome::Activated(metadata))
            if valid_provider_activation_metadata(
                &metadata,
                expected_revision,
                ProviderActivationResultKind::Activated,
            ) =>
        {
            json_response(StatusCode::OK, &ProviderDocument::from(&metadata))
        }
        Ok(ActivateBuiltinSecretProviderOutcome::AlreadyActive(metadata))
            if valid_provider_activation_metadata(
                &metadata,
                expected_revision,
                ProviderActivationResultKind::AlreadyActive,
            ) =>
        {
            json_response(StatusCode::OK, &ProviderDocument::from(&metadata))
        }
        Ok(
            ActivateBuiltinSecretProviderOutcome::Activated(_)
            | ActivateBuiltinSecretProviderOutcome::AlreadyActive(_),
        ) => SecretApiError::Internal.into_response(),
        Ok(ActivateBuiltinSecretProviderOutcome::Forbidden) => {
            SecretApiError::Forbidden.into_response()
        }
        Ok(ActivateBuiltinSecretProviderOutcome::SessionStale) => {
            SecretApiError::Unauthorized.into_response()
        }
        Ok(ActivateBuiltinSecretProviderOutcome::NotFound) => {
            SecretApiError::NotFound.into_response()
        }
        Ok(ActivateBuiltinSecretProviderOutcome::RevisionConflict { .. }) => {
            SecretApiError::Conflict.into_response()
        }
        Err(error) => backend_error(error).into_response(),
    }
}

fn actor_from_request(
    state: &SecretApiState,
    request: &Request,
) -> Result<ManagementActor, SecretApiError> {
    let snapshot = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .ok_or(SecretApiError::Unauthorized)?;
    let identity = snapshot.session().identity();
    if identity.kind() != SessionKind::Cli {
        return Err(SecretApiError::Unauthorized);
    }
    let revision = ManagementRevision::new(snapshot.session().authorization_revision())
        .map_err(|_| SecretApiError::Unauthorized)?;
    Ok(ManagementActor::new(
        identity.tenant_id().clone(),
        identity.principal_id().clone(),
        identity.session_id().clone(),
        revision,
        request_id(request.headers())?,
        state.clock.now(),
    ))
}

fn request_id(headers: &HeaderMap) -> Result<Option<ManagementRequestId>, SecretApiError> {
    optional_header(headers, REQUEST_ID_HEADER)?
        .map(|value| {
            ManagementRequestId::new(value.to_owned()).map_err(|_| SecretApiError::InvalidRequest)
        })
        .transpose()
}

fn required_uuid_header(headers: &HeaderMap, name: &str) -> Result<RunId, SecretApiError> {
    canonical_uuid(required_header(headers, name)?)
}

fn required_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, SecretApiError> {
    optional_header(headers, name)?.ok_or(SecretApiError::InvalidRequest)
}

fn optional_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, SecretApiError> {
    let name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| SecretApiError::InvalidRequest)?;
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SecretApiError::InvalidRequest);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| SecretApiError::InvalidRequest)
}

fn one_uuid_path(path: Result<Path<String>, PathRejection>) -> Result<RunId, SecretApiError> {
    path.map_err(|_| SecretApiError::InvalidRequest)
        .and_then(|Path(value)| canonical_uuid(&value))
}

fn two_uuid_path(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(RunId, RunId), SecretApiError> {
    let Path((first, second)) = path.map_err(|_| SecretApiError::InvalidRequest)?;
    Ok((canonical_uuid(&first)?, canonical_uuid(&second)?))
}

fn canonical_uuid(value: &str) -> Result<RunId, SecretApiError> {
    let parsed = value
        .parse::<RunId>()
        .map_err(|_| SecretApiError::InvalidRequest)?;
    if parsed.as_uuid().is_nil() || parsed.to_string() != value {
        return Err(SecretApiError::InvalidRequest);
    }
    Ok(parsed)
}

fn github_repository_name(
    owner: &str,
    repository: &str,
) -> Result<GithubRepositoryName, SecretApiError> {
    let length = owner
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(repository.len()))
        .filter(|length| *length <= 140)
        .ok_or(SecretApiError::InvalidRequest)?;
    let mut coordinate = String::with_capacity(length);
    coordinate.push_str(owner);
    coordinate.push('/');
    coordinate.push_str(repository);
    GithubRepositoryName::new(coordinate).map_err(|_| SecretApiError::InvalidRequest)
}

fn list_query(
    raw: Option<&str>,
) -> Result<(Option<RepositorySecretId>, SecretMetadataPageSize), SecretApiError> {
    let raw = raw.unwrap_or_default();
    if raw.len() > MAX_QUERY_BYTES {
        return Err(SecretApiError::InvalidRequest);
    }
    let mut after = None;
    let mut limit = None;
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        match name.as_ref() {
            "after" if after.is_none() => {
                after = Some(
                    RepositorySecretId::from_uuid(canonical_uuid(&value)?.as_uuid())
                        .map_err(|_| SecretApiError::InvalidRequest)?,
                );
            }
            "limit" if limit.is_none() => limit = Some(value.into_owned()),
            _ => return Err(SecretApiError::InvalidRequest),
        }
    }
    let limit = match limit {
        None => DEFAULT_PAGE_SIZE,
        Some(value)
            if !value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value
                .parse::<u16>()
                .map_err(|_| SecretApiError::InvalidRequest)?
        }
        Some(_) => return Err(SecretApiError::InvalidRequest),
    };
    Ok((
        after,
        SecretMetadataPageSize::new(limit).map_err(|_| SecretApiError::InvalidRequest)?,
    ))
}

fn optional_revision(headers: &HeaderMap) -> Result<Option<ManagementRevision>, SecretApiError> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SecretApiError::InvalidRequest);
    }
    parse_revision(value).map(Some)
}

fn required_revision(headers: &HeaderMap) -> Result<ManagementRevision, SecretApiError> {
    optional_revision(headers)?.ok_or(SecretApiError::InvalidRequest)
}

fn parse_revision(value: &HeaderValue) -> Result<ManagementRevision, SecretApiError> {
    let value = value.to_str().map_err(|_| SecretApiError::InvalidRequest)?;
    let digits = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(SecretApiError::InvalidRequest)?;
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SecretApiError::InvalidRequest);
    }
    ManagementRevision::new(
        digits
            .parse::<u64>()
            .map_err(|_| SecretApiError::InvalidRequest)?,
    )
    .map_err(|_| SecretApiError::InvalidRequest)
}

fn require_octet_stream(headers: &HeaderMap) -> Result<(), SecretApiError> {
    match optional_header(headers, header::CONTENT_TYPE.as_str())? {
        Some("application/octet-stream") => Ok(()),
        Some(_) | None => Err(SecretApiError::UnsupportedMediaType),
    }
}

async fn collect_secret_body(request: Request) -> Result<SecretIngressValue, SecretApiError> {
    require_octet_stream(request.headers())?;
    let mut stream = request.into_body().into_data_stream();
    let mut value = Zeroizing::new(Vec::with_capacity(MAX_SECRET_INGRESS_BYTES));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| SecretApiError::InvalidRequest)?;
        let within_limit = value
            .len()
            .checked_add(chunk.len())
            .is_some_and(|length| length <= MAX_SECRET_INGRESS_BYTES);
        if within_limit {
            value.extend_from_slice(&chunk);
        }
        wipe_body_chunk(chunk);
        if !within_limit {
            return Err(SecretApiError::TooLarge);
        }
    }
    SecretIngressValue::new(mem::take(&mut *value))
}

async fn require_empty_body(request: Request) -> Result<(), SecretApiError> {
    if request.headers().contains_key(header::CONTENT_TYPE) {
        return Err(SecretApiError::InvalidRequest);
    }
    let mut stream = request.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| SecretApiError::InvalidRequest)?;
        let empty = chunk.is_empty();
        wipe_body_chunk(chunk);
        if !empty {
            return Err(SecretApiError::InvalidRequest);
        }
    }
    Ok(())
}

fn wipe_body_chunk(chunk: Bytes) {
    if let Ok(mut chunk) = chunk.try_into_mut() {
        chunk.as_mut().fill(0);
    }
}

fn backend_error(error: SecretApiBackendError) -> SecretApiError {
    match error {
        SecretApiBackendError::InvalidRequest => SecretApiError::InvalidRequest,
        SecretApiBackendError::Unavailable => SecretApiError::Unavailable,
        SecretApiBackendError::CorruptData => SecretApiError::Internal,
    }
}

fn repository_error(error: SecretManagementRepositoryError) -> SecretApiError {
    match error {
        SecretManagementRepositoryError::InvalidRequest => SecretApiError::InvalidRequest,
        SecretManagementRepositoryError::Unavailable => SecretApiError::Unavailable,
        SecretManagementRepositoryError::CorruptData => SecretApiError::Internal,
    }
}

fn valid_secret_metadata(
    metadata: &RepositorySecretMetadata,
    expected_repository_id: RepositoryId,
    expected_name: Option<&RepositorySecretName>,
) -> bool {
    if metadata.id().as_uuid().is_nil()
        || metadata.repository_id().as_uuid().is_nil()
        || metadata.repository_id() != expected_repository_id
        || expected_name.is_some_and(|name| metadata.name() != name)
        || metadata.created_at().get() < 0
        || metadata.updated_at().get() < metadata.created_at().get()
    {
        return false;
    }
    match (metadata.state(), metadata.current_version_number()) {
        (RepositorySecretState::Provisioning, None) => true,
        (RepositorySecretState::Active | RepositorySecretState::Disabled, Some(version_number)) => {
            version_number > 0
        }
        (RepositorySecretState::Provisioning, Some(_))
        | (RepositorySecretState::Active | RepositorySecretState::Disabled, None) => false,
    }
}

fn valid_secret_page(
    page: &RepositorySecretMetadataPage,
    expected_repository_id: RepositoryId,
    after: Option<RepositorySecretId>,
    limit: SecretMetadataPageSize,
) -> bool {
    let records = page.records();
    if records.len() > usize::from(limit.get())
        || records
            .iter()
            .any(|metadata| !valid_secret_metadata(metadata, expected_repository_id, None))
        || records.windows(2).any(|pair| pair[0].id() >= pair[1].id())
        || after.is_some_and(|after| records.iter().any(|metadata| metadata.id() <= after))
    {
        return false;
    }
    match page.next_after() {
        Some(next_after) => {
            records.len() == usize::from(limit.get())
                && records
                    .last()
                    .is_some_and(|metadata| metadata.id() == next_after)
        }
        None => true,
    }
}

#[derive(Clone, Copy)]
enum ProviderActivationResultKind {
    Activated,
    AlreadyActive,
}

fn valid_provider_activation_metadata(
    metadata: &automata_ci_store::BuiltinSecretProviderMetadata,
    expected_revision: ManagementRevision,
    result_kind: ProviderActivationResultKind,
) -> bool {
    if metadata.state() != automata_ci_store::BuiltinSecretProviderState::Active
        || metadata.updated_at().get() < 0
    {
        return false;
    }
    match result_kind {
        ProviderActivationResultKind::Activated => expected_revision
            .value()
            .checked_add(1)
            .is_some_and(|revision| metadata.revision().value() == revision),
        ProviderActivationResultKind::AlreadyActive => metadata.revision() == expected_revision,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretApiError {
    InvalidRequest,
    UnsupportedMediaType,
    TooLarge,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Superseded,
    Deleted,
    Unavailable,
    Internal,
}

impl IntoResponse for SecretApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::Superseded => (StatusCode::CONFLICT, "mutation_superseded"),
            Self::Deleted => (StatusCode::GONE, "secret_deleted"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let mut response = json_response(status, &ErrorDocument { error: code });
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

#[derive(Serialize)]
struct ErrorDocument<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct RepositoryResolutionDocument {
    repository_id: String,
}

#[derive(Serialize)]
struct SecretPageDocument {
    items: Vec<SecretMetadataDocument>,
    next_after: Option<String>,
}

impl From<&automata_ci_store::RepositorySecretMetadataPage> for SecretPageDocument {
    fn from(page: &automata_ci_store::RepositorySecretMetadataPage) -> Self {
        Self {
            items: page
                .records()
                .iter()
                .map(SecretMetadataDocument::from)
                .collect(),
            next_after: page
                .next_after()
                .map(|value| value.as_uuid().hyphenated().to_string()),
        }
    }
}

#[derive(Serialize)]
struct SecretMetadataDocument {
    id: String,
    repository_id: String,
    name: String,
    provider_id: String,
    state: &'static str,
    current_version_number: Option<u64>,
    revision: u64,
    created_at_milliseconds: i64,
    updated_at_milliseconds: i64,
}

impl From<&RepositorySecretMetadata> for SecretMetadataDocument {
    fn from(value: &RepositorySecretMetadata) -> Self {
        Self {
            id: value.id().as_uuid().hyphenated().to_string(),
            repository_id: value.repository_id().as_uuid().hyphenated().to_string(),
            name: value.name().as_str().to_owned(),
            provider_id: value.provider_id().as_str().to_owned(),
            state: match value.state() {
                RepositorySecretState::Provisioning => "provisioning",
                RepositorySecretState::Active => "active",
                RepositorySecretState::Disabled => "disabled",
            },
            current_version_number: value.current_version_number(),
            revision: value.revision().value(),
            created_at_milliseconds: value.created_at().get(),
            updated_at_milliseconds: value.updated_at().get(),
        }
    }
}

#[derive(Serialize)]
struct ProviderDocument {
    id: &'static str,
    state: &'static str,
    revision: u64,
    updated_at_milliseconds: i64,
}

impl From<&automata_ci_store::BuiltinSecretProviderMetadata> for ProviderDocument {
    fn from(value: &automata_ci_store::BuiltinSecretProviderMetadata) -> Self {
        Self {
            id: automata_ci_store::BUILTIN_SECRET_PROVIDER_ID,
            state: match value.state() {
                automata_ci_store::BuiltinSecretProviderState::Unconfigured => "unconfigured",
                automata_ci_store::BuiltinSecretProviderState::Active => "active",
                automata_ci_store::BuiltinSecretProviderState::Disabled => "disabled",
            },
            revision: value.revision().value(),
            updated_at_milliseconds: value.updated_at().get(),
        }
    }
}

#[derive(Serialize)]
struct ProviderInspectionDocument {
    id: &'static str,
    state: &'static str,
    health: &'static str,
    revision: u64,
    activation: Option<ProviderActivationDocument>,
}

impl From<&automata_ci_store::BuiltinSecretProviderInspection> for ProviderInspectionDocument {
    fn from(value: &automata_ci_store::BuiltinSecretProviderInspection) -> Self {
        Self {
            id: automata_ci_store::BUILTIN_SECRET_PROVIDER_ID,
            state: match value.state() {
                automata_ci_store::BuiltinSecretProviderState::Unconfigured => "unconfigured",
                automata_ci_store::BuiltinSecretProviderState::Active => "active",
                automata_ci_store::BuiltinSecretProviderState::Disabled => "disabled",
            },
            health: match value.health() {
                automata_ci_store::BuiltinSecretProviderHealth::Unknown => "unknown",
                automata_ci_store::BuiltinSecretProviderHealth::Healthy => "healthy",
                automata_ci_store::BuiltinSecretProviderHealth::Degraded => "degraded",
                automata_ci_store::BuiltinSecretProviderHealth::Unavailable => "unavailable",
            },
            revision: value.revision().value(),
            activation: value
                .activation()
                .map(|evidence| ProviderActivationDocument {
                    expected_revision: evidence.expected_revision().value(),
                }),
        }
    }
}

#[derive(Serialize)]
struct ProviderActivationDocument {
    expected_revision: u64,
}

fn json_response(status: StatusCode, document: &impl Serialize) -> Response {
    match serde_json::to_vec(document) {
        Ok(body) => {
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(_) => SecretApiError::Internal.into_response(),
    }
}

fn empty_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use automata_ci_auth::{
        authorization::AuthorizationContext,
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject, TenantId},
        request_auth::ViewerDisplayMetadata,
        session::{DurableSession, DurableSessionIdentity, SessionId, SessionKind},
        time::UnixTimestamp,
    };
    use automata_ci_store::{
        BuiltinSecretProviderHealth, BuiltinSecretProviderInspection,
        BuiltinSecretProviderMetadata, BuiltinSecretProviderState, RepositorySecretMetadataPage,
    };
    use tower::ServiceExt as _;

    use super::*;

    const REPOSITORY: &str = "10000000-0000-4000-8000-000000000001";
    const FOREIGN_REPOSITORY: &str = "10000000-0000-4000-8000-000000000099";
    const SECRET: &str = "20000000-0000-4000-8000-000000000002";
    const OTHER_SECRET: &str = "20000000-0000-4000-8000-000000000003";
    const MUTATION: &str = "30000000-0000-4000-8000-000000000003";
    const VALUE: &[u8] = b"super-secret-value";

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(50)
        }
    }

    #[derive(Debug, Default)]
    struct FakeBackend {
        resolved_repository: Mutex<Option<String>>,
        looked_up_secret: Mutex<Option<(String, String)>>,
        provider_inspections: AtomicUsize,
        deny_reads: AtomicBool,
        nil_resolution: AtomicBool,
        lookup_corruption: AtomicUsize,
        list_corruption: AtomicUsize,
        listed_repository: Mutex<Option<String>>,
        mutation: Mutex<Option<MutationEvidence>>,
        deletion_repository: Mutex<Option<String>>,
        activation_corruption: AtomicUsize,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct MutationEvidence {
        repository: String,
        secret: String,
        mutation: String,
        name: String,
        replacement_revision: Option<u64>,
        provider: Option<String>,
        value_length: usize,
    }

    #[async_trait]
    impl RepositorySecretManagementReadRepository for FakeBackend {
        async fn resolve_github_repository_secret_metadata(
            &self,
            request: ResolveGithubRepositorySecretMetadata,
        ) -> Result<ResolveGithubRepositorySecretMetadataOutcome, SecretManagementRepositoryError>
        {
            *self
                .resolved_repository
                .lock()
                .expect("resolved repository lock") =
                Some(request.repository().as_str().to_owned());
            if self.deny_reads.load(Ordering::Relaxed) {
                return Ok(ResolveGithubRepositorySecretMetadataOutcome::NotFound);
            }
            if self.nil_resolution.load(Ordering::Relaxed) {
                let nil = "00000000-0000-0000-0000-000000000000"
                    .parse::<RunId>()
                    .expect("nil repository ID");
                return Ok(ResolveGithubRepositorySecretMetadataOutcome::Found(
                    RepositoryId::from_uuid(nil.as_uuid()),
                ));
            }
            let repository = REPOSITORY.parse::<RunId>().expect("repository ID");
            Ok(ResolveGithubRepositorySecretMetadataOutcome::Found(
                RepositoryId::from_uuid(repository.as_uuid()),
            ))
        }

        async fn get_repository_secret_metadata(
            &self,
            request: GetRepositorySecretMetadata,
        ) -> Result<GetRepositorySecretMetadataOutcome, SecretManagementRepositoryError> {
            *self.looked_up_secret.lock().expect("secret lookup lock") = Some((
                request.repository_id().as_uuid().hyphenated().to_string(),
                request.name().as_str().to_owned(),
            ));
            if self.deny_reads.load(Ordering::Relaxed) {
                return Ok(GetRepositorySecretMetadataOutcome::NotFound);
            }
            Ok(GetRepositorySecretMetadataOutcome::Found(lookup_metadata(
                request.repository_id(),
                self.lookup_corruption.load(Ordering::Relaxed),
            )))
        }

        async fn inspect_builtin_secret_provider(
            &self,
            _request: InspectBuiltinSecretProvider,
        ) -> Result<InspectBuiltinSecretProviderOutcome, SecretManagementRepositoryError> {
            self.provider_inspections.fetch_add(1, Ordering::Relaxed);
            if self.deny_reads.load(Ordering::Relaxed) {
                return Ok(InspectBuiltinSecretProviderOutcome::Forbidden);
            }
            Ok(InspectBuiltinSecretProviderOutcome::Found(
                BuiltinSecretProviderInspection::from_durable_parts(
                    BuiltinSecretProviderState::Unconfigured,
                    BuiltinSecretProviderHealth::Healthy,
                    ManagementRevision::new(4).expect("revision"),
                    true,
                ),
            ))
        }
    }

    #[async_trait]
    impl RepositorySecretApiBackend for FakeBackend {
        async fn list(
            &self,
            request: ListRepositorySecrets,
        ) -> Result<ListRepositorySecretsOutcome, SecretApiBackendError> {
            *self
                .listed_repository
                .lock()
                .expect("listed repository lock") =
                Some(request.repository_id().as_uuid().hyphenated().to_string());
            let corruption = self.list_corruption.load(Ordering::Relaxed);
            let repository_id = if corruption == 1 {
                parse_repository_id(FOREIGN_REPOSITORY)
            } else {
                request.repository_id()
            };
            let metadata = metadata(repository_id);
            let page = match corruption {
                2 => RepositorySecretMetadataPage::new(
                    vec![metadata],
                    Some(parse_secret_id(OTHER_SECRET)),
                ),
                3 => RepositorySecretMetadataPage::new(vec![metadata.clone(), metadata], None),
                4 => {
                    let cursor = metadata.id();
                    RepositorySecretMetadataPage::new(vec![metadata], Some(cursor))
                }
                _ => RepositorySecretMetadataPage::new(vec![metadata], None),
            };
            Ok(ListRepositorySecretsOutcome::Found(page))
        }

        async fn mutate(
            &self,
            request: ReserveRepositorySecretVersionMutation,
            value: SecretIngressValue,
        ) -> Result<RepositorySecretMutationOutcome, SecretApiBackendError> {
            assert_eq!(value.expose_for_test(), VALUE);
            *self.mutation.lock().expect("mutation lock") = Some(MutationEvidence {
                repository: request.repository_id().as_uuid().hyphenated().to_string(),
                secret: request.secret_id().as_uuid().hyphenated().to_string(),
                mutation: request.mutation_id().as_uuid().hyphenated().to_string(),
                name: request.name().as_str().to_owned(),
                replacement_revision: request.expected_revision().map(ManagementRevision::value),
                provider: request.provider_id().map(|value| value.as_str().to_owned()),
                value_length: value.expose_for_test().len(),
            });
            Ok(RepositorySecretMutationOutcome::Applied)
        }

        async fn delete(
            &self,
            request: DeleteRepositorySecret,
        ) -> Result<DeleteRepositorySecretOutcome, SecretApiBackendError> {
            *self
                .deletion_repository
                .lock()
                .expect("deletion repository lock") =
                Some(request.repository_id().as_uuid().hyphenated().to_string());
            Ok(DeleteRepositorySecretOutcome::AlreadyDeleted)
        }

        async fn activate_builtin(
            &self,
            request: ActivateBuiltinSecretProvider,
        ) -> Result<ActivateBuiltinSecretProviderOutcome, SecretApiBackendError> {
            let expected = request.expected_revision().value();
            let corruption = self.activation_corruption.load(Ordering::Relaxed);
            let (outcome, state, revision, updated_at) = match corruption {
                1 => (
                    ProviderActivationResultKind::Activated,
                    BuiltinSecretProviderState::Disabled,
                    expected + 1,
                    50_000,
                ),
                2 => (
                    ProviderActivationResultKind::Activated,
                    BuiltinSecretProviderState::Active,
                    expected,
                    50_000,
                ),
                3 => (
                    ProviderActivationResultKind::Activated,
                    BuiltinSecretProviderState::Active,
                    expected + 1,
                    -1,
                ),
                4 => (
                    ProviderActivationResultKind::AlreadyActive,
                    BuiltinSecretProviderState::Active,
                    expected + 1,
                    50_000,
                ),
                _ => (
                    ProviderActivationResultKind::Activated,
                    BuiltinSecretProviderState::Active,
                    expected + 1,
                    50_000,
                ),
            };
            let metadata = BuiltinSecretProviderMetadata::new(
                state,
                ManagementRevision::new(revision).expect("revision"),
                automata_ci_core::UnixMillis::new(updated_at),
            );
            Ok(match outcome {
                ProviderActivationResultKind::Activated => {
                    ActivateBuiltinSecretProviderOutcome::Activated(metadata)
                }
                ProviderActivationResultKind::AlreadyActive => {
                    ActivateBuiltinSecretProviderOutcome::AlreadyActive(metadata)
                }
            })
        }
    }

    fn metadata(repository_id: RepositoryId) -> RepositorySecretMetadata {
        metadata_parts(
            repository_id,
            "DEPLOY_TOKEN",
            RepositorySecretState::Active,
            Some(3),
            1_000,
            2_000,
        )
    }

    fn lookup_metadata(repository_id: RepositoryId, corruption: usize) -> RepositorySecretMetadata {
        match corruption {
            0 => metadata(repository_id),
            1 => metadata(parse_repository_id(FOREIGN_REPOSITORY)),
            2 => metadata_parts(
                repository_id,
                "OTHER_TOKEN",
                RepositorySecretState::Active,
                Some(3),
                1_000,
                2_000,
            ),
            3 => metadata_parts(
                repository_id,
                "DEPLOY_TOKEN",
                RepositorySecretState::Active,
                None,
                1_000,
                2_000,
            ),
            4 => metadata_parts(
                repository_id,
                "DEPLOY_TOKEN",
                RepositorySecretState::Provisioning,
                Some(3),
                1_000,
                2_000,
            ),
            5 => metadata_parts(
                repository_id,
                "DEPLOY_TOKEN",
                RepositorySecretState::Active,
                Some(3),
                -1,
                2_000,
            ),
            6 => metadata_parts(
                repository_id,
                "DEPLOY_TOKEN",
                RepositorySecretState::Active,
                Some(3),
                2_000,
                1_000,
            ),
            _ => panic!("unsupported test corruption mode"),
        }
    }

    fn metadata_parts(
        repository_id: RepositoryId,
        name: &str,
        state: RepositorySecretState,
        current_version_number: Option<u64>,
        created_at_milliseconds: i64,
        updated_at_milliseconds: i64,
    ) -> RepositorySecretMetadata {
        let secret = SECRET.parse::<RunId>().expect("secret ID");
        RepositorySecretMetadata::from_durable_parts(
            RepositorySecretId::from_uuid(secret.as_uuid()).expect("secret ID"),
            repository_id,
            RepositorySecretName::new(name).expect("secret name"),
            ManagedSecretProviderId::new("builtin").expect("provider"),
            state,
            current_version_number,
            ManagementRevision::new(9).expect("revision"),
            automata_ci_core::UnixMillis::new(created_at_milliseconds),
            automata_ci_core::UnixMillis::new(updated_at_milliseconds),
        )
    }

    fn parse_repository_id(value: &str) -> RepositoryId {
        RepositoryId::from_uuid(value.parse::<RunId>().expect("repository ID").as_uuid())
    }

    fn parse_secret_id(value: &str) -> RepositorySecretId {
        RepositorySecretId::from_uuid(value.parse::<RunId>().expect("secret ID").as_uuid())
            .expect("non-nil secret ID")
    }

    fn snapshot() -> AuthenticatedRequestSnapshot {
        snapshot_for(SessionKind::Cli)
    }

    fn snapshot_for(kind: SessionKind) -> AuthenticatedRequestSnapshot {
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let principal =
            PrincipalId::new("40000000-0000-4000-8000-000000000004").expect("principal");
        let provider = ProviderId::new("github").expect("provider");
        let subject = ProviderSubject::new("42").expect("subject");
        let identity = DurableSessionIdentity::new(
            SessionId::new("50000000-0000-4000-8000-000000000005").expect("session"),
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
            "octocat",
            Some("Octocat".to_owned()),
            UnixTimestamp::from_seconds(1),
        )
        .expect("human");
        let authorization =
            AuthorizationContext::authenticated_at_revision(tenant, principal, BTreeSet::new(), 7)
                .expect("authorization");
        AuthenticatedRequestSnapshot::new(
            session,
            human,
            ViewerDisplayMetadata::new("Octocat").expect("viewer"),
            authorization,
        )
        .expect("snapshot")
    }

    fn router(backend: Arc<FakeBackend>) -> Router {
        let reads: Arc<dyn RepositorySecretManagementReadRepository> = backend.clone();
        let backend: Arc<dyn RepositorySecretApiBackend> = backend;
        repository_secret_api_router(backend, reads, Arc::new(FixedClock))
    }

    fn put_request(value: Body) -> Request {
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/api/v1/repositories/{REPOSITORY}/secrets/{SECRET}"
            ))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(REQUEST_ID_HEADER, "request-1")
            .header(MUTATION_ID_HEADER, MUTATION)
            .header(SECRET_NAME_HEADER, "deploy_token")
            .extension(snapshot())
            .body(value)
            .expect("request")
    }

    #[tokio::test]
    async fn plaintext_put_is_bounded_and_crosses_only_the_typed_backend() {
        let backend = Arc::new(FakeBackend::default());
        let response = router(Arc::clone(&backend))
            .oneshot(put_request(Body::from(VALUE)))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            *backend.mutation.lock().expect("mutation lock"),
            Some(MutationEvidence {
                repository: REPOSITORY.to_owned(),
                secret: SECRET.to_owned(),
                mutation: MUTATION.to_owned(),
                name: "DEPLOY_TOKEN".to_owned(),
                replacement_revision: None,
                provider: None,
                value_length: VALUE.len(),
            })
        );
    }

    #[tokio::test]
    async fn json_secret_routes_independently_reject_browser_sessions_and_harden_fallbacks() {
        let backend = Arc::new(FakeBackend::default());
        let response = router(Arc::clone(&backend))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(BUILTIN_SECRET_PROVIDER_PATH)
                    .extension(snapshot_for(SessionKind::Browser))
                    .body(Body::empty())
                    .expect("browser request"),
            )
            .await
            .expect("browser response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(backend.provider_inspections.load(Ordering::Relaxed), 0);

        let response = router(backend)
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(BUILTIN_SECRET_PROVIDER_PATH)
                    .body(Body::empty())
                    .expect("unsupported method request"),
            )
            .await
            .expect("unsupported method response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }

    #[tokio::test]
    async fn replacement_binds_the_exact_revision_without_a_provider_override() {
        let backend = Arc::new(FakeBackend::default());
        let mut request = put_request(Body::from(VALUE));
        request
            .headers_mut()
            .insert(header::IF_MATCH, HeaderValue::from_static("\"9\""));
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let evidence = backend
            .mutation
            .lock()
            .expect("mutation lock")
            .take()
            .expect("mutation evidence");
        assert_eq!(evidence.replacement_revision, Some(9));
        assert_eq!(evidence.provider, None);
    }

    #[tokio::test]
    async fn repository_name_and_secret_name_reads_are_exact_and_value_free() {
        let backend = Arc::new(FakeBackend::default());
        let request = Request::builder()
            .method("GET")
            .uri("/api/v1/repository-targets/github/Automata-CI/automata")
            .extension(snapshot())
            .body(Body::empty())
            .expect("request");
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("bounded resolution body");
        let document: serde_json::Value = serde_json::from_slice(&body).expect("resolution JSON");
        assert_eq!(document["repository_id"], REPOSITORY);
        assert_eq!(
            backend
                .resolved_repository
                .lock()
                .expect("resolved repository lock")
                .as_deref(),
            Some("Automata-CI/automata")
        );

        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/repositories/{REPOSITORY}/secrets/lookup"))
            .header(SECRET_NAME_HEADER, "deploy_token")
            .extension(snapshot())
            .body(Body::empty())
            .expect("request");
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4_096)
            .await
            .expect("bounded metadata body");
        let document: serde_json::Value = serde_json::from_slice(&body).expect("metadata JSON");
        assert_eq!(document["name"], "DEPLOY_TOKEN");
        assert_eq!(document["id"], SECRET);
        assert!(document.get("value").is_none());
        assert!(document.get("handle").is_none());
        assert_eq!(
            *backend.looked_up_secret.lock().expect("secret lookup lock"),
            Some((REPOSITORY.to_owned(), "DEPLOY_TOKEN".to_owned()))
        );
    }

    #[tokio::test]
    async fn corrupt_found_reads_fail_closed_before_serialization() {
        let backend = Arc::new(FakeBackend::default());
        backend.nil_resolution.store(true, Ordering::Relaxed);
        let response = router(backend)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/repository-targets/github/automata-ci/automata")
                    .extension(snapshot())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_internal_response(response).await;

        for corruption in 1..=6 {
            let backend = Arc::new(FakeBackend::default());
            backend
                .lookup_corruption
                .store(corruption, Ordering::Relaxed);
            let response = router(backend)
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/api/v1/repositories/{REPOSITORY}/secrets/lookup"))
                        .header(SECRET_NAME_HEADER, "DEPLOY_TOKEN")
                        .extension(snapshot())
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_internal_response(response).await;
        }

        for (corruption, limit) in [(1, 1), (2, 1), (3, 1), (4, 2)] {
            let backend = Arc::new(FakeBackend::default());
            backend.list_corruption.store(corruption, Ordering::Relaxed);
            let response = router(backend)
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/api/v1/repositories/{REPOSITORY}/secrets?limit={limit}"
                        ))
                        .extension(snapshot())
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_internal_response(response).await;
        }

        let backend = Arc::new(FakeBackend::default());
        let response = router(backend)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/api/v1/repositories/{REPOSITORY}/secrets?after={SECRET}&limit=1"
                    ))
                    .extension(snapshot())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_internal_response(response).await;
    }

    async fn assert_internal_response(response: Response) {
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("bounded internal error body");
        assert_eq!(body.as_ref(), br#"{"error":"internal_error"}"#);
        assert!(!body.windows(VALUE.len()).any(|window| window == VALUE));
    }

    #[tokio::test]
    async fn provider_inspection_exposes_only_sanitized_atomic_activation_evidence() {
        let backend = Arc::new(FakeBackend::default());
        let request = Request::builder()
            .method("GET")
            .uri(BUILTIN_SECRET_PROVIDER_PATH)
            .extension(snapshot())
            .body(Body::empty())
            .expect("request");
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("bounded provider body");
        let document: serde_json::Value = serde_json::from_slice(&body).expect("provider JSON");
        assert_eq!(document["id"], "builtin");
        assert_eq!(document["state"], "unconfigured");
        assert_eq!(document["health"], "healthy");
        assert_eq!(document["revision"], 4);
        assert_eq!(document["activation"]["expected_revision"], 4);
        assert!(document.get("key").is_none());
        assert!(document.get("configuration").is_none());
        assert_eq!(backend.provider_inspections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn secret_lookup_name_is_one_bounded_header_not_a_request_target_segment() {
        let backend = Arc::new(FakeBackend::default());
        for headers in [Vec::new(), vec!["DEPLOY_TOKEN", "SECOND_TOKEN"]] {
            let mut request = Request::builder()
                .method("GET")
                .uri(format!("/api/v1/repositories/{REPOSITORY}/secrets/lookup"));
            for value in headers {
                request = request.header(SECRET_NAME_HEADER, value);
            }
            let response = router(Arc::clone(&backend))
                .oneshot(
                    request
                        .extension(snapshot())
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        assert!(
            backend
                .looked_up_secret
                .lock()
                .expect("secret lookup lock")
                .is_none()
        );
    }

    #[tokio::test]
    async fn missing_and_forbidden_operational_reads_are_non_enumerating() {
        let backend = Arc::new(FakeBackend::default());
        backend.deny_reads.store(true, Ordering::Relaxed);
        for uri in [
            (
                "/api/v1/repository-targets/github/automata-ci/automata".to_owned(),
                false,
            ),
            (
                format!("/api/v1/repositories/{REPOSITORY}/secrets/lookup"),
                true,
            ),
            (BUILTIN_SECRET_PROVIDER_PATH.to_owned(), false),
        ] {
            let mut request = Request::builder().method("GET").uri(uri.0);
            if uri.1 {
                request = request.header(SECRET_NAME_HEADER, "DEPLOY_TOKEN");
            }
            let request = request
                .extension(snapshot())
                .body(Body::empty())
                .expect("request");
            let response = router(Arc::clone(&backend))
                .oneshot(request)
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body = axum::body::to_bytes(response.into_body(), 1_024)
                .await
                .expect("bounded error body");
            assert_eq!(body.as_ref(), br#"{"error":"not_found"}"#);
        }
    }

    #[tokio::test]
    async fn list_returns_only_repository_scoped_value_free_metadata() {
        let backend = Arc::new(FakeBackend::default());
        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/repositories/{REPOSITORY}/secrets?limit=1"))
            .extension(snapshot())
            .body(Body::empty())
            .expect("request");
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = axum::body::to_bytes(response.into_body(), 4_096)
            .await
            .expect("bounded metadata body");
        let document: serde_json::Value =
            serde_json::from_slice(&response_body).expect("metadata JSON");
        assert_eq!(document["items"][0]["id"], SECRET);
        assert_eq!(document["items"][0]["repository_id"], REPOSITORY);
        assert_eq!(document["items"][0]["name"], "DEPLOY_TOKEN");
        assert_eq!(document["items"][0]["provider_id"], "builtin");
        assert_eq!(document["items"][0]["current_version_number"], 3);
        assert_eq!(document["items"][0]["revision"], 9);
        assert!(document["items"][0].get("value").is_none());
        assert!(
            !response_body
                .windows(VALUE.len())
                .any(|window| window == VALUE)
        );
        assert_eq!(
            backend
                .listed_repository
                .lock()
                .expect("listed repository lock")
                .as_deref(),
            Some(REPOSITORY)
        );
    }

    #[tokio::test]
    async fn built_in_activation_is_revision_guarded_and_value_free() {
        let backend = Arc::new(FakeBackend::default());
        let request = Request::builder()
            .method("POST")
            .uri(BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH)
            .header(header::IF_MATCH, "\"1\"")
            .extension(snapshot())
            .body(Body::empty())
            .expect("request");
        let response = router(backend).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("bounded provider body");
        let document: serde_json::Value =
            serde_json::from_slice(&response_body).expect("provider JSON");
        assert_eq!(document["id"], "builtin");
        assert_eq!(document["state"], "active");
        assert_eq!(document["revision"], 2);
        assert!(document.get("value").is_none());
    }

    #[tokio::test]
    async fn corrupt_provider_activation_metadata_fails_closed() {
        for corruption in 1..=4 {
            let backend = Arc::new(FakeBackend::default());
            backend
                .activation_corruption
                .store(corruption, Ordering::Relaxed);
            let request = Request::builder()
                .method("POST")
                .uri(BUILTIN_SECRET_PROVIDER_ACTIVATION_PATH)
                .header(header::IF_MATCH, "\"1\"")
                .extension(snapshot())
                .body(Body::empty())
                .expect("request");
            let response = router(backend).oneshot(request).await.expect("response");
            assert_internal_response(response).await;
        }
    }

    #[tokio::test]
    async fn oversized_plaintext_never_reaches_the_backend_or_response() {
        let backend = Arc::new(FakeBackend::default());
        let body = vec![b'X'; MAX_SECRET_INGRESS_BYTES + 1];
        let response = router(Arc::clone(&backend))
            .oneshot(put_request(Body::from(body)))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(backend.mutation.lock().expect("mutation lock").is_none());
        let response_body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("bounded error body");
        assert!(!response_body.windows(8).any(|window| window == b"XXXXXXXX"));
    }

    #[tokio::test]
    async fn plaintext_requires_one_exact_octet_stream_media_type() {
        let backend = Arc::new(FakeBackend::default());
        let mut request = put_request(Body::from(VALUE));
        request.headers_mut().remove(header::CONTENT_TYPE);
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let mut request = put_request(Body::from(VALUE));
        request.headers_mut().append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(backend.mutation.lock().expect("mutation lock").is_none());
    }

    #[tokio::test]
    async fn delete_binds_the_exact_repository_path_and_revision() {
        let backend = Arc::new(FakeBackend::default());
        let request = Request::builder()
            .method("DELETE")
            .uri(format!(
                "/api/v1/repositories/{REPOSITORY}/secrets/{SECRET}"
            ))
            .header(header::IF_MATCH, "\"9\"")
            .extension(snapshot())
            .body(Body::empty())
            .expect("request");
        let response = router(Arc::clone(&backend))
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            backend
                .deletion_repository
                .lock()
                .expect("deletion repository lock")
                .as_deref(),
            Some(REPOSITORY)
        );
    }

    #[test]
    fn identifiers_revisions_queries_and_debug_are_closed() {
        assert!(canonical_uuid(REPOSITORY).is_ok());
        for invalid in [
            "00000000-0000-0000-0000-000000000000",
            "10000000000040008000000000000001",
            "10000000-0000-4000-8000-000000000001/extra",
        ] {
            assert_eq!(canonical_uuid(invalid), Err(SecretApiError::InvalidRequest));
        }
        assert!(list_query(Some("after=bad")).is_err());
        assert!(list_query(Some("limit=01")).is_err());
        assert!(list_query(Some("limit=1&limit=2")).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"4\""));
        assert_eq!(required_revision(&headers).expect("revision").value(), 4);
        headers.insert(header::IF_MATCH, HeaderValue::from_static("W/\"4\""));
        assert!(required_revision(&headers).is_err());

        let value = SecretIngressValue::new(VALUE.to_vec()).expect("value");
        let debug = format!("{value:?}");
        assert_eq!(debug, "SecretIngressValue([REDACTED])");
        assert!(!debug.contains("super-secret"));
    }
}
