//! Native browser boundary for repository-scoped secret management.
//!
//! The renderer receives value-free metadata only. Plaintext is accepted by one
//! bounded, zeroizing form owner, survives authentication only as a move-only
//! request extension, and is consumed by the existing reserve/provider/confirm
//! backend without entering URLs, diagnostics, or response documents.

use std::{
    collections::HashMap,
    fmt, mem,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_auth::{
    authorization::{
        AuthorizationRequest, AuthorizationScope, OutputVisibility, Permission, SecretExposureClass,
    },
    management::{ManagementActor, ManagementRevision},
    request_auth::AuthenticatedRequestSnapshot,
    secret::SecretString,
    session::SessionKind,
    time::Clock,
};
use automata_ci_core::RunId;
use automata_ci_store::{
    ActivateBuiltinSecretProvider, ActivateBuiltinSecretProviderOutcome,
    BUILTIN_SECRET_PROVIDER_ID, BuiltinSecretProviderInspection, BuiltinSecretProviderMetadata,
    BuiltinSecretProviderState, DeleteRepositorySecret, DeleteRepositorySecretOutcome,
    GithubRepositoryName, HumanAuthorizationTarget, HumanWorkflowReadRepository,
    InspectBuiltinSecretProvider, InspectBuiltinSecretProviderOutcome, ListRepositorySecrets,
    ListRepositorySecretsOutcome, RepositoryCoordinate, RepositoryId, RepositorySecretId,
    RepositorySecretManagementReadRepository, RepositorySecretMetadata,
    RepositorySecretMetadataPage, RepositorySecretMutationId, RepositorySecretName,
    RepositorySecretState, ReserveRepositorySecretVersionMutation,
    ResolveGithubRepositorySecretMetadata, ResolveGithubRepositorySecretMetadataOutcome,
    SecretManagementRepositoryError, SecretMetadataPageSize, StoreError, TenantScope,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{OriginalUri, Path, Request, State, rejection::PathRejection},
    http::{Response, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::post,
};
use futures::StreamExt as _;
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    form,
    secret_api::{
        MAX_SECRET_INGRESS_BYTES, RepositorySecretApiBackend, RepositorySecretMutationOutcome,
        SecretApiBackendError, SecretIngressValue,
    },
    web::{apply_static_page_headers, error_page_response_with_action},
};

pub(crate) const REPOSITORY_SECRETS_SETTINGS_PATH: &str = "/{owner}/{repository}/settings/secrets";
pub(crate) const REPOSITORY_SECRET_REPLACE_PATH: &str =
    "/{owner}/{repository}/settings/secrets/{secret_id}/replace";
pub(crate) const REPOSITORY_SECRET_DELETE_PATH: &str =
    "/{owner}/{repository}/settings/secrets/{secret_id}/delete";
pub(crate) const REPOSITORY_SECRET_PROVIDER_ACTIVATE_PATH: &str =
    "/{owner}/{repository}/settings/secrets/provider/activate";

const SCM_PROVIDER: &str = "github";
const SECRET_CREATE_PERMISSION: &str = "secrets:create";
const SECRET_UPDATE_PERMISSION: &str = "secrets:update";
const SECRET_DELETE_PERMISSION: &str = "secrets:delete";
const REPOSITORY_SETTINGS_READ_PERMISSION: &str = "repositories:read";
const SECRET_PAGE_SIZE: u16 = 50;
const MAX_SECRET_NAME_BYTES: usize = 255;
const MAX_FORM_KEY_BYTES: usize = 40;
const MAX_CSRF_BYTES: usize = 256;
const MAX_REVISION_BYTES: usize = 20;
const UUID_TEXT_BYTES: usize = 36;
const FORM_ENVELOPE_BYTES: usize = 4 * 1_024;

/// Maximum encoded bytes accepted from one secret browser form.
///
/// URL encoding may expand each plaintext byte to three bytes. The fixed
/// envelope covers every non-secret field and delimiter without an unbounded
/// allocation path.
pub(crate) const MAX_REPOSITORY_SECRET_FORM_BYTES: usize =
    MAX_SECRET_INGRESS_BYTES * 3 + FORM_ENVELOPE_BYTES;

/// One bounded page request using the public value-free UUID cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepositorySecretsPageRequest {
    pub(crate) after: Option<RepositorySecretId>,
}

impl RepositorySecretsPageRequest {
    pub(crate) fn new(after: Option<&str>) -> Result<Self, RepositorySecretWebError> {
        let after = after
            .map(parse_secret_id)
            .transpose()
            .map_err(|_| RepositorySecretWebError::InvalidRequest)?;
        Ok(Self { after })
    }
}

/// Exact capability envelope for one newly created logical secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepositorySecretCreateCapability {
    pub(crate) secret_id: RepositorySecretId,
    pub(crate) mutation_id: RepositorySecretMutationId,
}

/// Value-free metadata and any exact row-scoped mutation capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositorySecretRow {
    pub(crate) metadata: RepositorySecretMetadata,
    pub(crate) replace_mutation_id: Option<RepositorySecretMutationId>,
    pub(crate) deletable: bool,
}

/// Authorized value-free data rendered by the repository Secrets page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositorySecretsPage {
    pub(crate) repository_id: RepositoryId,
    pub(crate) owner: String,
    pub(crate) repository: String,
    pub(crate) authorization_revision: ManagementRevision,
    pub(crate) access_visible: bool,
    pub(crate) rows: Vec<RepositorySecretRow>,
    pub(crate) next_after: Option<RepositorySecretId>,
    pub(crate) create: Option<RepositorySecretCreateCapability>,
    pub(crate) provider: Option<BuiltinSecretProviderInspection>,
}

/// Closed page-read result. Missing repositories and denied metadata authority
/// intentionally share `NotFound`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RepositorySecretsReadOutcome {
    Found(RepositorySecretsPage),
    SessionStale,
    NotFound,
}

/// Sanitized browser-secret application failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositorySecretWebError {
    InvalidRequest,
    Unavailable,
    Corrupt,
}

/// Successful and closed recovery states returned by one native-form mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositorySecretBrowserMutationOutcome {
    Created,
    Replaced,
    Deleted,
    ProviderActivated,
    Conflict,
    SessionStale,
    NotFound,
    Unavailable,
}

/// Operational browser application port shared by the SSR GET and native POST
/// routers. Implementations must reauthorize every call against the supplied
/// exact session revision.
#[async_trait]
pub(crate) trait RepositorySecretWebData: fmt::Debug + Send + Sync {
    async fn page(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        owner: &str,
        repository: &str,
        request: RepositorySecretsPageRequest,
    ) -> Result<RepositorySecretsReadOutcome, RepositorySecretWebError>;

    async fn mutate(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        owner: &str,
        repository: &str,
        form: VerifiedRepositorySecretForm,
    ) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError>;
}

/// Production application adapter over the existing value-free read and
/// reserve/provider/confirm ports.
pub(crate) struct OperationalRepositorySecretWebData {
    backend: Arc<dyn RepositorySecretApiBackend>,
    secret_reads: Arc<dyn RepositorySecretManagementReadRepository>,
    repository_reads: Arc<dyn HumanWorkflowReadRepository>,
    clock: Arc<dyn Clock>,
}

impl OperationalRepositorySecretWebData {
    #[must_use]
    pub(crate) fn new(
        backend: Arc<dyn RepositorySecretApiBackend>,
        secret_reads: Arc<dyn RepositorySecretManagementReadRepository>,
        repository_reads: Arc<dyn HumanWorkflowReadRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            backend,
            secret_reads,
            repository_reads,
            clock,
        }
    }

    fn actor(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<ManagementActor, RepositorySecretWebError> {
        if snapshot.session().identity().kind() != SessionKind::Browser {
            return Err(RepositorySecretWebError::InvalidRequest);
        }
        let revision = snapshot_revision(snapshot)?;
        let identity = snapshot.session().identity();
        Ok(ManagementActor::new(
            identity.tenant_id().clone(),
            identity.principal_id().clone(),
            identity.session_id().clone(),
            revision,
            None,
            self.clock.now(),
        ))
    }

    async fn resolve_repository(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        owner: &str,
        repository: &str,
    ) -> Result<ResolvedRepository, ResolveRepositoryError> {
        let github_name = github_repository_name(owner, repository)
            .map_err(|_| ResolveRepositoryError::NotFound)?;
        let actor = self
            .actor(snapshot)
            .map_err(|_| ResolveRepositoryError::SessionStale)?;
        let repository_id = match self
            .secret_reads
            .resolve_github_repository_secret_metadata(ResolveGithubRepositorySecretMetadata::new(
                actor,
                github_name,
            ))
            .await
            .map_err(map_repository_error)?
        {
            ResolveGithubRepositorySecretMetadataOutcome::Found(repository_id) => repository_id,
            ResolveGithubRepositorySecretMetadataOutcome::SessionStale => {
                return Err(ResolveRepositoryError::SessionStale);
            }
            ResolveGithubRepositorySecretMetadataOutcome::NotFound => {
                return Err(ResolveRepositoryError::NotFound);
            }
        };
        if repository_id.as_uuid().is_nil() {
            return Err(ResolveRepositoryError::Corrupt);
        }
        let tenant = TenantScope::from_authenticated_tenant_id(
            snapshot.session().identity().tenant_id().as_str(),
        )
        .map_err(|_| ResolveRepositoryError::Corrupt)?;
        let coordinate = RepositoryCoordinate::new(SCM_PROVIDER, owner, repository)
            .map_err(|_| ResolveRepositoryError::NotFound)?;
        let durable = self
            .repository_reads
            .resolve_repository(&tenant, &coordinate)
            .await
            .map_err(|error| map_store_error(&error))?
            .ok_or(ResolveRepositoryError::NotFound)?;
        if durable.id != repository_id
            || durable.resource.repository_id().as_uuid() != repository_id.as_uuid()
            || durable.resource.tenant_id() != snapshot.session().identity().tenant_id()
            || durable.scm_provider != SCM_PROVIDER
            || durable.owner != owner
            || durable.name != repository
        {
            return Err(ResolveRepositoryError::Corrupt);
        }
        Ok(ResolvedRepository {
            tenant,
            id: repository_id,
            resource: durable.resource,
            owner: durable.owner,
            name: durable.name,
        })
    }

    async fn capability(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        repository: &ResolvedRepository,
        permission_name: &'static str,
    ) -> Result<bool, RepositorySecretWebError> {
        self.capability_with_visibility(snapshot, repository, permission_name, None)
            .await
    }

    async fn capability_with_visibility(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        repository: &ResolvedRepository,
        permission_name: &'static str,
        visibility: Option<OutputVisibility>,
    ) -> Result<bool, RepositorySecretWebError> {
        let permission =
            Permission::new(permission_name).map_err(|_| RepositorySecretWebError::Corrupt)?;
        let request = AuthorizationRequest::new(
            AuthorizationScope::repository(repository.resource.clone()),
            permission,
        )
        .with_secret_exposure(SecretExposureClass::ReadableSecret);
        let target = match visibility {
            Some(visibility) => HumanAuthorizationTarget::immutable(request, visibility),
            None => HumanAuthorizationTarget::current_policy(request),
        };
        self.repository_reads
            .is_repository_request_allowed(
                &repository.tenant,
                repository.id,
                snapshot.authorization(),
                &target,
            )
            .await
            .map_err(|error| map_store_web_error(&error))
    }

    async fn metadata_page(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        repository_id: RepositoryId,
        request: RepositorySecretsPageRequest,
    ) -> Result<SecretMetadataRead, RepositorySecretWebError> {
        let limit = SecretMetadataPageSize::new(SECRET_PAGE_SIZE)
            .map_err(|_| RepositorySecretWebError::Corrupt)?;
        let list =
            ListRepositorySecrets::new(self.actor(snapshot)?, repository_id, request.after, limit)
                .map_err(|_| RepositorySecretWebError::InvalidRequest)?;
        match self.backend.list(list).await.map_err(map_backend_error)? {
            ListRepositorySecretsOutcome::Found(page) => {
                if !valid_secret_page(&page, repository_id, request.after, limit) {
                    return Err(RepositorySecretWebError::Corrupt);
                }
                Ok(SecretMetadataRead::Found(page))
            }
            ListRepositorySecretsOutcome::SessionStale => Ok(SecretMetadataRead::SessionStale),
            ListRepositorySecretsOutcome::Forbidden | ListRepositorySecretsOutcome::NotFound => {
                Ok(SecretMetadataRead::NotFound)
            }
        }
    }

    async fn provider(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<SecretProviderRead, RepositorySecretWebError> {
        let request = InspectBuiltinSecretProvider::new(self.actor(snapshot)?);
        match self
            .secret_reads
            .inspect_builtin_secret_provider(request)
            .await
            .map_err(map_repository_web_error)?
        {
            InspectBuiltinSecretProviderOutcome::Found(provider) => {
                if !valid_provider_inspection(&provider) {
                    return Err(RepositorySecretWebError::Corrupt);
                }
                Ok(SecretProviderRead::Found(Some(provider)))
            }
            InspectBuiltinSecretProviderOutcome::Forbidden
            | InspectBuiltinSecretProviderOutcome::NotFound => Ok(SecretProviderRead::Found(None)),
            InspectBuiltinSecretProviderOutcome::SessionStale => {
                Ok(SecretProviderRead::SessionStale)
            }
        }
    }

    async fn page_for_repository(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        resolved: ResolvedRepository,
        request: RepositorySecretsPageRequest,
    ) -> Result<RepositorySecretsReadOutcome, RepositorySecretWebError> {
        let page = match self.metadata_page(snapshot, resolved.id, request).await? {
            SecretMetadataRead::Found(page) => page,
            SecretMetadataRead::SessionStale => {
                return Ok(RepositorySecretsReadOutcome::SessionStale);
            }
            SecretMetadataRead::NotFound => return Ok(RepositorySecretsReadOutcome::NotFound),
        };
        let (can_create, can_update, can_delete, access_visible) = tokio::try_join!(
            self.capability(snapshot, &resolved, SECRET_CREATE_PERMISSION),
            self.capability(snapshot, &resolved, SECRET_UPDATE_PERMISSION),
            self.capability(snapshot, &resolved, SECRET_DELETE_PERMISSION),
            self.capability_with_visibility(
                snapshot,
                &resolved,
                REPOSITORY_SETTINGS_READ_PERMISSION,
                Some(OutputVisibility::Private),
            ),
        )?;
        let provider = match self.provider(snapshot).await? {
            SecretProviderRead::Found(provider) => provider,
            SecretProviderRead::SessionStale => {
                return Ok(RepositorySecretsReadOutcome::SessionStale);
            }
        };
        let rows = project_secret_rows(&page, can_update, can_delete)?;
        let create = create_capability(can_create)?;
        Ok(RepositorySecretsReadOutcome::Found(RepositorySecretsPage {
            repository_id: resolved.id,
            owner: resolved.owner,
            repository: resolved.name,
            authorization_revision: snapshot_revision(snapshot)?,
            access_visible,
            rows,
            next_after: page.next_after(),
            create,
            provider,
        }))
    }

    async fn mutate_for_repository(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        repository_id: RepositoryId,
        form: VerifiedRepositorySecretForm,
    ) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError> {
        match form {
            VerifiedRepositorySecretForm::Create {
                secret_id,
                mutation_id,
                name,
                value,
                ..
            } => {
                let request = ReserveRepositorySecretVersionMutation::create(
                    self.actor(snapshot)?,
                    mutation_id,
                    secret_id,
                    repository_id,
                    name,
                    None,
                )
                .map_err(|_| RepositorySecretWebError::InvalidRequest)?;
                map_secret_mutation(
                    self.backend.mutate(request, value).await,
                    RepositorySecretBrowserMutationOutcome::Created,
                )
            }
            VerifiedRepositorySecretForm::Replace {
                secret_id,
                mutation_id,
                name,
                expected_revision,
                value,
                ..
            } => {
                let request = ReserveRepositorySecretVersionMutation::replace(
                    self.actor(snapshot)?,
                    mutation_id,
                    secret_id,
                    repository_id,
                    name,
                    expected_revision,
                )
                .map_err(|_| RepositorySecretWebError::InvalidRequest)?;
                map_secret_mutation(
                    self.backend.mutate(request, value).await,
                    RepositorySecretBrowserMutationOutcome::Replaced,
                )
            }
            VerifiedRepositorySecretForm::Delete {
                secret_id,
                expected_revision,
                ..
            } => {
                self.delete(snapshot, repository_id, secret_id, expected_revision)
                    .await
            }
            VerifiedRepositorySecretForm::ActivateProvider {
                expected_revision, ..
            } => self.activate_provider(snapshot, expected_revision).await,
        }
    }

    async fn delete(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        repository_id: RepositoryId,
        secret_id: RepositorySecretId,
        expected_revision: ManagementRevision,
    ) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError> {
        let request = DeleteRepositorySecret::new(
            self.actor(snapshot)?,
            repository_id,
            secret_id,
            expected_revision,
        )
        .map_err(|_| RepositorySecretWebError::InvalidRequest)?;
        match self
            .backend
            .delete(request)
            .await
            .map_err(map_backend_error)?
        {
            DeleteRepositorySecretOutcome::Deleted(receipt) if receipt.secret_id() == secret_id => {
                Ok(RepositorySecretBrowserMutationOutcome::Deleted)
            }
            DeleteRepositorySecretOutcome::Deleted(_) => Err(RepositorySecretWebError::Corrupt),
            DeleteRepositorySecretOutcome::AlreadyDeleted => {
                Ok(RepositorySecretBrowserMutationOutcome::Deleted)
            }
            DeleteRepositorySecretOutcome::RevisionConflict { .. } => {
                Ok(RepositorySecretBrowserMutationOutcome::Conflict)
            }
            DeleteRepositorySecretOutcome::SessionStale => {
                Ok(RepositorySecretBrowserMutationOutcome::SessionStale)
            }
            DeleteRepositorySecretOutcome::Forbidden | DeleteRepositorySecretOutcome::NotFound => {
                Ok(RepositorySecretBrowserMutationOutcome::NotFound)
            }
        }
    }

    async fn activate_provider(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        expected_revision: ManagementRevision,
    ) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError> {
        let request = ActivateBuiltinSecretProvider::new(self.actor(snapshot)?, expected_revision);
        match self
            .backend
            .activate_builtin(request)
            .await
            .map_err(map_backend_error)?
        {
            ActivateBuiltinSecretProviderOutcome::Activated(metadata)
                if valid_provider_activation(&metadata, expected_revision, true) =>
            {
                Ok(RepositorySecretBrowserMutationOutcome::ProviderActivated)
            }
            ActivateBuiltinSecretProviderOutcome::AlreadyActive(metadata)
                if valid_provider_activation(&metadata, expected_revision, false) =>
            {
                Ok(RepositorySecretBrowserMutationOutcome::ProviderActivated)
            }
            ActivateBuiltinSecretProviderOutcome::Activated(_)
            | ActivateBuiltinSecretProviderOutcome::AlreadyActive(_) => {
                Err(RepositorySecretWebError::Corrupt)
            }
            ActivateBuiltinSecretProviderOutcome::RevisionConflict { .. } => {
                Ok(RepositorySecretBrowserMutationOutcome::Conflict)
            }
            ActivateBuiltinSecretProviderOutcome::SessionStale => {
                Ok(RepositorySecretBrowserMutationOutcome::SessionStale)
            }
            ActivateBuiltinSecretProviderOutcome::Forbidden
            | ActivateBuiltinSecretProviderOutcome::NotFound => {
                Ok(RepositorySecretBrowserMutationOutcome::NotFound)
            }
        }
    }
}

impl fmt::Debug for OperationalRepositorySecretWebData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalRepositorySecretWebData")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RepositorySecretWebData for OperationalRepositorySecretWebData {
    async fn page(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        owner: &str,
        repository: &str,
        request: RepositorySecretsPageRequest,
    ) -> Result<RepositorySecretsReadOutcome, RepositorySecretWebError> {
        let resolved = match self.resolve_repository(snapshot, owner, repository).await {
            Ok(resolved) => resolved,
            Err(ResolveRepositoryError::SessionStale) => {
                return Ok(RepositorySecretsReadOutcome::SessionStale);
            }
            Err(ResolveRepositoryError::NotFound) => {
                return Ok(RepositorySecretsReadOutcome::NotFound);
            }
            Err(ResolveRepositoryError::Unavailable) => {
                return Err(RepositorySecretWebError::Unavailable);
            }
            Err(ResolveRepositoryError::Corrupt) => {
                return Err(RepositorySecretWebError::Corrupt);
            }
        };
        self.page_for_repository(snapshot, resolved, request).await
    }

    async fn mutate(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        owner: &str,
        repository: &str,
        form: VerifiedRepositorySecretForm,
    ) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError> {
        if form.expected_authorization_revision() != snapshot_revision(snapshot)? {
            return Ok(RepositorySecretBrowserMutationOutcome::SessionStale);
        }
        let resolved = match self.resolve_repository(snapshot, owner, repository).await {
            Ok(resolved) => resolved,
            Err(ResolveRepositoryError::SessionStale) => {
                return Ok(RepositorySecretBrowserMutationOutcome::SessionStale);
            }
            Err(ResolveRepositoryError::NotFound) => {
                return Ok(RepositorySecretBrowserMutationOutcome::NotFound);
            }
            Err(ResolveRepositoryError::Unavailable) => {
                return Ok(RepositorySecretBrowserMutationOutcome::Unavailable);
            }
            Err(ResolveRepositoryError::Corrupt) => {
                return Err(RepositorySecretWebError::Corrupt);
            }
        };
        self.mutate_for_repository(snapshot, resolved.id, form)
            .await
    }
}

#[derive(Debug)]
struct ResolvedRepository {
    tenant: TenantScope,
    id: RepositoryId,
    resource: automata_ci_auth::authorization::RepositoryResource,
    owner: String,
    name: String,
}

#[derive(Debug)]
enum SecretMetadataRead {
    Found(RepositorySecretMetadataPage),
    SessionStale,
    NotFound,
}

#[derive(Debug)]
enum SecretProviderRead {
    Found(Option<BuiltinSecretProviderInspection>),
    SessionStale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolveRepositoryError {
    SessionStale,
    NotFound,
    Unavailable,
    Corrupt,
}

fn snapshot_revision(
    snapshot: &AuthenticatedRequestSnapshot,
) -> Result<ManagementRevision, RepositorySecretWebError> {
    let revision = snapshot.session().authorization_revision();
    if snapshot.authorization().authorization_revision() != Some(revision) {
        return Err(RepositorySecretWebError::Corrupt);
    }
    let revision =
        ManagementRevision::new(revision).map_err(|_| RepositorySecretWebError::InvalidRequest)?;
    if revision.value() > i64::MAX.unsigned_abs() {
        return Err(RepositorySecretWebError::Corrupt);
    }
    Ok(revision)
}

fn github_repository_name(
    owner: &str,
    repository: &str,
) -> Result<GithubRepositoryName, RepositorySecretWebError> {
    let length = owner
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(repository.len()))
        .filter(|length| *length <= 140)
        .ok_or(RepositorySecretWebError::InvalidRequest)?;
    let mut coordinate = String::with_capacity(length);
    coordinate.push_str(owner);
    coordinate.push('/');
    coordinate.push_str(repository);
    GithubRepositoryName::new(coordinate).map_err(|_| RepositorySecretWebError::InvalidRequest)
}

fn new_secret_id() -> Result<RepositorySecretId, RepositorySecretWebError> {
    RepositorySecretId::from_uuid(RunId::new().as_uuid())
        .map_err(|_| RepositorySecretWebError::Corrupt)
}

fn new_mutation_id(
    secret_id: RepositorySecretId,
) -> Result<RepositorySecretMutationId, RepositorySecretWebError> {
    for _ in 0..2 {
        if let Ok(id) = RepositorySecretMutationId::from_uuid(RunId::new().as_uuid(), secret_id) {
            return Ok(id);
        }
    }
    Err(RepositorySecretWebError::Corrupt)
}

fn project_secret_rows(
    page: &RepositorySecretMetadataPage,
    can_update: bool,
    can_delete: bool,
) -> Result<Vec<RepositorySecretRow>, RepositorySecretWebError> {
    page.records()
        .iter()
        .map(|metadata| {
            let replace_mutation_id = (can_update
                && metadata.state() == RepositorySecretState::Active
                && metadata.revision().value() < i64::MAX.unsigned_abs())
            .then(|| new_mutation_id(metadata.id()))
            .transpose()?;
            Ok(RepositorySecretRow {
                metadata: metadata.clone(),
                replace_mutation_id,
                deletable: can_delete && metadata.revision().value() < i64::MAX.unsigned_abs(),
            })
        })
        .collect()
}

fn create_capability(
    can_create: bool,
) -> Result<Option<RepositorySecretCreateCapability>, RepositorySecretWebError> {
    if !can_create {
        return Ok(None);
    }
    let secret_id = new_secret_id()?;
    Ok(Some(RepositorySecretCreateCapability {
        secret_id,
        mutation_id: new_mutation_id(secret_id)?,
    }))
}

fn map_secret_mutation(
    result: Result<RepositorySecretMutationOutcome, SecretApiBackendError>,
    success: RepositorySecretBrowserMutationOutcome,
) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError> {
    match result.map_err(map_backend_error)? {
        RepositorySecretMutationOutcome::Applied => Ok(success),
        RepositorySecretMutationOutcome::AppliedThenSuperseded
        | RepositorySecretMutationOutcome::AppliedThenDeleted
        | RepositorySecretMutationOutcome::CasLost
        | RepositorySecretMutationOutcome::Cancelled
        | RepositorySecretMutationOutcome::Conflict
        | RepositorySecretMutationOutcome::RevisionConflict => {
            Ok(RepositorySecretBrowserMutationOutcome::Conflict)
        }
        RepositorySecretMutationOutcome::Forbidden | RepositorySecretMutationOutcome::NotFound => {
            Ok(RepositorySecretBrowserMutationOutcome::NotFound)
        }
        RepositorySecretMutationOutcome::SessionStale => {
            Ok(RepositorySecretBrowserMutationOutcome::SessionStale)
        }
        RepositorySecretMutationOutcome::ProviderUnavailable => {
            Ok(RepositorySecretBrowserMutationOutcome::Unavailable)
        }
    }
}

fn map_backend_error(error: SecretApiBackendError) -> RepositorySecretWebError {
    match error {
        SecretApiBackendError::InvalidRequest => RepositorySecretWebError::InvalidRequest,
        SecretApiBackendError::Unavailable => RepositorySecretWebError::Unavailable,
        SecretApiBackendError::CorruptData => RepositorySecretWebError::Corrupt,
    }
}

fn map_repository_error(error: SecretManagementRepositoryError) -> ResolveRepositoryError {
    match error {
        SecretManagementRepositoryError::InvalidRequest
        | SecretManagementRepositoryError::CorruptData => ResolveRepositoryError::Corrupt,
        SecretManagementRepositoryError::Unavailable => ResolveRepositoryError::Unavailable,
    }
}

fn map_repository_web_error(error: SecretManagementRepositoryError) -> RepositorySecretWebError {
    match error {
        SecretManagementRepositoryError::InvalidRequest => RepositorySecretWebError::InvalidRequest,
        SecretManagementRepositoryError::Unavailable => RepositorySecretWebError::Unavailable,
        SecretManagementRepositoryError::CorruptData => RepositorySecretWebError::Corrupt,
    }
}

fn map_store_error(error: &StoreError) -> ResolveRepositoryError {
    match error {
        StoreError::CorruptData(_) => ResolveRepositoryError::Corrupt,
        _ => ResolveRepositoryError::Unavailable,
    }
}

fn map_store_web_error(error: &StoreError) -> RepositorySecretWebError {
    match error {
        StoreError::CorruptData(_) => RepositorySecretWebError::Corrupt,
        _ => RepositorySecretWebError::Unavailable,
    }
}

fn valid_secret_metadata(
    metadata: &RepositorySecretMetadata,
    expected_repository_id: RepositoryId,
) -> bool {
    if metadata.id().as_uuid().is_nil()
        || metadata.repository_id().as_uuid().is_nil()
        || metadata.repository_id() != expected_repository_id
        || metadata.provider_id().as_str() != BUILTIN_SECRET_PROVIDER_ID
        || metadata.revision().value() > i64::MAX.unsigned_abs()
        || metadata.created_at().get() < 0
        || metadata.updated_at().get() < metadata.created_at().get()
    {
        return false;
    }
    match (metadata.state(), metadata.current_version_number()) {
        (RepositorySecretState::Provisioning, None) => true,
        (RepositorySecretState::Active | RepositorySecretState::Disabled, Some(version)) => {
            version > 0
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
            .any(|metadata| !valid_secret_metadata(metadata, expected_repository_id))
        || records.windows(2).any(|pair| pair[0].id() >= pair[1].id())
        || after.is_some_and(|after| records.iter().any(|metadata| metadata.id() <= after))
    {
        return false;
    }
    page.next_after().is_none_or(|next| {
        records.len() == usize::from(limit.get())
            && records.last().is_some_and(|metadata| metadata.id() == next)
    })
}

fn valid_provider_inspection(provider: &BuiltinSecretProviderInspection) -> bool {
    provider.revision().value() <= i64::MAX.unsigned_abs()
        && provider.activation().is_none_or(|activation| {
            provider.state() != BuiltinSecretProviderState::Active
                && activation.expected_revision() == provider.revision()
        })
}

fn valid_provider_activation(
    metadata: &BuiltinSecretProviderMetadata,
    expected_revision: ManagementRevision,
    advanced: bool,
) -> bool {
    if metadata.state() != BuiltinSecretProviderState::Active || metadata.updated_at().get() < 0 {
        return false;
    }
    if advanced {
        expected_revision
            .value()
            .checked_add(1)
            .is_some_and(|revision| metadata.revision().value() == revision)
    } else {
        metadata.revision() == expected_revision
    }
}

/// Exact non-CSRF business form retained after independent browser mutation
/// verification. The value-bearing variants are move-only and redacted.
pub(crate) enum VerifiedRepositorySecretForm {
    Create {
        expected_authorization_revision: ManagementRevision,
        secret_id: RepositorySecretId,
        mutation_id: RepositorySecretMutationId,
        name: RepositorySecretName,
        value: SecretIngressValue,
    },
    Replace {
        expected_authorization_revision: ManagementRevision,
        secret_id: RepositorySecretId,
        mutation_id: RepositorySecretMutationId,
        name: RepositorySecretName,
        expected_revision: ManagementRevision,
        value: SecretIngressValue,
    },
    Delete {
        expected_authorization_revision: ManagementRevision,
        secret_id: RepositorySecretId,
        expected_revision: ManagementRevision,
    },
    ActivateProvider {
        expected_authorization_revision: ManagementRevision,
        expected_revision: ManagementRevision,
    },
}

impl VerifiedRepositorySecretForm {
    const fn expected_authorization_revision(&self) -> ManagementRevision {
        match self {
            Self::Create {
                expected_authorization_revision,
                ..
            }
            | Self::Replace {
                expected_authorization_revision,
                ..
            }
            | Self::Delete {
                expected_authorization_revision,
                ..
            }
            | Self::ActivateProvider {
                expected_authorization_revision,
                ..
            } => *expected_authorization_revision,
        }
    }
}

impl fmt::Debug for VerifiedRepositorySecretForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Create { .. } => "Create",
            Self::Replace { .. } => "Replace",
            Self::Delete { .. } => "Delete",
            Self::ActivateProvider { .. } => "ActivateProvider",
        };
        formatter
            .debug_struct("VerifiedRepositorySecretForm")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// Business-field result retained only after the browser CSRF envelope passes.
#[derive(Clone)]
pub(crate) struct RepositorySecretFormSubmission {
    form: Arc<Mutex<Option<Result<VerifiedRepositorySecretForm, RepositorySecretFormError>>>>,
}

impl RepositorySecretFormSubmission {
    fn valid(form: VerifiedRepositorySecretForm) -> Self {
        Self {
            form: Arc::new(Mutex::new(Some(Ok(form)))),
        }
    }

    fn invalid() -> Self {
        Self {
            form: Arc::new(Mutex::new(Some(Err(RepositorySecretFormError::Invalid)))),
        }
    }

    fn take(&self) -> Option<Result<VerifiedRepositorySecretForm, RepositorySecretFormError>> {
        self.form.lock().ok()?.take()
    }

    #[cfg(test)]
    pub(crate) fn take_for_test(
        &self,
    ) -> Option<Result<VerifiedRepositorySecretForm, RepositorySecretFormError>> {
        self.take()
    }
}

impl fmt::Debug for RepositorySecretFormSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositorySecretFormSubmission")
            .finish_non_exhaustive()
    }
}

/// Parsed form with separately owned CSRF proof. Debug never walks the form.
pub(crate) struct ParsedRepositorySecretForm {
    csrf_token: SecretString,
    submission: RepositorySecretFormSubmission,
}

impl ParsedRepositorySecretForm {
    pub(crate) fn into_parts(self) -> (SecretString, RepositorySecretFormSubmission) {
        (self.csrf_token, self.submission)
    }
}

impl fmt::Debug for ParsedRepositorySecretForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedRepositorySecretForm")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositorySecretFormError {
    Invalid,
    TooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositorySecretFormKind {
    Create,
    Replace(RepositorySecretId),
    Delete(RepositorySecretId),
    ActivateProvider,
}

pub(crate) fn is_repository_secret_form(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::POST && repository_secret_form_kind(path).is_ok()
}

/// Collects and parses one native form without ever materializing the raw body
/// or secret value in an ordinary `String` or shared `Bytes` owner.
pub(crate) async fn collect_repository_secret_form(
    path: &str,
    body: Body,
) -> Result<ParsedRepositorySecretForm, RepositorySecretFormError> {
    let kind = repository_secret_form_kind(path)?;
    let mut stream = body.into_data_stream();
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_REPOSITORY_SECRET_FORM_BYTES));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| RepositorySecretFormError::Invalid)?;
        let within_limit = bytes
            .len()
            .checked_add(chunk.len())
            .is_some_and(|length| length <= MAX_REPOSITORY_SECRET_FORM_BYTES);
        if within_limit {
            bytes.extend_from_slice(&chunk);
        }
        wipe_body_chunk(chunk);
        if !within_limit {
            return Err(RepositorySecretFormError::TooLarge);
        }
    }
    parse_repository_secret_form(kind, &bytes)
}

fn repository_secret_form_kind(
    path: &str,
) -> Result<RepositorySecretFormKind, RepositorySecretFormError> {
    let Some(path) = path.strip_prefix('/') else {
        return Err(RepositorySecretFormError::Invalid);
    };
    let segments = path.split('/').collect::<Vec<_>>();
    match segments.as_slice() {
        [owner, repository, "settings", "secrets"]
            if !owner.is_empty() && !repository.is_empty() =>
        {
            Ok(RepositorySecretFormKind::Create)
        }
        [
            owner,
            repository,
            "settings",
            "secrets",
            "provider",
            "activate",
        ] if !owner.is_empty() && !repository.is_empty() => {
            Ok(RepositorySecretFormKind::ActivateProvider)
        }
        [
            owner,
            repository,
            "settings",
            "secrets",
            secret_id,
            "replace",
        ] if !owner.is_empty() && !repository.is_empty() => parse_secret_id(secret_id)
            .map(RepositorySecretFormKind::Replace)
            .map_err(|_| RepositorySecretFormError::Invalid),
        [
            owner,
            repository,
            "settings",
            "secrets",
            secret_id,
            "delete",
        ] if !owner.is_empty() && !repository.is_empty() => parse_secret_id(secret_id)
            .map(RepositorySecretFormKind::Delete)
            .map_err(|_| RepositorySecretFormError::Invalid),
        _ => Err(RepositorySecretFormError::Invalid),
    }
}

#[derive(Default)]
struct FormFields {
    csrf_token: Option<SecretString>,
    expected_authorization_revision: Option<String>,
    expected_revision: Option<String>,
    secret_id: Option<String>,
    mutation_id: Option<String>,
    name: Option<String>,
    value: Option<SecretIngressValue>,
}

fn parse_repository_secret_form(
    kind: RepositorySecretFormKind,
    body: &[u8],
) -> Result<ParsedRepositorySecretForm, RepositorySecretFormError> {
    if body.is_empty() || body.len() > MAX_REPOSITORY_SECRET_FORM_BYTES {
        return Err(RepositorySecretFormError::Invalid);
    }
    let mut fields = FormFields::default();
    let mut field_count = 0_usize;
    for pair in body.split(|byte| *byte == b'&') {
        if pair.is_empty() {
            return Err(RepositorySecretFormError::Invalid);
        }
        field_count = field_count
            .checked_add(1)
            .ok_or(RepositorySecretFormError::Invalid)?;
        if field_count > 6 {
            return Err(RepositorySecretFormError::Invalid);
        }
        let separator = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(RepositorySecretFormError::Invalid)?;
        let name = decode_text_component(&pair[..separator], MAX_FORM_KEY_BYTES)?;
        let encoded = &pair[separator + 1..];
        match name.as_str() {
            "csrf_token" => set_once(
                &mut fields.csrf_token,
                SecretString::new(decode_text_component(encoded, MAX_CSRF_BYTES)?)
                    .map_err(|_| RepositorySecretFormError::Invalid)?,
            )?,
            "expected_authorization_revision" => set_once(
                &mut fields.expected_authorization_revision,
                decode_text_component(encoded, MAX_REVISION_BYTES)?,
            )?,
            "expected_revision" => set_once(
                &mut fields.expected_revision,
                decode_text_component(encoded, MAX_REVISION_BYTES)?,
            )?,
            "secret_id" => set_once(
                &mut fields.secret_id,
                decode_text_component(encoded, UUID_TEXT_BYTES)?,
            )?,
            "mutation_id" => set_once(
                &mut fields.mutation_id,
                decode_text_component(encoded, UUID_TEXT_BYTES)?,
            )?,
            "name" => set_once(
                &mut fields.name,
                decode_text_component(encoded, MAX_SECRET_NAME_BYTES)?,
            )?,
            "value" => set_once(&mut fields.value, decode_secret_component(encoded)?)?,
            _ => return Err(RepositorySecretFormError::Invalid),
        }
    }
    let csrf_token = fields
        .csrf_token
        .take()
        .ok_or(RepositorySecretFormError::Invalid)?;
    let submission = parse_business_form(kind, fields).map_or_else(
        |_| RepositorySecretFormSubmission::invalid(),
        RepositorySecretFormSubmission::valid,
    );
    Ok(ParsedRepositorySecretForm {
        csrf_token,
        submission,
    })
}

fn parse_business_form(
    kind: RepositorySecretFormKind,
    mut fields: FormFields,
) -> Result<VerifiedRepositorySecretForm, RepositorySecretFormError> {
    let expected_authorization_revision =
        parse_required_revision(fields.expected_authorization_revision.take())?;
    match kind {
        RepositorySecretFormKind::Create => {
            let secret_id = parse_secret_id(&required(fields.secret_id.take())?)?;
            let mutation_id = parse_mutation_id(&required(fields.mutation_id.take())?, secret_id)?;
            let name = RepositorySecretName::new(required(fields.name.take())?)
                .map_err(|_| RepositorySecretFormError::Invalid)?;
            let value = fields
                .value
                .take()
                .ok_or(RepositorySecretFormError::Invalid)?;
            require_no_extra(&fields)?;
            Ok(VerifiedRepositorySecretForm::Create {
                expected_authorization_revision,
                secret_id,
                mutation_id,
                name,
                value,
            })
        }
        RepositorySecretFormKind::Replace(secret_id) => {
            let mutation_id = parse_mutation_id(&required(fields.mutation_id.take())?, secret_id)?;
            let name = RepositorySecretName::new(required(fields.name.take())?)
                .map_err(|_| RepositorySecretFormError::Invalid)?;
            let expected_revision = parse_required_revision(fields.expected_revision.take())?;
            let value = fields
                .value
                .take()
                .ok_or(RepositorySecretFormError::Invalid)?;
            require_no_extra(&fields)?;
            Ok(VerifiedRepositorySecretForm::Replace {
                expected_authorization_revision,
                secret_id,
                mutation_id,
                name,
                expected_revision,
                value,
            })
        }
        RepositorySecretFormKind::Delete(secret_id) => {
            let expected_revision = parse_required_revision(fields.expected_revision.take())?;
            require_no_extra(&fields)?;
            Ok(VerifiedRepositorySecretForm::Delete {
                expected_authorization_revision,
                secret_id,
                expected_revision,
            })
        }
        RepositorySecretFormKind::ActivateProvider => {
            let expected_revision = parse_required_revision(fields.expected_revision.take())?;
            require_no_extra(&fields)?;
            Ok(VerifiedRepositorySecretForm::ActivateProvider {
                expected_authorization_revision,
                expected_revision,
            })
        }
    }
}

fn require_no_extra(fields: &FormFields) -> Result<(), RepositorySecretFormError> {
    if fields.expected_authorization_revision.is_some()
        || fields.expected_revision.is_some()
        || fields.secret_id.is_some()
        || fields.mutation_id.is_some()
        || fields.name.is_some()
        || fields.value.is_some()
    {
        return Err(RepositorySecretFormError::Invalid);
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), RepositorySecretFormError> {
    if slot.replace(value).is_some() {
        return Err(RepositorySecretFormError::Invalid);
    }
    Ok(())
}

fn required(value: Option<String>) -> Result<String, RepositorySecretFormError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(RepositorySecretFormError::Invalid)
}

fn parse_required_revision(
    value: Option<String>,
) -> Result<ManagementRevision, RepositorySecretFormError> {
    let value = required(value)?;
    parse_revision(&value)
}

fn parse_revision(value: &str) -> Result<ManagementRevision, RepositorySecretFormError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RepositorySecretFormError::Invalid);
    }
    let revision = value
        .parse::<u64>()
        .ok()
        .and_then(|revision| ManagementRevision::new(revision).ok())
        .filter(|revision| revision.value() <= i64::MAX.unsigned_abs())
        .ok_or(RepositorySecretFormError::Invalid)?;
    Ok(revision)
}

fn parse_secret_id(value: &str) -> Result<RepositorySecretId, RepositorySecretFormError> {
    let parsed = value
        .parse::<RunId>()
        .map_err(|_| RepositorySecretFormError::Invalid)?;
    if parsed.as_uuid().is_nil() || parsed.to_string() != value {
        return Err(RepositorySecretFormError::Invalid);
    }
    RepositorySecretId::from_uuid(parsed.as_uuid()).map_err(|_| RepositorySecretFormError::Invalid)
}

fn parse_mutation_id(
    value: &str,
    secret_id: RepositorySecretId,
) -> Result<RepositorySecretMutationId, RepositorySecretFormError> {
    let parsed = value
        .parse::<RunId>()
        .map_err(|_| RepositorySecretFormError::Invalid)?;
    if parsed.as_uuid().is_nil() || parsed.to_string() != value {
        return Err(RepositorySecretFormError::Invalid);
    }
    RepositorySecretMutationId::from_uuid(parsed.as_uuid(), secret_id)
        .map_err(|_| RepositorySecretFormError::Invalid)
}

fn decode_text_component(
    value: &[u8],
    maximum: usize,
) -> Result<String, RepositorySecretFormError> {
    let mut decoded = decode_component(value, maximum)?;
    String::from_utf8(mem::take(&mut *decoded)).map_err(|error| {
        let mut bytes = error.into_bytes();
        bytes.zeroize();
        RepositorySecretFormError::Invalid
    })
}

fn decode_secret_component(value: &[u8]) -> Result<SecretIngressValue, RepositorySecretFormError> {
    let mut decoded = decode_component(value, MAX_SECRET_INGRESS_BYTES)?;
    SecretIngressValue::new(mem::take(&mut *decoded))
        .map_err(|_| RepositorySecretFormError::Invalid)
}

fn decode_component(
    value: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, RepositorySecretFormError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len().min(maximum)));
    form::decode_into(value, &mut decoded, maximum)
        .map_err(|_| RepositorySecretFormError::Invalid)?;
    Ok(decoded)
}

fn wipe_body_chunk(chunk: Bytes) {
    if let Ok(mut chunk) = chunk.try_into_mut() {
        chunk.as_mut().zeroize();
    }
}

#[derive(Clone)]
struct RepositorySecretBrowserState {
    data: Arc<dyn RepositorySecretWebData>,
}

impl fmt::Debug for RepositorySecretBrowserState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepositorySecretBrowserState")
            .finish_non_exhaustive()
    }
}

/// Builds the browser-only native POST routes. The ordinary human middleware
/// owns cookie authentication, Origin/fetch checks, and hidden-CSRF verification
/// before these handlers can take the move-only form extension.
pub(crate) fn repository_secret_browser_router(data: Arc<dyn RepositorySecretWebData>) -> Router {
    Router::new()
        .route(
            REPOSITORY_SECRETS_SETTINGS_PATH,
            post(repository_secret_mutation),
        )
        .route(
            REPOSITORY_SECRET_REPLACE_PATH,
            post(repository_secret_mutation),
        )
        .route(
            REPOSITORY_SECRET_DELETE_PATH,
            post(repository_secret_mutation),
        )
        .route(
            REPOSITORY_SECRET_PROVIDER_ACTIVATE_PATH,
            post(repository_secret_mutation),
        )
        .with_state(RepositorySecretBrowserState { data })
}

async fn repository_secret_mutation(
    State(state): State<RepositorySecretBrowserState>,
    path: Result<Path<HashMap<String, String>>, PathRejection>,
    OriginalUri(original_uri): OriginalUri,
    mut request: Request,
) -> Response<Body> {
    if original_uri.query().is_some() {
        return secret_error(StatusCode::BAD_REQUEST, None);
    }
    let Ok(Path(path)) = path else {
        return secret_error(StatusCode::BAD_REQUEST, None);
    };
    let (Some(owner), Some(repository)) = (path.get("owner"), path.get("repository")) else {
        return secret_error(StatusCode::BAD_REQUEST, None);
    };
    if github_repository_name(owner, repository).is_err() {
        return secret_error(StatusCode::NOT_FOUND, None);
    }
    let href = repository_secrets_href(owner, repository);
    let Some(snapshot) = request
        .extensions()
        .get::<AuthenticatedRequestSnapshot>()
        .cloned()
    else {
        return secret_error(StatusCode::UNAUTHORIZED, Some(&href));
    };
    let Some(submission) = request
        .extensions_mut()
        .remove::<RepositorySecretFormSubmission>()
    else {
        return secret_error(StatusCode::FORBIDDEN, Some(&href));
    };
    let Some(Ok(form)) = submission.take() else {
        return secret_error(StatusCode::BAD_REQUEST, Some(&href));
    };
    match state.data.mutate(&snapshot, owner, repository, form).await {
        Ok(RepositorySecretBrowserMutationOutcome::Created) => redirect_notice(&href, "created"),
        Ok(RepositorySecretBrowserMutationOutcome::Replaced) => redirect_notice(&href, "replaced"),
        Ok(RepositorySecretBrowserMutationOutcome::Deleted) => redirect_notice(&href, "deleted"),
        Ok(RepositorySecretBrowserMutationOutcome::ProviderActivated) => {
            redirect_notice(&href, "provider-activated")
        }
        Ok(RepositorySecretBrowserMutationOutcome::Conflict) => redirect_notice(&href, "conflict"),
        Ok(RepositorySecretBrowserMutationOutcome::SessionStale) => {
            secret_error(StatusCode::UNAUTHORIZED, Some(&href))
        }
        Ok(RepositorySecretBrowserMutationOutcome::NotFound) => {
            secret_error(StatusCode::NOT_FOUND, Some(&href))
        }
        Ok(RepositorySecretBrowserMutationOutcome::Unavailable)
        | Err(RepositorySecretWebError::Unavailable) => {
            secret_error(StatusCode::SERVICE_UNAVAILABLE, Some(&href))
        }
        Err(RepositorySecretWebError::InvalidRequest) => {
            secret_error(StatusCode::BAD_REQUEST, Some(&href))
        }
        Err(RepositorySecretWebError::Corrupt) => {
            secret_error(StatusCode::INTERNAL_SERVER_ERROR, Some(&href))
        }
    }
}

fn repository_secrets_href(owner: &str, repository: &str) -> String {
    format!("/{owner}/{repository}/settings/secrets")
}

fn redirect_notice(href: &str, notice: &'static str) -> Response<Body> {
    let destination = format!("{href}?notice={notice}");
    let mut response = Redirect::to(&destination).into_response();
    apply_static_page_headers(response.headers_mut());
    response
}

fn secret_error(status: StatusCode, href: Option<&str>) -> Response<Body> {
    let (heading, description) = match status {
        StatusCode::BAD_REQUEST => (
            "Invalid secret request",
            "The secret change was not applied. Reload the page and try again.",
        ),
        StatusCode::UNAUTHORIZED => (
            "Sign in required",
            "Your session is no longer current. Sign in again before changing repository secrets.",
        ),
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => (
            "Page not found",
            "The requested repository secret is not available.",
        ),
        StatusCode::SERVICE_UNAVAILABLE => (
            "Secrets temporarily unavailable",
            "Repository secret management is temporarily unavailable. Try again in a moment.",
        ),
        _ => (
            "Unable to change repository secrets",
            "An unexpected error prevented the secret change from being applied.",
        ),
    };
    let mut response = error_page_response_with_action(
        status,
        heading,
        description,
        href.unwrap_or("/repositories"),
        if href.is_some() {
            "Review repository secrets"
        } else {
            "Back to workflow runs"
        },
    );
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, "1".parse().expect("fixed header"));
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    use super::*;

    const SECRET_ID: &str = "77777777-7777-4777-8777-777777777777";
    const MUTATION_ID: &str = "88888888-8888-4888-8888-888888888888";

    #[test]
    fn native_secret_route_classification_is_exact_and_id_bound() {
        for path in [
            "/acme/payments/settings/secrets",
            "/acme/payments/settings/secrets/provider/activate",
            "/acme/payments/settings/secrets/77777777-7777-4777-8777-777777777777/replace",
            "/acme/payments/settings/secrets/77777777-7777-4777-8777-777777777777/delete",
        ] {
            assert!(is_repository_secret_form(&Method::POST, path));
            assert!(!is_repository_secret_form(&Method::GET, path));
        }
        for path in [
            "/acme/payments/settings/secrets/",
            "/acme/payments/settings/secrets/not-a-uuid/replace",
            "/acme/payments/settings/secrets/77777777-7777-4777-8777-777777777777/value",
            "/acme/payments/settings/secrets/provider/activate/extra",
        ] {
            assert!(!is_repository_secret_form(&Method::POST, path));
        }
    }

    #[tokio::test]
    async fn create_form_keeps_plaintext_move_only_and_debug_redacted() {
        let body = format!(
            "csrf_token=csrf-proof&expected_authorization_revision=7&secret_id={SECRET_ID}&\
             mutation_id={MUTATION_ID}&name=DEPLOY_TOKEN&value=private%25value"
        );
        let parsed =
            collect_repository_secret_form("/acme/payments/settings/secrets", Body::from(body))
                .await
                .expect("valid bounded create form");
        assert!(!format!("{parsed:?}").contains("private"));
        let (csrf, submission) = parsed.into_parts();
        assert_eq!(csrf.expose_secret(), "csrf-proof");
        assert!(!format!("{submission:?}").contains("private"));

        let duplicate_owner = submission.clone();
        let form = submission
            .take()
            .expect("one-shot form")
            .expect("valid business form");
        assert!(duplicate_owner.take().is_none());
        assert!(!format!("{form:?}").contains("private"));
        let VerifiedRepositorySecretForm::Create {
            expected_authorization_revision,
            secret_id,
            mutation_id,
            name,
            value: _,
        } = form
        else {
            panic!("expected create form");
        };
        assert_eq!(expected_authorization_revision.value(), 7);
        assert_eq!(secret_id.as_uuid().hyphenated().to_string(), SECRET_ID);
        assert_eq!(mutation_id.as_uuid().hyphenated().to_string(), MUTATION_ID);
        assert_eq!(name.as_str(), "DEPLOY_TOKEN");
    }

    #[tokio::test]
    async fn form_parser_rejects_oversize_duplicate_unknown_and_invalid_business_fields() {
        let oversized = collect_repository_secret_form(
            "/acme/payments/settings/secrets",
            Body::from(vec![b'x'; MAX_REPOSITORY_SECRET_FORM_BYTES + 1]),
        )
        .await;
        assert!(matches!(
            oversized,
            Err(RepositorySecretFormError::TooLarge)
        ));

        for body in [
            "csrf_token=a&csrf_token=b",
            "csrf_token=a&unexpected=field",
            "csrf_token=a&expected_authorization_revision=7&secret_id=77777777-7777-4777-8777-777777777777&mutation_id=88888888-8888-4888-8888-888888888888&name=DEPLOY_TOKEN&value=x&extra=y",
        ] {
            assert!(matches!(
                collect_repository_secret_form(
                    "/acme/payments/settings/secrets",
                    Body::from(body),
                )
                .await,
                Err(RepositorySecretFormError::Invalid)
            ));
        }

        let reserved = format!(
            "csrf_token=a&expected_authorization_revision=7&secret_id={SECRET_ID}&\
             mutation_id={MUTATION_ID}&name=GITHUB_TOKEN&value=x"
        );
        let parsed =
            collect_repository_secret_form("/acme/payments/settings/secrets", Body::from(reserved))
                .await
                .expect("CSRF envelope remains independently parseable");
        let (_, submission) = parsed.into_parts();
        assert!(matches!(
            submission.take(),
            Some(Err(RepositorySecretFormError::Invalid))
        ));
    }

    #[test]
    fn exhausted_metadata_revision_emits_no_revision_advancing_capability() {
        let repository_id = RepositoryId::from_uuid(
            "11111111-1111-4111-8111-111111111111"
                .parse::<RunId>()
                .expect("repository UUID")
                .as_uuid(),
        );
        let secret_id = parse_secret_id(SECRET_ID).expect("secret ID");
        let metadata = RepositorySecretMetadata::from_durable_parts(
            secret_id,
            repository_id,
            RepositorySecretName::new("DEPLOY_TOKEN").expect("secret name"),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider ID"),
            RepositorySecretState::Active,
            Some(1),
            ManagementRevision::new(i64::MAX.unsigned_abs()).expect("maximum revision"),
            automata_ci_core::UnixMillis::new(1),
            automata_ci_core::UnixMillis::new(2),
        );
        let page = RepositorySecretMetadataPage::new(vec![metadata], None);

        let rows = project_secret_rows(&page, true, true).expect("value-free projection");

        assert_eq!(rows.len(), 1);
        assert!(rows[0].replace_mutation_id.is_none());
        assert!(!rows[0].deletable);
    }
}
