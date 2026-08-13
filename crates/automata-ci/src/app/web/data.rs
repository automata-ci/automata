use std::{fmt, fmt::Write as _, pin::Pin};

use async_trait::async_trait;
use automata_ci_auth::{
    authorization::{
        AuthorizationContext, AuthorizationScope, RepositoryPublicationPolicy, RepositoryResource,
        RunnerGroupResource,
    },
    human::TenantId,
    management::{
        ChangeMemberStatus, CreateRole, DeleteRole, DirectBindingGrantOptions,
        DirectBindingGrantOptionsState, GrantRole, HumanRbacManagementRepository,
        ListManagementRecords, ListManagementRoleBindings, ManagedPrincipalId, ManagementActor,
        ManagementDetailOutcome, ManagementMutationCapabilities, ManagementMutationOutcome,
        ManagementPageSize, ManagementReadOutcome, ManagementRepositoryError, ManagementRequestId,
        ManagementRevision, ManagementRoleBindingCursor, ManagementRoleBindingRecord, MemberRecord,
        ReadDirectBindingGrantOptions, ReadManagementMutationCapabilities, ReadMemberDetail,
        ReadRoleDetail, RevokeRole, RoleBindingId, RoleBindingStatus, RoleDetailRecord, RoleId,
        RoleKind, RoleRecord, SetRolePermission, UpdateRole,
    },
    request_auth::AuthenticatedRequestSnapshot,
    time::Clock,
};
use automata_ci_core::{JobId, RunId, UnixMillis, WorkflowId};
use bytes::Bytes;
use futures::Stream;
use thiserror::Error;

use crate::app::github_auth::GITHUB_WEB_BEGIN_PATH;
use crate::app::rbac_management::{
    RbacGrantScope, RbacMutationApplied, RbacWebMutationOutcome, VerifiedRbacManagementForm,
};
use crate::app::repository_secrets::{RepositorySecretsPageRequest, RepositorySecretsReadOutcome};

/// Maximum number of workflow runs returned by one page.
pub(crate) const RUN_PAGE_SIZE: usize = 25;
/// Fixed number of authorized repositories returned by one directory page.
pub(crate) const REPOSITORY_PAGE_SIZE: usize = 25;
/// Maximum number of jobs rendered in one run-navigation page.
pub(crate) const RUN_JOB_PAGE_SIZE: usize = 200;
/// Maximum number of rendered log lines returned by one page.
pub(crate) const LOG_PAGE_SIZE: usize = 200;
/// Maximum decoded text admitted to one rendered log page.
///
/// The bound leaves room below the renderer request ceiling for worst-case
/// JSON escaping, job navigation, timestamps, and the rest of the page model.
pub(crate) const LOG_PAGE_DECODED_BYTES: usize = 128 * 1024;
/// Maximum text admitted to one rendered log line.
pub(crate) const LOG_LINE_BYTES: usize = 64 * 1024;
/// Fixed member page size for the authenticated RBAC user list.
pub(crate) const RBAC_USER_PAGE_SIZE: u16 = 50;
/// Fixed role page size for the authenticated RBAC role list.
pub(crate) const RBAC_ROLE_PAGE_SIZE: u16 = 50;
/// Fixed assignment page size for the authenticated RBAC binding list.
pub(crate) const RBAC_BINDING_PAGE_SIZE: u16 = 50;
/// Maximum assignments representable atomically on one member-detail page.
pub(crate) const RBAC_USER_DETAIL_BINDING_LIMIT: u16 = 100;

/// Fresh durable setup-page state returned at the exact anonymous GET boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetupPageAvailabilityState {
    /// The operator-authorized installation challenge is currently `Armed`.
    Armed,
    /// Every other durable installation state; the page must remain absent.
    Absent,
}

/// Sanitized failure to read the current setup-page state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum SetupPageAvailabilityError {
    /// The durable state cannot currently be read.
    #[error("setup-page availability is temporarily unavailable")]
    Unavailable,
    /// The durable state cannot be interpreted safely.
    #[error("setup-page availability failed integrity validation")]
    Corrupt,
}

/// Supplies one fresh durable installation-state decision for every setup GET.
///
/// Production implementations must call `InstallationRepository::load()` (or
/// an equivalent linearizable current-state read) on every invocation and map
/// only the exact `InstallationState::Armed` variant to `Armed`.
#[async_trait]
pub(crate) trait SetupPageAvailability: fmt::Debug + Send + Sync {
    /// Reads the current setup-page state without retaining operator proof data.
    async fn current(&self) -> Result<SetupPageAvailabilityState, SetupPageAvailabilityError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestContext {
    tenant_id: TenantId,
    authorization: AuthorizationContext,
    viewer: Option<Viewer>,
    sign_in_action: Option<String>,
    access_management_available: bool,
}

impl RequestContext {
    pub(crate) const fn anonymous(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            authorization: AuthorizationContext::anonymous(),
            viewer: None,
            sign_in_action: None,
            access_management_available: false,
        }
    }

    pub(crate) fn new(
        tenant_id: TenantId,
        authorization: AuthorizationContext,
        viewer: Option<Viewer>,
        sign_in_action: Option<String>,
    ) -> Result<Self, RequestContextError> {
        if authorization
            .tenant_id()
            .is_some_and(|authorized| authorized != &tenant_id)
        {
            return Err(RequestContextError::TenantMismatch);
        }
        if sign_in_action
            .as_deref()
            .is_some_and(|action| action != GITHUB_WEB_BEGIN_PATH)
        {
            return Err(RequestContextError::InvalidSignInAction);
        }
        if viewer.is_some() && sign_in_action.is_some() {
            return Err(RequestContextError::AuthenticatedSignInAction);
        }
        Ok(Self {
            tenant_id,
            authorization,
            viewer,
            sign_in_action,
            access_management_available: false,
        })
    }

    /// Records that this router composed the authenticated Access surface.
    #[must_use]
    pub(crate) fn with_access_management_available(mut self, available: bool) -> Self {
        self.access_management_available = available && self.viewer.is_some();
        self
    }

    pub(crate) const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub(crate) const fn authorization(&self) -> &AuthorizationContext {
        &self.authorization
    }

    pub(crate) const fn viewer(&self) -> Option<&Viewer> {
        self.viewer.as_ref()
    }

    pub(crate) const fn sign_in_action(&self) -> Option<&String> {
        self.sign_in_action.as_ref()
    }

    pub(crate) const fn access_management_available(&self) -> bool {
        self.access_management_available
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RequestContextError {
    #[error("request tenant does not match authenticated tenant")]
    TenantMismatch,
    #[error("request sign-in action is not the canonical browser login action")]
    InvalidSignInAction,
    #[error("authenticated requests cannot expose a sign-in action")]
    AuthenticatedSignInAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Viewer {
    pub(crate) display_name: String,
}

/// One bounded, canonical request for the RBAC user list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacUserListRequest {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: ManagementPageSize,
}

impl RbacUserListRequest {
    pub(crate) fn new(cursor: Option<String>) -> Result<Self, RbacWebDataError> {
        if let Some(cursor) = cursor.as_deref() {
            ManagedPrincipalId::new(cursor).map_err(|_| RbacWebDataError::InvalidRequest)?;
        }
        let limit =
            ManagementPageSize::new(RBAC_USER_PAGE_SIZE).map_err(|_| RbacWebDataError::Corrupt)?;
        Ok(Self { cursor, limit })
    }
}

/// Authorized member metadata returned to the RBAC user-list renderer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacUserListPage {
    pub(crate) users: Vec<MemberRecord>,
    pub(crate) next_cursor: Option<String>,
}

/// One exact, bounded request for an RBAC member detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacUserDetailRequest {
    pub(crate) principal_id: ManagedPrincipalId,
    pub(crate) binding_limit: ManagementPageSize,
}

impl RbacUserDetailRequest {
    pub(crate) fn new(principal_id: &str) -> Result<Self, RbacWebDataError> {
        Ok(Self {
            principal_id: ManagedPrincipalId::new(principal_id)
                .map_err(|_| RbacWebDataError::InvalidRequest)?,
            binding_limit: ManagementPageSize::new(RBAC_USER_DETAIL_BINDING_LIMIT)
                .map_err(|_| RbacWebDataError::Corrupt)?,
        })
    }
}

/// Authorized member metadata and its complete representable assignment set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacUserDetailPage {
    pub(crate) user: MemberRecord,
    pub(crate) assignments: Vec<ManagementRoleBindingRecord>,
}

/// One bounded, canonical request for the RBAC role list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacRoleListRequest {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: ManagementPageSize,
}

impl RbacRoleListRequest {
    pub(crate) fn new(cursor: Option<String>) -> Result<Self, RbacWebDataError> {
        if let Some(cursor) = cursor.as_deref() {
            RoleId::new(cursor).map_err(|_| RbacWebDataError::InvalidRequest)?;
        }
        let limit =
            ManagementPageSize::new(RBAC_ROLE_PAGE_SIZE).map_err(|_| RbacWebDataError::Corrupt)?;
        Ok(Self { cursor, limit })
    }
}

/// Authorized role-list metadata and its exact mutation-authority fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacRoleListPage {
    pub(crate) roles: Vec<RoleRecord>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) mutation_authorization_revision: ManagementRevision,
}

/// One exact request for an RBAC role detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RbacRoleDetailRequest {
    pub(crate) role_id: RoleId,
}

impl RbacRoleDetailRequest {
    pub(crate) fn new(role_id: &str) -> Result<Self, RbacWebDataError> {
        Ok(Self {
            role_id: RoleId::new(role_id).map_err(|_| RbacWebDataError::InvalidRequest)?,
        })
    }
}

/// One bounded, canonical request for management-visible role assignments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacDirectBindingListRequest {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: ManagementPageSize,
}

impl RbacDirectBindingListRequest {
    pub(crate) fn new(cursor: Option<String>) -> Result<Self, RbacWebDataError> {
        if let Some(cursor) = cursor.as_deref() {
            ManagementRoleBindingCursor::new(cursor)
                .map_err(|_| RbacWebDataError::InvalidRequest)?;
        }
        let limit = ManagementPageSize::new(RBAC_BINDING_PAGE_SIZE)
            .map_err(|_| RbacWebDataError::Corrupt)?;
        Ok(Self { cursor, limit })
    }
}

/// Authorized joined assignment metadata and its exact mutation-authority fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RbacDirectBindingListPage {
    pub(crate) bindings: Vec<ManagementRoleBindingRecord>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) mutation_authorization_revision: ManagementRevision,
}

/// Closed authorization result for one RBAC web read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RbacWebReadOutcome<T> {
    Authorized(T),
    Forbidden,
    SessionStale,
    NotFound,
}

/// Sanitized RBAC web-read failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RbacWebDataError {
    #[error("the RBAC web request is invalid")]
    InvalidRequest,
    #[error("RBAC management data is temporarily unavailable")]
    Unavailable,
    #[error("RBAC management data failed integrity validation")]
    Corrupt,
    #[error("RBAC management data cannot fit the released page contract")]
    Unrepresentable,
}

/// Authenticated, authorization-aware read boundary for RBAC web pages.
#[async_trait]
pub(crate) trait RbacWebData: fmt::Debug + Send + Sync {
    async fn mutation_capabilities(
        &self,
        _snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<RbacWebReadOutcome<ManagementMutationCapabilities>, RbacWebDataError> {
        Err(RbacWebDataError::Unavailable)
    }

    async fn direct_binding_grant_options(
        &self,
        _snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<RbacWebReadOutcome<DirectBindingGrantOptionsState>, RbacWebDataError> {
        Err(RbacWebDataError::Unavailable)
    }

    async fn mutate(
        &self,
        _snapshot: &AuthenticatedRequestSnapshot,
        _form: VerifiedRbacManagementForm,
    ) -> Result<RbacWebMutationOutcome, RbacWebDataError> {
        Err(RbacWebDataError::Unavailable)
    }

    async fn list_users(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacUserListRequest,
    ) -> Result<RbacWebReadOutcome<RbacUserListPage>, RbacWebDataError>;

    async fn user_detail(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacUserDetailRequest,
    ) -> Result<RbacWebReadOutcome<RbacUserDetailPage>, RbacWebDataError>;

    async fn list_roles(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacRoleListRequest,
    ) -> Result<RbacWebReadOutcome<RbacRoleListPage>, RbacWebDataError>;

    async fn role_detail(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacRoleDetailRequest,
    ) -> Result<RbacWebReadOutcome<RoleDetailRecord>, RbacWebDataError>;

    async fn list_direct_bindings(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacDirectBindingListRequest,
    ) -> Result<RbacWebReadOutcome<RbacDirectBindingListPage>, RbacWebDataError>;
}

/// Adapter from the durable management port to presentation-safe web reads.
#[derive(Clone)]
pub(crate) struct ManagementRbacWebData {
    repository: std::sync::Arc<dyn HumanRbacManagementRepository>,
    clock: std::sync::Arc<dyn Clock>,
}

impl ManagementRbacWebData {
    pub(crate) const fn new(
        repository: std::sync::Arc<dyn HumanRbacManagementRepository>,
        clock: std::sync::Arc<dyn Clock>,
    ) -> Self {
        Self { repository, clock }
    }

    fn actor(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<ManagementActor, RbacWebDataError> {
        self.actor_with_request_id(snapshot, None)
    }

    fn actor_with_request_id(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request_id: Option<ManagementRequestId>,
    ) -> Result<ManagementActor, RbacWebDataError> {
        let identity = snapshot.session().identity();
        let authorization_revision =
            ManagementRevision::new(snapshot.session().authorization_revision())
                .map_err(|_| RbacWebDataError::Corrupt)?;
        Ok(ManagementActor::new(
            identity.tenant_id().clone(),
            identity.principal_id().clone(),
            identity.session_id().clone(),
            authorization_revision,
            request_id,
            self.clock.now(),
        ))
    }
}

impl fmt::Debug for ManagementRbacWebData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementRbacWebData")
            .finish_non_exhaustive()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the mutation adapter keeps every closed domain outcome in one auditable boundary"
)]
#[async_trait]
impl RbacWebData for ManagementRbacWebData {
    async fn mutation_capabilities(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<RbacWebReadOutcome<ManagementMutationCapabilities>, RbacWebDataError> {
        let request = ReadManagementMutationCapabilities::new(self.actor(snapshot)?);
        match self.repository.read_mutation_capabilities(&request).await {
            Ok(ManagementReadOutcome::Authorized(capabilities)) => {
                Ok(RbacWebReadOutcome::Authorized(capabilities))
            }
            Ok(ManagementReadOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementReadOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Err(error) => Err(repository_error(error)),
        }
    }

    async fn direct_binding_grant_options(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
    ) -> Result<RbacWebReadOutcome<DirectBindingGrantOptionsState>, RbacWebDataError> {
        let request = ReadDirectBindingGrantOptions::new(self.actor(snapshot)?);
        match self
            .repository
            .read_direct_binding_grant_options(&request)
            .await
        {
            Ok(ManagementReadOutcome::Authorized(options)) => {
                Ok(RbacWebReadOutcome::Authorized(options))
            }
            Ok(ManagementReadOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementReadOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Err(error) => Err(repository_error(error)),
        }
    }

    async fn mutate(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        form: VerifiedRbacManagementForm,
    ) -> Result<RbacWebMutationOutcome, RbacWebDataError> {
        let snapshot_revision =
            ManagementRevision::new(snapshot.session().authorization_revision())
                .map_err(|_| RbacWebDataError::Corrupt)?;
        if snapshot_revision != form.expected_authorization_revision() {
            return Ok(RbacWebMutationOutcome::Conflict);
        }
        if mutation_target_revision_is_exhausted(&form) {
            return Ok(RbacWebMutationOutcome::Conflict);
        }
        let request_id = ManagementRequestId::new(format!("rbac-{}", random_uuid_text()?))
            .map_err(|_| RbacWebDataError::Corrupt)?;
        let actor = self.actor_with_request_id(snapshot, Some(request_id))?;
        match form {
            VerifiedRbacManagementForm::ChangeMemberStatus {
                principal_id,
                expected_revision,
                status,
                reason,
                ..
            } => {
                let request =
                    ChangeMemberStatus::new(actor, principal_id, expected_revision, status, reason)
                        .map_err(|_| RbacWebDataError::InvalidRequest)?;
                finish_mutation(
                    self.repository.change_member_status(request).await,
                    |record| {
                        if record.principal_id() != principal_id
                            || record.status() != status
                            || record.revision() != next_revision(expected_revision)?
                        {
                            return Err(RbacWebDataError::Corrupt);
                        }
                        Ok(RbacMutationApplied::MemberStatus { principal_id })
                    },
                )
            }
            VerifiedRbacManagementForm::CreateRole {
                name, display_name, ..
            } => {
                let role_id =
                    RoleId::new(random_uuid_text()?).map_err(|_| RbacWebDataError::Corrupt)?;
                let request = CreateRole::new(actor, role_id, name.clone(), display_name.clone())
                    .map_err(|_| RbacWebDataError::InvalidRequest)?;
                finish_mutation(self.repository.create_role(request).await, |role| {
                    if role.id() != role_id
                        || role.name() != &name
                        || role.display_name() != display_name
                        || role.kind() != RoleKind::Custom
                        || role.immutable()
                        || role.revision().value() != 1
                        || !role.permissions().is_empty()
                    {
                        return Err(RbacWebDataError::Corrupt);
                    }
                    Ok(RbacMutationApplied::RoleCreated { role_id })
                })
            }
            VerifiedRbacManagementForm::UpdateRole {
                role_id,
                expected_revision,
                display_name,
                ..
            } => {
                let request =
                    UpdateRole::new(actor, role_id, expected_revision, display_name.clone())
                        .map_err(|_| RbacWebDataError::InvalidRequest)?;
                finish_mutation(self.repository.update_role(request).await, |role| {
                    if role.id() != role_id
                        || role.display_name() != display_name
                        || role.kind() != RoleKind::Custom
                        || role.immutable()
                        || role.revision() != next_revision(expected_revision)?
                    {
                        return Err(RbacWebDataError::Corrupt);
                    }
                    Ok(RbacMutationApplied::RoleUpdated { role_id })
                })
            }
            VerifiedRbacManagementForm::DeleteRole {
                role_id,
                expected_revision,
                ..
            } => {
                let request = DeleteRole::new(actor, role_id, expected_revision);
                finish_mutation(self.repository.delete_role(request).await, |()| {
                    Ok(RbacMutationApplied::RoleDeleted)
                })
            }
            VerifiedRbacManagementForm::SetRolePermission {
                role_id,
                permission,
                expected_revision,
                present,
                ..
            } => {
                let request = SetRolePermission::new(
                    actor,
                    role_id,
                    expected_revision,
                    permission.clone(),
                    present,
                );
                finish_mutation(self.repository.set_role_permission(request).await, |role| {
                    if role.id() != role_id
                        || role.kind() != RoleKind::Custom
                        || role.immutable()
                        || role.revision() != next_revision(expected_revision)?
                        || role.permissions().contains(&permission) != present
                    {
                        return Err(RbacWebDataError::Corrupt);
                    }
                    Ok(RbacMutationApplied::RolePermission { role_id })
                })
            }
            VerifiedRbacManagementForm::GrantRole {
                principal_id,
                role_id,
                scope,
                valid_until,
                ..
            } => {
                let option_request = ReadDirectBindingGrantOptions::new(actor.clone());
                let options = match self
                    .repository
                    .read_direct_binding_grant_options(&option_request)
                    .await
                {
                    Ok(ManagementReadOutcome::Authorized(
                        DirectBindingGrantOptionsState::Available(options),
                    )) => options,
                    Ok(ManagementReadOutcome::Authorized(
                        DirectBindingGrantOptionsState::Overflow { .. },
                    )) => return Ok(RbacWebMutationOutcome::Conflict),
                    Ok(ManagementReadOutcome::Forbidden) => {
                        return Ok(RbacWebMutationOutcome::Forbidden);
                    }
                    Ok(ManagementReadOutcome::SessionStale) => {
                        return Ok(RbacWebMutationOutcome::SessionStale);
                    }
                    Err(error) => return Err(repository_error(error)),
                };
                if options.authorization_revision() != snapshot_revision
                    || !options
                        .principals()
                        .iter()
                        .any(|option| option.principal_id() == principal_id)
                    || !options
                        .roles()
                        .iter()
                        .any(|option| option.role_id() == role_id)
                    || !grant_scope_is_available(&options, scope)
                {
                    return Ok(RbacWebMutationOutcome::Conflict);
                }
                let authorization_scope = match scope {
                    RbacGrantScope::Tenant => AuthorizationScope::tenant(actor.tenant_id().clone()),
                    RbacGrantScope::Repository(repository_id) => AuthorizationScope::repository(
                        RepositoryResource::new(actor.tenant_id().clone(), repository_id),
                    ),
                    RbacGrantScope::RunnerGroup(runner_group_id) => {
                        AuthorizationScope::runner_group(RunnerGroupResource::new(
                            actor.tenant_id().clone(),
                            runner_group_id,
                        ))
                    }
                };
                let binding_id = RoleBindingId::new(random_uuid_text()?)
                    .map_err(|_| RbacWebDataError::Corrupt)?;
                let Ok(request) = GrantRole::new(
                    actor,
                    binding_id,
                    principal_id,
                    role_id,
                    authorization_scope.clone(),
                    valid_until,
                ) else {
                    return Ok(RbacWebMutationOutcome::Conflict);
                };
                finish_mutation(self.repository.grant_role(request).await, |binding| {
                    if binding.id() != binding_id
                        || binding.principal_id() != principal_id
                        || binding.role_id() != role_id
                        || binding.scope() != &authorization_scope
                        || binding.status() != RoleBindingStatus::Active
                        || binding.valid_until() != valid_until
                        || binding.revision().value() != 1
                    {
                        return Err(RbacWebDataError::Corrupt);
                    }
                    Ok(RbacMutationApplied::BindingGranted { binding_id })
                })
            }
            VerifiedRbacManagementForm::RevokeRole {
                binding_id,
                expected_revision,
                reason,
                ..
            } => {
                let request = RevokeRole::new(actor, binding_id, expected_revision, reason)
                    .map_err(|_| RbacWebDataError::InvalidRequest)?;
                finish_mutation(self.repository.revoke_role(request).await, |binding| {
                    if binding.id() != binding_id
                        || binding.status() != RoleBindingStatus::Revoked
                        || binding.revision() != next_revision(expected_revision)?
                    {
                        return Err(RbacWebDataError::Corrupt);
                    }
                    Ok(RbacMutationApplied::BindingRevoked)
                })
            }
        }
    }

    async fn list_users(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacUserListRequest,
    ) -> Result<RbacWebReadOutcome<RbacUserListPage>, RbacWebDataError> {
        let actor = self.actor(snapshot)?;
        let authorization_revision = actor.authorization_revision();
        let list = ListManagementRecords::new(actor, request.cursor.clone(), request.limit)
            .map_err(|_| RbacWebDataError::InvalidRequest)?;
        match self.repository.list_members(&list).await {
            Ok(ManagementReadOutcome::Authorized(page)) => {
                if page
                    .next_cursor()
                    .is_some_and(|cursor| ManagedPrincipalId::new(cursor).is_err())
                    || page.mutation_authorization_revision() != Some(authorization_revision)
                {
                    return Err(RbacWebDataError::Corrupt);
                }
                Ok(RbacWebReadOutcome::Authorized(RbacUserListPage {
                    users: page.items().to_vec(),
                    next_cursor: page.next_cursor().map(str::to_owned),
                }))
            }
            Ok(ManagementReadOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementReadOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Err(
                ManagementRepositoryError::InvalidRequest | ManagementRepositoryError::CorruptData,
            ) => Err(RbacWebDataError::Corrupt),
            Err(ManagementRepositoryError::Unavailable) => Err(RbacWebDataError::Unavailable),
        }
    }

    async fn user_detail(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacUserDetailRequest,
    ) -> Result<RbacWebReadOutcome<RbacUserDetailPage>, RbacWebDataError> {
        let actor = self.actor(snapshot)?;
        let authorization_revision = actor.authorization_revision();
        let detail = ReadMemberDetail::new(actor.clone(), request.principal_id);
        let user = match self.repository.read_member_detail(&detail).await {
            Ok(ManagementDetailOutcome::Authorized(user)) => user,
            Ok(ManagementDetailOutcome::Forbidden) => return Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementDetailOutcome::SessionStale) => {
                return Ok(RbacWebReadOutcome::SessionStale);
            }
            Ok(ManagementDetailOutcome::NotFound) => return Ok(RbacWebReadOutcome::NotFound),
            Err(error) => return Err(repository_error(error)),
        };
        let list = ListManagementRoleBindings::new(
            actor,
            None,
            request.binding_limit,
            Some(request.principal_id),
        )
        .map_err(|_| RbacWebDataError::Corrupt)?;
        match self.repository.list_management_role_bindings(&list).await {
            Ok(ManagementReadOutcome::Authorized(page)) => {
                if page.mutation_authorization_revision() != Some(authorization_revision)
                    || page
                        .items()
                        .iter()
                        .any(|binding| binding.principal() != &user)
                {
                    return Err(RbacWebDataError::Corrupt);
                }
                if page.next_cursor().is_some() {
                    return Err(RbacWebDataError::Unrepresentable);
                }
                Ok(RbacWebReadOutcome::Authorized(RbacUserDetailPage {
                    user,
                    assignments: page.items().to_vec(),
                }))
            }
            Ok(ManagementReadOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementReadOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Err(error) => Err(repository_error(error)),
        }
    }

    async fn list_roles(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacRoleListRequest,
    ) -> Result<RbacWebReadOutcome<RbacRoleListPage>, RbacWebDataError> {
        let actor = self.actor(snapshot)?;
        let authorization_revision = actor.authorization_revision();
        let list = ListManagementRecords::new(actor, request.cursor.clone(), request.limit)
            .map_err(|_| RbacWebDataError::InvalidRequest)?;
        match self.repository.list_roles(&list).await {
            Ok(ManagementReadOutcome::Authorized(page)) => {
                if page
                    .next_cursor()
                    .is_some_and(|cursor| RoleId::new(cursor).is_err())
                    || page.mutation_authorization_revision() != Some(authorization_revision)
                {
                    return Err(RbacWebDataError::Corrupt);
                }
                Ok(RbacWebReadOutcome::Authorized(RbacRoleListPage {
                    roles: page.items().to_vec(),
                    next_cursor: page.next_cursor().map(str::to_owned),
                    mutation_authorization_revision: authorization_revision,
                }))
            }
            Ok(ManagementReadOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementReadOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Err(error) => Err(repository_error(error)),
        }
    }

    async fn role_detail(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacRoleDetailRequest,
    ) -> Result<RbacWebReadOutcome<RoleDetailRecord>, RbacWebDataError> {
        let detail = ReadRoleDetail::new(self.actor(snapshot)?, request.role_id);
        match self.repository.read_role_detail(&detail).await {
            Ok(ManagementDetailOutcome::Authorized(detail)) => {
                Ok(RbacWebReadOutcome::Authorized(detail))
            }
            Ok(ManagementDetailOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementDetailOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Ok(ManagementDetailOutcome::NotFound) => Ok(RbacWebReadOutcome::NotFound),
            Err(error) => Err(repository_error(error)),
        }
    }

    async fn list_direct_bindings(
        &self,
        snapshot: &AuthenticatedRequestSnapshot,
        request: &RbacDirectBindingListRequest,
    ) -> Result<RbacWebReadOutcome<RbacDirectBindingListPage>, RbacWebDataError> {
        let actor = self.actor(snapshot)?;
        let authorization_revision = actor.authorization_revision();
        let list =
            ListManagementRoleBindings::new(actor, request.cursor.as_deref(), request.limit, None)
                .map_err(|_| RbacWebDataError::InvalidRequest)?;
        match self.repository.list_management_role_bindings(&list).await {
            Ok(ManagementReadOutcome::Authorized(page)) => {
                if page
                    .next_cursor()
                    .is_some_and(|cursor| ManagementRoleBindingCursor::new(cursor).is_err())
                    || page.mutation_authorization_revision() != Some(authorization_revision)
                {
                    return Err(RbacWebDataError::Corrupt);
                }
                Ok(RbacWebReadOutcome::Authorized(RbacDirectBindingListPage {
                    bindings: page.items().to_vec(),
                    next_cursor: page.next_cursor().map(str::to_owned),
                    mutation_authorization_revision: authorization_revision,
                }))
            }
            Ok(ManagementReadOutcome::Forbidden) => Ok(RbacWebReadOutcome::Forbidden),
            Ok(ManagementReadOutcome::SessionStale) => Ok(RbacWebReadOutcome::SessionStale),
            Err(error) => Err(repository_error(error)),
        }
    }
}

fn finish_mutation<T>(
    result: Result<ManagementMutationOutcome<T>, ManagementRepositoryError>,
    validate: impl FnOnce(T) -> Result<RbacMutationApplied, RbacWebDataError>,
) -> Result<RbacWebMutationOutcome, RbacWebDataError> {
    match result {
        Ok(ManagementMutationOutcome::Applied(value)) => {
            validate(value).map(RbacWebMutationOutcome::Applied)
        }
        Ok(ManagementMutationOutcome::Forbidden) => Ok(RbacWebMutationOutcome::Forbidden),
        Ok(ManagementMutationOutcome::SessionStale) => Ok(RbacWebMutationOutcome::SessionStale),
        Ok(ManagementMutationOutcome::NotFound) => Ok(RbacWebMutationOutcome::NotFound),
        Ok(
            ManagementMutationOutcome::AlreadyExists
            | ManagementMutationOutcome::RevisionConflict { .. }
            | ManagementMutationOutcome::Immutable
            | ManagementMutationOutcome::ResourceInUse
            | ManagementMutationOutcome::SelfModificationForbidden
            | ManagementMutationOutcome::LastManager,
        ) => Ok(RbacWebMutationOutcome::Conflict),
        Err(error) => Err(repository_error(error)),
    }
}

fn next_revision(revision: ManagementRevision) -> Result<ManagementRevision, RbacWebDataError> {
    revision
        .value()
        .checked_add(1)
        .and_then(|value| ManagementRevision::new(value).ok())
        .ok_or(RbacWebDataError::Corrupt)
}

fn mutation_target_revision_is_exhausted(form: &VerifiedRbacManagementForm) -> bool {
    let expected_revision = match form {
        VerifiedRbacManagementForm::ChangeMemberStatus {
            expected_revision, ..
        }
        | VerifiedRbacManagementForm::UpdateRole {
            expected_revision, ..
        }
        | VerifiedRbacManagementForm::SetRolePermission {
            expected_revision, ..
        }
        | VerifiedRbacManagementForm::RevokeRole {
            expected_revision, ..
        } => Some(*expected_revision),
        VerifiedRbacManagementForm::CreateRole { .. }
        | VerifiedRbacManagementForm::DeleteRole { .. }
        | VerifiedRbacManagementForm::GrantRole { .. } => None,
    };
    expected_revision.is_some_and(|revision| revision.value() == i64::MAX as u64)
}

fn grant_scope_is_available(options: &DirectBindingGrantOptions, scope: RbacGrantScope) -> bool {
    match scope {
        RbacGrantScope::Tenant => true,
        RbacGrantScope::Repository(repository_id) => options
            .repositories()
            .iter()
            .any(|option| option.repository_id() == repository_id),
        RbacGrantScope::RunnerGroup(runner_group_id) => options
            .runner_groups()
            .iter()
            .any(|option| option.runner_group_id() == runner_group_id),
    }
}

fn random_uuid_text() -> Result<String, RbacWebDataError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RbacWebDataError::Corrupt)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        write!(&mut value, "{byte:02x}").map_err(|_| RbacWebDataError::Corrupt)?;
    }
    Ok(value)
}

const fn repository_error(error: ManagementRepositoryError) -> RbacWebDataError {
    match error {
        ManagementRepositoryError::InvalidRequest | ManagementRepositoryError::CorruptData => {
            RbacWebDataError::Corrupt
        }
        ManagementRepositoryError::Unavailable => RbacWebDataError::Unavailable,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryPath {
    pub(crate) owner: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Repository {
    pub(crate) id: String,
    pub(crate) scm_provider: String,
    pub(crate) owner: String,
    pub(crate) name: String,
    pub(crate) settings_visible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryDirectoryRequest {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryDirectoryItem {
    pub(crate) repository: Repository,
    pub(crate) actions_visible: bool,
    pub(crate) settings_destination: Option<RepositorySettingsDestination>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositorySettingsDestination {
    Access,
    Secrets,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryDirectoryPage {
    pub(crate) repositories: Vec<RepositoryDirectoryItem>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Workflow {
    pub(crate) id: WorkflowId,
    pub(crate) name: String,
    pub(crate) path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkflowDefinition {
    pub(crate) id: WorkflowId,
    pub(crate) name: String,
    pub(crate) enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Status {
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Skipped,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StatusFilter {
    All,
    Queued,
    InProgress,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunListRequest {
    pub(crate) workflow_id: Option<WorkflowId>,
    pub(crate) workflow_cursor: Option<String>,
    pub(crate) status: StatusFilter,
    pub(crate) git_ref: Option<String>,
    pub(crate) cursor: Option<String>,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunListPage {
    pub(crate) repository: Repository,
    pub(crate) workflows: Vec<WorkflowDefinition>,
    pub(crate) selected_workflow: Option<WorkflowDefinition>,
    pub(crate) workflow_previous_cursor: Option<String>,
    pub(crate) workflow_next_cursor: Option<String>,
    pub(crate) runs: Vec<RunSummary>,
    pub(crate) previous_cursor: Option<String>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunDetailRequest {
    pub(crate) job_cursor: Option<String>,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositorySettingsPage {
    pub(crate) repository: Repository,
    pub(crate) policy: RepositoryPublicationPolicy,
    pub(crate) revision: u64,
    pub(crate) editable: bool,
    pub(crate) secrets_visible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunSummary {
    pub(crate) id: RunId,
    pub(crate) number: u64,
    pub(crate) attempt: u32,
    pub(crate) title: Option<String>,
    pub(crate) workflow: Workflow,
    pub(crate) status: Status,
    pub(crate) git_ref: Option<String>,
    pub(crate) event: String,
    pub(crate) actor: Option<String>,
    pub(crate) head_sha: String,
    pub(crate) commit_subject: Option<String>,
    pub(crate) created_at: UnixMillis,
    pub(crate) finished_at: Option<UnixMillis>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunDetailPage {
    pub(crate) repository: Repository,
    pub(crate) run: RunSummary,
    pub(crate) jobs: VisibleCollection<JobSummary>,
    pub(crate) job_previous_cursor: Option<String>,
    pub(crate) job_next_cursor: Option<String>,
    pub(crate) artifacts: VisibleCollection<ArtifactSummary>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectionVisibility {
    Full,
    Restricted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VisibleCollection<T> {
    pub(crate) visibility: CollectionVisibility,
    pub(crate) items: Vec<T>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JobSummary {
    pub(crate) id: JobId,
    pub(crate) name: String,
    pub(crate) attempt: Option<u32>,
    pub(crate) runner_label: Option<String>,
    pub(crate) status: Status,
    pub(crate) started_at: Option<UnixMillis>,
    pub(crate) finished_at: Option<UnixMillis>,
    pub(crate) logs_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactSummary {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) digest: String,
    pub(crate) expires_at_seconds: Option<i64>,
    pub(crate) downloadable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JobLogRequest {
    pub(crate) cursor: Option<String>,
    pub(crate) limit: usize,
    pub(crate) maximum_decoded_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JobLogPage {
    pub(crate) repository: Repository,
    pub(crate) run: RunSummary,
    pub(crate) jobs: Vec<JobNavigationItem>,
    pub(crate) previous_navigation_job_id: Option<JobId>,
    pub(crate) next_navigation_job_id: Option<JobId>,
    pub(crate) job: JobSummary,
    pub(crate) lines: Vec<LogLine>,
    pub(crate) previous_cursor: Option<String>,
    pub(crate) next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JobNavigationItem {
    pub(crate) id: JobId,
    pub(crate) name: String,
    pub(crate) status: Status,
    pub(crate) logs_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogChannel {
    Stdout,
    Stderr,
    System,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LogLine {
    pub(crate) sequence: u64,
    /// One-based fragment when a durable frame exceeds the UI line limit.
    pub(crate) fragment: Option<u32>,
    pub(crate) emitted_at: UnixMillis,
    pub(crate) channel: LogChannel,
    pub(crate) text: String,
}

pub(crate) type ArtifactBody =
    Pin<Box<dyn Stream<Item = Result<Bytes, WebDataError>> + Send + 'static>>;

pub(crate) struct ArtifactDownload {
    pub(crate) file_name: String,
    pub(crate) media_type: String,
    pub(crate) size: u64,
    pub(crate) digest: String,
    pub(crate) body: ArtifactBody,
}

impl fmt::Debug for ArtifactDownload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactDownload")
            .field("file_name", &self.file_name)
            .field("media_type", &self.media_type)
            .field("size", &self.size)
            .field("digest", &self.digest)
            .field("body", &"<stream>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum WebDataError {
    #[error("workflow data request is invalid")]
    InvalidRequest,
    #[error("workflow data is temporarily unavailable")]
    Unavailable,
    #[error("workflow data failed integrity validation")]
    Corrupt,
}

/// Tenant-scoped, authorization-enforcing read boundary for human workflow pages.
///
/// Implementations must make missing and unauthorized repositories, settings,
/// runs, jobs, and artifacts indistinguishable by returning `Ok(None)`. Every
/// lookup must bind the trusted tenant and repository resource before resolving
/// child IDs.
#[async_trait]
pub(crate) trait WebData: fmt::Debug + Send + Sync {
    async fn repository_page(
        &self,
        context: &RequestContext,
        request: &RepositoryDirectoryRequest,
    ) -> Result<RepositoryDirectoryPage, WebDataError>;

    async fn list_runs(
        &self,
        context: &RequestContext,
        repository: &RepositoryPath,
        request: &RunListRequest,
    ) -> Result<Option<RunListPage>, WebDataError>;

    async fn run_detail(
        &self,
        context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        request: &RunDetailRequest,
    ) -> Result<Option<RunDetailPage>, WebDataError>;

    async fn repository_settings(
        &self,
        context: &RequestContext,
        repository: &RepositoryPath,
    ) -> Result<Option<RepositorySettingsPage>, WebDataError>;

    async fn repository_secrets(
        &self,
        _snapshot: &AuthenticatedRequestSnapshot,
        _repository: &RepositoryPath,
        _request: RepositorySecretsPageRequest,
    ) -> Result<RepositorySecretsReadOutcome, WebDataError> {
        Ok(RepositorySecretsReadOutcome::NotFound)
    }

    async fn job_log(
        &self,
        context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        job_id: JobId,
        request: &JobLogRequest,
    ) -> Result<Option<JobLogPage>, WebDataError>;

    async fn artifact(
        &self,
        context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        artifact_id: i64,
    ) -> Result<Option<ArtifactDownload>, WebDataError>;
}

#[derive(Debug, Default)]
pub(crate) struct EmptyWebData;

#[async_trait]
impl WebData for EmptyWebData {
    async fn repository_page(
        &self,
        _context: &RequestContext,
        _request: &RepositoryDirectoryRequest,
    ) -> Result<RepositoryDirectoryPage, WebDataError> {
        Ok(RepositoryDirectoryPage {
            repositories: Vec::new(),
            next_cursor: None,
        })
    }

    async fn list_runs(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
        _request: &RunListRequest,
    ) -> Result<Option<RunListPage>, WebDataError> {
        Ok(None)
    }

    async fn run_detail(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
        _run_id: RunId,
        _request: &RunDetailRequest,
    ) -> Result<Option<RunDetailPage>, WebDataError> {
        Ok(None)
    }

    async fn repository_settings(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
    ) -> Result<Option<RepositorySettingsPage>, WebDataError> {
        Ok(None)
    }

    async fn job_log(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
        _run_id: RunId,
        _job_id: JobId,
        _request: &JobLogRequest,
    ) -> Result<Option<JobLogPage>, WebDataError> {
        Ok(None)
    }

    async fn artifact(
        &self,
        _context: &RequestContext,
        _repository: &RepositoryPath,
        _run_id: RunId,
        _artifact_id: i64,
    ) -> Result<Option<ArtifactDownload>, WebDataError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use automata_ci_auth::{
        authorization::{Permission, RepositoryResourceId, RoleName},
        human::{AuthenticatedHuman, PrincipalId, ProviderId, ProviderSubject},
        management::{
            DirectBindingGrantOptionCollection, DirectBindingPrincipalOption,
            DirectBindingRepositoryOption, DirectBindingRoleOption, ManagementActor,
            ManagementDetailFuture, ManagementMutationFuture, ManagementPage, ManagementReadFuture,
            RoleBindingRecord,
        },
        request_auth::ViewerDisplayMetadata,
        session::{DurableSession, DurableSessionIdentity, SessionId, SessionKind},
        time::UnixTimestamp,
    };

    use super::*;

    const ACTOR_PRINCIPAL_ID: &str = "11111111-1111-4111-8111-111111111111";
    const TARGET_PRINCIPAL_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const ROLE_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const OTHER_ROLE_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const REPOSITORY_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const OTHER_REPOSITORY_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    const SESSION_AUTHORIZATION_REVISION: u64 = 4;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ActorProbe {
        authorization_revision: ManagementRevision,
        request_id: Option<String>,
        now: UnixTimestamp,
    }

    impl ActorProbe {
        fn from_actor(actor: &ManagementActor) -> Self {
            Self {
                authorization_revision: actor.authorization_revision(),
                request_id: actor
                    .request_id()
                    .map(|request_id| request_id.as_str().to_owned()),
                now: actor.now(),
            }
        }
    }

    #[derive(Debug)]
    struct RecordingManagementRepository {
        grant_options: Result<
            ManagementReadOutcome<DirectBindingGrantOptionsState>,
            ManagementRepositoryError,
        >,
        delete_outcome: Result<ManagementMutationOutcome<()>, ManagementRepositoryError>,
        update_outcome: Result<ManagementMutationOutcome<RoleRecord>, ManagementRepositoryError>,
        grant_outcome:
            Result<ManagementMutationOutcome<RoleBindingRecord>, ManagementRepositoryError>,
        option_reads: AtomicUsize,
        mutation_dispatches: AtomicUsize,
        option_actors: Mutex<Vec<ActorProbe>>,
        mutation_actors: Mutex<Vec<ActorProbe>>,
    }

    impl Default for RecordingManagementRepository {
        fn default() -> Self {
            Self {
                grant_options: Err(ManagementRepositoryError::Unavailable),
                delete_outcome: Ok(ManagementMutationOutcome::NotFound),
                update_outcome: Ok(ManagementMutationOutcome::NotFound),
                grant_outcome: Ok(ManagementMutationOutcome::NotFound),
                option_reads: AtomicUsize::new(0),
                mutation_dispatches: AtomicUsize::new(0),
                option_actors: Mutex::new(Vec::new()),
                mutation_actors: Mutex::new(Vec::new()),
            }
        }
    }

    impl RecordingManagementRepository {
        fn record_mutation(&self, actor: &ManagementActor) {
            self.mutation_dispatches.fetch_add(1, Ordering::SeqCst);
            self.mutation_actors
                .lock()
                .expect("mutation actor lock")
                .push(ActorProbe::from_actor(actor));
        }
    }

    fn unavailable_read<'a, T: Send + 'a>() -> ManagementReadFuture<'a, T> {
        Box::pin(async { Err(ManagementRepositoryError::Unavailable) })
    }

    fn unavailable_detail<'a, T: Send + 'a>() -> ManagementDetailFuture<'a, T> {
        Box::pin(async { Err(ManagementRepositoryError::Unavailable) })
    }

    fn unavailable_mutation<'a, T: Send + 'a>() -> ManagementMutationFuture<'a, T> {
        Box::pin(async { Err(ManagementRepositoryError::Unavailable) })
    }

    impl HumanRbacManagementRepository for RecordingManagementRepository {
        fn read_mutation_capabilities<'a>(
            &'a self,
            _request: &'a ReadManagementMutationCapabilities,
        ) -> ManagementReadFuture<'a, ManagementMutationCapabilities> {
            unavailable_read()
        }

        fn read_direct_binding_grant_options<'a>(
            &'a self,
            request: &'a ReadDirectBindingGrantOptions,
        ) -> ManagementReadFuture<'a, DirectBindingGrantOptionsState> {
            self.option_reads.fetch_add(1, Ordering::SeqCst);
            self.option_actors
                .lock()
                .expect("option actor lock")
                .push(ActorProbe::from_actor(request.actor()));
            let result = self.grant_options.clone();
            Box::pin(async move { result })
        }

        fn list_members<'a>(
            &'a self,
            _request: &'a ListManagementRecords,
        ) -> ManagementReadFuture<'a, ManagementPage<MemberRecord>> {
            unavailable_read()
        }

        fn list_roles<'a>(
            &'a self,
            _request: &'a ListManagementRecords,
        ) -> ManagementReadFuture<'a, ManagementPage<RoleRecord>> {
            unavailable_read()
        }

        fn list_role_bindings<'a>(
            &'a self,
            _request: &'a ListManagementRecords,
        ) -> ManagementReadFuture<'a, ManagementPage<RoleBindingRecord>> {
            unavailable_read()
        }

        fn read_member_detail<'a>(
            &'a self,
            _request: &'a ReadMemberDetail,
        ) -> ManagementDetailFuture<'a, MemberRecord> {
            unavailable_detail()
        }

        fn read_role_detail<'a>(
            &'a self,
            _request: &'a ReadRoleDetail,
        ) -> ManagementDetailFuture<'a, RoleDetailRecord> {
            unavailable_detail()
        }

        fn list_management_role_bindings<'a>(
            &'a self,
            _request: &'a ListManagementRoleBindings,
        ) -> ManagementReadFuture<'a, ManagementPage<ManagementRoleBindingRecord>> {
            unavailable_read()
        }

        fn create_role(&self, request: CreateRole) -> ManagementMutationFuture<'_, RoleRecord> {
            self.record_mutation(request.actor());
            unavailable_mutation()
        }

        fn update_role(&self, request: UpdateRole) -> ManagementMutationFuture<'_, RoleRecord> {
            self.record_mutation(request.actor());
            let result = self.update_outcome.clone();
            Box::pin(async move { result })
        }

        fn delete_role(&self, request: DeleteRole) -> ManagementMutationFuture<'_, ()> {
            self.record_mutation(request.actor());
            let result = self.delete_outcome.clone();
            Box::pin(async move { result })
        }

        fn set_role_permission(
            &self,
            request: SetRolePermission,
        ) -> ManagementMutationFuture<'_, RoleRecord> {
            self.record_mutation(request.actor());
            unavailable_mutation()
        }

        fn grant_role(
            &self,
            request: GrantRole,
        ) -> ManagementMutationFuture<'_, RoleBindingRecord> {
            self.record_mutation(request.actor());
            let result = self.grant_outcome.clone();
            Box::pin(async move { result })
        }

        fn revoke_role(
            &self,
            request: RevokeRole,
        ) -> ManagementMutationFuture<'_, RoleBindingRecord> {
            self.record_mutation(request.actor());
            unavailable_mutation()
        }

        fn change_member_status(
            &self,
            request: ChangeMemberStatus,
        ) -> ManagementMutationFuture<'_, MemberRecord> {
            self.record_mutation(request.actor());
            unavailable_mutation()
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_seconds(700)
        }
    }

    fn management_revision(value: u64) -> ManagementRevision {
        ManagementRevision::new(value).expect("management revision")
    }

    fn role_id(value: &str) -> RoleId {
        RoleId::new(value).expect("role ID")
    }

    fn target_principal_id() -> ManagedPrincipalId {
        ManagedPrincipalId::new(TARGET_PRINCIPAL_ID).expect("target principal")
    }

    fn snapshot() -> AuthenticatedRequestSnapshot {
        let tenant_id = TenantId::new("tenant-a").expect("tenant");
        let principal_id = PrincipalId::new(ACTOR_PRINCIPAL_ID).expect("principal");
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
            SESSION_AUTHORIZATION_REVISION,
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
            SESSION_AUTHORIZATION_REVISION,
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

    fn adapter(repository: Arc<RecordingManagementRepository>) -> ManagementRbacWebData {
        let repository_port: Arc<dyn HumanRbacManagementRepository> = repository;
        ManagementRbacWebData::new(repository_port, Arc::new(FixedClock))
    }

    fn delete_form(expected_authorization_revision: u64) -> VerifiedRbacManagementForm {
        VerifiedRbacManagementForm::DeleteRole {
            role_id: role_id(ROLE_ID),
            expected_authorization_revision: management_revision(expected_authorization_revision),
            expected_revision: management_revision(7),
        }
    }

    fn grant_options() -> DirectBindingGrantOptions {
        DirectBindingGrantOptions::new(
            management_revision(SESSION_AUTHORIZATION_REVISION),
            vec![
                DirectBindingPrincipalOption::new(target_principal_id(), "Grace Hopper")
                    .expect("principal option"),
            ],
            vec![
                DirectBindingRoleOption::new(
                    role_id(ROLE_ID),
                    RoleName::new("release-reviewer").expect("role name"),
                    "Release reviewer",
                    RoleKind::Custom,
                    false,
                )
                .expect("role option"),
            ],
            vec![
                DirectBindingRepositoryOption::new(
                    RepositoryResourceId::new(REPOSITORY_ID).expect("repository ID"),
                    "acme/payments",
                )
                .expect("repository option"),
            ],
            Vec::new(),
        )
        .expect("grant options")
    }

    fn grant_form(scope: RbacGrantScope) -> VerifiedRbacManagementForm {
        VerifiedRbacManagementForm::GrantRole {
            expected_authorization_revision: management_revision(SESSION_AUTHORIZATION_REVISION),
            principal_id: target_principal_id(),
            role_id: role_id(ROLE_ID),
            scope,
            valid_until: None,
        }
    }

    #[tokio::test]
    async fn mutation_rejects_stale_authorization_and_exhausted_target_without_dispatch() {
        let repository = Arc::new(RecordingManagementRepository::default());
        let data = adapter(repository.clone());
        let snapshot = snapshot();

        assert_eq!(
            data.mutate(&snapshot, delete_form(3)).await,
            Ok(RbacWebMutationOutcome::Conflict)
        );
        assert_eq!(repository.option_reads.load(Ordering::SeqCst), 0);
        assert_eq!(repository.mutation_dispatches.load(Ordering::SeqCst), 0);

        let exhausted = VerifiedRbacManagementForm::UpdateRole {
            role_id: role_id(ROLE_ID),
            expected_authorization_revision: management_revision(SESSION_AUTHORIZATION_REVISION),
            expected_revision: management_revision(i64::MAX as u64),
            display_name: "Release reviewer".to_owned(),
        };
        assert_eq!(
            data.mutate(&snapshot, exhausted).await,
            Ok(RbacWebMutationOutcome::Conflict)
        );
        assert_eq!(repository.option_reads.load(Ordering::SeqCst), 0);
        assert_eq!(repository.mutation_dispatches.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn direct_grant_revalidates_one_fresh_option_snapshot_before_dispatch() {
        let repository = Arc::new(RecordingManagementRepository {
            grant_options: Ok(ManagementReadOutcome::Authorized(
                DirectBindingGrantOptionsState::Available(grant_options()),
            )),
            ..RecordingManagementRepository::default()
        });
        let data = adapter(repository.clone());
        let snapshot = snapshot();

        assert_eq!(
            data.mutate(
                &snapshot,
                grant_form(RbacGrantScope::Repository(
                    RepositoryResourceId::new(REPOSITORY_ID).expect("repository ID"),
                )),
            )
            .await,
            Ok(RbacWebMutationOutcome::NotFound)
        );
        assert_eq!(repository.option_reads.load(Ordering::SeqCst), 1);
        assert_eq!(repository.mutation_dispatches.load(Ordering::SeqCst), 1);

        let option_actors = repository.option_actors.lock().expect("option actor lock");
        let mutation_actors = repository
            .mutation_actors
            .lock()
            .expect("mutation actor lock");
        assert_eq!(option_actors.as_slice(), mutation_actors.as_slice());
        assert_eq!(option_actors.len(), 1);
        assert_eq!(
            option_actors[0].authorization_revision,
            management_revision(SESSION_AUTHORIZATION_REVISION)
        );
        assert_eq!(option_actors[0].now, UnixTimestamp::from_seconds(700));
        assert!(
            option_actors[0]
                .request_id
                .as_deref()
                .is_some_and(|request_id| request_id.starts_with("rbac-"))
        );
    }

    #[tokio::test]
    async fn direct_grant_closes_overflow_and_out_of_option_scope_without_dispatch() {
        let overflow_repository = Arc::new(RecordingManagementRepository {
            grant_options: Ok(ManagementReadOutcome::Authorized(
                DirectBindingGrantOptionsState::Overflow {
                    authorization_revision: management_revision(SESSION_AUTHORIZATION_REVISION),
                    collection: DirectBindingGrantOptionCollection::Repositories,
                },
            )),
            ..RecordingManagementRepository::default()
        });
        let overflow_data = adapter(overflow_repository.clone());
        let snapshot = snapshot();
        let submitted_scope = RbacGrantScope::Repository(
            RepositoryResourceId::new(REPOSITORY_ID).expect("repository ID"),
        );

        assert_eq!(
            overflow_data
                .mutate(&snapshot, grant_form(submitted_scope))
                .await,
            Ok(RbacWebMutationOutcome::Conflict)
        );
        assert_eq!(overflow_repository.option_reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            overflow_repository
                .mutation_dispatches
                .load(Ordering::SeqCst),
            0
        );

        let missing_scope_repository = Arc::new(RecordingManagementRepository {
            grant_options: Ok(ManagementReadOutcome::Authorized(
                DirectBindingGrantOptionsState::Available(grant_options()),
            )),
            ..RecordingManagementRepository::default()
        });
        let missing_scope_data = adapter(missing_scope_repository.clone());
        let unlisted_scope = RbacGrantScope::Repository(
            RepositoryResourceId::new(OTHER_REPOSITORY_ID).expect("repository ID"),
        );
        assert_eq!(
            missing_scope_data
                .mutate(&snapshot, grant_form(unlisted_scope))
                .await,
            Ok(RbacWebMutationOutcome::Conflict)
        );
        assert_eq!(
            missing_scope_repository.option_reads.load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            missing_scope_repository
                .mutation_dispatches
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn repository_closed_mutation_outcomes_map_without_fallback() {
        let closed_outcomes = [
            (
                Ok(ManagementMutationOutcome::Forbidden),
                Ok(RbacWebMutationOutcome::Forbidden),
            ),
            (
                Ok(ManagementMutationOutcome::SessionStale),
                Ok(RbacWebMutationOutcome::SessionStale),
            ),
            (
                Ok(ManagementMutationOutcome::NotFound),
                Ok(RbacWebMutationOutcome::NotFound),
            ),
            (
                Ok(ManagementMutationOutcome::AlreadyExists),
                Ok(RbacWebMutationOutcome::Conflict),
            ),
            (
                Ok(ManagementMutationOutcome::RevisionConflict {
                    current: management_revision(9),
                }),
                Ok(RbacWebMutationOutcome::Conflict),
            ),
            (
                Ok(ManagementMutationOutcome::Immutable),
                Ok(RbacWebMutationOutcome::Conflict),
            ),
            (
                Ok(ManagementMutationOutcome::ResourceInUse),
                Ok(RbacWebMutationOutcome::Conflict),
            ),
            (
                Ok(ManagementMutationOutcome::SelfModificationForbidden),
                Ok(RbacWebMutationOutcome::Conflict),
            ),
            (
                Ok(ManagementMutationOutcome::LastManager),
                Ok(RbacWebMutationOutcome::Conflict),
            ),
            (
                Err(ManagementRepositoryError::InvalidRequest),
                Err(RbacWebDataError::Corrupt),
            ),
            (
                Err(ManagementRepositoryError::CorruptData),
                Err(RbacWebDataError::Corrupt),
            ),
            (
                Err(ManagementRepositoryError::Unavailable),
                Err(RbacWebDataError::Unavailable),
            ),
        ];

        for (repository_outcome, expected) in closed_outcomes {
            let repository = Arc::new(RecordingManagementRepository {
                delete_outcome: repository_outcome,
                ..RecordingManagementRepository::default()
            });
            let data = adapter(repository.clone());
            assert_eq!(
                data.mutate(&snapshot(), delete_form(SESSION_AUTHORIZATION_REVISION),)
                    .await,
                expected
            );
            assert_eq!(repository.option_reads.load(Ordering::SeqCst), 0);
            assert_eq!(repository.mutation_dispatches.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn corrupt_applied_role_identity_and_revision_fail_closed() {
        let form = || VerifiedRbacManagementForm::UpdateRole {
            role_id: role_id(ROLE_ID),
            expected_authorization_revision: management_revision(SESSION_AUTHORIZATION_REVISION),
            expected_revision: management_revision(7),
            display_name: "Release reviewer".to_owned(),
        };
        let role_record = |id, revision| {
            RoleRecord::new(
                role_id(id),
                RoleName::new("release-reviewer").expect("role name"),
                "Release reviewer",
                RoleKind::Custom,
                false,
                management_revision(revision),
                BTreeSet::from([Permission::new("runs:read").expect("permission")]),
            )
            .expect("role record")
        };

        for corrupt in [role_record(OTHER_ROLE_ID, 8), role_record(ROLE_ID, 7)] {
            let repository = Arc::new(RecordingManagementRepository {
                update_outcome: Ok(ManagementMutationOutcome::Applied(corrupt)),
                ..RecordingManagementRepository::default()
            });
            let data = adapter(repository.clone());
            assert_eq!(
                data.mutate(&snapshot(), form()).await,
                Err(RbacWebDataError::Corrupt)
            );
            assert_eq!(repository.option_reads.load(Ordering::SeqCst), 0);
            assert_eq!(repository.mutation_dispatches.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn request_context_keeps_login_and_viewer_states_atomic() {
        let tenant = TenantId::new("tenant-a").expect("tenant");
        let anonymous = RequestContext::new(
            tenant.clone(),
            AuthorizationContext::anonymous(),
            None,
            Some(GITHUB_WEB_BEGIN_PATH.to_owned()),
        )
        .expect("anonymous context");
        assert!(!anonymous.access_management_available());
        assert!(
            !anonymous
                .with_access_management_available(true)
                .access_management_available()
        );
        assert_eq!(
            RequestContext::new(
                tenant.clone(),
                AuthorizationContext::anonymous(),
                None,
                Some("/login".to_owned()),
            ),
            Err(RequestContextError::InvalidSignInAction)
        );
        assert_eq!(
            RequestContext::new(
                tenant.clone(),
                AuthorizationContext::anonymous(),
                Some(Viewer {
                    display_name: "Ada Lovelace".to_owned(),
                }),
                Some(GITHUB_WEB_BEGIN_PATH.to_owned()),
            ),
            Err(RequestContextError::AuthenticatedSignInAction)
        );

        let authenticated = RequestContext::new(
            tenant,
            AuthorizationContext::anonymous(),
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("authenticated context");
        assert!(!authenticated.access_management_available());
        assert!(
            authenticated
                .with_access_management_available(true)
                .access_management_available()
        );
    }

    #[test]
    fn rbac_user_list_request_accepts_only_a_canonical_principal_cursor() {
        let cursor = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let request = RbacUserListRequest::new(Some(cursor.to_owned())).expect("valid cursor");
        assert_eq!(request.cursor.as_deref(), Some(cursor));
        assert_eq!(request.limit.value(), RBAC_USER_PAGE_SIZE);

        for invalid in [
            "",
            "not-a-uuid",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(
                RbacUserListRequest::new(Some(invalid.to_owned())),
                Err(RbacWebDataError::InvalidRequest)
            );
        }
    }

    #[test]
    fn rbac_detail_role_and_binding_requests_accept_only_current_canonical_ids() {
        let principal = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let role = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let binding = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let user = RbacUserDetailRequest::new(principal).expect("user detail request");
        assert_eq!(user.principal_id.to_string(), principal);
        assert_eq!(user.binding_limit.value(), RBAC_USER_DETAIL_BINDING_LIMIT);
        assert_eq!(
            RbacRoleDetailRequest::new(role)
                .expect("role detail request")
                .role_id
                .to_string(),
            role
        );
        assert_eq!(
            RbacRoleListRequest::new(Some(role.to_owned()))
                .expect("role list request")
                .limit
                .value(),
            RBAC_ROLE_PAGE_SIZE
        );
        let direct_cursor = format!("d:{binding}");
        assert_eq!(
            RbacDirectBindingListRequest::new(Some(direct_cursor.clone()))
                .expect("binding list request")
                .cursor
                .as_deref(),
            Some(direct_cursor.as_str())
        );

        for invalid in ["", "not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            assert_eq!(
                RbacUserDetailRequest::new(invalid),
                Err(RbacWebDataError::InvalidRequest)
            );
            assert_eq!(
                RbacRoleDetailRequest::new(invalid),
                Err(RbacWebDataError::InvalidRequest)
            );
        }
        for invalid in [
            binding,
            "d:not-a-uuid",
            "g:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:not-a-uuid",
        ] {
            assert_eq!(
                RbacDirectBindingListRequest::new(Some(invalid.to_owned())),
                Err(RbacWebDataError::InvalidRequest)
            );
        }
    }
}
