use std::collections::HashSet;

use automata_ci_auth::{
    authorization::{AuthorizationScope, OutputVisibility, RepositoryPublicationPolicy},
    login::LoginReturnPath,
    management::{
        DirectBindingGrantOptionsState, ManagedPrincipalId, ManagementMutationCapabilities,
        ManagementRevision, ManagementRoleBindingCursor, ManagementRoleBindingRecord,
        ManagementRoleBindingSource, ManagementScopeRecord, MemberRecord, MemberStatus,
        RoleBindingStatus, RoleDetailRecord, RoleId, RoleKind, RoleRecord,
    },
    secret::CsrfToken,
    time::UnixTimestamp,
};
use automata_ci_core::UnixMillis;
use automata_ci_store::{
    BUILTIN_SECRET_PROVIDER_ID, BuiltinSecretProviderHealth, BuiltinSecretProviderInspection,
    BuiltinSecretProviderState, RepositorySecretId, RepositorySecretState,
};
use automata_ci_ui_renderer::{ClientAssetManifest, MAX_RENDER_REQUEST_UTF8_BYTES};
use serde::Serialize;
use thiserror::Error;

const RENDER_REQUEST_SCHEMA_VERSION: u8 = 1;
use time::OffsetDateTime;
use url::Url;

use crate::app::github_auth::{GITHUB_SETUP_WEB_BEGIN_PATH, GITHUB_WEB_LOGOUT_PATH};
use crate::app::repository_secrets::{
    RepositorySecretCreateCapability, RepositorySecretRow,
    RepositorySecretsPage as RepositorySecretsData,
};

use super::data::{
    ArtifactSummary, CollectionVisibility, JobLogPage as JobLogData, JobSummary,
    REPOSITORY_PAGE_SIZE, RbacDirectBindingListPage as RbacDirectBindingListData,
    RbacRoleListPage as RbacRoleListData, RbacUserDetailPage as RbacUserDetailData,
    RbacUserListPage as RbacUserListData, Repository as RepositoryData,
    RepositoryDirectoryItem as RepositoryDirectoryItemData,
    RepositoryDirectoryPage as RepositoryDirectoryData,
    RepositoryDirectoryRequest as RepositoryDirectoryRequestData, RepositorySettingsDestination,
    RepositorySettingsPage as RepositorySettingsData, RequestContext,
    RunDetailPage as RunDetailData, RunDetailRequest as RunDetailRequestData,
    RunListPage as RunListData, RunListRequest as RunListRequestData, RunSummary,
    Status as DataStatus, StatusFilter,
};
use super::encoding::percent_encode;
use super::text::{
    forbidden_display_character, has_visible_display_character, is_safe_display_text,
};

const MAX_WORKFLOWS: usize = 250;
const MAX_RUNS: usize = 250;
const MAX_JOBS: usize = 200;
const MAX_ARTIFACTS: usize = 500;
const MAX_REPOSITORY_SECRETS: usize = 50;
const MAX_RBAC_USERS: usize = 500;
const MAX_RBAC_ROLES: usize = 500;
const MAX_RBAC_BINDINGS: usize = 500;
const MAX_RBAC_PERMISSIONS: usize = 500;
const SHELL_DESCRIPTION: &str =
    "Browse repositories and review workflow runs, jobs, logs, and artifacts.";
const RBAC_SHELL_DESCRIPTION: &str =
    "Review tenant users, roles, permissions, and direct role bindings.";
const SETUP_SHELL_DESCRIPTION: &str =
    "Complete the one-time administrator setup for this Automata installation.";
const REPOSITORIES_PATH: &str = "/repositories";
const SETUP_PATH: &str = "/setup";
const SETUP_RETURN_PATH: &str = "/";
const RBAC_USERS_PATH: &str = "/settings/access/users";
const RBAC_ROLES_PATH: &str = "/settings/access/roles";
const RBAC_DIRECT_BINDINGS_PATH: &str = "/settings/access/direct-bindings";
const GITHUB_SCM_PROVIDER: &str = "github";
const GITHUB_SOURCE_ORIGIN: &str = "https://github.com/";

#[derive(Debug, Error)]
pub(super) enum ModelError {
    #[error("failed to serialize the UI page model")]
    Serialize(#[from] serde_json::Error),
    #[error("the UI page model exceeds its renderer byte limit")]
    TooLarge,
    #[error("durable workflow data cannot be represented by the UI contract")]
    InvalidData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderRequest<P> {
    schema_version: u8,
    host: RenderHost,
    page: P,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderHost {
    locale: &'static str,
    assets: RenderAssets,
    csp_nonce: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RenderAssets {
    client_entry: &'static str,
    stylesheets: &'static [&'static str],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Shell {
    product_name: &'static str,
    home_href: String,
    sign_in: Option<SignIn>,
    sign_out: Option<SignOut>,
    document_title: String,
    description: &'static str,
    viewer: Option<Viewer>,
    navigation: Vec<NavigationItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignIn {
    action: String,
    return_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignOut {
    action: &'static str,
    csrf_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Viewer {
    display_name: String,
}

#[derive(Debug, Serialize)]
struct NavigationItem {
    label: &'static str,
    href: String,
    current: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Repository {
    owner: String,
    name: String,
    source_href: String,
    runs_href: String,
    settings_href: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryDirectoryPage {
    kind: &'static str,
    shell: Shell,
    heading: &'static str,
    summary: &'static str,
    repositories: Vec<RepositoryDirectoryItem>,
    pagination: RepositoryDirectoryPagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryDirectoryItem {
    owner: String,
    name: String,
    source_href: String,
    actions_href: Option<String>,
    settings_href: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryDirectoryPagination {
    next_href: Option<String>,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupPage {
    kind: &'static str,
    shell: Shell,
    form: SetupForm,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupForm {
    action: &'static str,
    return_path: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunListPage {
    kind: &'static str,
    shell: Shell,
    repository: Repository,
    heading: &'static str,
    summary: String,
    filters: RunFilters,
    workflow_navigation: Option<WorkflowNavigation>,
    runs: Vec<RunListItem>,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowNavigation {
    selected_workflow: Option<WorkflowNavigationItem>,
    workflows: Vec<WorkflowNavigationItem>,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
struct WorkflowNavigationItem {
    id: String,
    name: String,
    href: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunFilters {
    action: String,
    status: &'static str,
    branch: String,
    clear_href: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunListItem {
    id: String,
    number: String,
    name: String,
    workflow_name: String,
    workflow_href: String,
    href: String,
    status: Status,
    source_ref: Option<SourceRef>,
    event: String,
    actor: Option<String>,
    commit: Commit,
    created_at: Timestamp,
    duration_label: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDetailPage {
    kind: &'static str,
    shell: Shell,
    repository: Repository,
    run: RunDetail,
    jobs: VisibleCollection<Job>,
    job_pagination: Pagination,
    artifacts: VisibleCollection<Artifact>,
    rerun: Option<RunRerunControls>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunRerunControls {
    endpoint: String,
    csrf_token: String,
    failed_jobs_available: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySettingsPage {
    kind: &'static str,
    shell: Shell,
    repository: Repository,
    heading: &'static str,
    summary: String,
    settings_navigation: RepositorySettingsNavigation,
    revision: String,
    policy: RepositoryPublicationPolicyModel,
    update: Option<RepositorySettingsUpdate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySettingsNavigation {
    access_href: Option<String>,
    secrets_href: Option<String>,
    current: &'static str,
}

#[derive(Debug, Serialize)]
struct RepositoryPublicationPolicyModel {
    dashboard: &'static str,
    logs: &'static str,
    artifacts: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySettingsUpdate {
    action: String,
    csrf_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretsPage {
    kind: &'static str,
    shell: Shell,
    repository: Repository,
    heading: &'static str,
    summary: String,
    settings_navigation: RepositorySettingsNavigation,
    notice: Option<&'static str>,
    maximum_value_bytes: usize,
    provider: Option<RepositorySecretProvider>,
    create: Option<RepositorySecretCreate>,
    secrets: Vec<RepositorySecret>,
    pagination: RepositorySecretPagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretProvider {
    id: &'static str,
    state: &'static str,
    health: &'static str,
    activation: Option<RepositorySecretProviderActivation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretProviderActivation {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    expected_revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretCreate {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    secret_id: String,
    mutation_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecret {
    id: String,
    name: String,
    provider_id: String,
    state: &'static str,
    current_version: Option<String>,
    revision: String,
    updated_at: Timestamp,
    replace: Option<RepositorySecretReplace>,
    delete: Option<RepositorySecretDelete>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretReplace {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    mutation_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretDelete {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositorySecretPagination {
    first_href: Option<String>,
    next_href: Option<String>,
    label: String,
}

#[derive(Clone, Copy)]
pub(super) struct ShellMutation<'a> {
    csrf_token: &'a CsrfToken,
}

impl<'a> ShellMutation<'a> {
    pub(super) const fn new(csrf_token: &'a CsrfToken) -> Self {
        Self { csrf_token }
    }
}

#[derive(Debug, Serialize)]
struct VisibleCollection<T> {
    visibility: &'static str,
    items: Vec<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDetail {
    number: String,
    name: String,
    workflow_name: String,
    workflow_href: String,
    status: Status,
    source_ref: Option<SourceRef>,
    event: String,
    actor: Option<String>,
    commit: Commit,
    created_at: Timestamp,
    duration_label: Option<String>,
    attempt: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Job {
    id: String,
    name: String,
    href: Option<String>,
    runner_label: Option<String>,
    status: Status,
    started_at: Option<Timestamp>,
    duration_label: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    id: String,
    name: String,
    size_label: String,
    digest: String,
    download_href: Option<String>,
    expires_at: Option<Timestamp>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobLogPage {
    kind: &'static str,
    shell: Shell,
    repository: Repository,
    run: JobLogRun,
    jobs: Vec<JobLogNavigationItem>,
    navigation_pagination: Pagination,
    job: JobLogJob,
    log_visibility: &'static str,
    live: Option<JobLogLive>,
    notice: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobLogLive {
    ticket_href: String,
}

fn job_log_live(ticket_href: String) -> JobLogLive {
    JobLogLive { ticket_href }
}

#[derive(Debug, Serialize)]
struct DeepLinkSignInPage {
    kind: &'static str,
    shell: Shell,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobLogRun {
    number: String,
    name: String,
    href: String,
    workflow_name: String,
    workflow_href: String,
    attempt: u32,
}

#[derive(Debug, Serialize)]
struct JobLogNavigationItem {
    id: String,
    name: String,
    href: Option<String>,
    status: Status,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct JobLogJob {
    id: String,
    name: String,
    href: String,
    attempt: u32,
    runner_label: Option<String>,
    status: Status,
    started_at: Option<Timestamp>,
    duration_label: Option<String>,
}

#[derive(Debug, Serialize)]
struct Status {
    label: &'static str,
    tone: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Commit {
    short_sha: String,
    message: Option<String>,
    href: String,
}

#[derive(Debug, Serialize)]
struct SourceRef {
    name: String,
    kind: &'static str,
    href: String,
}

#[derive(Debug, Serialize)]
struct Timestamp {
    iso: String,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Pagination {
    previous_href: Option<String>,
    next_href: Option<String>,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacManagementNavigation {
    users_href: &'static str,
    roles_href: &'static str,
    direct_bindings_href: &'static str,
    current: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacManagedUser {
    id: String,
    href: String,
    provider_id: String,
    provider_login: String,
    display_name: Option<String>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacUserListPage {
    kind: &'static str,
    shell: Shell,
    management_nav: RbacManagementNavigation,
    heading: &'static str,
    summary: &'static str,
    users: Vec<RbacManagedUser>,
    notice: Option<&'static str>,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacUserDetailPage {
    kind: &'static str,
    shell: Shell,
    management_nav: RbacManagementNavigation,
    heading: String,
    summary: &'static str,
    user: RbacManagedUser,
    role_assignments: Vec<RbacUserRoleAssignment>,
    notice: Option<&'static str>,
    status_update: Option<RbacMemberStatusUpdate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacMemberStatusUpdate {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    expected_revision: String,
    operation: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacUserRoleAssignment {
    binding_id: String,
    binding_href: String,
    role_id: String,
    role_href: String,
    role_name: String,
    role_display_name: String,
    scope: RbacScope,
    source: &'static str,
    status: &'static str,
    valid_until: Option<Timestamp>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacRoleSummary {
    id: String,
    href: String,
    name: String,
    display_name: String,
    kind: &'static str,
    immutable: bool,
    permission_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacRoleListPage {
    kind: &'static str,
    shell: Shell,
    management_nav: RbacManagementNavigation,
    heading: &'static str,
    summary: &'static str,
    roles: Vec<RbacRoleSummary>,
    notice: Option<&'static str>,
    create: Option<RbacRoleCreate>,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacRoleCreate {
    action: &'static str,
    csrf_token: String,
    expected_authorization_revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacRoleDetailPage {
    kind: &'static str,
    shell: Shell,
    management_nav: RbacManagementNavigation,
    heading: String,
    summary: &'static str,
    role: RbacRoleSummary,
    permissions: Vec<RbacPermission>,
    notice: Option<&'static str>,
    update: Option<RbacRoleUpdate>,
    delete: Option<RbacRoleDelete>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacRoleUpdate {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    expected_revision: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacRoleDelete {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    expected_revision: String,
}

#[derive(Debug, Serialize)]
struct RbacPermission {
    name: String,
    description: String,
    granted: bool,
    update: Option<RbacPermissionUpdate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacPermissionUpdate {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    expected_revision: String,
    operation: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum RbacScope {
    Tenant { label: String },
    Repository { label: String },
    RunnerGroup { label: String },
}

#[derive(Debug, Serialize)]
struct RbacBindingPrincipal {
    id: String,
    href: String,
    label: String,
}

#[derive(Debug, Serialize)]
struct RbacBindingRole {
    id: String,
    href: String,
    name: String,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacBinding {
    id: String,
    revision: String,
    principal: RbacBindingPrincipal,
    role: RbacBindingRole,
    scope: RbacScope,
    source: &'static str,
    status: &'static str,
    valid_until: Option<Timestamp>,
    revoke: Option<RbacBindingRevoke>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacBindingRevoke {
    action: String,
    csrf_token: String,
    expected_authorization_revision: String,
    expected_revision: String,
}

#[derive(Debug, Serialize)]
struct RbacSelectOption {
    value: String,
    label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacDirectGrant {
    action: &'static str,
    csrf_token: String,
    expected_authorization_revision: String,
    principals: Vec<RbacSelectOption>,
    roles: Vec<RbacSelectOption>,
    scopes: Vec<RbacSelectOption>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RbacDirectBindingListPage {
    kind: &'static str,
    shell: Shell,
    management_nav: RbacManagementNavigation,
    heading: &'static str,
    summary: &'static str,
    bindings: Vec<RbacBinding>,
    notice: Option<&'static str>,
    grant: Option<RbacDirectGrant>,
    read_only_reason: Option<&'static str>,
    pagination: Pagination,
}

pub(super) fn rbac_user_list(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    request_cursor: Option<&str>,
    notice: Option<&'static str>,
    data: &RbacUserListData,
) -> Result<String, ModelError> {
    if context.viewer().is_none()
        || data.users.len() > MAX_RBAC_USERS
        || !all_unique(data.users.iter().map(MemberRecord::principal_id))
        || !valid_rbac_user_cursor(request_cursor)
        || !valid_rbac_user_cursor(data.next_cursor.as_deref())
        || request_cursor.is_some_and(|cursor| data.next_cursor.as_deref() == Some(cursor))
    {
        return Err(ModelError::InvalidData);
    }
    let users = data
        .users
        .iter()
        .map(rbac_managed_user)
        .collect::<Result<Vec<_>, _>>()?;
    let current_href = rbac_list_href(RBAC_USERS_PATH, request_cursor);
    let return_path =
        LoginReturnPath::new(current_href.clone()).map_err(|_| ModelError::InvalidData)?;
    serialize_request(
        assets,
        csp_nonce,
        RbacUserListPage {
            kind: "user-list",
            shell: rbac_shell(
                context,
                mutation,
                &return_path,
                "Users · Access management · Automata".to_owned(),
            )?,
            management_nav: rbac_management_navigation("users"),
            heading: "Users",
            summary: "Review authenticated tenant members and their current status.",
            notice,
            pagination: Pagination {
                previous_href: None,
                next_href: data
                    .next_cursor
                    .as_deref()
                    .map(|cursor| rbac_list_href(RBAC_USERS_PATH, Some(cursor))),
                label: pluralized(users.len(), "user", "users"),
            },
            users,
        },
    )
}

fn valid_rbac_user_cursor(cursor: Option<&str>) -> bool {
    cursor.is_none_or(|cursor| ManagedPrincipalId::new(cursor).is_ok())
}

fn rbac_managed_user(record: &MemberRecord) -> Result<RbacManagedUser, ModelError> {
    if !is_safe_display_text(record.provider_id().as_str(), 128)
        || !is_safe_display_text(record.provider_login(), 255)
        || record
            .display_name()
            .is_some_and(|display_name| !is_safe_display_text(display_name, 255))
    {
        return Err(ModelError::InvalidData);
    }
    let id = record.principal_id().to_string();
    Ok(RbacManagedUser {
        href: format!("{RBAC_USERS_PATH}/{id}"),
        id,
        provider_id: record.provider_id().as_str().to_owned(),
        provider_login: record.provider_login().to_owned(),
        display_name: record.display_name().map(str::to_owned),
        status: match record.status() {
            MemberStatus::Active => "active",
            MemberStatus::Suspended => "disabled",
        },
    })
}

fn rbac_shell(
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    return_path: &LoginReturnPath,
    document_title: String,
) -> Result<Shell, ModelError> {
    if context.viewer().is_none() {
        return Err(ModelError::InvalidData);
    }
    let mut shell = global_shell(
        context,
        mutation,
        REPOSITORIES_PATH,
        return_path,
        document_title,
    )?;
    shell.description = RBAC_SHELL_DESCRIPTION;
    shell.navigation = vec![
        NavigationItem {
            label: "Repositories",
            href: REPOSITORIES_PATH.to_owned(),
            current: false,
        },
        NavigationItem {
            label: "Access",
            href: RBAC_USERS_PATH.to_owned(),
            current: true,
        },
    ];
    Ok(shell)
}

const fn rbac_management_navigation(current: &'static str) -> RbacManagementNavigation {
    RbacManagementNavigation {
        users_href: RBAC_USERS_PATH,
        roles_href: RBAC_ROLES_PATH,
        direct_bindings_href: RBAC_DIRECT_BINDINGS_PATH,
        current,
    }
}

fn rbac_list_href(path: &str, cursor: Option<&str>) -> String {
    cursor.map_or_else(
        || path.to_owned(),
        |cursor| query_href(path, &[("cursor", cursor)]),
    )
}

#[derive(Clone, Copy)]
struct RbacFormAuthority<'a> {
    csrf_token: &'a CsrfToken,
    authorization_revision: ManagementRevision,
}

fn rbac_form_authority<'a>(
    mutation: Option<ShellMutation<'a>>,
    capabilities: Option<&ManagementMutationCapabilities>,
    page_authorization_revision: ManagementRevision,
    allowed: bool,
) -> Result<Option<RbacFormAuthority<'a>>, ModelError> {
    if capabilities.is_some_and(|capabilities| {
        capabilities.authorization_revision() != page_authorization_revision
    }) || (capabilities.is_some() && mutation.is_none())
    {
        return Err(ModelError::InvalidData);
    }
    if !allowed {
        return Ok(None);
    }
    let (Some(mutation), Some(capabilities)) = (mutation, capabilities) else {
        return Ok(None);
    };
    if !mutation.csrf_token.has_generated_shape() {
        return Err(ModelError::InvalidData);
    }
    Ok(Some(RbacFormAuthority {
        csrf_token: mutation.csrf_token,
        authorization_revision: capabilities.authorization_revision(),
    }))
}

fn rbac_csrf(authority: RbacFormAuthority<'_>) -> String {
    authority.csrf_token.expose_secret().to_owned()
}

const fn revision_can_advance(revision: ManagementRevision) -> bool {
    revision.value() < i64::MAX as u64
}

#[allow(
    clippy::too_many_arguments,
    reason = "page data, read fence, capability, and shell authority stay explicit"
)]
pub(super) fn rbac_user_detail(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    principal_id: ManagedPrincipalId,
    data: &RbacUserDetailData,
    notice: Option<&'static str>,
    page_authorization_revision: ManagementRevision,
    capabilities: Option<&ManagementMutationCapabilities>,
) -> Result<String, ModelError> {
    if context.viewer().is_none()
        || data.user.principal_id() != principal_id
        || data.assignments.len() > MAX_RBAC_BINDINGS
        || !all_unique(data.assignments.iter().map(ManagementRoleBindingRecord::id))
        || data
            .assignments
            .iter()
            .any(|assignment| assignment.principal() != &data.user)
    {
        return Err(ModelError::InvalidData);
    }
    let user = rbac_managed_user(&data.user)?;
    let heading = data
        .user
        .display_name()
        .unwrap_or_else(|| data.user.provider_login());
    if !is_safe_display_text(heading, 255) {
        return Err(ModelError::InvalidData);
    }
    let current_href = format!("{RBAC_USERS_PATH}/{principal_id}");
    let return_path =
        LoginReturnPath::new(current_href.clone()).map_err(|_| ModelError::InvalidData)?;
    let role_assignments = data
        .assignments
        .iter()
        .map(|assignment| rbac_user_role_assignment(context, assignment))
        .collect::<Result<Vec<_>, _>>()?;
    let is_self = context
        .authorization()
        .principal_id()
        .is_some_and(|actor| actor.as_str() == principal_id.to_string());
    let status_authority = rbac_form_authority(
        mutation,
        capabilities,
        page_authorization_revision,
        capabilities.is_some_and(|capabilities| capabilities.members_manage()) && !is_self,
    )?;
    let status_update = status_authority
        .filter(|_| revision_can_advance(data.user.revision()))
        .map(|authority| RbacMemberStatusUpdate {
            action: format!("{RBAC_USERS_PATH}/{principal_id}/status"),
            csrf_token: rbac_csrf(authority),
            expected_authorization_revision: authority.authorization_revision.value().to_string(),
            expected_revision: data.user.revision().value().to_string(),
            operation: match data.user.status() {
                MemberStatus::Active => "disable",
                MemberStatus::Suspended => "enable",
            },
        });
    serialize_request(
        assets,
        csp_nonce,
        RbacUserDetailPage {
            kind: "user-detail",
            shell: rbac_shell(
                context,
                mutation,
                &return_path,
                format!("{heading} · Access management · Automata"),
            )?,
            management_nav: rbac_management_navigation("users"),
            heading: heading.to_owned(),
            summary: "Stable provider identity, current status, and visible role assignments.",
            user,
            role_assignments,
            notice,
            status_update,
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "page data, read fence, capability, and shell authority stay explicit"
)]
pub(super) fn rbac_role_list(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    request_cursor: Option<&str>,
    notice: Option<&'static str>,
    data: &RbacRoleListData,
    capabilities: Option<&ManagementMutationCapabilities>,
) -> Result<String, ModelError> {
    if context.viewer().is_none()
        || data.roles.len() > MAX_RBAC_ROLES
        || !all_unique(data.roles.iter().map(RoleRecord::id))
        || !all_unique(data.roles.iter().map(|role| role.name().as_str()))
        || !valid_rbac_role_cursor(request_cursor)
        || !valid_rbac_role_cursor(data.next_cursor.as_deref())
        || request_cursor.is_some_and(|cursor| data.next_cursor.as_deref() == Some(cursor))
    {
        return Err(ModelError::InvalidData);
    }
    let roles = data
        .roles
        .iter()
        .map(rbac_role_summary)
        .collect::<Result<Vec<_>, _>>()?;
    let current_href = rbac_list_href(RBAC_ROLES_PATH, request_cursor);
    let return_path =
        LoginReturnPath::new(current_href.clone()).map_err(|_| ModelError::InvalidData)?;
    let create_authority = rbac_form_authority(
        mutation,
        capabilities,
        data.mutation_authorization_revision,
        capabilities.is_some_and(|capabilities| capabilities.roles_manage()),
    )?;
    serialize_request(
        assets,
        csp_nonce,
        RbacRoleListPage {
            kind: "role-list",
            shell: rbac_shell(
                context,
                mutation,
                &return_path,
                "Roles · Access management · Automata".to_owned(),
            )?,
            management_nav: rbac_management_navigation("roles"),
            heading: "Roles",
            summary: "Review built-in and custom roles and their explicit permission grants.",
            roles,
            notice,
            create: create_authority.map(|authority| RbacRoleCreate {
                action: RBAC_ROLES_PATH,
                csrf_token: rbac_csrf(authority),
                expected_authorization_revision: authority
                    .authorization_revision
                    .value()
                    .to_string(),
            }),
            pagination: Pagination {
                previous_href: None,
                next_href: data
                    .next_cursor
                    .as_deref()
                    .map(|cursor| rbac_list_href(RBAC_ROLES_PATH, Some(cursor))),
                label: pluralized(data.roles.len(), "role", "roles"),
            },
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "page data, read fence, capability, and shell authority stay explicit"
)]
pub(super) fn rbac_role_detail(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    role_id: RoleId,
    data: &RoleDetailRecord,
    notice: Option<&'static str>,
    page_authorization_revision: ManagementRevision,
    capabilities: Option<&ManagementMutationCapabilities>,
) -> Result<String, ModelError> {
    let role = data.role();
    if context.viewer().is_none()
        || role.id() != role_id
        || data.permission_catalog().len() > MAX_RBAC_PERMISSIONS
        || !all_unique(
            data.permission_catalog()
                .iter()
                .map(|permission| permission.permission().as_str()),
        )
    {
        return Err(ModelError::InvalidData);
    }
    let role_summary = rbac_role_summary(role)?;
    let role_authority = rbac_form_authority(
        mutation,
        capabilities,
        page_authorization_revision,
        capabilities.is_some_and(|capabilities| capabilities.roles_manage()) && !role.immutable(),
    )?;
    let role_update_authority = role_authority.filter(|_| revision_can_advance(role.revision()));
    let permissions = data
        .permission_catalog()
        .iter()
        .map(|permission| {
            if !is_safe_display_text(permission.description(), 4_096) {
                return Err(ModelError::InvalidData);
            }
            Ok(RbacPermission {
                name: permission.permission().as_str().to_owned(),
                description: permission.description().to_owned(),
                granted: permission.granted(),
                update: role_update_authority.map(|authority| RbacPermissionUpdate {
                    action: format!(
                        "{RBAC_ROLES_PATH}/{role_id}/permissions/{}",
                        permission.permission().as_str()
                    ),
                    csrf_token: rbac_csrf(authority),
                    expected_authorization_revision: authority
                        .authorization_revision
                        .value()
                        .to_string(),
                    expected_revision: role.revision().value().to_string(),
                    operation: if permission.granted() {
                        "remove"
                    } else {
                        "add"
                    },
                }),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let current_href = format!("{RBAC_ROLES_PATH}/{role_id}");
    let return_path =
        LoginReturnPath::new(current_href.clone()).map_err(|_| ModelError::InvalidData)?;
    serialize_request(
        assets,
        csp_nonce,
        RbacRoleDetailPage {
            kind: "role-detail",
            shell: rbac_shell(
                context,
                mutation,
                &return_path,
                format!("{} · Access management · Automata", role.display_name()),
            )?,
            management_nav: rbac_management_navigation("roles"),
            heading: role.display_name().to_owned(),
            summary: "Review this role and its explicit permission grants.",
            role: role_summary,
            permissions,
            notice,
            update: role_update_authority.map(|authority| RbacRoleUpdate {
                action: format!("{RBAC_ROLES_PATH}/{role_id}"),
                csrf_token: rbac_csrf(authority),
                expected_authorization_revision: authority
                    .authorization_revision
                    .value()
                    .to_string(),
                expected_revision: role.revision().value().to_string(),
            }),
            delete: role_authority.map(|authority| RbacRoleDelete {
                action: format!("{RBAC_ROLES_PATH}/{role_id}/delete"),
                csrf_token: rbac_csrf(authority),
                expected_authorization_revision: authority
                    .authorization_revision
                    .value()
                    .to_string(),
                expected_revision: role.revision().value().to_string(),
            }),
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "page data, coherent options, read fence, and shell authority stay explicit"
)]
pub(super) fn rbac_direct_binding_list(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    request_cursor: Option<&str>,
    notice: Option<&'static str>,
    data: &RbacDirectBindingListData,
    capabilities: Option<&ManagementMutationCapabilities>,
    grant_options: Option<&DirectBindingGrantOptionsState>,
) -> Result<String, ModelError> {
    if context.viewer().is_none()
        || data.bindings.len() > MAX_RBAC_BINDINGS
        || !all_unique(data.bindings.iter().map(ManagementRoleBindingRecord::id))
        || !valid_rbac_binding_cursor(request_cursor)
        || !valid_rbac_binding_cursor(data.next_cursor.as_deref())
        || request_cursor.is_some_and(|cursor| data.next_cursor.as_deref() == Some(cursor))
    {
        return Err(ModelError::InvalidData);
    }
    let binding_authority = rbac_form_authority(
        mutation,
        capabilities,
        data.mutation_authorization_revision,
        capabilities.is_some_and(|capabilities| capabilities.role_bindings_manage()),
    )?;
    if grant_options.is_some() && binding_authority.is_none() {
        return Err(ModelError::InvalidData);
    }
    let bindings = data
        .bindings
        .iter()
        .map(|binding| rbac_binding(context, binding, binding_authority))
        .collect::<Result<Vec<_>, _>>()?;
    let (grant, read_only_reason) = rbac_direct_grant(
        context,
        binding_authority,
        data.mutation_authorization_revision,
        grant_options,
        capabilities,
    )?;
    let current_href = rbac_list_href(RBAC_DIRECT_BINDINGS_PATH, request_cursor);
    let return_path =
        LoginReturnPath::new(current_href.clone()).map_err(|_| ModelError::InvalidData)?;
    serialize_request(
        assets,
        csp_nonce,
        RbacDirectBindingListPage {
            kind: "direct-binding-list",
            shell: rbac_shell(
                context,
                mutation,
                &return_path,
                "Direct bindings · Access management · Automata".to_owned(),
            )?,
            management_nav: rbac_management_navigation("direct-bindings"),
            heading: "Direct bindings",
            summary: "Review exact direct and provider-observed role assignments and scopes.",
            notice,
            grant,
            read_only_reason,
            pagination: Pagination {
                previous_href: None,
                next_href: data
                    .next_cursor
                    .as_deref()
                    .map(|cursor| rbac_list_href(RBAC_DIRECT_BINDINGS_PATH, Some(cursor))),
                label: pluralized(data.bindings.len(), "binding", "bindings"),
            },
            bindings,
        },
    )
}

fn valid_rbac_role_cursor(cursor: Option<&str>) -> bool {
    cursor.is_none_or(|cursor| RoleId::new(cursor).is_ok())
}

fn valid_rbac_binding_cursor(cursor: Option<&str>) -> bool {
    cursor.is_none_or(|cursor| ManagementRoleBindingCursor::new(cursor).is_ok())
}

fn rbac_role_summary(role: &RoleRecord) -> Result<RbacRoleSummary, ModelError> {
    if !is_safe_display_text(role.display_name(), 255)
        || role.permissions().len() > MAX_RBAC_PERMISSIONS
    {
        return Err(ModelError::InvalidData);
    }
    let id = role.id().to_string();
    Ok(RbacRoleSummary {
        href: format!("{RBAC_ROLES_PATH}/{id}"),
        id,
        name: role.name().as_str().to_owned(),
        display_name: role.display_name().to_owned(),
        kind: match role.kind() {
            RoleKind::BuiltIn => "built-in",
            RoleKind::Custom => "custom",
        },
        immutable: role.immutable(),
        permission_count: role.permissions().len(),
    })
}

fn rbac_user_role_assignment(
    context: &RequestContext,
    binding: &ManagementRoleBindingRecord,
) -> Result<RbacUserRoleAssignment, ModelError> {
    let id = binding.id().to_string();
    let role_id = binding.role().id().to_string();
    if !is_safe_display_text(binding.role().display_name(), 255) {
        return Err(ModelError::InvalidData);
    }
    Ok(RbacUserRoleAssignment {
        binding_href: RBAC_DIRECT_BINDINGS_PATH.to_owned(),
        binding_id: id,
        role_href: format!("{RBAC_ROLES_PATH}/{role_id}"),
        role_id,
        role_name: binding.role().name().as_str().to_owned(),
        role_display_name: binding.role().display_name().to_owned(),
        scope: rbac_scope(context, binding.scope())?,
        source: rbac_binding_source(binding.source()),
        status: rbac_binding_status(binding.status()),
        valid_until: binding
            .valid_until()
            .map(management_timestamp)
            .transpose()?,
    })
}

fn rbac_binding(
    context: &RequestContext,
    binding: &ManagementRoleBindingRecord,
    authority: Option<RbacFormAuthority<'_>>,
) -> Result<RbacBinding, ModelError> {
    let principal = rbac_managed_user(binding.principal())?;
    let principal_label = binding
        .principal()
        .display_name()
        .unwrap_or_else(|| binding.principal().provider_login());
    if !is_safe_display_text(principal_label, 255)
        || !is_safe_display_text(binding.role().display_name(), 255)
    {
        return Err(ModelError::InvalidData);
    }
    let role_id = binding.role().id().to_string();
    Ok(RbacBinding {
        id: binding.id().to_string(),
        revision: binding.revision().value().to_string(),
        principal: RbacBindingPrincipal {
            id: principal.id,
            href: principal.href,
            label: principal_label.to_owned(),
        },
        role: RbacBindingRole {
            href: format!("{RBAC_ROLES_PATH}/{role_id}"),
            id: role_id,
            name: binding.role().name().as_str().to_owned(),
            label: binding.role().display_name().to_owned(),
        },
        scope: rbac_scope(context, binding.scope())?,
        source: rbac_binding_source(binding.source()),
        status: rbac_binding_status(binding.status()),
        valid_until: binding
            .valid_until()
            .map(management_timestamp)
            .transpose()?,
        revoke: authority
            .filter(|_| {
                binding.source().is_direct() && binding.status() == RoleBindingStatus::Active
            })
            .filter(|_| revision_can_advance(binding.revision()))
            .map(|authority| RbacBindingRevoke {
                action: format!("{RBAC_DIRECT_BINDINGS_PATH}/{}/revoke", binding.id()),
                csrf_token: rbac_csrf(authority),
                expected_authorization_revision: authority
                    .authorization_revision
                    .value()
                    .to_string(),
                expected_revision: binding.revision().value().to_string(),
            }),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "all fail-closed coherent grant-option states remain visible in one projection"
)]
fn rbac_direct_grant(
    _context: &RequestContext,
    authority: Option<RbacFormAuthority<'_>>,
    page_authorization_revision: ManagementRevision,
    grant_options: Option<&DirectBindingGrantOptionsState>,
    capabilities: Option<&ManagementMutationCapabilities>,
) -> Result<(Option<RbacDirectGrant>, Option<&'static str>), ModelError> {
    let Some(capabilities) = capabilities else {
        if grant_options.is_some() {
            return Err(ModelError::InvalidData);
        }
        return Ok((None, Some("management-unavailable")));
    };
    if !capabilities.role_bindings_manage() {
        if grant_options.is_some() || authority.is_some() {
            return Err(ModelError::InvalidData);
        }
        return Ok((None, Some("not-authorized")));
    }
    let Some(authority) = authority else {
        return Err(ModelError::InvalidData);
    };
    let Some(grant_options) = grant_options else {
        return Ok((None, Some("options-unavailable")));
    };
    let options = match grant_options {
        DirectBindingGrantOptionsState::Overflow {
            authorization_revision,
            ..
        } => {
            if *authorization_revision != page_authorization_revision {
                return Err(ModelError::InvalidData);
            }
            return Ok((None, Some("options-overflow")));
        }
        DirectBindingGrantOptionsState::Available(options) => options,
    };
    if options.authorization_revision() != page_authorization_revision {
        return Err(ModelError::InvalidData);
    }
    let principals = options
        .principals()
        .iter()
        .map(|option| {
            if !is_safe_display_text(option.display_name(), 255) {
                return Err(ModelError::InvalidData);
            }
            Ok(RbacSelectOption {
                value: option.principal_id().to_string(),
                label: option.display_name().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let roles = options
        .roles()
        .iter()
        .map(|option| {
            if !is_safe_display_text(option.display_name(), 255) {
                return Err(ModelError::InvalidData);
            }
            Ok(RbacSelectOption {
                value: option.role_id().to_string(),
                label: option.display_name().to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if principals.is_empty() || roles.is_empty() {
        return Ok((None, Some("no-options")));
    }
    let mut scopes = Vec::with_capacity(
        1_usize
            .checked_add(options.repositories().len())
            .and_then(|count| count.checked_add(options.runner_groups().len()))
            .ok_or(ModelError::InvalidData)?,
    );
    scopes.push(RbacSelectOption {
        value: "tenant".to_owned(),
        label: "Entire tenant".to_owned(),
    });
    for option in options.repositories() {
        if !is_safe_display_text(option.display_name(), 255) {
            return Err(ModelError::InvalidData);
        }
        scopes.push(RbacSelectOption {
            value: format!("repository:{}", option.repository_id()),
            label: format!("Repository · {}", option.display_name()),
        });
    }
    for option in options.runner_groups() {
        if !is_safe_display_text(option.display_name(), 255) {
            return Err(ModelError::InvalidData);
        }
        scopes.push(RbacSelectOption {
            value: format!("runner-group:{}", option.runner_group_id()),
            label: format!("Runner group · {}", option.display_name()),
        });
    }
    Ok((
        Some(RbacDirectGrant {
            action: RBAC_DIRECT_BINDINGS_PATH,
            csrf_token: rbac_csrf(authority),
            expected_authorization_revision: authority.authorization_revision.value().to_string(),
            principals,
            roles,
            scopes,
        }),
        None,
    ))
}

fn rbac_scope(
    context: &RequestContext,
    scope: &ManagementScopeRecord,
) -> Result<RbacScope, ModelError> {
    if scope.scope().tenant_id() != context.tenant_id()
        || !is_safe_display_text(scope.display_name(), 255)
    {
        return Err(ModelError::InvalidData);
    }
    Ok(match scope.scope() {
        AuthorizationScope::Tenant { .. } => RbacScope::Tenant {
            label: scope.display_name().to_owned(),
        },
        AuthorizationScope::Repository { .. } => RbacScope::Repository {
            label: scope.display_name().to_owned(),
        },
        AuthorizationScope::RunnerGroup { .. } => RbacScope::RunnerGroup {
            label: scope.display_name().to_owned(),
        },
    })
}

const fn rbac_binding_source(source: ManagementRoleBindingSource) -> &'static str {
    match source {
        ManagementRoleBindingSource::Direct(_) => "direct",
        ManagementRoleBindingSource::ProviderObserved { .. } => "provider-observed",
    }
}

const fn rbac_binding_status(status: RoleBindingStatus) -> &'static str {
    match status {
        RoleBindingStatus::Active => "active",
        RoleBindingStatus::Revoked => "revoked",
    }
}

fn management_timestamp(value: UnixTimestamp) -> Result<Timestamp, ModelError> {
    let seconds = i64::try_from(value.as_seconds()).map_err(|_| ModelError::InvalidData)?;
    timestamp_seconds(seconds)
}

pub(super) fn repository_directory(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    request: &RepositoryDirectoryRequestData,
    data: &RepositoryDirectoryData,
) -> Result<String, ModelError> {
    if request.limit != REPOSITORY_PAGE_SIZE
        || data.repositories.len() > REPOSITORY_PAGE_SIZE
        || data.repositories.iter().any(|item| {
            !valid_repository(&item.repository)
                || (item.repository.settings_visible && context.viewer().is_none())
                || item.repository.settings_visible
                    != matches!(
                        item.settings_destination,
                        Some(RepositorySettingsDestination::Access)
                    )
                || (item.settings_destination.is_some() && context.viewer().is_none())
        })
        || !all_unique(data.repositories.iter().map(|item| &item.repository.id))
        || !all_unique(data.repositories.iter().map(|item| {
            format!(
                "{}/{}",
                item.repository.owner.to_ascii_lowercase(),
                item.repository.name.to_ascii_lowercase()
            )
        }))
    {
        return Err(ModelError::InvalidData);
    }
    let current_href = request.cursor.as_deref().map_or_else(
        || REPOSITORIES_PATH.to_owned(),
        |cursor| query_href(REPOSITORIES_PATH, &[("cursor", cursor)]),
    );
    let return_path = login_return_path(current_href, REPOSITORIES_PATH.to_owned())?;
    let repositories = data
        .repositories
        .iter()
        .map(repository_directory_item)
        .collect::<Result<Vec<_>, _>>()?;
    serialize_request(
        assets,
        csp_nonce,
        RepositoryDirectoryPage {
            kind: "repository-directory",
            shell: global_shell(
                context,
                mutation,
                REPOSITORIES_PATH,
                &return_path,
                "Repositories · Automata".to_owned(),
            )?,
            heading: "Repositories",
            summary: "Browse repositories available under your current access.",
            pagination: RepositoryDirectoryPagination {
                next_href: data
                    .next_cursor
                    .as_deref()
                    .map(|cursor| query_href(REPOSITORIES_PATH, &[("cursor", cursor)])),
                label: format!(
                    "{} on this page",
                    pluralized(repositories.len(), "repository", "repositories")
                ),
            },
            repositories,
        },
    )
}

fn repository_directory_item(
    data: &RepositoryDirectoryItemData,
) -> Result<RepositoryDirectoryItem, ModelError> {
    let paths = RepositoryPaths::new(&data.repository);
    let source = GitHubSourceLinks::from_repository(&data.repository)?;
    Ok(RepositoryDirectoryItem {
        owner: data.repository.owner.clone(),
        name: data.repository.name.clone(),
        source_href: source.repository_href(),
        actions_href: data.actions_visible.then(|| paths.actions.clone()),
        settings_href: data
            .settings_destination
            .map(|destination| match destination {
                RepositorySettingsDestination::Access => paths.settings.clone(),
                RepositorySettingsDestination::Secrets => paths.secrets.clone(),
            }),
    })
}

pub(super) fn installation_setup(
    assets: ClientAssetManifest,
    csp_nonce: String,
) -> Result<String, ModelError> {
    serialize_request(
        assets,
        csp_nonce,
        SetupPage {
            kind: "setup",
            shell: setup_shell(),
            form: SetupForm {
                action: GITHUB_SETUP_WEB_BEGIN_PATH,
                return_path: SETUP_RETURN_PATH,
            },
        },
    )
}

pub(super) fn run_list(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    request: &RunListRequestData,
    data: &RunListData,
) -> Result<String, ModelError> {
    let selected_status = request.status;
    let branch = request.git_ref.as_deref();
    let request_cursor = request.cursor.as_deref();
    let request_workflow_cursor = request.workflow_cursor.as_deref();
    let selected_workflow_id = data.selected_workflow.as_ref().map(|workflow| workflow.id);
    if !valid_run_list_data(context, request, data) {
        return Err(ModelError::InvalidData);
    }

    let paths = RepositoryPaths::new(&data.repository);
    let source = GitHubSourceLinks::from_repository(&data.repository)?;
    let action =
        selected_workflow_id.map_or_else(|| paths.actions.clone(), |id| paths.workflow(id));
    let page_runs = data
        .runs
        .iter()
        .map(|run| run_list_item(&paths, &source, run))
        .collect::<Result<Vec<_>, _>>()?;
    let workflow_navigation = workflow_navigation(&paths, &action, request, data);
    let pagination = Pagination {
        previous_href: data.previous_cursor.as_deref().map(|cursor| {
            run_list_href(
                &action,
                selected_status,
                branch,
                Some(cursor),
                request_workflow_cursor,
            )
        }),
        next_href: data.next_cursor.as_deref().map(|cursor| {
            run_list_href(
                &action,
                selected_status,
                branch,
                Some(cursor),
                request_workflow_cursor,
            )
        }),
        label: pluralized(page_runs.len(), "workflow run", "workflow runs"),
    };
    let repository = repository_model(&data.repository, &paths, &source);
    let summary = format!(
        "Workflow runs for {}/{}.",
        data.repository.owner, data.repository.name
    );
    let return_path = login_return_path(
        run_list_href(
            &action,
            selected_status,
            branch,
            request_cursor,
            request_workflow_cursor,
        ),
        action.clone(),
    )?;
    let shell = shell(
        context,
        mutation,
        &paths,
        &return_path,
        "Workflow runs · Automata".to_owned(),
    )?;

    serialize_request(
        assets,
        csp_nonce,
        RunListPage {
            kind: "run-list",
            shell,
            repository,
            heading: "Workflow runs",
            summary,
            filters: RunFilters {
                action: action.clone(),
                status: status_filter_value(selected_status),
                branch: branch.unwrap_or_default().to_owned(),
                clear_href: action,
            },
            workflow_navigation,
            runs: page_runs,
            pagination,
        },
    )
}

fn valid_run_list_data(
    context: &RequestContext,
    request: &RunListRequestData,
    data: &RunListData,
) -> bool {
    data.runs.len() <= MAX_RUNS
        && data.workflows.len() <= MAX_WORKFLOWS
        && valid_repository(&data.repository)
        && (!data.repository.settings_visible || context.viewer().is_some())
        && all_unique(data.workflows.iter().map(|workflow| workflow.id))
        && data
            .workflows
            .iter()
            .all(|workflow| valid_text(&workflow.name))
        && data
            .selected_workflow
            .as_ref()
            .is_none_or(|workflow| valid_text(&workflow.name))
        && all_unique(data.runs.iter().map(|run| run.id))
        && data.runs.iter().all(valid_run)
        && data.selected_workflow.as_ref().map(|workflow| workflow.id) == request.workflow_id
        && data.selected_workflow.as_ref().is_none_or(|selected| {
            data.workflows
                .iter()
                .find(|workflow| workflow.id == selected.id)
                .is_none_or(|workflow| workflow == selected)
        })
}

fn workflow_navigation(
    paths: &RepositoryPaths,
    action: &str,
    request: &RunListRequestData,
    data: &RunListData,
) -> Option<WorkflowNavigation> {
    (!data.workflows.is_empty() || data.selected_workflow.is_some()).then(|| WorkflowNavigation {
        selected_workflow: data
            .selected_workflow
            .as_ref()
            .map(|workflow| workflow_navigation_item(paths, workflow)),
        workflows: data
            .workflows
            .iter()
            .map(|workflow| workflow_navigation_item(paths, workflow))
            .collect(),
        pagination: Pagination {
            previous_href: data.workflow_previous_cursor.as_deref().map(|cursor| {
                run_list_href(
                    action,
                    request.status,
                    request.git_ref.as_deref(),
                    request.cursor.as_deref(),
                    Some(cursor),
                )
            }),
            next_href: data.workflow_next_cursor.as_deref().map(|cursor| {
                run_list_href(
                    action,
                    request.status,
                    request.git_ref.as_deref(),
                    request.cursor.as_deref(),
                    Some(cursor),
                )
            }),
            label: pluralized(data.workflows.len(), "workflow", "workflows"),
        },
    })
}

fn workflow_navigation_item(
    paths: &RepositoryPaths,
    workflow: &super::data::WorkflowDefinition,
) -> WorkflowNavigationItem {
    WorkflowNavigationItem {
        id: workflow.id.to_string(),
        name: workflow.name.clone(),
        href: paths.workflow(workflow.id),
        enabled: workflow.enabled,
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn run_detail(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    request: &RunDetailRequestData,
    data: &RunDetailData,
) -> Result<String, ModelError> {
    if !valid_repository(&data.repository)
        || (data.repository.settings_visible && context.viewer().is_none())
        || !valid_run(&data.run)
        || data.jobs.items.len() > MAX_JOBS
        || data.artifacts.items.len() > MAX_ARTIFACTS
        || !all_unique(data.jobs.items.iter().map(|job| job.id))
        || !all_unique(data.artifacts.items.iter().map(|artifact| artifact.id))
        || data.jobs.items.iter().any(|job| !valid_job(job))
        || data
            .artifacts
            .items
            .iter()
            .any(|artifact| !valid_artifact(artifact))
    {
        return Err(ModelError::InvalidData);
    }

    let paths = RepositoryPaths::new(&data.repository);
    let source = GitHubSourceLinks::from_repository(&data.repository)?;
    let title = run_title(&data.run);
    let jobs = data
        .jobs
        .items
        .iter()
        .map(|job| job_model(&paths, data.run.id, job))
        .collect::<Result<Vec<_>, _>>()?;
    let artifacts = data
        .artifacts
        .items
        .iter()
        .map(|artifact| artifact_model(&paths, data.run.id, artifact))
        .collect::<Result<Vec<_>, _>>()?;
    let run = RunDetail {
        number: data.run.number.to_string(),
        name: title.clone(),
        workflow_name: data.run.workflow.name.clone(),
        workflow_href: paths.workflow(data.run.workflow.id),
        status: status(data.run.status),
        source_ref: source.source_ref(data.run.git_ref.as_deref())?,
        event: data.run.event.clone(),
        actor: data.run.actor.clone(),
        commit: source.commit(&data.run)?,
        created_at: timestamp(data.run.created_at)?,
        duration_label: elapsed_duration_label(Some(data.run.created_at), data.run.finished_at),
        attempt: data.run.attempt,
    };
    let run_href = paths.run(data.run.id);
    let rerun = mutation
        .filter(|_| {
            matches!(
                data.run.status,
                super::data::Status::Succeeded
                    | super::data::Status::Failed
                    | super::data::Status::Cancelled
                    | super::data::Status::TimedOut
                    | super::data::Status::Skipped
                    | super::data::Status::Lost
            )
        })
        .map(|mutation| RunRerunControls {
            endpoint: format!("{run_href}/reruns"),
            csrf_token: mutation.csrf_token.expose_secret().to_owned(),
            failed_jobs_available: matches!(
                data.run.status,
                super::data::Status::Failed
                    | super::data::Status::TimedOut
                    | super::data::Status::Lost
            ),
        });
    let job_pagination = Pagination {
        previous_href: data
            .job_previous_cursor
            .as_deref()
            .map(|cursor| run_detail_href(&run_href, Some(cursor))),
        next_href: data
            .job_next_cursor
            .as_deref()
            .map(|cursor| run_detail_href(&run_href, Some(cursor))),
        label: pluralized(jobs.len(), "job", "jobs"),
    };
    let return_path = login_return_path(
        run_detail_href(&run_href, request.job_cursor.as_deref()),
        paths.actions.clone(),
    )?;
    let shell = shell(
        context,
        mutation,
        &paths,
        &return_path,
        format!("{title} · {} · Automata", data.run.workflow.name),
    )?;

    serialize_request(
        assets,
        csp_nonce,
        RunDetailPage {
            kind: "run-detail",
            shell,
            repository: repository_model(&data.repository, &paths, &source),
            run,
            jobs: VisibleCollection {
                visibility: collection_visibility(data.jobs.visibility),
                items: jobs,
            },
            job_pagination,
            artifacts: VisibleCollection {
                visibility: collection_visibility(data.artifacts.visibility),
                items: artifacts,
            },
            rerun,
        },
    )
}

pub(super) fn job_log(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    data: JobLogData,
) -> Result<String, ModelError> {
    if !valid_job_log_data(&data)
        || (data.repository.settings_visible && context.viewer().is_none())
    {
        return Err(ModelError::InvalidData);
    }
    let paths = RepositoryPaths::new(&data.repository);
    let source = GitHubSourceLinks::from_repository(&data.repository)?;
    let run_href = paths.run(data.run.id);
    let job_href = paths.job(data.run.id, data.job.id);
    let selected_job = JobLogJob {
        id: data.job.id.to_string(),
        name: data.job.name.clone(),
        href: job_href.clone(),
        attempt: data.job.attempt.ok_or(ModelError::InvalidData)?,
        runner_label: data.job.runner_label.clone(),
        status: status(data.job.status),
        started_at: data.job.started_at.map(timestamp).transpose()?,
        duration_label: elapsed_duration_label(data.job.started_at, data.job.finished_at),
    };
    let navigation = data
        .jobs
        .into_iter()
        .map(|job| JobLogNavigationItem {
            id: job.id.to_string(),
            name: job.name,
            href: Some(paths.job(data.run.id, job.id)),
            status: status(job.status),
        })
        .collect::<Vec<_>>();
    let navigation_pagination = Pagination {
        previous_href: data
            .previous_navigation_job_id
            .map(|job_id| paths.job(data.run.id, job_id)),
        next_href: data
            .next_navigation_job_id
            .map(|job_id| paths.job(data.run.id, job_id)),
        label: pluralized(navigation.len(), "job", "jobs"),
    };
    let live = data
        .live_available
        .then(|| job_log_live(format!("{job_href}/live-ticket")));
    let title = format!("{} logs · Automata", data.job.name);
    let notice = job_log_notice(data.job.status);
    let return_path = login_return_path(job_href.clone(), job_href.clone())?;

    serialize_request(
        assets,
        csp_nonce,
        JobLogPage {
            kind: "job-log",
            shell: shell(context, mutation, &paths, &return_path, title)?,
            repository: repository_model(&data.repository, &paths, &source),
            run: JobLogRun {
                number: data.run.number.to_string(),
                name: run_title(&data.run),
                href: run_href,
                workflow_name: data.run.workflow.name.clone(),
                workflow_href: paths.workflow(data.run.workflow.id),
                attempt: data.run.attempt,
            },
            jobs: navigation,
            navigation_pagination,
            job: selected_job,
            log_visibility: collection_visibility(data.log_visibility),
            live,
            notice,
        },
    )
}

pub(super) fn deep_link_sign_in(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    return_path: String,
) -> Result<String, ModelError> {
    if context.viewer().is_some() || context.sign_in_action().is_none() {
        return Err(ModelError::InvalidData);
    }
    let return_path = LoginReturnPath::new(return_path).map_err(|_| ModelError::InvalidData)?;
    serialize_request(
        assets,
        csp_nonce,
        DeepLinkSignInPage {
            kind: "deep-link-sign-in",
            shell: global_shell(
                context,
                None,
                REPOSITORIES_PATH,
                &return_path,
                "Sign in to view this run · Automata".to_owned(),
            )?,
        },
    )
}

fn valid_job_log_data(data: &JobLogData) -> bool {
    valid_repository(&data.repository)
        && valid_run(&data.run)
        && valid_job(&data.job)
        && !data.jobs.is_empty()
        && data.jobs.len() <= MAX_JOBS
        && all_unique(data.jobs.iter().map(|job| job.id))
        && !(data.previous_navigation_job_id.is_some()
            && data.previous_navigation_job_id == data.next_navigation_job_id)
        && data
            .previous_navigation_job_id
            .is_none_or(|id| !data.jobs.iter().any(|job| job.id == id))
        && data
            .next_navigation_job_id
            .is_none_or(|id| !data.jobs.iter().any(|job| job.id == id))
        && data
            .jobs
            .iter()
            .find(|job| job.id == data.job.id)
            .is_some_and(|job| {
                job.name == data.job.name && job.status == data.job.status && job.logs_available
            })
        && (data.log_visibility == CollectionVisibility::Full) == data.job.logs_available
        && (data.log_visibility == CollectionVisibility::Full || !data.live_available)
}

pub(super) fn repository_settings(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    data: RepositorySettingsData,
    mutation: Option<ShellMutation<'_>>,
) -> Result<String, ModelError> {
    let RepositorySettingsData {
        repository,
        policy,
        revision,
        editable,
        secrets_visible,
    } = data;
    if !valid_repository(&repository)
        || !repository.settings_visible
        || context.viewer().is_none()
        || revision == 0
        || revision > i64::MAX.unsigned_abs()
        || (editable && revision == i64::MAX.unsigned_abs())
    {
        return Err(ModelError::InvalidData);
    }
    let paths = RepositoryPaths::new(&repository);
    let source = GitHubSourceLinks::from_repository(&repository)?;
    let update = match (editable, mutation) {
        (true, Some(mutation)) => Some(RepositorySettingsUpdate {
            action: paths.settings.clone(),
            csrf_token: mutation.csrf_token.expose_secret().to_owned(),
        }),
        (false, _) => None,
        (true, None) => return Err(ModelError::InvalidData),
    };
    let summary = format!(
        "Choose who can view new workflow runs and their output in {}/{}.",
        repository.owner, repository.name
    );
    let return_path = login_return_path(paths.settings.clone(), paths.actions.clone())?;
    serialize_request(
        assets,
        csp_nonce,
        RepositorySettingsPage {
            kind: "repository-settings",
            shell: shell(
                context,
                mutation,
                &paths,
                &return_path,
                "Repository access settings · Automata".to_owned(),
            )?,
            repository: repository_model(&repository, &paths, &source),
            heading: "Repository access",
            summary,
            settings_navigation: RepositorySettingsNavigation {
                access_href: Some(paths.settings.clone()),
                secrets_href: secrets_visible.then(|| paths.secrets.clone()),
                current: "access",
            },
            revision: revision.to_string(),
            policy: publication_policy(policy),
            update,
        },
    )
}

pub(super) fn repository_secrets(
    assets: ClientAssetManifest,
    csp_nonce: String,
    context: &RequestContext,
    mutation: ShellMutation<'_>,
    request_after: Option<automata_ci_store::RepositorySecretId>,
    notice: Option<&'static str>,
    data: &RepositorySecretsData,
) -> Result<String, ModelError> {
    let repository = RepositoryData {
        id: data.repository_id.as_uuid().hyphenated().to_string(),
        scm_provider: GITHUB_SCM_PROVIDER.to_owned(),
        owner: data.owner.clone(),
        name: data.repository.clone(),
        settings_visible: true,
    };
    if !valid_repository(&repository)
        || context.viewer().is_none()
        || data.authorization_revision.value() > i64::MAX.unsigned_abs()
        || data.rows.len() > MAX_REPOSITORY_SECRETS
        || !all_unique(data.rows.iter().map(|row| row.metadata.id()))
        || !all_unique(data.rows.iter().map(|row| row.metadata.name().as_str()))
        || data
            .rows
            .iter()
            .any(|row| !valid_repository_secret_row(row, data.repository_id))
        || request_after.is_some_and(|after| data.rows.iter().any(|row| row.metadata.id() <= after))
    {
        return Err(ModelError::InvalidData);
    }
    let paths = RepositoryPaths::new(&repository);
    let source = GitHubSourceLinks::from_repository(&repository)?;
    let authorization_revision = data.authorization_revision.value().to_string();
    let csrf_token = mutation.csrf_token.expose_secret().to_owned();
    let create = data.create.map(|create| {
        repository_secret_create(&paths, create, &csrf_token, &authorization_revision)
    });
    let provider = repository_secret_provider(
        &paths,
        data.provider.as_ref(),
        &csrf_token,
        &authorization_revision,
    );
    let secrets =
        repository_secret_models(&paths, &data.rows, &csrf_token, &authorization_revision)?;
    let (current_href, pagination) =
        repository_secret_pagination(&paths, request_after, data.next_after, secrets.len());
    let summary = format!(
        "Review encrypted secret metadata stored for {}/{}.",
        repository.owner, repository.name
    );
    let return_path = login_return_path(current_href, paths.settings.clone())?;
    let mut repository_model = repository_model(&repository, &paths, &source);
    repository_model.settings_href = Some(if data.access_visible {
        paths.settings.clone()
    } else {
        paths.secrets.clone()
    });
    serialize_request(
        assets,
        csp_nonce,
        RepositorySecretsPage {
            kind: "repository-secrets",
            shell: shell(
                context,
                Some(mutation),
                &paths,
                &return_path,
                "Repository secrets · Automata".to_owned(),
            )?,
            repository: repository_model,
            heading: "Repository secrets",
            summary,
            settings_navigation: RepositorySettingsNavigation {
                access_href: data.access_visible.then(|| paths.settings.clone()),
                secrets_href: Some(paths.secrets.clone()),
                current: "secrets",
            },
            notice,
            maximum_value_bytes: crate::app::secret_api::MAX_SECRET_INGRESS_BYTES,
            provider,
            create,
            secrets,
            pagination,
        },
    )
}

fn repository_secret_provider(
    paths: &RepositoryPaths,
    provider: Option<&BuiltinSecretProviderInspection>,
    csrf_token: &str,
    authorization_revision: &str,
) -> Option<RepositorySecretProvider> {
    provider.map(|provider| RepositorySecretProvider {
        id: BUILTIN_SECRET_PROVIDER_ID,
        state: provider_state(provider.state()),
        health: provider_health(provider.health()),
        activation: provider
            .activation()
            .filter(|activation| activation.expected_revision().value() < i64::MAX.unsigned_abs())
            .map(|activation| RepositorySecretProviderActivation {
                action: format!("{}/provider/activate", paths.secrets),
                csrf_token: csrf_token.to_owned(),
                expected_authorization_revision: authorization_revision.to_owned(),
                expected_revision: activation.expected_revision().value().to_string(),
            }),
    })
}

fn repository_secret_models(
    paths: &RepositoryPaths,
    rows: &[RepositorySecretRow],
    csrf_token: &str,
    authorization_revision: &str,
) -> Result<Vec<RepositorySecret>, ModelError> {
    rows.iter()
        .map(|row| {
            let id = row.metadata.id().as_uuid().hyphenated().to_string();
            let action_root = format!("{}/{}", paths.secrets, id);
            Ok(RepositorySecret {
                id,
                name: row.metadata.name().as_str().to_owned(),
                provider_id: row.metadata.provider_id().as_str().to_owned(),
                state: secret_state(row.metadata.state()),
                current_version: row
                    .metadata
                    .current_version_number()
                    .map(|version| version.to_string()),
                revision: row.metadata.revision().value().to_string(),
                updated_at: timestamp(row.metadata.updated_at())?,
                replace: row
                    .replace_mutation_id
                    .map(|mutation_id| RepositorySecretReplace {
                        action: format!("{action_root}/replace"),
                        csrf_token: csrf_token.to_owned(),
                        expected_authorization_revision: authorization_revision.to_owned(),
                        mutation_id: mutation_id.as_uuid().hyphenated().to_string(),
                    }),
                delete: row.deletable.then(|| RepositorySecretDelete {
                    action: format!("{action_root}/delete"),
                    csrf_token: csrf_token.to_owned(),
                    expected_authorization_revision: authorization_revision.to_owned(),
                }),
            })
        })
        .collect()
}

fn repository_secret_pagination(
    paths: &RepositoryPaths,
    request_after: Option<RepositorySecretId>,
    next_after: Option<RepositorySecretId>,
    count: usize,
) -> (String, RepositorySecretPagination) {
    let cursor_href = |after: RepositorySecretId| {
        query_href(
            &paths.secrets,
            &[("after", &after.as_uuid().hyphenated().to_string())],
        )
    };
    let current_href = request_after.map_or_else(|| paths.secrets.clone(), cursor_href);
    let pagination = RepositorySecretPagination {
        first_href: request_after.map(|_| paths.secrets.clone()),
        next_href: next_after.map(cursor_href),
        label: pluralized(count, "secret", "secrets"),
    };
    (current_href, pagination)
}

fn repository_secret_create(
    paths: &RepositoryPaths,
    create: RepositorySecretCreateCapability,
    csrf_token: &str,
    authorization_revision: &str,
) -> RepositorySecretCreate {
    RepositorySecretCreate {
        action: paths.secrets.clone(),
        csrf_token: csrf_token.to_owned(),
        expected_authorization_revision: authorization_revision.to_owned(),
        secret_id: create.secret_id.as_uuid().hyphenated().to_string(),
        mutation_id: create.mutation_id.as_uuid().hyphenated().to_string(),
    }
}

fn valid_repository_secret_row(
    row: &RepositorySecretRow,
    repository_id: automata_ci_store::RepositoryId,
) -> bool {
    let metadata = &row.metadata;
    metadata.repository_id() == repository_id
        && metadata.provider_id().as_str() == BUILTIN_SECRET_PROVIDER_ID
        && metadata.revision().value() <= i64::MAX.unsigned_abs()
        && metadata.created_at().get() >= 0
        && metadata.updated_at().get() >= metadata.created_at().get()
        && (!row.deletable || metadata.revision().value() < i64::MAX.unsigned_abs())
        && match (metadata.state(), metadata.current_version_number()) {
            (RepositorySecretState::Provisioning, None) => row.replace_mutation_id.is_none(),
            (RepositorySecretState::Active, Some(version)) => version > 0,
            (RepositorySecretState::Disabled, Some(version)) => {
                version > 0 && row.replace_mutation_id.is_none()
            }
            (RepositorySecretState::Provisioning, Some(_))
            | (RepositorySecretState::Active | RepositorySecretState::Disabled, None) => false,
        }
}

const fn secret_state(state: RepositorySecretState) -> &'static str {
    match state {
        RepositorySecretState::Provisioning => "provisioning",
        RepositorySecretState::Active => "active",
        RepositorySecretState::Disabled => "disabled",
    }
}

const fn provider_state(state: BuiltinSecretProviderState) -> &'static str {
    match state {
        BuiltinSecretProviderState::Unconfigured => "unconfigured",
        BuiltinSecretProviderState::Active => "active",
        BuiltinSecretProviderState::Disabled => "disabled",
    }
}

const fn provider_health(health: BuiltinSecretProviderHealth) -> &'static str {
    match health {
        BuiltinSecretProviderHealth::Unknown => "unknown",
        BuiltinSecretProviderHealth::Healthy => "healthy",
        BuiltinSecretProviderHealth::Degraded => "degraded",
        BuiltinSecretProviderHealth::Unavailable => "unavailable",
    }
}

fn serialize_request<P: Serialize>(
    assets: ClientAssetManifest,
    csp_nonce: String,
    page: P,
) -> Result<String, ModelError> {
    let json = serde_json::to_string(&RenderRequest {
        schema_version: RENDER_REQUEST_SCHEMA_VERSION,
        host: RenderHost {
            locale: "en",
            assets: RenderAssets {
                client_entry: assets.script_path,
                stylesheets: assets.stylesheet_paths,
            },
            csp_nonce,
        },
        page,
    })?;
    if json.len() > MAX_RENDER_REQUEST_UTF8_BYTES {
        return Err(ModelError::TooLarge);
    }
    Ok(json)
}

fn shell(
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    paths: &RepositoryPaths,
    return_path: &LoginReturnPath,
    document_title: String,
) -> Result<Shell, ModelError> {
    global_shell(
        context,
        mutation,
        &paths.actions,
        return_path,
        document_title,
    )
}

fn global_shell(
    context: &RequestContext,
    mutation: Option<ShellMutation<'_>>,
    current_actions_href: &str,
    return_path: &LoginReturnPath,
    document_title: String,
) -> Result<Shell, ModelError> {
    if mutation.is_some_and(|mutation| !mutation.csrf_token.has_generated_shape())
        || (context.viewer().is_none() && mutation.is_some())
    {
        return Err(ModelError::InvalidData);
    }
    let on_repository_directory = current_actions_href == REPOSITORIES_PATH;
    let mut navigation = vec![NavigationItem {
        label: "Repositories",
        href: REPOSITORIES_PATH.to_owned(),
        current: on_repository_directory,
    }];
    if !on_repository_directory {
        navigation.push(NavigationItem {
            label: "Actions",
            href: current_actions_href.to_owned(),
            current: true,
        });
    }
    if context.access_management_available() {
        navigation.push(NavigationItem {
            label: "Access",
            href: RBAC_USERS_PATH.to_owned(),
            current: false,
        });
    }
    Ok(Shell {
        product_name: "Automata",
        home_href: REPOSITORIES_PATH.to_owned(),
        sign_in: context.sign_in_action().map(|action| SignIn {
            action: action.clone(),
            return_path: return_path.as_str().to_owned(),
        }),
        sign_out: context.viewer().and_then(|_| {
            mutation.map(|mutation| SignOut {
                action: GITHUB_WEB_LOGOUT_PATH,
                csrf_token: mutation.csrf_token.expose_secret().to_owned(),
            })
        }),
        document_title,
        description: SHELL_DESCRIPTION,
        viewer: context.viewer().map(|viewer| Viewer {
            display_name: if valid_text(&viewer.display_name) {
                viewer.display_name.clone()
            } else {
                "Signed-in user".to_owned()
            },
        }),
        navigation,
    })
}

fn setup_shell() -> Shell {
    Shell {
        product_name: "Automata",
        home_href: SETUP_PATH.to_owned(),
        sign_in: None,
        sign_out: None,
        document_title: "Set up Automata".to_owned(),
        description: SETUP_SHELL_DESCRIPTION,
        viewer: None,
        navigation: vec![NavigationItem {
            label: "Setup",
            href: SETUP_PATH.to_owned(),
            current: true,
        }],
    }
}

fn login_return_path(candidate: String, fallback: String) -> Result<LoginReturnPath, ModelError> {
    LoginReturnPath::new(candidate)
        .or_else(|_| LoginReturnPath::new(fallback))
        .map_err(|_| ModelError::InvalidData)
}

fn repository_model(
    data: &RepositoryData,
    paths: &RepositoryPaths,
    source: &GitHubSourceLinks,
) -> Repository {
    Repository {
        owner: data.owner.clone(),
        name: data.name.clone(),
        source_href: source.repository_href(),
        runs_href: paths.actions.clone(),
        settings_href: data.settings_visible.then(|| paths.settings.clone()),
    }
}

const fn publication_policy(
    policy: RepositoryPublicationPolicy,
) -> RepositoryPublicationPolicyModel {
    RepositoryPublicationPolicyModel {
        dashboard: publication_audience(policy.dashboard()),
        logs: publication_audience(policy.logs()),
        artifacts: publication_audience(policy.artifacts()),
    }
}

const fn publication_audience(audience: OutputVisibility) -> &'static str {
    match audience {
        OutputVisibility::Private => "private",
        OutputVisibility::Authenticated => "authenticated",
        OutputVisibility::Public => "public",
    }
}

fn run_list_item(
    paths: &RepositoryPaths,
    source: &GitHubSourceLinks,
    run: &RunSummary,
) -> Result<RunListItem, ModelError> {
    Ok(RunListItem {
        id: run.id.to_string(),
        number: run.number.to_string(),
        name: run_title(run),
        workflow_name: run.workflow.name.clone(),
        workflow_href: paths.workflow(run.workflow.id),
        href: paths.run(run.id),
        status: status(run.status),
        source_ref: source.source_ref(run.git_ref.as_deref())?,
        event: run.event.clone(),
        actor: run.actor.clone(),
        commit: source.commit(run)?,
        created_at: timestamp(run.created_at)?,
        duration_label: elapsed_duration_label(Some(run.created_at), run.finished_at),
    })
}

fn job_model(
    paths: &RepositoryPaths,
    run_id: automata_ci_core::RunId,
    job: &JobSummary,
) -> Result<Job, ModelError> {
    Ok(Job {
        id: job.id.to_string(),
        name: job.name.clone(),
        href: Some(paths.job(run_id, job.id)),
        runner_label: job.runner_label.clone(),
        status: status(job.status),
        started_at: job.started_at.map(timestamp).transpose()?,
        duration_label: elapsed_duration_label(job.started_at, job.finished_at),
    })
}

const fn collection_visibility(value: CollectionVisibility) -> &'static str {
    match value {
        CollectionVisibility::Full => "full",
        CollectionVisibility::Restricted => "restricted",
    }
}

fn artifact_model(
    paths: &RepositoryPaths,
    run_id: automata_ci_core::RunId,
    artifact: &ArtifactSummary,
) -> Result<Artifact, ModelError> {
    Ok(Artifact {
        id: artifact.id.to_string(),
        name: artifact.name.clone(),
        size_label: size_label(artifact.size),
        digest: artifact.digest.clone(),
        download_href: artifact
            .downloadable
            .then(|| paths.artifact(run_id, artifact.id)),
        expires_at: artifact
            .expires_at_seconds
            .map(timestamp_seconds)
            .transpose()?,
    })
}

fn status(value: DataStatus) -> Status {
    match value {
        DataStatus::Queued => Status {
            label: "Queued",
            tone: "queued",
        },
        DataStatus::InProgress => Status {
            label: "In progress",
            tone: "running",
        },
        DataStatus::Succeeded => Status {
            label: "Succeeded",
            tone: "success",
        },
        DataStatus::Failed => Status {
            label: "Failed",
            tone: "failure",
        },
        DataStatus::Cancelled => Status {
            label: "Cancelled",
            tone: "neutral",
        },
        DataStatus::TimedOut => Status {
            label: "Timed out",
            tone: "failure",
        },
        DataStatus::Skipped => Status {
            label: "Skipped",
            tone: "neutral",
        },
        DataStatus::Lost => Status {
            label: "Lost",
            tone: "warning",
        },
    }
}

const fn job_log_notice(status: DataStatus) -> Option<&'static str> {
    match status {
        DataStatus::Queued => Some("This job is queued. This page updates automatically."),
        DataStatus::InProgress => Some(
            "This job is still running. This page updates automatically as logs are committed.",
        ),
        _ => None,
    }
}

fn run_title(run: &RunSummary) -> String {
    run.title
        .as_ref()
        .or(run.commit_subject.as_ref())
        .cloned()
        .unwrap_or_else(|| run.workflow.name.clone())
}

fn timestamp(value: UnixMillis) -> Result<Timestamp, ModelError> {
    timestamp_from_millis(value.get(), false)
}

fn timestamp_seconds(value: i64) -> Result<Timestamp, ModelError> {
    value
        .checked_mul(1_000)
        .ok_or(ModelError::InvalidData)
        .and_then(|millis| timestamp_from_millis(millis, false))
}

fn timestamp_from_millis(value: i64, time_only: bool) -> Result<Timestamp, ModelError> {
    let nanos = i128::from(value)
        .checked_mul(1_000_000)
        .ok_or(ModelError::InvalidData)?;
    let value =
        OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| ModelError::InvalidData)?;
    let date = value.date();
    let time = value.time();
    let year = date.year();
    if !(0..=9_999).contains(&year) {
        return Err(ModelError::InvalidData);
    }
    let iso = format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        u8::from(date.month()),
        date.day(),
        time.hour(),
        time.minute(),
        time.second()
    );
    let label = if time_only {
        format!(
            "{:02}:{:02}:{:02}",
            time.hour(),
            time.minute(),
            time.second()
        )
    } else {
        format!(
            "{} {} {year}, {:02}:{:02} UTC",
            date.day(),
            month_name(u8::from(date.month())),
            time.hour(),
            time.minute()
        )
    };
    Ok(Timestamp { iso, label })
}

const fn month_name(month: u8) -> &'static str {
    match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "",
    }
}

fn elapsed_duration_label(start: Option<UnixMillis>, end: Option<UnixMillis>) -> Option<String> {
    let milliseconds = start
        .zip(end)
        .and_then(|(start, end)| end.get().checked_sub(start.get()))
        .and_then(|value| u64::try_from(value).ok())?;
    Some(format_duration(milliseconds))
}

fn format_duration(milliseconds: u64) -> String {
    let total_seconds = milliseconds / 1_000;
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn size_label(bytes: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = KIB * 1_024;
    const GIB: u64 = MIB * 1_024;
    if bytes >= GIB {
        scaled_size_label(bytes, GIB, "GiB")
    } else if bytes >= MIB {
        scaled_size_label(bytes, MIB, "MiB")
    } else if bytes >= KIB {
        scaled_size_label(bytes, KIB, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn scaled_size_label(bytes: u64, unit: u64, suffix: &str) -> String {
    let rounded_tenths = (u128::from(bytes) * 10 + u128::from(unit / 2)) / u128::from(unit);
    format!(
        "{}.{:01} {suffix}",
        rounded_tenths / 10,
        rounded_tenths % 10
    )
}

const fn status_filter_value(status: StatusFilter) -> &'static str {
    match status {
        StatusFilter::All => "all",
        StatusFilter::Queued => "queued",
        StatusFilter::InProgress => "in_progress",
        StatusFilter::Completed => "completed",
    }
}

fn pluralized(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[derive(Debug)]
struct GitHubSourceLinks {
    repository: Url,
}

impl GitHubSourceLinks {
    fn from_repository(repository: &RepositoryData) -> Result<Self, ModelError> {
        Self::new(
            &repository.scm_provider,
            &repository.owner,
            &repository.name,
        )
    }

    fn new(provider: &str, owner: &str, name: &str) -> Result<Self, ModelError> {
        if provider != GITHUB_SCM_PROVIDER
            || !valid_github_owner(owner)
            || !valid_github_repository_name(name)
        {
            return Err(ModelError::InvalidData);
        }
        let mut repository =
            Url::parse(GITHUB_SOURCE_ORIGIN).map_err(|_| ModelError::InvalidData)?;
        {
            let mut segments = repository
                .path_segments_mut()
                .map_err(|()| ModelError::InvalidData)?;
            segments.push(owner).push(name);
        }
        Ok(Self { repository })
    }

    fn repository_href(&self) -> String {
        self.repository.to_string()
    }

    fn commit(&self, run: &RunSummary) -> Result<Commit, ModelError> {
        Ok(Commit {
            short_sha: run.head_sha.chars().take(7).collect(),
            message: run.commit_subject.clone(),
            href: self.href(&["commit", &run.head_sha])?,
        })
    }

    fn source_ref(&self, git_ref: Option<&str>) -> Result<Option<SourceRef>, ModelError> {
        let Some(git_ref) = git_ref else {
            return Ok(None);
        };
        if let Some(name) = git_ref.strip_prefix("refs/heads/") {
            return self.tree_ref(name, "branch");
        }
        if let Some(name) = git_ref.strip_prefix("refs/tags/") {
            return self.tree_ref(name, "tag");
        }
        let Some(pull_ref) = git_ref.strip_prefix("refs/pull/") else {
            return Ok(None);
        };
        let mut parts = pull_ref.split('/');
        let (Some(number), Some(target), None) = (parts.next(), parts.next(), parts.next()) else {
            return Ok(None);
        };
        if !valid_pull_request_number(number) || !matches!(target, "head" | "merge") {
            return Ok(None);
        }
        Ok(Some(SourceRef {
            name: format!("pull/{number}/{target}"),
            kind: "ref",
            href: self.href(&["pull", number])?,
        }))
    }

    fn tree_ref(&self, name: &str, kind: &'static str) -> Result<Option<SourceRef>, ModelError> {
        if !valid_source_segment(name) {
            return Ok(None);
        }
        Ok(Some(SourceRef {
            name: name.to_owned(),
            kind,
            href: self.href(&["tree", name])?,
        }))
    }

    fn href(&self, suffix: &[&str]) -> Result<String, ModelError> {
        let mut href = self.repository.clone();
        {
            let mut segments = href
                .path_segments_mut()
                .map_err(|()| ModelError::InvalidData)?;
            for segment in suffix {
                segments.push(segment);
            }
        }
        Ok(href.to_string())
    }
}

fn valid_pull_request_number(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit() && *byte != b'0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok()
}

fn valid_source_segment(value: &str) -> bool {
    has_visible_display_character(value)
        && !matches!(value, "." | "..")
        && !value.chars().any(forbidden_display_character)
}

fn valid_github_owner(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=39).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

fn valid_github_repository_name(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Debug)]
struct RepositoryPaths {
    actions: String,
    settings: String,
    secrets: String,
}

impl RepositoryPaths {
    fn new(repository: &RepositoryData) -> Self {
        let repository_root = format!(
            "/{}/{}",
            encode_path_segment(&repository.owner),
            encode_path_segment(&repository.name)
        );
        Self {
            actions: format!("{repository_root}/actions"),
            settings: format!("{repository_root}/settings/access"),
            secrets: format!("{repository_root}/settings/secrets"),
        }
    }

    fn workflow(&self, workflow_id: automata_ci_core::WorkflowId) -> String {
        format!("{}/workflows/{workflow_id}", self.actions)
    }

    fn run(&self, run_id: automata_ci_core::RunId) -> String {
        format!("{}/runs/{run_id}", self.actions)
    }

    fn job(&self, run_id: automata_ci_core::RunId, job_id: automata_ci_core::JobId) -> String {
        format!("{}/runs/{run_id}/jobs/{job_id}", self.actions)
    }

    fn artifact(&self, run_id: automata_ci_core::RunId, artifact_id: i64) -> String {
        format!("{}/runs/{run_id}/artifacts/{artifact_id}", self.actions)
    }
}

fn run_list_href(
    action: &str,
    status: StatusFilter,
    branch: Option<&str>,
    cursor: Option<&str>,
    workflow_cursor: Option<&str>,
) -> String {
    let mut pairs = Vec::new();
    if status != StatusFilter::All {
        pairs.push(("status", status_filter_value(status)));
    }
    if let Some(branch) = branch.filter(|value| !value.is_empty()) {
        pairs.push(("branch", branch));
    }
    if let Some(cursor) = cursor {
        pairs.push(("cursor", cursor));
    }
    if let Some(cursor) = workflow_cursor {
        pairs.push(("workflow_cursor", cursor));
    }
    query_href(action, &pairs)
}

fn run_detail_href(action: &str, job_cursor: Option<&str>) -> String {
    let mut pairs = Vec::new();
    if let Some(cursor) = job_cursor {
        pairs.push(("job_cursor", cursor));
    }
    query_href(action, &pairs)
}

fn query_href(action: &str, pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return action.to_owned();
    }
    let mut href = String::with_capacity(action.len() + 32);
    href.push_str(action);
    href.push('?');
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            href.push('&');
        }
        href.push_str(name);
        href.push('=');
        href.push_str(&encode_query_component(value));
    }
    href
}

fn encode_path_segment(value: &str) -> String {
    percent_encode(value.as_bytes())
}

fn encode_query_component(value: &str) -> String {
    percent_encode(value.as_bytes())
}

fn valid_repository(repository: &RepositoryData) -> bool {
    valid_text(&repository.scm_provider)
        && valid_text(&repository.owner)
        && valid_text(&repository.name)
}

fn valid_run(run: &RunSummary) -> bool {
    !run.id.as_uuid().is_nil()
        && !run.workflow.id.as_uuid().is_nil()
        && run.number > 0
        && (1..=10_000).contains(&run.attempt)
        && valid_text(&run.workflow.name)
        && valid_text(&run.workflow.path)
        && valid_text(&run.event)
        && run.title.as_deref().is_none_or(valid_text)
        && run.git_ref.as_deref().is_none_or(valid_text)
        && run.actor.as_deref().is_none_or(valid_text)
        && run.commit_subject.as_deref().is_none_or(valid_text)
        && matches!(run.head_sha.len(), 40 | 64)
        && run
            .head_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && run
            .finished_at
            .is_none_or(|finished| finished.get() >= run.created_at.get())
}

fn valid_job(job: &JobSummary) -> bool {
    !job.id.as_uuid().is_nil()
        && valid_text(&job.name)
        && job.attempt.is_none_or(|attempt| attempt > 0)
        && (!job.logs_available || job.attempt.is_some())
        && job.runner_label.as_deref().is_none_or(valid_text)
        && job
            .started_at
            .zip(job.finished_at)
            .is_none_or(|(started, finished)| finished.get() >= started.get())
}

fn valid_artifact(artifact: &ArtifactSummary) -> bool {
    artifact.id > 0
        && valid_text(&artifact.name)
        && artifact.digest.len() == 64
        && artifact
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_text(value: &str) -> bool {
    is_safe_display_text(value, 1_024)
}

fn all_unique<T>(values: impl IntoIterator<Item = T>) -> bool
where
    T: Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use automata_ci_auth::{
        authorization::{
            AuthorizationContext, AuthorizationScope, OutputVisibility, Permission,
            RepositoryPublicationPolicy, RoleName,
        },
        human::{ProviderId, TenantId},
        management::{
            DirectRoleBindingSource, ManagedPrincipalId, ManagementBindingRole, ManagementRevision,
            ManagementRoleBindingRecord, ManagementRoleBindingSource, ManagementScopeRecord,
            MemberRecord, MemberStatus, RoleBindingId, RoleBindingStatus, RoleDetailRecord, RoleId,
            RoleKind, RolePermissionRecord, RoleRecord,
        },
        secret::{CsrfToken, SecretString},
    };
    use automata_ci_core::{JobId, RunId, WorkflowId};
    use automata_ci_ui_renderer::{RenderPolicy, Renderer, WasmtimeRenderer, client_assets};
    use serde_json::Value;

    use super::*;
    use crate::app::web::data::{
        RUN_PAGE_SIZE, Repository as DataRepository, Viewer as DataViewer, Workflow,
        WorkflowDefinition,
    };

    const SETUP_BOOTSTRAP_SENTINEL: &str = "setup-bootstrap-sentinel-0123456789abcdef";

    #[test]
    fn installation_setup_model_is_fixed_and_value_free() {
        let request = installation_setup(client_assets(), "setup-nonce".to_owned())
            .expect("fixed setup model must serialize");
        let document: Value =
            serde_json::from_str(&request).expect("setup render request must be JSON");
        let page = document["page"]
            .as_object()
            .expect("setup page must be an object");

        assert_eq!(RENDER_REQUEST_SCHEMA_VERSION, 1);
        assert_eq!(document["schemaVersion"], RENDER_REQUEST_SCHEMA_VERSION);

        assert_eq!(page.keys().collect::<Vec<_>>(), ["form", "kind", "shell"]);
        assert_eq!(page["kind"], "setup");
        assert_eq!(page["form"]["action"], "/setup/auth/github");
        assert_eq!(page["form"]["returnPath"], "/");
        assert_eq!(page["shell"]["homeHref"], "/setup");
        assert_eq!(page["shell"]["signIn"], Value::Null);
        assert_eq!(page["shell"]["signOut"], Value::Null);
        assert_eq!(page["shell"]["viewer"], Value::Null);
        assert_eq!(page["shell"]["navigation"][0]["href"], "/setup");
        assert!(!request.contains("bootstrap_token"));
        assert!(!request.contains(SETUP_BOOTSTRAP_SENTINEL));
    }

    #[test]
    fn route_components_are_percent_encoded_without_form_aliases() {
        assert_eq!(encode_path_segment("feature/a b"), "feature%2Fa%20b");
        assert_eq!(
            query_href("/actions", &[("branch", "feature/a b")]),
            "/actions?branch=feature%2Fa%20b"
        );
    }

    #[test]
    fn public_job_metadata_keeps_its_detail_destination_when_logs_are_restricted() {
        let paths = RepositoryPaths::new(&fixture_repository());
        let run_id =
            RunId::from_str("550e8400-e29b-41d4-a716-446655440000").expect("fixture run ID");
        let job_id =
            JobId::from_str("650e8400-e29b-41d4-a716-446655440000").expect("fixture job ID");
        let job = JobSummary {
            id: job_id,
            name: "Workspace tests".to_owned(),
            attempt: None,
            runner_label: None,
            status: DataStatus::Queued,
            started_at: None,
            finished_at: None,
            logs_available: false,
        };

        let model = job_model(&paths, run_id, &job).expect("valid job model");

        assert_eq!(
            model.href.as_deref(),
            Some(
                "/automata-ci/automata/actions/runs/550e8400-e29b-41d4-a716-446655440000/jobs/650e8400-e29b-41d4-a716-446655440000"
            )
        );
    }

    #[test]
    fn durations_remain_compact_and_nonnegative() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(62_000), "1m 2s");
        assert_eq!(format_duration(3_661_000), "1h 1m 1s");
        assert_eq!(
            elapsed_duration_label(Some(UnixMillis::new(1)), Some(UnixMillis::new(62_001))),
            Some("1m 2s".to_owned())
        );
        assert_eq!(elapsed_duration_label(Some(UnixMillis::new(1)), None), None);
        assert_eq!(elapsed_duration_label(None, Some(UnixMillis::new(1))), None);
        assert_eq!(
            elapsed_duration_label(Some(UnixMillis::new(2)), Some(UnixMillis::new(1))),
            None
        );
    }

    #[test]
    fn size_labels_round_without_lossy_floating_point_conversion() {
        assert_eq!(size_label(1_023), "1023 B");
        assert_eq!(size_label(1_024), "1.0 KiB");
        assert_eq!(size_label(1_536), "1.5 KiB");
        assert_eq!(size_label(1_572_864), "1.5 MiB");
        assert_eq!(size_label(u64::MAX), "17179869184.0 GiB");
    }

    #[test]
    fn display_text_rejects_blank_control_and_bidirectional_formatting() {
        assert!(valid_text("Build and test"));
        assert!(valid_text("Deploy\u{200d}service"));
        assert!(!valid_text(" \t\n"));
        assert!(!valid_text("\u{200b}\u{fe0f}"));
        assert!(!valid_text("\u{3164}"));
        assert!(!valid_source_segment("\u{200b}\u{fe0f}"));
        assert!(!valid_text("Build\u{0000}test"));
        for formatting in [
            '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}',
        ] {
            let spoofed = format!("safe{formatting}copy");
            assert!(!valid_text(&spoofed));
            assert!(!valid_source_segment(&spoofed));
        }
    }

    #[test]
    fn repository_directory_is_honest_for_empty_pages() {
        let context = RequestContext::anonymous(TenantId::new("tenant-a").expect("fixture tenant"));
        let request = RepositoryDirectoryRequestData {
            cursor: None,
            limit: REPOSITORY_PAGE_SIZE,
        };
        let empty = RepositoryDirectoryData {
            repositories: Vec::new(),
            next_cursor: None,
        };
        let json = repository_directory(
            client_assets(),
            "nonce".to_owned(),
            &context,
            None,
            &request,
            &empty,
        )
        .expect("empty repository-directory page model");
        let value: Value = serde_json::from_str(&json).expect("page JSON");

        assert_eq!(value["page"]["kind"], "repository-directory");
        assert_eq!(value["page"]["shell"]["homeHref"], REPOSITORIES_PATH);
        assert_eq!(
            value["page"]["shell"]["navigation"][0]["label"],
            "Repositories"
        );
        assert_eq!(value["page"]["repositories"], serde_json::json!([]));
        assert!(value["page"].get("repository").is_none());
        assert!(!json.contains("github.com"));
    }

    #[test]
    fn repository_directory_sanitizes_viewer_display_names() {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("fixture tenant"),
            AuthorizationContext::anonymous(),
            Some(DataViewer {
                display_name: "\u{200b}\u{202e}".to_owned(),
            }),
            None,
        )
        .expect("fixture viewer context");
        let request = RepositoryDirectoryRequestData {
            cursor: None,
            limit: REPOSITORY_PAGE_SIZE,
        };
        let empty = RepositoryDirectoryData {
            repositories: Vec::new(),
            next_cursor: None,
        };
        let json = repository_directory(
            client_assets(),
            "nonce".to_owned(),
            &context,
            None,
            &request,
            &empty,
        )
        .expect("safe viewer projection");
        let value: Value = serde_json::from_str(&json).expect("page JSON");
        assert_eq!(
            value["page"]["shell"]["viewer"]["displayName"],
            "Signed-in user"
        );
    }

    #[test]
    fn repository_directory_exposes_only_authorized_destinations() {
        let (context, csrf, _) = repository_settings_fixture();
        let context = context.with_access_management_available(true);
        let request = RepositoryDirectoryRequestData {
            cursor: None,
            limit: REPOSITORY_PAGE_SIZE,
        };
        let mut repository = fixture_repository();
        repository.settings_visible = true;
        let directory = RepositoryDirectoryData {
            repositories: vec![RepositoryDirectoryItemData {
                repository,
                actions_visible: false,
                settings_destination: Some(RepositorySettingsDestination::Access),
            }],
            next_cursor: Some("next_page".to_owned()),
        };
        let json = repository_directory(
            client_assets(),
            "nonce".to_owned(),
            &context,
            Some(ShellMutation::new(&csrf)),
            &request,
            &directory,
        )
        .expect("authenticated shell mutation capability");
        let value: Value = serde_json::from_str(&json).expect("page JSON");
        assert_eq!(
            value["page"]["shell"]["signOut"]["action"],
            GITHUB_WEB_LOGOUT_PATH
        );
        assert_eq!(
            value["page"]["shell"]["signOut"]["csrfToken"],
            csrf.expose_secret()
        );
        assert_eq!(
            value["page"]["shell"]["navigation"][0]["label"],
            "Repositories"
        );
        assert_eq!(value["page"]["shell"]["navigation"][1]["label"], "Access");
        assert_eq!(
            value["page"]["shell"]["navigation"][1]["href"],
            RBAC_USERS_PATH
        );
        assert_eq!(value["page"]["repositories"][0]["owner"], "automata-ci");
        assert!(value["page"]["repositories"][0]["actionsHref"].is_null());
        assert_eq!(
            value["page"]["repositories"][0]["settingsHref"],
            "/automata-ci/automata/settings/access"
        );
        assert_eq!(
            value["page"]["pagination"]["nextHref"],
            "/repositories?cursor=next_page"
        );

        let directory = RepositoryDirectoryData {
            repositories: vec![RepositoryDirectoryItemData {
                repository: fixture_repository(),
                actions_visible: false,
                settings_destination: Some(RepositorySettingsDestination::Secrets),
            }],
            next_cursor: None,
        };
        let json = repository_directory(
            client_assets(),
            "nonce".to_owned(),
            &context,
            Some(ShellMutation::new(&csrf)),
            &request,
            &directory,
        )
        .expect("secret-metadata-only repository directory");
        let value: Value = serde_json::from_str(&json).expect("page JSON");
        assert_eq!(
            value["page"]["repositories"][0]["settingsHref"],
            "/automata-ci/automata/settings/secrets"
        );
    }

    #[test]
    fn run_identity_and_workflow_scope_are_serialized_separately() {
        let workflow_id = WorkflowId::from_str("99999999-9999-4999-8999-999999999999")
            .expect("fixture workflow ID");
        let run = fixture_run(DataStatus::InProgress, workflow_id);
        let context = RequestContext::anonymous(TenantId::new("tenant-a").expect("fixture tenant"));
        let request = fixture_run_list_request(
            Some(workflow_id),
            StatusFilter::InProgress,
            Some("main"),
            None,
        );
        let data = RunListData {
            repository: fixture_repository(),
            workflows: vec![fixture_workflow_definition(&run.workflow, false)],
            selected_workflow: Some(fixture_workflow_definition(&run.workflow, false)),
            workflow_previous_cursor: None,
            workflow_next_cursor: None,
            runs: vec![run],
            previous_cursor: None,
            next_cursor: Some("next_cursor".to_owned()),
        };
        let json = run_list(
            client_assets(),
            "nonce".to_owned(),
            &context,
            None,
            &request,
            &data,
        )
        .expect("valid page model");
        let value: Value = serde_json::from_str(&json).expect("page JSON");

        assert_eq!(
            value["page"]["runs"][0]["id"],
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(value["page"]["runs"][0]["number"], "1842");
        assert!(value["page"]["runs"][0]["durationLabel"].is_null());
        assert_eq!(
            value["page"]["runs"][0]["workflowHref"],
            format!("/automata-ci/automata/actions/workflows/{workflow_id}")
        );
        assert_eq!(value["page"]["runs"][0]["sourceRef"]["name"], "main");
        assert_eq!(value["page"]["runs"][0]["sourceRef"]["kind"], "branch");
        assert_eq!(
            value["page"]["runs"][0]["sourceRef"]["href"],
            "https://github.com/automata-ci/automata/tree/main"
        );
        assert!(value["page"]["runs"][0].get("branch").is_none());
        assert_eq!(
            value["page"]["runs"][0]["commit"]["href"],
            "https://github.com/automata-ci/automata/commit/0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(
            value["page"]["workflowNavigation"]["selectedWorkflow"]["id"],
            workflow_id.to_string()
        );
        assert_eq!(
            value["page"]["workflowNavigation"]["workflows"][0]["enabled"],
            false
        );
        assert_eq!(
            value["page"]["pagination"]["nextHref"],
            format!(
                "/automata-ci/automata/actions/workflows/{workflow_id}?status=in_progress&branch=main&cursor=next_cursor"
            )
        );
        assert!(value["page"]["repository"]["settingsHref"].is_null());

        let mut corrupt = data;
        corrupt.workflows[0].name = "spoofed\u{202e}workflow".to_owned();
        assert!(matches!(
            run_list(
                client_assets(),
                "nonce".to_owned(),
                &context,
                None,
                &request,
                &corrupt,
            ),
            Err(ModelError::InvalidData)
        ));
    }

    #[test]
    fn repository_settings_require_every_atomic_update_capability_gate() {
        let (context, csrf, data) = repository_settings_fixture();
        let json = repository_settings(
            client_assets(),
            "nonce".to_owned(),
            &context,
            data.clone(),
            Some(ShellMutation::new(&csrf)),
        )
        .expect("editable repository settings model");
        let value: Value = serde_json::from_str(&json).expect("page JSON");

        assert_eq!(value["page"]["kind"], "repository-settings");
        assert_eq!(value["page"]["revision"], "7");
        assert_eq!(value["page"]["policy"]["dashboard"], "public");
        assert_eq!(value["page"]["policy"]["logs"], "authenticated");
        assert_eq!(value["page"]["policy"]["artifacts"], "private");
        assert_eq!(
            value["page"]["summary"],
            "Choose who can view new workflow runs and their output in automata-ci/automata."
        );
        assert!(value["page"].get("readOnlyReason").is_none());
        assert!(value["page"].get("notice").is_none());
        assert_eq!(
            value["page"]["repository"]["settingsHref"],
            "/automata-ci/automata/settings/access"
        );
        assert_eq!(
            value["page"]["update"]["action"],
            "/automata-ci/automata/settings/access"
        );
        assert_eq!(value["page"]["update"]["csrfToken"], csrf.expose_secret());

        let read_only = repository_settings(
            client_assets(),
            "nonce".to_owned(),
            &context,
            RepositorySettingsData {
                editable: false,
                ..data.clone()
            },
            Some(ShellMutation::new(&csrf)),
        )
        .expect("read-only repository settings model");
        let read_only: Value = serde_json::from_str(&read_only).expect("page JSON");
        assert!(read_only["page"]["update"].is_null());
        assert!(read_only["page"].get("readOnlyReason").is_none());

        assert!(matches!(
            repository_settings(
                client_assets(),
                "nonce".to_owned(),
                &context,
                data.clone(),
                None,
            ),
            Err(ModelError::InvalidData)
        ));

        let anonymous =
            RequestContext::anonymous(TenantId::new("tenant-a").expect("fixture tenant"));
        assert!(matches!(
            repository_settings(
                client_assets(),
                "nonce".to_owned(),
                &anonymous,
                data,
                Some(ShellMutation::new(&csrf)),
            ),
            Err(ModelError::InvalidData)
        ));
    }

    #[test]
    fn rbac_user_list_projects_the_exact_renderer_contract() {
        let (context, csrf, _) = repository_settings_fixture();
        let active = managed_user(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            MemberStatus::Active,
            11,
            7,
        );
        let disabled = managed_user(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "grace-hopper",
            None,
            MemberStatus::Suspended,
            4,
            3,
        );
        let json = rbac_user_list(
            client_assets(),
            "nonce".to_owned(),
            &context,
            Some(ShellMutation::new(&csrf)),
            Some("99999999-9999-4999-8999-999999999999"),
            None,
            &RbacUserListData {
                users: vec![active, disabled],
                next_cursor: Some("cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned()),
            },
        )
        .expect("valid RBAC user-list page");
        let value: Value = serde_json::from_str(&json).expect("page JSON");
        let page = &value["page"];

        assert_exact_object_keys(
            page,
            &[
                "kind",
                "shell",
                "managementNav",
                "heading",
                "summary",
                "users",
                "notice",
                "pagination",
            ],
        );
        assert_exact_object_keys(
            &page["users"][0],
            &[
                "id",
                "href",
                "providerId",
                "providerLogin",
                "displayName",
                "status",
            ],
        );
        assert_eq!(page["kind"], "user-list");
        assert_eq!(page["shell"]["homeHref"], REPOSITORIES_PATH);
        assert_eq!(page["shell"]["navigation"][0]["label"], "Repositories");
        assert_eq!(page["shell"]["navigation"][0]["href"], REPOSITORIES_PATH);
        assert_eq!(page["shell"]["navigation"][1]["label"], "Access");
        assert_eq!(page["shell"]["navigation"][1]["href"], RBAC_USERS_PATH);
        assert_eq!(page["managementNav"]["current"], "users");
        assert_eq!(page["managementNav"]["rolesHref"], RBAC_ROLES_PATH);
        assert_eq!(
            page["users"][0]["id"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(
            page["users"][0]["href"],
            "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(page["users"][0]["providerId"], "github");
        assert_eq!(page["users"][0]["status"], "active");
        assert!(page["users"][1]["displayName"].is_null());
        assert_eq!(page["users"][1]["status"], "disabled");
        assert!(page["pagination"]["previousHref"].is_null());
        assert_eq!(page["pagination"]["label"], "2 users");
        assert_eq!(
            page["pagination"]["nextHref"],
            "/settings/access/users?cursor=cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        );
        assert!(page.get("roles").is_none());
    }

    #[test]
    fn rbac_user_list_fails_closed_on_renderer_limits_and_duplicate_ids() {
        let (context, _, _) = repository_settings_fixture();
        let user = managed_user(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            MemberStatus::Active,
            1,
            1,
        );
        assert!(matches!(
            rbac_user_list(
                client_assets(),
                "nonce".to_owned(),
                &context,
                None,
                None,
                None,
                &RbacUserListData {
                    users: vec![user.clone(), user],
                    next_cursor: None,
                },
            ),
            Err(ModelError::InvalidData)
        ));

        let oversized_provider = MemberRecord::new(
            ManagedPrincipalId::new("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("principal ID"),
            ProviderId::new("p".repeat(129)).expect("domain provider ID"),
            "provider-login",
            None,
            MemberStatus::Active,
            ManagementRevision::new(1).expect("revision"),
            ManagementRevision::new(1).expect("revision"),
        )
        .expect("domain member permits the wider provider ID");
        assert!(matches!(
            rbac_user_list(
                client_assets(),
                "nonce".to_owned(),
                &context,
                None,
                None,
                None,
                &RbacUserListData {
                    users: vec![oversized_provider],
                    next_cursor: None,
                },
            ),
            Err(ModelError::InvalidData)
        ));

        assert!(matches!(
            rbac_user_list(
                client_assets(),
                "nonce".to_owned(),
                &context,
                None,
                Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                None,
                &RbacUserListData {
                    users: Vec::new(),
                    next_cursor: Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned()),
                },
            ),
            Err(ModelError::InvalidData)
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture audits the exact serialized field set for all five RBAC pages"
    )]
    fn all_rbac_page_variants_serialize_the_current_read_only_contract() {
        let (context, csrf, _) = repository_settings_fixture();
        let mutation = Some(ShellMutation::new(&csrf));
        let user_record = managed_user(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            MemberStatus::Active,
            11,
            7,
        );

        let user_detail = serialize_request(
            client_assets(),
            "nonce".to_owned(),
            RbacUserDetailPage {
                kind: "user-detail",
                shell: rbac_shell(
                    &context,
                    mutation,
                    &LoginReturnPath::new(RBAC_USERS_PATH).expect("return path"),
                    "Ada Lovelace · Access management · Automata".to_owned(),
                )
                .expect("management shell"),
                management_nav: rbac_management_navigation("users"),
                heading: "Ada Lovelace".to_owned(),
                summary: "Stable provider identity, current status, and visible role assignments.",
                user: rbac_managed_user(&user_record).expect("managed user"),
                notice: None,
                status_update: None,
                role_assignments: vec![RbacUserRoleAssignment {
                    binding_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".to_owned(),
                    binding_href: "/settings/access/direct-bindings".to_owned(),
                    role_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
                    role_href: "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                        .to_owned(),
                    role_name: "release-reviewer".to_owned(),
                    role_display_name: "Release reviewer".to_owned(),
                    scope: RbacScope::Repository {
                        label: "automata-ci/automata".to_owned(),
                    },
                    source: "direct",
                    status: "active",
                    valid_until: Some(Timestamp {
                        iso: "2026-09-01T00:00:00Z".to_owned(),
                        label: "1 Sep 2026, 00:00 UTC".to_owned(),
                    }),
                }],
            },
        )
        .expect("user-detail JSON");
        let user_detail: Value = serde_json::from_str(&user_detail).expect("user-detail value");
        assert_exact_object_keys(
            &user_detail["page"],
            &[
                "kind",
                "shell",
                "managementNav",
                "heading",
                "summary",
                "user",
                "roleAssignments",
                "notice",
                "statusUpdate",
            ],
        );
        assert_eq!(user_detail["page"]["kind"], "user-detail");
        assert_exact_object_keys(
            &user_detail["page"]["roleAssignments"][0],
            &[
                "bindingId",
                "bindingHref",
                "roleId",
                "roleHref",
                "roleName",
                "roleDisplayName",
                "scope",
                "source",
                "status",
                "validUntil",
            ],
        );
        assert_eq!(
            user_detail["page"]["roleAssignments"][0]["scope"]["kind"],
            "repository"
        );
        assert_exact_object_keys(
            &user_detail["page"]["roleAssignments"][0]["scope"],
            &["kind", "label"],
        );
        assert_eq!(user_detail["page"]["shell"]["homeHref"], REPOSITORIES_PATH);
        assert_eq!(
            user_detail["page"]["shell"]["navigation"],
            serde_json::json!([
                {"label": "Repositories", "href": "/repositories", "current": false},
                {"label": "Access", "href": "/settings/access/users", "current": true}
            ])
        );

        let role_list = serialize_request(
            client_assets(),
            "nonce".to_owned(),
            RbacRoleListPage {
                kind: "role-list",
                shell: rbac_shell(
                    &context,
                    mutation,
                    &LoginReturnPath::new(RBAC_ROLES_PATH).expect("return path"),
                    "Roles · Access management · Automata".to_owned(),
                )
                .expect("management shell"),
                management_nav: rbac_management_navigation("roles"),
                heading: "Roles",
                summary: "Review built-in and custom roles and their explicit permission grants.",
                roles: vec![test_rbac_role()],
                notice: None,
                create: None,
                pagination: Pagination {
                    previous_href: None,
                    next_href: None,
                    label: "1 role".to_owned(),
                },
            },
        )
        .expect("role-list JSON");
        let role_list: Value = serde_json::from_str(&role_list).expect("role-list value");
        assert_exact_object_keys(
            &role_list["page"],
            &[
                "kind",
                "shell",
                "managementNav",
                "heading",
                "summary",
                "roles",
                "notice",
                "create",
                "pagination",
            ],
        );
        assert_eq!(role_list["page"]["roles"][0]["kind"], "custom");
        assert_exact_object_keys(
            &role_list["page"]["roles"][0],
            &[
                "id",
                "href",
                "name",
                "displayName",
                "kind",
                "immutable",
                "permissionCount",
            ],
        );

        let role_detail = serialize_request(
            client_assets(),
            "nonce".to_owned(),
            RbacRoleDetailPage {
                kind: "role-detail",
                shell: rbac_shell(
                    &context,
                    mutation,
                    &LoginReturnPath::new(RBAC_ROLES_PATH).expect("return path"),
                    "Release reviewer · Access management · Automata".to_owned(),
                )
                .expect("management shell"),
                management_nav: rbac_management_navigation("roles"),
                heading: "Release reviewer".to_owned(),
                summary: "Review this role and its explicit permission grants.",
                role: test_rbac_role(),
                permissions: vec![RbacPermission {
                    name: "runs:read".to_owned(),
                    description: "Read authorized workflow-run metadata.".to_owned(),
                    granted: true,
                    update: None,
                }],
                notice: None,
                update: None,
                delete: None,
            },
        )
        .expect("role-detail JSON");
        let role_detail: Value = serde_json::from_str(&role_detail).expect("role-detail value");
        assert_exact_object_keys(
            &role_detail["page"],
            &[
                "kind",
                "shell",
                "managementNav",
                "heading",
                "summary",
                "role",
                "permissions",
                "notice",
                "update",
                "delete",
            ],
        );
        assert_exact_object_keys(
            &role_detail["page"]["permissions"][0],
            &["name", "description", "granted", "update"],
        );

        let binding_list = serialize_request(
            client_assets(),
            "nonce".to_owned(),
            RbacDirectBindingListPage {
                kind: "direct-binding-list",
                shell: rbac_shell(
                    &context,
                    mutation,
                    &LoginReturnPath::new(RBAC_DIRECT_BINDINGS_PATH).expect("return path"),
                    "Direct bindings · Access management · Automata".to_owned(),
                )
                .expect("management shell"),
                management_nav: rbac_management_navigation("direct-bindings"),
                heading: "Direct bindings",
                summary: "Review exact direct and provider-observed role assignments and scopes.",
                bindings: vec![RbacBinding {
                    id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".to_owned(),
                    revision: "4".to_owned(),
                    principal: RbacBindingPrincipal {
                        id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
                        href: "/settings/access/users/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                            .to_owned(),
                        label: "Ada Lovelace".to_owned(),
                    },
                    role: RbacBindingRole {
                        id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
                        href: "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                            .to_owned(),
                        name: "release-reviewer".to_owned(),
                        label: "Release reviewer".to_owned(),
                    },
                    scope: RbacScope::RunnerGroup {
                        label: "Trusted runners".to_owned(),
                    },
                    source: "direct",
                    status: "active",
                    valid_until: None,
                    revoke: None,
                }],
                notice: None,
                grant: None,
                read_only_reason: Some("management-unavailable"),
                pagination: Pagination {
                    previous_href: None,
                    next_href: None,
                    label: "1 binding".to_owned(),
                },
            },
        )
        .expect("direct-binding-list JSON");
        let binding_list: Value =
            serde_json::from_str(&binding_list).expect("direct-binding-list value");
        assert_exact_object_keys(
            &binding_list["page"],
            &[
                "kind",
                "shell",
                "managementNav",
                "heading",
                "summary",
                "bindings",
                "notice",
                "grant",
                "readOnlyReason",
                "pagination",
            ],
        );
        assert_eq!(binding_list["page"]["kind"], "direct-binding-list");
        assert_exact_object_keys(
            &binding_list["page"]["bindings"][0],
            &[
                "id",
                "revision",
                "principal",
                "role",
                "scope",
                "source",
                "status",
                "validUntil",
                "revoke",
            ],
        );
        assert_eq!(
            binding_list["page"]["bindings"][0]["scope"]["kind"],
            "runner-group"
        );
        assert!(binding_list["page"]["bindings"][0]["validUntil"].is_null());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial fixture covers all revision-advancing RBAC projections"
    )]
    fn rbac_revision_exhaustion_suppresses_only_advancing_mutations() {
        let (context, csrf, _) = repository_settings_fixture();
        let context = context.with_access_management_available(true);
        let authorization_revision = ManagementRevision::new(7).expect("authorization revision");
        let maximum_revision =
            ManagementRevision::new(i64::MAX as u64).expect("maximum durable revision");
        let advanceable_revision =
            ManagementRevision::new(i64::MAX as u64 - 1).expect("advanceable durable revision");

        let capabilities =
            ManagementMutationCapabilities::new(authorization_revision, true, true, true);
        let principal_id = ManagedPrincipalId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .expect("fixture principal ID");
        let exhausted_user = managed_user(
            &principal_id.to_string(),
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            MemberStatus::Active,
            authorization_revision.value(),
            maximum_revision.value(),
        );
        let exhausted_user_json = rbac_user_detail(
            client_assets(),
            "nonce".to_owned(),
            &context,
            Some(ShellMutation::new(&csrf)),
            principal_id,
            &RbacUserDetailData {
                user: exhausted_user,
                assignments: Vec::new(),
            },
            None,
            authorization_revision,
            Some(&capabilities),
        )
        .expect("exhausted member page");
        let exhausted_user_value: Value =
            serde_json::from_str(&exhausted_user_json).expect("member page JSON");
        assert!(exhausted_user_value["page"]["statusUpdate"].is_null());

        let advanceable_user = managed_user(
            &principal_id.to_string(),
            "ada-lovelace",
            Some("Ada Lovelace".to_owned()),
            MemberStatus::Active,
            authorization_revision.value(),
            advanceable_revision.value(),
        );
        let advanceable_user_json = rbac_user_detail(
            client_assets(),
            "nonce".to_owned(),
            &context,
            Some(ShellMutation::new(&csrf)),
            principal_id,
            &RbacUserDetailData {
                user: advanceable_user,
                assignments: Vec::new(),
            },
            None,
            authorization_revision,
            Some(&capabilities),
        )
        .expect("advanceable member page");
        let advanceable_user_value: Value =
            serde_json::from_str(&advanceable_user_json).expect("member page JSON");
        assert_eq!(
            advanceable_user_value["page"]["statusUpdate"]["expectedRevision"],
            advanceable_revision.value().to_string()
        );

        let role_id = RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("fixture role ID");
        let permission = Permission::new("runs:read").expect("fixture permission");
        let exhausted_role = RoleRecord::new(
            role_id,
            RoleName::new("release-reviewer").expect("fixture role name"),
            "Release reviewer",
            RoleKind::Custom,
            false,
            maximum_revision,
            std::collections::BTreeSet::from([permission.clone()]),
        )
        .expect("fixture role");
        let exhausted_role_detail = RoleDetailRecord::new(
            exhausted_role,
            vec![
                RolePermissionRecord::new(
                    permission,
                    "Read authorized workflow-run metadata.",
                    false,
                    true,
                )
                .expect("fixture permission entry"),
            ],
        )
        .expect("fixture role detail");
        let exhausted_role_json = rbac_role_detail(
            client_assets(),
            "nonce".to_owned(),
            &context,
            Some(ShellMutation::new(&csrf)),
            role_id,
            &exhausted_role_detail,
            None,
            authorization_revision,
            Some(&capabilities),
        )
        .expect("exhausted role page");
        let exhausted_role_value: Value =
            serde_json::from_str(&exhausted_role_json).expect("role page JSON");
        assert!(exhausted_role_value["page"]["update"].is_null());
        assert!(exhausted_role_value["page"]["permissions"][0]["update"].is_null());
        assert_eq!(
            exhausted_role_value["page"]["delete"]["expectedRevision"],
            maximum_revision.value().to_string()
        );

        let authority = RbacFormAuthority {
            csrf_token: &csrf,
            authorization_revision,
        };
        let exhausted_binding = direct_management_binding(maximum_revision);
        let exhausted_binding_projection =
            rbac_binding(&context, &exhausted_binding, Some(authority))
                .expect("exhausted binding projection");
        assert_eq!(
            exhausted_binding_projection.revision,
            maximum_revision.value().to_string()
        );
        assert!(exhausted_binding_projection.revoke.is_none());

        let advanceable_binding = direct_management_binding(advanceable_revision);
        let advanceable_binding_projection =
            rbac_binding(&context, &advanceable_binding, Some(authority))
                .expect("advanceable binding projection");
        assert_eq!(
            advanceable_binding_projection
                .revoke
                .expect("advanceable direct binding revoke")
                .expected_revision,
            advanceable_revision.value().to_string()
        );
    }

    #[test]
    fn repository_settings_host_model_matches_embedded_renderer_contract() {
        let (context, csrf, data) = repository_settings_fixture();
        let json = repository_settings(
            client_assets(),
            "nonce".to_owned(),
            &context,
            data,
            Some(ShellMutation::new(&csrf)),
        )
        .expect("valid repository settings model");
        let renderer =
            WasmtimeRenderer::new(RenderPolicy::default()).expect("embedded renderer initializes");
        let rendered_page = renderer
            .render(&json)
            .expect("the host settings model satisfies the embedded UI contract");

        assert!(rendered_page.as_str().contains("Repository access"));
        assert!(
            rendered_page
                .as_str()
                .contains("name=\"expected_revision\"")
        );
    }

    #[test]
    fn authorized_repository_settings_are_discoverable_from_actions() {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("fixture tenant"),
            AuthorizationContext::anonymous(),
            Some(DataViewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("fixture viewer context");
        let mut repository = fixture_repository();
        repository.settings_visible = true;
        let request = fixture_run_list_request(None, StatusFilter::All, None, None);
        let json = run_list(
            client_assets(),
            "nonce".to_owned(),
            &context,
            None,
            &request,
            &RunListData {
                repository,
                workflows: Vec::new(),
                selected_workflow: None,
                workflow_previous_cursor: None,
                workflow_next_cursor: None,
                runs: Vec::new(),
                previous_cursor: None,
                next_cursor: None,
            },
        )
        .expect("authorized settings link");
        let value: Value = serde_json::from_str(&json).expect("page JSON");
        assert_eq!(
            value["page"]["repository"]["settingsHref"],
            "/automata-ci/automata/settings/access"
        );
    }

    #[test]
    fn repository_settings_reject_zero_revision_and_noncanonical_csrf() {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("fixture tenant"),
            AuthorizationContext::anonymous(),
            Some(DataViewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("fixture viewer context");
        let mut repository = fixture_repository();
        repository.settings_visible = true;
        let data = RepositorySettingsData {
            repository: repository.clone(),
            policy: RepositoryPublicationPolicy::default(),
            revision: 0,
            editable: true,
            secrets_visible: false,
        };
        assert!(matches!(
            repository_settings(client_assets(), "nonce".to_owned(), &context, data, None,),
            Err(ModelError::InvalidData)
        ));

        let overflow = RepositorySettingsData {
            repository: repository.clone(),
            policy: RepositoryPublicationPolicy::default(),
            revision: i64::MAX.unsigned_abs() + 1,
            editable: false,
            secrets_visible: false,
        };
        assert!(matches!(
            repository_settings(
                client_assets(),
                "nonce".to_owned(),
                &context,
                overflow,
                None,
            ),
            Err(ModelError::InvalidData)
        ));

        let terminal_revision = RepositorySettingsData {
            repository: repository.clone(),
            policy: RepositoryPublicationPolicy::default(),
            revision: i64::MAX.unsigned_abs(),
            editable: true,
            secrets_visible: false,
        };
        let (_, csrf, _) = repository_settings_fixture();
        assert!(matches!(
            repository_settings(
                client_assets(),
                "nonce".to_owned(),
                &context,
                terminal_revision,
                Some(ShellMutation::new(&csrf)),
            ),
            Err(ModelError::InvalidData)
        ));

        let invalid = CsrfToken::from_secret(
            SecretString::new("not-a-generated-token").expect("bounded invalid fixture"),
        );
        assert!(matches!(
            repository_settings(
                client_assets(),
                "nonce".to_owned(),
                &context,
                RepositorySettingsData {
                    repository,
                    policy: RepositoryPublicationPolicy::default(),
                    revision: 1,
                    editable: true,
                    secrets_visible: false,
                },
                Some(ShellMutation::new(&invalid)),
            ),
            Err(ModelError::InvalidData)
        ));

        let hidden = RepositorySettingsData {
            repository: fixture_repository(),
            policy: RepositoryPublicationPolicy::default(),
            revision: 1,
            editable: false,
            secrets_visible: false,
        };
        assert!(matches!(
            repository_settings(client_assets(), "nonce".to_owned(), &context, hidden, None,),
            Err(ModelError::InvalidData)
        ));
    }

    #[test]
    fn repository_secrets_model_is_value_free_and_exactly_revision_fenced() {
        let (context, csrf, mut data) = repository_secrets_fixture();
        let request = repository_secrets(
            client_assets(),
            "nonce".to_owned(),
            &context,
            ShellMutation::new(&csrf),
            None,
            None,
            &data,
        )
        .expect("repository Secrets model");
        assert!(!request.contains("\"value\":"));
        let value: Value = serde_json::from_str(&request).expect("page JSON");
        assert_eq!(value["page"]["kind"], "repository-secrets");
        assert_eq!(
            value["page"]["summary"],
            "Review encrypted secret metadata stored for automata-ci/automata."
        );
        assert_eq!(value["page"]["settingsNavigation"]["current"], "secrets");
        assert_eq!(
            value["page"]["maximumValueBytes"],
            crate::app::secret_api::MAX_SECRET_INGRESS_BYTES
        );
        assert_eq!(
            value["page"]["create"]["expectedAuthorizationRevision"],
            "12"
        );
        assert!(
            !value["page"]["create"]
                .as_object()
                .expect("create capability")
                .contains_key("maximumValueBytes")
        );
        assert_eq!(value["page"]["secrets"][0]["name"], "DEPLOY_TOKEN");
        assert_eq!(value["page"]["secrets"][0]["revision"], "5");
        assert_eq!(
            value["page"]["secrets"][0]["replace"]["action"],
            "/automata-ci/automata/settings/secrets/77777777-7777-4777-8777-777777777777/replace"
        );
        assert_eq!(
            value["page"]["secrets"][0]["delete"]["action"],
            "/automata-ci/automata/settings/secrets/77777777-7777-4777-8777-777777777777/delete"
        );

        data.provider = Some(
            automata_ci_store::BuiltinSecretProviderInspection::from_durable_parts(
                automata_ci_store::BuiltinSecretProviderState::Unconfigured,
                automata_ci_store::BuiltinSecretProviderHealth::Unknown,
                ManagementRevision::new(i64::MAX.unsigned_abs()).expect("maximum revision"),
                true,
            ),
        );
        let exhausted_provider_request = repository_secrets(
            client_assets(),
            "nonce".to_owned(),
            &context,
            ShellMutation::new(&csrf),
            None,
            None,
            &data,
        )
        .expect("exhausted provider remains readable");
        let exhausted_provider: Value =
            serde_json::from_str(&exhausted_provider_request).expect("page JSON");
        assert!(exhausted_provider["page"]["provider"]["activation"].is_null());
    }

    #[test]
    fn github_source_links_encode_segments_and_classify_exact_refs() {
        let source = GitHubSourceLinks::new("github", "acme-lab", "payments_api")
            .expect("GitHub repository source");
        assert_eq!(
            source.repository_href(),
            "https://github.com/acme-lab/payments_api"
        );

        let branch = source
            .source_ref(Some("refs/heads/feature/source #1"))
            .expect("supported branch ref")
            .expect("source ref");
        assert_eq!(branch.name, "feature/source #1");
        assert_eq!(branch.kind, "branch");
        assert_eq!(
            branch.href,
            "https://github.com/acme-lab/payments_api/tree/feature%2Fsource%20%231"
        );

        let tag = source
            .source_ref(Some("refs/tags/v1.2.3"))
            .expect("supported tag ref")
            .expect("source ref");
        assert_eq!(tag.name, "v1.2.3");
        assert_eq!(tag.kind, "tag");
        assert_eq!(
            tag.href,
            "https://github.com/acme-lab/payments_api/tree/v1.2.3"
        );

        let special_path_segment = source
            .source_ref(Some("refs/heads/release@stable"))
            .expect("supported branch ref")
            .expect("source ref");
        assert_eq!(
            special_path_segment.href,
            "https://github.com/acme-lab/payments_api/tree/release@stable"
        );

        for target in ["head", "merge"] {
            let source_ref = source
                .source_ref(Some(&format!("refs/pull/42/{target}")))
                .expect("supported pull ref")
                .expect("source ref");
            assert_eq!(source_ref.name, format!("pull/42/{target}"));
            assert_eq!(source_ref.kind, "ref");
            assert_eq!(
                source_ref.href,
                "https://github.com/acme-lab/payments_api/pull/42"
            );
        }
        assert!(source.source_ref(None).expect("absent ref").is_none());

        let mut run = fixture_run(DataStatus::Succeeded, WorkflowId::new());
        run.head_sha = "a".repeat(64);
        let commit = source.commit(&run).expect("full SHA-256 commit link");
        assert_eq!(commit.short_sha, "aaaaaaa");
        assert_eq!(
            commit.href,
            format!(
                "https://github.com/acme-lab/payments_api/commit/{}",
                "a".repeat(64)
            )
        );
    }

    #[test]
    fn github_source_links_require_canonical_repository_coordinates() {
        for owner in [
            "",
            "-acme",
            "acme-",
            "acme--labs",
            "acme_labs",
            "acme/labs",
            "áсme",
        ] {
            assert!(matches!(
                GitHubSourceLinks::new("github", owner, "payments"),
                Err(ModelError::InvalidData)
            ));
        }
        for repository in ["", ".", "..", "payments/api", "payments api", "páyments"] {
            assert!(matches!(
                GitHubSourceLinks::new("github", "acme", repository),
                Err(ModelError::InvalidData)
            ));
        }
        assert!(matches!(
            GitHubSourceLinks::new("github", &"a".repeat(40), "payments"),
            Err(ModelError::InvalidData)
        ));
        assert!(matches!(
            GitHubSourceLinks::new("github", "acme", &"r".repeat(101)),
            Err(ModelError::InvalidData)
        ));
    }

    #[test]
    fn source_links_reject_unsupported_providers_and_omit_unmappable_refs() {
        assert!(matches!(
            GitHubSourceLinks::new("gitlab", "acme", "payments"),
            Err(ModelError::InvalidData)
        ));

        let source =
            GitHubSourceLinks::new("github", "acme", "payments").expect("GitHub repository source");
        for git_ref in [
            "main",
            "refs/heads/",
            "refs/heads/\u{200b}",
            "refs/heads/..",
            "refs/tags/",
            "refs/remotes/origin/main",
            "refs/pull/0/head",
            "refs/pull/01/head",
            "refs/pull/42/base",
            "refs/pull/42/head/extra",
        ] {
            assert!(
                source
                    .source_ref(Some(git_ref))
                    .expect("unmappable refs are safely omitted")
                    .is_none(),
                "unsupported ref {git_ref} must be omitted atomically"
            );
        }
    }

    #[test]
    fn worst_case_encoded_filters_and_refs_fit_the_renderer_url_ceiling() {
        const RENDERER_URL_CEILING: usize = 4_096;
        let branch_filter = "é".repeat(506);
        let cursor = "c".repeat(512);
        let run_action = format!("/{}/{}", "a".repeat(39), "r".repeat(100));
        let run_href = run_list_href(
            &format!("{run_action}/actions"),
            StatusFilter::Completed,
            Some(&branch_filter),
            Some(&cursor),
            None,
        );
        assert!(run_href.len() <= RENDERER_URL_CEILING);
        assert!(run_href.len() > 2_048);
        assert_eq!(
            login_return_path(run_href, format!("{run_action}/actions"))
                .expect("oversized filter falls back to its canonical action")
                .as_str(),
            format!("{run_action}/actions")
        );

        let job_action = format!(
            "{run_action}/actions/runs/{}/jobs/{}",
            RunId::new(),
            automata_ci_core::JobId::new()
        );
        let log_href = query_href(&job_action, &[("q", &"é".repeat(512))]);
        assert!(log_href.len() > 2_048);
        assert_eq!(
            login_return_path(log_href, job_action.clone())
                .expect("oversized search falls back to the selected job")
                .as_str(),
            job_action
        );

        let source = GitHubSourceLinks::new("github", &"a".repeat(39), &"r".repeat(100))
            .expect("maximum GitHub repository identity");
        let git_ref = format!("refs/heads/{}", "é".repeat(506));
        assert!(git_ref.len() <= 1_024);
        let source_ref = source
            .source_ref(Some(&git_ref))
            .expect("maximum source ref")
            .expect("supported branch ref");
        assert!(source_ref.href.len() <= RENDERER_URL_CEILING);
    }

    #[test]
    fn run_list_omits_an_unmappable_ref_but_rejects_an_unsupported_provider() {
        let workflow_id = WorkflowId::new();
        let mut run = fixture_run(DataStatus::Succeeded, workflow_id);
        run.git_ref = Some("refs/remotes/origin/main".to_owned());
        let context = RequestContext::anonymous(TenantId::new("tenant-a").expect("fixture tenant"));
        let data = RunListData {
            repository: fixture_repository(),
            workflows: vec![fixture_workflow_definition(&run.workflow, true)],
            selected_workflow: None,
            workflow_previous_cursor: None,
            workflow_next_cursor: None,
            runs: vec![run],
            previous_cursor: None,
            next_cursor: None,
        };
        let request = fixture_run_list_request(None, StatusFilter::All, None, None);
        let json = run_list(
            client_assets(),
            "nonce".to_owned(),
            &context,
            None,
            &request,
            &data,
        )
        .expect("an unusual durable ref must not fail the page");
        let value: Value = serde_json::from_str(&json).expect("page JSON");
        assert!(value["page"]["runs"][0]["sourceRef"].is_null());

        let mut unsupported = data;
        unsupported.repository.scm_provider = "gitlab".to_owned();
        assert!(matches!(
            run_list(
                client_assets(),
                "nonce".to_owned(),
                &context,
                None,
                &request,
                &unsupported,
            ),
            Err(ModelError::InvalidData)
        ));
    }

    #[test]
    fn every_status_keeps_its_exact_label_and_tone() {
        for (input, expected_label, expected_tone) in [
            (DataStatus::Queued, "Queued", "queued"),
            (DataStatus::InProgress, "In progress", "running"),
            (DataStatus::Succeeded, "Succeeded", "success"),
            (DataStatus::Failed, "Failed", "failure"),
            (DataStatus::Cancelled, "Cancelled", "neutral"),
            (DataStatus::TimedOut, "Timed out", "failure"),
            (DataStatus::Skipped, "Skipped", "neutral"),
            (DataStatus::Lost, "Lost", "warning"),
        ] {
            let rendered = status(input);
            assert_eq!(rendered.label, expected_label);
            assert_eq!(rendered.tone, expected_tone);
        }
    }

    #[test]
    fn job_log_notice_tracks_lifecycle_instead_of_pagination() {
        assert_eq!(
            job_log_notice(DataStatus::Queued),
            Some("This job is queued. This page updates automatically.")
        );
        assert_eq!(
            job_log_notice(DataStatus::InProgress),
            Some(
                "This job is still running. This page updates automatically as logs are committed."
            )
        );
        for terminal in [
            DataStatus::Succeeded,
            DataStatus::Failed,
            DataStatus::Cancelled,
            DataStatus::TimedOut,
            DataStatus::Skipped,
            DataStatus::Lost,
        ] {
            assert_eq!(job_log_notice(terminal), None);
        }
    }

    fn repository_settings_fixture() -> (RequestContext, CsrfToken, RepositorySettingsData) {
        let context = RequestContext::new(
            TenantId::new("tenant-a").expect("fixture tenant"),
            AuthorizationContext::anonymous(),
            Some(DataViewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("fixture viewer context");
        let csrf = CsrfToken::from_generated_secret(
            SecretString::new("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
                .expect("bounded CSRF fixture"),
        )
        .expect("canonical CSRF fixture");
        let mut repository = fixture_repository();
        repository.settings_visible = true;
        let data = RepositorySettingsData {
            repository,
            policy: RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Authenticated,
                OutputVisibility::Private,
            ),
            revision: 7,
            editable: true,
            secrets_visible: true,
        };
        (context, csrf, data)
    }

    fn repository_secrets_fixture() -> (RequestContext, CsrfToken, RepositorySecretsData) {
        let (context, csrf, _) = repository_settings_fixture();
        let repository_id = automata_ci_store::RepositoryId::from_uuid(
            RunId::from_str("11111111-1111-4111-8111-111111111111")
                .expect("repository UUID")
                .as_uuid(),
        );
        let secret_id = automata_ci_store::RepositorySecretId::from_uuid(
            RunId::from_str("77777777-7777-4777-8777-777777777777")
                .expect("secret UUID")
                .as_uuid(),
        )
        .expect("secret ID");
        let replace_mutation_id = automata_ci_store::RepositorySecretMutationId::from_uuid(
            RunId::from_str("88888888-8888-4888-8888-888888888888")
                .expect("replace UUID")
                .as_uuid(),
            secret_id,
        )
        .expect("replace mutation ID");
        let create_secret_id = automata_ci_store::RepositorySecretId::from_uuid(
            RunId::from_str("99999999-9999-4999-8999-999999999999")
                .expect("create secret UUID")
                .as_uuid(),
        )
        .expect("create secret ID");
        let create_mutation_id = automata_ci_store::RepositorySecretMutationId::from_uuid(
            RunId::from_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                .expect("create mutation UUID")
                .as_uuid(),
            create_secret_id,
        )
        .expect("create mutation ID");
        let metadata = automata_ci_store::RepositorySecretMetadata::from_durable_parts(
            secret_id,
            repository_id,
            automata_ci_store::RepositorySecretName::new("DEPLOY_TOKEN").expect("secret name"),
            automata_ci_store::ManagedSecretProviderId::new(BUILTIN_SECRET_PROVIDER_ID)
                .expect("provider ID"),
            RepositorySecretState::Active,
            Some(2),
            ManagementRevision::new(5).expect("metadata revision"),
            UnixMillis::new(1_754_742_600_000),
            UnixMillis::new(1_754_742_660_000),
        );
        let data = RepositorySecretsData {
            repository_id,
            owner: "automata-ci".to_owned(),
            repository: "automata".to_owned(),
            authorization_revision: ManagementRevision::new(12).expect("authorization revision"),
            access_visible: true,
            rows: vec![RepositorySecretRow {
                metadata,
                replace_mutation_id: Some(replace_mutation_id),
                deletable: true,
            }],
            next_after: None,
            create: Some(RepositorySecretCreateCapability {
                secret_id: create_secret_id,
                mutation_id: create_mutation_id,
            }),
            provider: None,
        };
        (context, csrf, data)
    }

    fn managed_user(
        principal_id: &str,
        provider_login: &str,
        display_name: Option<String>,
        status: MemberStatus,
        authorization_revision: u64,
        revision: u64,
    ) -> MemberRecord {
        MemberRecord::new(
            ManagedPrincipalId::new(principal_id).expect("fixture principal ID"),
            ProviderId::new("github").expect("fixture provider"),
            provider_login,
            display_name,
            status,
            ManagementRevision::new(authorization_revision).expect("authorization revision"),
            ManagementRevision::new(revision).expect("member revision"),
        )
        .expect("fixture member")
    }

    fn direct_management_binding(revision: ManagementRevision) -> ManagementRoleBindingRecord {
        ManagementRoleBindingRecord::new(
            RoleBindingId::new("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").expect("fixture binding ID"),
            managed_user(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "ada-lovelace",
                Some("Ada Lovelace".to_owned()),
                MemberStatus::Active,
                7,
                3,
            ),
            ManagementBindingRole::new(
                RoleId::new("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("fixture role ID"),
                RoleName::new("release-reviewer").expect("fixture role name"),
                "Release reviewer",
            )
            .expect("fixture binding role"),
            ManagementScopeRecord::new(
                AuthorizationScope::tenant(
                    TenantId::new("tenant-a").expect("fixture scope tenant"),
                ),
                "Production tenant",
            )
            .expect("fixture binding scope"),
            ManagementRoleBindingSource::Direct(DirectRoleBindingSource::Manual),
            RoleBindingStatus::Active,
            None,
            revision,
        )
        .expect("fixture direct binding")
    }

    fn test_rbac_role() -> RbacRoleSummary {
        RbacRoleSummary {
            id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
            href: "/settings/access/roles/cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
            name: "release-reviewer".to_owned(),
            display_name: "Release reviewer".to_owned(),
            kind: "custom",
            immutable: false,
            permission_count: 1,
        }
    }

    fn assert_exact_object_keys(value: &Value, expected: &[&str]) {
        let object = value.as_object().expect("fixture must be a JSON object");
        let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    fn fixture_repository() -> DataRepository {
        DataRepository {
            id: "11111111-1111-4111-8111-111111111111".to_owned(),
            scm_provider: "github".to_owned(),
            owner: "automata-ci".to_owned(),
            name: "automata".to_owned(),
            settings_visible: false,
        }
    }

    fn fixture_run(status: DataStatus, workflow_id: WorkflowId) -> RunSummary {
        RunSummary {
            id: RunId::from_str("550e8400-e29b-41d4-a716-446655440000").expect("fixture run ID"),
            number: 1_842,
            attempt: 1,
            title: Some("Build and test release candidate".to_owned()),
            workflow: Workflow {
                id: workflow_id,
                name: "CI".to_owned(),
                path: ".ci/workflows/ci.yml".to_owned(),
            },
            status,
            git_ref: Some("refs/heads/main".to_owned()),
            event: "push".to_owned(),
            actor: None,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            commit_subject: None,
            created_at: UnixMillis::new(1_786_003_200_000),
            finished_at: None,
        }
    }

    fn fixture_workflow_definition(workflow: &Workflow, enabled: bool) -> WorkflowDefinition {
        WorkflowDefinition {
            id: workflow.id,
            name: workflow.name.clone(),
            enabled,
        }
    }

    fn fixture_run_list_request(
        workflow_id: Option<WorkflowId>,
        status: StatusFilter,
        branch: Option<&str>,
        cursor: Option<&str>,
    ) -> RunListRequestData {
        RunListRequestData {
            workflow_id,
            workflow_cursor: None,
            status,
            git_ref: branch.map(str::to_owned),
            cursor: cursor.map(str::to_owned),
            limit: RUN_PAGE_SIZE,
        }
    }
}
