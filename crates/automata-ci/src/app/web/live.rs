use std::{
    collections::{HashSet, VecDeque},
    fmt::Write as _,
    str::FromStr as _,
    sync::Arc,
};

use async_trait::async_trait;
use automata_ci_auth::authorization::{
    AuthorizationRequest, AuthorizationScope, OutputVisibility, Permission, SecretExposureClass,
    repository_read_permissions,
};
use automata_ci_blob::{BlobStoreError, BlobStoreErrorKind, ImmutableBlobStore};
use automata_ci_core::{
    AttemptId, JobConclusion, JobId, JobLifecycle, LogFrame, LogSequence, LogStreamId, RunId,
    Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_results_github::{
    ARTIFACT_MANIFEST_MEDIA_TYPE, ArtifactManifest, MAXIMUM_ARTIFACT_MANIFEST_BYTES,
};
use automata_ci_store::{
    HumanArtifactBlock, HumanArtifactDownload as StoredArtifactDownload, HumanArtifactId,
    HumanArtifactScope, HumanArtifactSummary, HumanAuthorizationTarget, HumanGitRef, HumanJob,
    HumanJobDetail, HumanJobNavigation, HumanJobScope, HumanLiveLogScope, HumanLogSegmentCursor,
    HumanLogSegmentPageDirection, HumanLogSegmentPageSize, HumanLogSegmentQuery,
    HumanOutputPublication, HumanPageSize, HumanRawLogDisposition, HumanRepository,
    HumanRepositoryCursor, HumanRepositoryListQuery, HumanRepositoryPage, HumanRun,
    HumanRunConclusion, HumanRunCursor, HumanRunDetail, HumanRunListQuery, HumanRunPageDirection,
    HumanRunScope, HumanRunStatusFilter, HumanWorkflow, HumanWorkflowListQuery,
    HumanWorkflowReadRepository, RepositoryCoordinate, RepositoryId, StoreError, TenantScope,
    WorkflowRunStatus,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::stream;
use sha2::{Digest as _, Sha256};

use super::{
    codec::{LogSegmentExpectation, decode_log_segment},
    data::{
        ArtifactDownload, ArtifactSummary, AuthorizedLiveLog, CollectionVisibility, JobLogLive,
        JobLogPage, JobLogRequest, JobNavigationItem, JobSummary, LiveLogBatch, LiveLogRecord,
        LogChannel, LogLine, Repository, RepositoryDirectoryItem, RepositoryDirectoryPage,
        RepositoryDirectoryRequest, RepositoryPath, RepositorySettingsDestination,
        RepositorySettingsPage, RequestContext, RunDetailPage, RunDetailRequest, RunListPage,
        RunListRequest, RunSummary, Status, StatusFilter, VisibleCollection, WebData, WebDataError,
        Workflow, WorkflowDefinition,
    },
    text::is_safe_display_text,
};
use crate::app::repository_secrets::{
    RepositorySecretWebData, RepositorySecretWebError, RepositorySecretsPageRequest,
    RepositorySecretsReadOutcome,
};

const SCM_PROVIDER: &str = "github";
const MAX_WORKFLOW_SCAN_PAGES: usize = 17;
const WORKFLOW_PAGE_SIZE: u16 = 250;
const LOG_SEGMENT_PAGE_SIZE: u16 = 32;
const MAX_RENDERED_JOBS: usize = 200;
const MAX_DURABLE_RUN_JOBS: usize = 4_096;
const MAX_RENDERED_ARTIFACTS: usize = 500;
const CURSOR_VERSION: u8 = 1;
const REPOSITORY_CURSOR_KIND: u8 = b'p';
const RUN_CURSOR_KIND: u8 = b'r';
const LOG_CURSOR_KIND: u8 = b'l';
const WORKFLOW_CURSOR_KIND: u8 = b'w';
const JOB_CURSOR_KIND: u8 = b'j';
const RUN_CURSOR_BYTES: usize = 94;
const LOG_CURSOR_BYTES: usize = 95;
const WORKFLOW_CURSOR_BYTES: usize = 68;
const JOB_CURSOR_BYTES: usize = 75;
const REPOSITORY_CURSOR_FIXED_BYTES: usize = 38;
const MAX_REPOSITORY_OWNER_BYTES: usize = 39;
const MAX_REPOSITORY_NAME_BYTES: usize = 100;
const MAX_REPOSITORY_CURSOR_BYTES: usize =
    REPOSITORY_CURSOR_FIXED_BYTES + MAX_REPOSITORY_OWNER_BYTES + MAX_REPOSITORY_NAME_BYTES;
const BINDING_BYTES: usize = 16;
const BLOCK_LIST_DIGEST_DOMAIN: &[u8] = b"automata-results-block-list-v1\0";
const REPOSITORY_SETTINGS_READ_PERMISSION: &str = "repositories:read";
const REPOSITORY_SETTINGS_UPDATE_PERMISSION: &str = "repositories:visibility:update";
const SECRET_METADATA_READ_PERMISSION: &str = "secrets:metadata:read";

/// Production, tenant-scoped human workflow read adapter.
pub(crate) struct LiveWebData {
    reads: Arc<dyn HumanWorkflowReadRepository>,
    objects: Arc<dyn ImmutableBlobStore>,
    repository_secrets: Option<Arc<dyn RepositorySecretWebData>>,
}

impl std::fmt::Debug for LiveWebData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiveWebData")
            .finish_non_exhaustive()
    }
}

impl LiveWebData {
    #[must_use]
    pub(crate) fn new(
        reads: Arc<dyn HumanWorkflowReadRepository>,
        objects: Arc<dyn ImmutableBlobStore>,
    ) -> Self {
        Self {
            reads,
            objects,
            repository_secrets: None,
        }
    }

    #[must_use]
    pub(crate) fn with_repository_secrets(
        mut self,
        repository_secrets: Arc<dyn RepositorySecretWebData>,
    ) -> Self {
        self.repository_secrets = Some(repository_secrets);
        self
    }

    fn tenant(context: &RequestContext) -> Result<TenantScope, WebDataError> {
        TenantScope::from_authenticated_tenant_id(context.tenant_id().as_str().to_owned())
            .map_err(|_| WebDataError::Corrupt)
    }

    async fn resolve_repository_exact(
        &self,
        tenant: &TenantScope,
        path: &RepositoryPath,
    ) -> Result<Option<HumanRepository>, WebDataError> {
        let Ok(coordinate) = RepositoryCoordinate::new(SCM_PROVIDER, &path.owner, &path.name)
        else {
            return Ok(None);
        };
        let repository = self
            .reads
            .resolve_repository(tenant, &coordinate)
            .await
            .map_err(map_store_error)?;
        let Some(repository) = repository else {
            return Ok(None);
        };
        if repository.scm_provider != SCM_PROVIDER
            || repository.owner != path.owner
            || repository.name != path.name
            || repository.resource.tenant_id().as_str() != tenant.as_str()
            || repository.resource.repository_id().as_uuid() != repository.id.as_uuid()
        {
            return Err(WebDataError::Corrupt);
        }
        Ok(Some(repository))
    }

    async fn repository(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        path: &RepositoryPath,
    ) -> Result<Option<HumanRepository>, WebDataError> {
        let Some(repository) = self.resolve_repository_exact(tenant, path).await? else {
            return Ok(None);
        };
        if !self
            .allowed(
                context,
                tenant,
                &repository,
                repository_read_permissions::REPOSITORY_READ,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?
        {
            return Ok(None);
        }
        Ok(Some(repository))
    }

    async fn dashboard_job_metadata_allowed(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        visibility: OutputVisibility,
    ) -> Result<bool, WebDataError> {
        if !self
            .allowed(
                context,
                tenant,
                repository,
                repository_read_permissions::REPOSITORY_READ,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?
        {
            return Ok(false);
        }
        for permission_name in [
            repository_read_permissions::WORKFLOW_READ,
            repository_read_permissions::RUN_READ,
            repository_read_permissions::JOB_READ,
        ] {
            if !self
                .allowed(
                    context,
                    tenant,
                    repository,
                    permission_name,
                    Some(visibility),
                    SecretExposureClass::ReadableSecret,
                )
                .await?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn allowed(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        permission_name: &'static str,
        durable_visibility: Option<OutputVisibility>,
        secret_exposure: SecretExposureClass,
    ) -> Result<bool, WebDataError> {
        if repository.resource.tenant_id() != context.tenant_id()
            || repository.resource.repository_id().as_uuid() != repository.id.as_uuid()
        {
            return Err(WebDataError::Corrupt);
        }
        let request = AuthorizationRequest::new(
            AuthorizationScope::repository(repository.resource.clone()),
            permission(permission_name),
        )
        .with_secret_exposure(secret_exposure);
        let target = match durable_visibility {
            Some(visibility) => HumanAuthorizationTarget::immutable(request, visibility),
            None => HumanAuthorizationTarget::current_policy(request),
        };
        self.reads
            .is_repository_request_allowed(tenant, repository.id, context.authorization(), &target)
            .await
            .map_err(map_store_error)
    }

    async fn settings_visible(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
    ) -> Result<bool, WebDataError> {
        if context.viewer().is_none() {
            return Ok(false);
        }
        self.allowed(
            context,
            tenant,
            repository,
            REPOSITORY_SETTINGS_READ_PERMISSION,
            Some(OutputVisibility::Private),
            SecretExposureClass::ReadableSecret,
        )
        .await
    }

    async fn log_access_allowed(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        visibility: OutputVisibility,
    ) -> Result<bool, WebDataError> {
        self.allowed(
            context,
            tenant,
            repository,
            repository_read_permissions::LOG_READ,
            Some(visibility),
            SecretExposureClass::Secretless,
        )
        .await
    }

    async fn cached_log_access_allowed(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        cache: &mut Vec<(OutputVisibility, bool)>,
        visibility: OutputVisibility,
    ) -> Result<bool, WebDataError> {
        if let Some((_, decision)) = cache.iter().find(|(cached, _)| *cached == visibility) {
            return Ok(*decision);
        }
        let decision = self
            .log_access_allowed(context, tenant, repository, visibility)
            .await?;
        cache.push((visibility, decision));
        Ok(decision)
    }

    async fn cached_artifact_access(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        cache: &mut Vec<(HumanOutputPublication, ArtifactAccess)>,
        publication: &HumanOutputPublication,
    ) -> Result<ArtifactAccess, WebDataError> {
        if let Some((_, decision)) = cache.iter().find(|(cached, _)| cached == publication) {
            return Ok(*decision);
        }
        let (visibility, exposure) = publication_target(publication);
        let readable = self
            .allowed(
                context,
                tenant,
                repository,
                repository_read_permissions::ARTIFACT_READ,
                Some(visibility),
                exposure,
            )
            .await?;
        let downloadable = if readable {
            self.allowed(
                context,
                tenant,
                repository,
                repository_read_permissions::ARTIFACT_DOWNLOAD,
                Some(visibility),
                exposure,
            )
            .await?
        } else {
            false
        };
        let decision = ArtifactAccess {
            readable,
            downloadable,
        };
        cache.push((publication.clone(), decision));
        Ok(decision)
    }

    async fn workflows(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        request: &RunListRequest,
    ) -> Result<Option<WorkflowNavigationPage>, WebDataError> {
        let decoded_cursor = match request.workflow_cursor.as_deref() {
            Some(cursor) => {
                let Some(cursor) =
                    decode_workflow_cursor(cursor, tenant, repository.id, request.workflow_id)
                else {
                    return Ok(None);
                };
                Some(cursor)
            }
            None => None,
        };
        let Some(all_workflows) = self
            .load_workflow_definitions(context, tenant, repository.id)
            .await?
        else {
            return Ok(None);
        };
        Ok(workflow_navigation_page(
            &all_workflows,
            decoded_cursor,
            tenant,
            repository.id,
            request.workflow_id,
        ))
    }

    async fn load_workflow_definitions(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository_id: RepositoryId,
    ) -> Result<Option<Vec<WorkflowDefinition>>, WebDataError> {
        let workflow_permission = permission(repository_read_permissions::WORKFLOW_READ);
        let mut query = HumanWorkflowListQuery::new(tenant.clone(), repository_id);
        query.limit = HumanPageSize::new(WORKFLOW_PAGE_SIZE).map_err(|_| WebDataError::Corrupt)?;
        let mut all_workflows = Vec::new();
        let mut seen_ids = HashSet::new();
        let mut exhausted = false;
        for page_index in 0..MAX_WORKFLOW_SCAN_PAGES {
            let page = self
                .reads
                .list_workflows(&query, context.authorization(), &workflow_permission)
                .await
                .map_err(map_store_error)?;
            let Some(page) = page else {
                return Ok(None);
            };
            if page.workflows.len() > usize::from(WORKFLOW_PAGE_SIZE) {
                return Err(WebDataError::Corrupt);
            }
            for workflow in page.workflows {
                if !seen_ids.insert(workflow.id) {
                    return Err(WebDataError::Corrupt);
                }
                all_workflows.push(map_workflow(&workflow));
            }
            let Some(cursor) = page.next_cursor else {
                exhausted = true;
                break;
            };
            if page_index + 1 == MAX_WORKFLOW_SCAN_PAGES {
                continue;
            }
            query.cursor = Some(cursor);
        }
        if !exhausted {
            return Err(WebDataError::Corrupt);
        }
        Ok(Some(all_workflows))
    }
}

fn workflow_navigation_page(
    all_workflows: &[WorkflowDefinition],
    decoded_cursor: Option<DecodedWorkflowCursor>,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    selected_workflow_id: Option<WorkflowId>,
) -> Option<WorkflowNavigationPage> {
    let selected_index = selected_workflow_id.and_then(|selected| {
        all_workflows
            .iter()
            .position(|workflow| workflow.id == selected)
    });
    if selected_workflow_id.is_some() && selected_index.is_none() {
        return None;
    }
    let page_size = usize::from(WORKFLOW_PAGE_SIZE);
    let start = match decoded_cursor {
        None => selected_index.map_or(0, |index| index / page_size * page_size),
        Some(cursor) => {
            let boundary_index = all_workflows
                .iter()
                .position(|workflow| workflow.id == cursor.position)?;
            navigation_page_start(
                all_workflows.len(),
                page_size,
                boundary_index,
                cursor.direction,
            )?
        }
    };
    let end = start.saturating_add(page_size).min(all_workflows.len());
    let previous_cursor = (start > 0).then(|| {
        encode_workflow_cursor(
            tenant,
            repository_id,
            selected_workflow_id,
            all_workflows[start].id,
            NavigationPageDirection::Previous,
        )
    });
    let next_cursor = (end < all_workflows.len()).then(|| {
        encode_workflow_cursor(
            tenant,
            repository_id,
            selected_workflow_id,
            all_workflows[end - 1].id,
            NavigationPageDirection::Next,
        )
    });
    Some(WorkflowNavigationPage {
        workflows: all_workflows[start..end].to_vec(),
        selected_workflow: selected_index.map(|index| all_workflows[index].clone()),
        previous_cursor,
        next_cursor,
    })
}

fn navigation_page_start(
    item_count: usize,
    page_size: usize,
    boundary_index: usize,
    direction: NavigationPageDirection,
) -> Option<usize> {
    match direction {
        NavigationPageDirection::Previous => (boundary_index > 0
            && boundary_index.is_multiple_of(page_size))
        .then(|| boundary_index.saturating_sub(page_size)),
        NavigationPageDirection::Next => {
            let start = boundary_index.checked_add(1)?;
            (start.is_multiple_of(page_size) && start < item_count).then_some(start)
        }
    }
}

fn run_jobs_are_canonical(jobs: &[HumanJob]) -> bool {
    let mut ids = HashSet::with_capacity(jobs.len());
    jobs.iter().all(|job| ids.insert(job.id))
        && jobs.windows(2).all(|pair| {
            (pair[0].created_at, pair[0].id.as_uuid()) < (pair[1].created_at, pair[1].id.as_uuid())
        })
}

fn run_job_page_bounds(
    jobs: &[HumanJob],
    page_size: usize,
    cursor: Option<DecodedJobCursor>,
) -> Option<(usize, usize)> {
    if page_size == 0 || page_size > MAX_RENDERED_JOBS {
        return None;
    }
    let start = match cursor {
        None => 0,
        Some(cursor) => {
            let boundary_index = jobs
                .iter()
                .position(|job| job.id == cursor.position && job.created_at == cursor.created_at)?;
            navigation_page_start(jobs.len(), page_size, boundary_index, cursor.direction)?
        }
    };
    Some((start, start.saturating_add(page_size).min(jobs.len())))
}

fn job_page_cursor(
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job: &HumanJob,
    direction: NavigationPageDirection,
) -> String {
    encode_job_cursor(
        tenant,
        repository_id,
        run_id,
        DecodedJobCursor {
            created_at: job.created_at,
            position: job.id,
            direction,
        },
    )
}

fn permission(name: &'static str) -> Permission {
    Permission::new(name).expect("static repository-read permission is valid")
}

#[allow(clippy::needless_pass_by_value)]
fn map_store_error(error: StoreError) -> WebDataError {
    if matches!(error, StoreError::CorruptData(_)) {
        WebDataError::Corrupt
    } else {
        WebDataError::Unavailable
    }
}

const fn map_blob_error(error: BlobStoreError) -> WebDataError {
    match error.kind() {
        BlobStoreErrorKind::Unauthorized | BlobStoreErrorKind::Unavailable => {
            WebDataError::Unavailable
        }
        BlobStoreErrorKind::NotFound
        | BlobStoreErrorKind::Conflict
        | BlobStoreErrorKind::Integrity
        | BlobStoreErrorKind::TooLarge
        | BlobStoreErrorKind::InvalidResponse => WebDataError::Corrupt,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedRunCursor {
    position: HumanRunCursor,
    direction: HumanRunPageDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedLogCursor {
    sequence: LogSequence,
    line_ordinal: u32,
    direction: HumanLogSegmentPageDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NavigationPageDirection {
    Previous,
    Next,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedWorkflowCursor {
    position: WorkflowId,
    direction: NavigationPageDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedJobCursor {
    created_at: UnixMillis,
    position: JobId,
    direction: NavigationPageDirection,
}

#[derive(Debug)]
struct WorkflowNavigationPage {
    workflows: Vec<WorkflowDefinition>,
    selected_workflow: Option<WorkflowDefinition>,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

#[derive(Debug)]
struct RunJobPage {
    visibility: CollectionVisibility,
    jobs: Vec<JobSummary>,
    previous_cursor: Option<String>,
    next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArtifactAccess {
    readable: bool,
    downloadable: bool,
}

fn encode_repository_cursor(
    tenant: &TenantScope,
    position: &HumanRepositoryCursor,
) -> Result<String, WebDataError> {
    if !valid_normalized_repository_owner(&position.normalized_owner)
        || !valid_normalized_repository_name(&position.normalized_name)
        || position.id.as_uuid().is_nil()
    {
        return Err(WebDataError::Corrupt);
    }
    let owner_length =
        u16::try_from(position.normalized_owner.len()).map_err(|_| WebDataError::Corrupt)?;
    let name_length =
        u16::try_from(position.normalized_name.len()).map_err(|_| WebDataError::Corrupt)?;
    let mut bytes = Vec::with_capacity(
        REPOSITORY_CURSOR_FIXED_BYTES
            + position.normalized_owner.len()
            + position.normalized_name.len(),
    );
    bytes.extend_from_slice(&[CURSOR_VERSION, REPOSITORY_CURSOR_KIND]);
    bytes.extend_from_slice(&binding_digest(b"tenant", tenant.as_str()));
    bytes.extend_from_slice(&owner_length.to_be_bytes());
    bytes.extend_from_slice(&name_length.to_be_bytes());
    bytes.extend_from_slice(position.id.as_uuid().as_bytes());
    bytes.extend_from_slice(position.normalized_owner.as_bytes());
    bytes.extend_from_slice(position.normalized_name.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_repository_cursor(value: &str, tenant: &TenantScope) -> Option<HumanRepositoryCursor> {
    let bytes = canonical_variable_cursor_bytes(
        value,
        REPOSITORY_CURSOR_FIXED_BYTES + 2,
        MAX_REPOSITORY_CURSOR_BYTES,
    )?;
    if bytes[0] != CURSOR_VERSION
        || bytes[1] != REPOSITORY_CURSOR_KIND
        || bytes[2..18] != binding_digest(b"tenant", tenant.as_str())
    {
        return None;
    }
    let owner_length = usize::from(u16::from_be_bytes(bytes[18..20].try_into().ok()?));
    let name_length = usize::from(u16::from_be_bytes(bytes[20..22].try_into().ok()?));
    let expected_length = REPOSITORY_CURSOR_FIXED_BYTES
        .checked_add(owner_length)?
        .checked_add(name_length)?;
    if bytes.len() != expected_length {
        return None;
    }
    let id = RepositoryId::from_uuid(uuid::Uuid::from_slice(&bytes[22..38]).ok()?);
    if id.as_uuid().is_nil() {
        return None;
    }
    let owner_end = REPOSITORY_CURSOR_FIXED_BYTES.checked_add(owner_length)?;
    let normalized_owner =
        std::str::from_utf8(&bytes[REPOSITORY_CURSOR_FIXED_BYTES..owner_end]).ok()?;
    let normalized_name = std::str::from_utf8(&bytes[owner_end..]).ok()?;
    if !valid_normalized_repository_owner(normalized_owner)
        || !valid_normalized_repository_name(normalized_name)
    {
        return None;
    }
    Some(HumanRepositoryCursor {
        normalized_owner: normalized_owner.to_owned(),
        normalized_name: normalized_name.to_owned(),
        id,
    })
}

fn valid_normalized_repository_owner(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=MAX_REPOSITORY_OWNER_BYTES).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !bytes.windows(2).any(|pair| pair == b"--")
}

fn valid_normalized_repository_name(value: &str) -> bool {
    (1..=MAX_REPOSITORY_NAME_BYTES).contains(&value.len())
        && !matches!(value, "." | "..")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_github_repository_identity(owner: &str, name: &str) -> bool {
    let owner_bytes = owner.as_bytes();
    let valid_owner = (1..=MAX_REPOSITORY_OWNER_BYTES).contains(&owner_bytes.len())
        && owner_bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && owner_bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && owner_bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && !owner_bytes.windows(2).any(|pair| pair == b"--");
    let valid_name = (1..=MAX_REPOSITORY_NAME_BYTES).contains(&name.len())
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    valid_owner && valid_name
}

fn encode_run_cursor(
    tenant: &TenantScope,
    repository_id: RepositoryId,
    request: &RunListRequest,
    position: HumanRunCursor,
    direction: HumanRunPageDirection,
) -> String {
    let mut bytes = Vec::with_capacity(RUN_CURSOR_BYTES);
    bytes.extend_from_slice(&[
        CURSOR_VERSION,
        RUN_CURSOR_KIND,
        run_direction_byte(direction),
        status_filter_byte(request.status),
        u8::from(request.workflow_id.is_some()),
        u8::from(request.git_ref.is_some()),
    ]);
    bytes.extend_from_slice(&binding_digest(b"tenant", tenant.as_str()));
    bytes.extend_from_slice(repository_id.as_uuid().as_bytes());
    let workflow_id = request
        .workflow_id
        .map_or([0_u8; 16], |id| *id.as_uuid().as_bytes());
    bytes.extend_from_slice(&workflow_id);
    bytes.extend_from_slice(
        request
            .git_ref
            .as_deref()
            .map_or([0_u8; BINDING_BYTES], |git_ref| {
                binding_digest(b"git-ref", git_ref)
            })
            .as_slice(),
    );
    bytes.extend_from_slice(&position.created_at.get().to_be_bytes());
    bytes.extend_from_slice(position.id.as_uuid().as_bytes());
    debug_assert_eq!(bytes.len(), RUN_CURSOR_BYTES);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_run_cursor(
    value: &str,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    request: &RunListRequest,
) -> Option<DecodedRunCursor> {
    let bytes = canonical_cursor_bytes(value, RUN_CURSOR_BYTES)?;
    if bytes[0] != CURSOR_VERSION
        || bytes[1] != RUN_CURSOR_KIND
        || bytes[3] != status_filter_byte(request.status)
        || bytes[4] != u8::from(request.workflow_id.is_some())
        || bytes[5] != u8::from(request.git_ref.is_some())
        || bytes[6..22] != binding_digest(b"tenant", tenant.as_str())
        || bytes[22..38] != *repository_id.as_uuid().as_bytes()
    {
        return None;
    }
    let expected_workflow = request
        .workflow_id
        .map_or([0_u8; 16], |id| *id.as_uuid().as_bytes());
    let expected_ref = request
        .git_ref
        .as_deref()
        .map_or([0_u8; BINDING_BYTES], |git_ref| {
            binding_digest(b"git-ref", git_ref)
        });
    if bytes[38..54] != expected_workflow || bytes[54..70] != expected_ref {
        return None;
    }
    let direction = run_direction(bytes[2])?;
    let created_at = UnixMillis::new(i64::from_be_bytes(bytes[70..78].try_into().ok()?));
    let id = parse_uuid_id::<RunId>(&bytes[78..94])?;
    if id.as_uuid().is_nil() {
        return None;
    }
    Some(DecodedRunCursor {
        position: HumanRunCursor { created_at, id },
        direction,
    })
}

fn encode_log_cursor(
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    stream_id: LogStreamId,
    cursor: DecodedLogCursor,
) -> String {
    let mut bytes = Vec::with_capacity(LOG_CURSOR_BYTES);
    bytes.extend_from_slice(&[
        CURSOR_VERSION,
        LOG_CURSOR_KIND,
        log_direction_byte(cursor.direction),
    ]);
    bytes.extend_from_slice(&binding_digest(b"tenant", tenant.as_str()));
    bytes.extend_from_slice(repository_id.as_uuid().as_bytes());
    bytes.extend_from_slice(run_id.as_uuid().as_bytes());
    bytes.extend_from_slice(job_id.as_uuid().as_bytes());
    bytes.extend_from_slice(stream_id.as_uuid().as_bytes());
    bytes.extend_from_slice(&cursor.sequence.get().to_be_bytes());
    bytes.extend_from_slice(&cursor.line_ordinal.to_be_bytes());
    debug_assert_eq!(bytes.len(), LOG_CURSOR_BYTES);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_log_cursor(
    value: &str,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    job_id: JobId,
    stream_id: LogStreamId,
) -> Option<DecodedLogCursor> {
    let bytes = canonical_cursor_bytes(value, LOG_CURSOR_BYTES)?;
    if bytes[0] != CURSOR_VERSION
        || bytes[1] != LOG_CURSOR_KIND
        || bytes[3..19] != binding_digest(b"tenant", tenant.as_str())
        || bytes[19..35] != *repository_id.as_uuid().as_bytes()
        || bytes[35..51] != *run_id.as_uuid().as_bytes()
        || bytes[51..67] != *job_id.as_uuid().as_bytes()
        || bytes[67..83] != *stream_id.as_uuid().as_bytes()
    {
        return None;
    }
    let direction = log_direction(bytes[2])?;
    let line_ordinal = u32::from_be_bytes(bytes[91..95].try_into().ok()?);
    let sequence = u64::from_be_bytes(bytes[83..91].try_into().ok()?);
    if sequence > i64::MAX.unsigned_abs()
        || (direction == HumanLogSegmentPageDirection::Older
            && line_ordinal > 0
            && sequence == i64::MAX.unsigned_abs())
    {
        return None;
    }
    Some(DecodedLogCursor {
        sequence: LogSequence::new(sequence),
        line_ordinal,
        direction,
    })
}

fn encode_workflow_cursor(
    tenant: &TenantScope,
    repository_id: RepositoryId,
    selected_workflow_id: Option<WorkflowId>,
    position: WorkflowId,
    direction: NavigationPageDirection,
) -> String {
    let mut bytes = Vec::with_capacity(WORKFLOW_CURSOR_BYTES);
    bytes.extend_from_slice(&[
        CURSOR_VERSION,
        WORKFLOW_CURSOR_KIND,
        navigation_direction_byte(direction),
        u8::from(selected_workflow_id.is_some()),
    ]);
    bytes.extend_from_slice(&binding_digest(b"tenant", tenant.as_str()));
    bytes.extend_from_slice(repository_id.as_uuid().as_bytes());
    bytes
        .extend_from_slice(&selected_workflow_id.map_or([0_u8; 16], |id| *id.as_uuid().as_bytes()));
    bytes.extend_from_slice(position.as_uuid().as_bytes());
    debug_assert_eq!(bytes.len(), WORKFLOW_CURSOR_BYTES);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_workflow_cursor(
    value: &str,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    selected_workflow_id: Option<WorkflowId>,
) -> Option<DecodedWorkflowCursor> {
    let bytes = canonical_cursor_bytes(value, WORKFLOW_CURSOR_BYTES)?;
    if bytes[0] != CURSOR_VERSION
        || bytes[1] != WORKFLOW_CURSOR_KIND
        || bytes[3] != u8::from(selected_workflow_id.is_some())
        || bytes[4..20] != binding_digest(b"tenant", tenant.as_str())
        || bytes[20..36] != *repository_id.as_uuid().as_bytes()
        || bytes[36..52] != selected_workflow_id.map_or([0_u8; 16], |id| *id.as_uuid().as_bytes())
    {
        return None;
    }
    Some(DecodedWorkflowCursor {
        position: parse_uuid_id(&bytes[52..68])?,
        direction: navigation_direction(bytes[2])?,
    })
}

fn encode_job_cursor(
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
    cursor: DecodedJobCursor,
) -> String {
    let mut bytes = Vec::with_capacity(JOB_CURSOR_BYTES);
    bytes.extend_from_slice(&[
        CURSOR_VERSION,
        JOB_CURSOR_KIND,
        navigation_direction_byte(cursor.direction),
    ]);
    bytes.extend_from_slice(&binding_digest(b"tenant", tenant.as_str()));
    bytes.extend_from_slice(repository_id.as_uuid().as_bytes());
    bytes.extend_from_slice(run_id.as_uuid().as_bytes());
    bytes.extend_from_slice(&cursor.created_at.get().to_be_bytes());
    bytes.extend_from_slice(cursor.position.as_uuid().as_bytes());
    debug_assert_eq!(bytes.len(), JOB_CURSOR_BYTES);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_job_cursor(
    value: &str,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    run_id: RunId,
) -> Option<DecodedJobCursor> {
    let bytes = canonical_cursor_bytes(value, JOB_CURSOR_BYTES)?;
    if bytes[0] != CURSOR_VERSION
        || bytes[1] != JOB_CURSOR_KIND
        || bytes[3..19] != binding_digest(b"tenant", tenant.as_str())
        || bytes[19..35] != *repository_id.as_uuid().as_bytes()
        || bytes[35..51] != *run_id.as_uuid().as_bytes()
    {
        return None;
    }
    Some(DecodedJobCursor {
        created_at: UnixMillis::new(i64::from_be_bytes(bytes[51..59].try_into().ok()?)),
        position: parse_uuid_id(&bytes[59..75])?,
        direction: navigation_direction(bytes[2])?,
    })
}

fn canonical_cursor_bytes(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    canonical_variable_cursor_bytes(value, expected_len, expected_len)
}

fn canonical_variable_cursor_bytes(
    value: &str,
    minimum_len: usize,
    maximum_len: usize,
) -> Option<Vec<u8>> {
    if value.is_empty() || value.bytes().any(|byte| !is_base64url(byte)) {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    if !(minimum_len..=maximum_len).contains(&decoded.len())
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return None;
    }
    Some(decoded)
}

const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn binding_digest(domain: &[u8], value: &str) -> [u8; BINDING_BYTES] {
    let mut digest = Sha256::new();
    digest.update(b"automata-web-cursor-v1\0");
    digest.update(domain);
    digest.update([0]);
    digest.update(value.as_bytes());
    digest.finalize()[..BINDING_BYTES]
        .try_into()
        .expect("SHA-256 prefix has the requested size")
}

fn parse_uuid_id<T>(bytes: &[u8]) -> Option<T>
where
    T: std::str::FromStr,
{
    if bytes.len() != 16 || bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    canonical_uuid_text(bytes).parse().ok()
}

fn canonical_uuid_text(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
    }
    value
}

const fn run_direction_byte(direction: HumanRunPageDirection) -> u8 {
    match direction {
        HumanRunPageDirection::Older => 0,
        HumanRunPageDirection::Newer => 1,
    }
}

const fn run_direction(value: u8) -> Option<HumanRunPageDirection> {
    match value {
        0 => Some(HumanRunPageDirection::Older),
        1 => Some(HumanRunPageDirection::Newer),
        _ => None,
    }
}

const fn log_direction_byte(direction: HumanLogSegmentPageDirection) -> u8 {
    match direction {
        HumanLogSegmentPageDirection::Older => 0,
        HumanLogSegmentPageDirection::Newer => 1,
    }
}

const fn log_direction(value: u8) -> Option<HumanLogSegmentPageDirection> {
    match value {
        0 => Some(HumanLogSegmentPageDirection::Older),
        1 => Some(HumanLogSegmentPageDirection::Newer),
        _ => None,
    }
}

const fn navigation_direction_byte(direction: NavigationPageDirection) -> u8 {
    match direction {
        NavigationPageDirection::Previous => 0,
        NavigationPageDirection::Next => 1,
    }
}

const fn navigation_direction(value: u8) -> Option<NavigationPageDirection> {
    match value {
        0 => Some(NavigationPageDirection::Previous),
        1 => Some(NavigationPageDirection::Next),
        _ => None,
    }
}

const fn status_filter_byte(filter: StatusFilter) -> u8 {
    match filter {
        StatusFilter::All => 0,
        StatusFilter::Queued => 1,
        StatusFilter::InProgress => 2,
        StatusFilter::Completed => 3,
    }
}

fn normalize_git_ref(value: &str) -> Option<HumanGitRef> {
    if value.is_empty() {
        return None;
    }
    let value = if value.starts_with("refs/") {
        value.to_owned()
    } else {
        format!("refs/heads/{value}")
    };
    HumanGitRef::new(value).ok()
}

fn map_repository(repository: &HumanRepository, settings_visible: bool) -> Repository {
    Repository {
        id: repository.id.as_uuid().to_string(),
        scm_provider: repository.scm_provider.clone(),
        owner: repository.owner.clone(),
        name: repository.name.clone(),
        settings_visible,
    }
}

fn map_workflow(workflow: &HumanWorkflow) -> WorkflowDefinition {
    let name = workflow
        .projected_name
        .as_ref()
        .and_then(|projected| visible_text(&projected.name))
        .unwrap_or_else(|| workflow.path.clone());
    WorkflowDefinition {
        id: workflow.id,
        name,
        enabled: workflow.enabled,
    }
}

fn workflow_from_run(run: &HumanRun) -> Workflow {
    Workflow {
        id: run.workflow_id,
        name: visible_text(&run.workflow_name).unwrap_or_else(|| run.workflow_path.clone()),
        path: run.workflow_path.clone(),
    }
}

fn map_run(run: &HumanRun) -> Result<RunSummary, WebDataError> {
    Ok(RunSummary {
        id: run.id,
        number: run.run_number,
        attempt: run.run_attempt,
        title: run
            .display_title
            .as_ref()
            .and_then(|title| visible_text(title)),
        workflow: workflow_from_run(run),
        status: run_status(run)?,
        git_ref: run
            .git_ref
            .as_ref()
            .and_then(|git_ref| visible_text(git_ref)),
        event: visible_text(&run.event_name).unwrap_or_else(|| "unknown".to_owned()),
        actor: run.actor.as_ref().and_then(|actor| visible_text(actor)),
        head_sha: hex_bytes(run.head_commit.as_bytes()),
        commit_subject: run
            .commit_subject
            .as_ref()
            .and_then(|subject| visible_text(subject)),
        created_at: run.created_at,
        finished_at: run.finished_at,
    })
}

fn run_status(run: &HumanRun) -> Result<Status, WebDataError> {
    match (run.status, run.conclusion) {
        (WorkflowRunStatus::Queued, None) => Ok(Status::Queued),
        (WorkflowRunStatus::InProgress, None) => Ok(Status::InProgress),
        (WorkflowRunStatus::Cancelled, _) => Ok(Status::Cancelled),
        (WorkflowRunStatus::Completed, Some(conclusion)) => Ok(conclusion_status(conclusion)),
        _ => Err(WebDataError::Corrupt),
    }
}

const fn conclusion_status(conclusion: HumanRunConclusion) -> Status {
    match conclusion {
        HumanRunConclusion::Success => Status::Succeeded,
        HumanRunConclusion::Failure => Status::Failed,
        HumanRunConclusion::Cancelled => Status::Cancelled,
        HumanRunConclusion::TimedOut => Status::TimedOut,
        HumanRunConclusion::Skipped => Status::Skipped,
        HumanRunConclusion::Lost => Status::Lost,
    }
}

const fn lifecycle_status(lifecycle: JobLifecycle) -> Status {
    match lifecycle {
        JobLifecycle::Queued => Status::Queued,
        JobLifecycle::Leased
        | JobLifecycle::Preparing
        | JobLifecycle::Running
        | JobLifecycle::Cancelling
        | JobLifecycle::Finalizing => Status::InProgress,
        JobLifecycle::Succeeded => Status::Succeeded,
        JobLifecycle::Failed => Status::Failed,
        JobLifecycle::Cancelled => Status::Cancelled,
        JobLifecycle::TimedOut => Status::TimedOut,
        JobLifecycle::Skipped => Status::Skipped,
        JobLifecycle::Lost => Status::Lost,
    }
}

const fn job_conclusion_status(conclusion: JobConclusion) -> Status {
    match conclusion {
        JobConclusion::Success => Status::Succeeded,
        JobConclusion::Failure => Status::Failed,
        JobConclusion::Cancelled => Status::Cancelled,
        JobConclusion::TimedOut => Status::TimedOut,
        JobConclusion::Skipped => Status::Skipped,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
    }
    value
}

fn visible_text(value: &str) -> Option<String> {
    is_safe_display_text(value, 1_024).then(|| value.to_owned())
}

fn map_job(job: &HumanJob, logs_available: bool) -> Result<JobSummary, WebDataError> {
    let status = job
        .latest_attempt
        .as_ref()
        .map_or(Status::Queued, |attempt| {
            lifecycle_status(attempt.lifecycle)
        });
    if let Some(attempt) = &job.latest_attempt
        && let Some(terminal) = &attempt.terminal_result
        && (terminal.attempt_id != attempt.id
            || status != job_conclusion_status(terminal.conclusion)
            || attempt.finished_at != Some(terminal.completed_at))
    {
        return Err(WebDataError::Corrupt);
    }
    Ok(JobSummary {
        id: job.id,
        name: visible_text(&job.display_name).unwrap_or_else(|| "Workflow job".to_owned()),
        attempt: job
            .latest_attempt
            .as_ref()
            .map(|attempt| attempt.number.get()),
        runner_label: job
            .latest_attempt
            .as_ref()
            .and_then(|attempt| attempt.runner.as_ref())
            .and_then(|runner| visible_text(&runner.name)),
        status,
        started_at: job
            .latest_attempt
            .as_ref()
            .and_then(|attempt| attempt.started_at),
        finished_at: job
            .latest_attempt
            .as_ref()
            .and_then(|attempt| attempt.finished_at),
        logs_available,
    })
}

fn map_navigation(
    job: &HumanJobNavigation,
    logs_available: bool,
) -> Result<JobNavigationItem, WebDataError> {
    let status = match (job.lifecycle, job.conclusion) {
        (None, None) => Status::Queued,
        (Some(lifecycle), conclusion) => {
            let status = lifecycle_status(lifecycle);
            if let Some(conclusion) = conclusion
                && status != conclusion_status(conclusion)
            {
                return Err(WebDataError::Corrupt);
            }
            status
        }
        (None, Some(_)) => return Err(WebDataError::Corrupt),
    };
    Ok(JobNavigationItem {
        id: job.id,
        name: visible_text(&job.display_name).unwrap_or_else(|| "Workflow job".to_owned()),
        status,
        logs_available,
    })
}

fn map_artifact(artifact: &HumanArtifactSummary, downloadable: bool) -> ArtifactSummary {
    ArtifactSummary {
        id: artifact.id.get(),
        name: visible_text(&artifact.name)
            .unwrap_or_else(|| format!("Artifact {}", artifact.id.get())),
        size: artifact.content_size,
        digest: artifact.content_digest.to_string(),
        expires_at_seconds: artifact.expires_at_seconds,
        downloadable,
    }
}

fn map_status_filter(filter: StatusFilter) -> Option<HumanRunStatusFilter> {
    match filter {
        StatusFilter::All => None,
        StatusFilter::Queued => Some(HumanRunStatusFilter::Queued),
        StatusFilter::InProgress => Some(HumanRunStatusFilter::InProgress),
        StatusFilter::Completed => Some(HumanRunStatusFilter::Completed),
    }
}

const fn run_matches_status_filter(run: &HumanRun, filter: StatusFilter) -> bool {
    match filter {
        StatusFilter::All => true,
        StatusFilter::Queued => matches!(run.status, WorkflowRunStatus::Queued),
        StatusFilter::InProgress => matches!(run.status, WorkflowRunStatus::InProgress),
        StatusFilter::Completed => matches!(
            run.status,
            WorkflowRunStatus::Completed | WorkflowRunStatus::Cancelled
        ),
    }
}

fn publication_target(
    publication: &HumanOutputPublication,
) -> (OutputVisibility, SecretExposureClass) {
    (
        publication.effective_visibility,
        publication.secret_exposure,
    )
}

fn durable_job_log_visibility(
    run: &HumanRun,
    publication: Option<&HumanOutputPublication>,
) -> Result<OutputVisibility, WebDataError> {
    let requested = run.publication.requested_log_visibility;
    match publication {
        None => Ok(requested),
        Some(publication) if publication.requested_visibility == requested => {
            Ok(publication.effective_visibility)
        }
        Some(_) => Err(WebDataError::Corrupt),
    }
}

fn log_stream_safety_is_valid(stream: &automata_ci_store::HumanLogStream) -> bool {
    automata_ci_store::human_output_publication_safety_schema_is_current(i32::from(
        stream.publication.safety_schema,
    )) && stream.raw_log_disposition == HumanRawLogDisposition::Persist
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RenderedFrameLine {
    sequence: LogSequence,
    ordinal: u32,
    emitted_at: UnixMillis,
    channel: LogChannel,
    text: String,
    fragmented: bool,
}

fn render_frame_lines(frame: &LogFrame) -> Result<Vec<RenderedFrameLine>, WebDataError> {
    if frame.payload().is_empty() && frame.is_end_of_stream() {
        return Ok(Vec::new());
    }
    let decoded = String::from_utf8_lossy(frame.payload());
    let mut chunks = Vec::new();
    let mut remaining = decoded.as_ref();
    while !remaining.is_empty() {
        let (line, rest) = match remaining.find('\n') {
            Some(index) => (&remaining[..index], &remaining[index + 1..]),
            None => (remaining, ""),
        };
        let line = line.strip_suffix('\r').unwrap_or(line);
        split_utf8_line(line, &mut chunks);
        remaining = rest;
    }
    if decoded.is_empty() {
        chunks.push(String::new());
    }
    let fragmented = chunks.len() > 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, text)| {
            Ok(RenderedFrameLine {
                sequence: frame.sequence(),
                ordinal: u32::try_from(index).map_err(|_| WebDataError::Corrupt)?,
                emitted_at: frame.emitted_at(),
                channel: match frame.channel() {
                    automata_ci_core::LogChannel::Stdout => LogChannel::Stdout,
                    automata_ci_core::LogChannel::Stderr => LogChannel::Stderr,
                    automata_ci_core::LogChannel::System => LogChannel::System,
                },
                text,
                fragmented,
            })
        })
        .collect()
}

fn split_utf8_line(line: &str, chunks: &mut Vec<String>) {
    let sanitized = sanitize_log_text(line);
    if sanitized.is_empty() {
        chunks.push(String::new());
        return;
    }
    let mut remaining = sanitized.as_str();
    while !remaining.is_empty() {
        let mut split = remaining.len().min(super::data::LOG_LINE_BYTES);
        while !remaining.is_char_boundary(split) {
            split -= 1;
        }
        chunks.push(remaining[..split].to_owned());
        remaining = &remaining[split..];
    }
}

fn sanitize_log_text(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\t' || !must_escape_log_character(character) {
            sanitized.push(character);
        } else {
            write!(&mut sanitized, "\\u{{{:04X}}}", u32::from(character))
                .expect("writing to a string cannot fail");
        }
    }
    sanitized
}

fn must_escape_log_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn visible_log_line(line: RenderedFrameLine) -> LogLine {
    LogLine {
        sequence: line.sequence.get(),
        fragment: line.fragmented.then_some(line.ordinal + 1),
        emitted_at: line.emitted_at,
        channel: line.channel,
        text: line.text,
    }
}

fn rendered_line_cursor(
    line: &RenderedFrameLine,
    direction: HumanLogSegmentPageDirection,
) -> DecodedLogCursor {
    DecodedLogCursor {
        sequence: line.sequence,
        line_ordinal: line.ordinal,
        direction,
    }
}

fn segment_cursor(
    cursor: HumanLogSegmentCursor,
    direction: HumanLogSegmentPageDirection,
) -> DecodedLogCursor {
    DecodedLogCursor {
        sequence: cursor.sequence,
        line_ordinal: 0,
        direction,
    }
}

fn candidate_is_on_requested_side(
    candidate: &RenderedFrameLine,
    cursor: Option<DecodedLogCursor>,
) -> bool {
    let Some(cursor) = cursor else {
        return true;
    };
    let candidate_position = (candidate.sequence.get(), candidate.ordinal);
    let boundary = (cursor.sequence.get(), cursor.line_ordinal);
    match cursor.direction {
        HumanLogSegmentPageDirection::Newer => candidate_position >= boundary,
        HumanLogSegmentPageDirection::Older => candidate_position < boundary,
    }
}

fn cursor_boundary_is_valid(
    cursor: Option<DecodedLogCursor>,
    saw_boundary: bool,
    page: &automata_ci_store::HumanLogSegmentPage,
) -> bool {
    let Some(cursor) = cursor else {
        return true;
    };
    if saw_boundary {
        return true;
    }
    cursor.direction == HumanLogSegmentPageDirection::Older
        && cursor.line_ordinal == 0
        && page.newer_cursor.is_some_and(|next| {
            next.direction == HumanLogSegmentPageDirection::Newer
                && next.sequence == cursor.sequence
        })
}

fn log_page_cursors(
    requested: Option<DecodedLogCursor>,
    lines: &[RenderedFrameLine],
    discarded_reverse_line: bool,
    forward_next: Option<DecodedLogCursor>,
    page: &automata_ci_store::HumanLogSegmentPage,
) -> (Option<DecodedLogCursor>, Option<DecodedLogCursor>) {
    let direction = requested.map_or(HumanLogSegmentPageDirection::Newer, |cursor| {
        cursor.direction
    });
    match direction {
        HumanLogSegmentPageDirection::Newer => {
            let previous = lines
                .first()
                .map(|line| rendered_line_cursor(line, HumanLogSegmentPageDirection::Older))
                .filter(cursor_has_preceding_position)
                .or_else(|| {
                    requested
                        .filter(cursor_has_preceding_position)
                        .map(|cursor| DecodedLogCursor {
                            direction: HumanLogSegmentPageDirection::Older,
                            ..cursor
                        })
                })
                .or_else(|| {
                    page.older_cursor
                        .map(|cursor| segment_cursor(cursor, HumanLogSegmentPageDirection::Older))
                });
            let next = forward_next.or_else(|| {
                page.newer_cursor
                    .map(|cursor| segment_cursor(cursor, HumanLogSegmentPageDirection::Newer))
            });
            (previous, next)
        }
        HumanLogSegmentPageDirection::Older => {
            let previous = if discarded_reverse_line || page.older_cursor.is_some() {
                lines
                    .first()
                    .map(|line| rendered_line_cursor(line, HumanLogSegmentPageDirection::Older))
                    .filter(cursor_has_preceding_position)
                    .or_else(|| {
                        page.older_cursor.map(|cursor| {
                            segment_cursor(cursor, HumanLogSegmentPageDirection::Older)
                        })
                    })
            } else {
                None
            };
            let next = requested.map(|cursor| DecodedLogCursor {
                direction: HumanLogSegmentPageDirection::Newer,
                ..cursor
            });
            (previous, next)
        }
    }
}

const fn cursor_has_preceding_position(cursor: &DecodedLogCursor) -> bool {
    cursor.sequence.get() > 0 || cursor.line_ordinal > 0
}

fn block_list_digest(blocks: &[HumanArtifactBlock]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(BLOCK_LIST_DIGEST_DOMAIN);
    hasher.update(
        u64::try_from(blocks.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for block in blocks {
        hasher.update(
            u64::try_from(block.block_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(block.block_id.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn validate_manifest(
    stored: &StoredArtifactDownload,
    run_id: RunId,
    bytes: &[u8],
) -> Result<(), WebDataError> {
    if stored.manifest.media_type().as_str() != ARTIFACT_MANIFEST_MEDIA_TYPE {
        return Err(WebDataError::Corrupt);
    }
    let manifest: ArtifactManifest =
        serde_json::from_slice(bytes).map_err(|_| WebDataError::Corrupt)?;
    let canonical = serde_json::to_vec(&manifest).map_err(|_| WebDataError::Corrupt)?;
    if canonical != bytes
        || manifest.validate_schema().is_err()
        || manifest.artifact_id != stored.artifact.id.get()
        || manifest.run_id != run_id.to_string()
        || manifest.name != stored.artifact.name
        || manifest.mime_type != stored.artifact.mime_type
        || manifest.size != stored.artifact.content_size
        || manifest.sha256 != stored.artifact.content_digest.to_string()
        || manifest.blocks.len() != stored.blocks.len()
        || !valid_canonical_uuid(&manifest.upload_id)
        || JobId::from_str(&manifest.job_id)
            .ok()
            .is_none_or(|id| id.as_uuid().is_nil() || id.to_string() != manifest.job_id)
        || AttemptId::from_str(&manifest.attempt_id)
            .ok()
            .is_none_or(|id| id.as_uuid().is_nil() || id.to_string() != manifest.attempt_id)
        || manifest.fencing_token == 0
        || block_list_digest(&stored.blocks) != stored.block_list_digest
        || stored.committed_at_seconds > stored.artifact.finalized_at_seconds
    {
        return Err(WebDataError::Corrupt);
    }
    let mut total = 0_u64;
    for (index, (manifest_block, stored_block)) in
        manifest.blocks.iter().zip(&stored.blocks).enumerate()
    {
        if stored_block.ordinal != u32::try_from(index + 1).map_err(|_| WebDataError::Corrupt)?
            || manifest_block.block_id != stored_block.block_id
            || manifest_block.object_key != stored_block.descriptor.key().as_str()
            || manifest_block.size != stored_block.descriptor.size()
            || manifest_block.sha256 != stored_block.descriptor.digest().to_string()
            || manifest_block.media_type != stored_block.descriptor.media_type().as_str()
        {
            return Err(WebDataError::Corrupt);
        }
        total = total
            .checked_add(stored_block.descriptor.size())
            .ok_or(WebDataError::Corrupt)?;
    }
    if total != stored.artifact.content_size {
        return Err(WebDataError::Corrupt);
    }
    Ok(())
}

fn valid_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}

struct ArtifactStreamState {
    objects: Arc<dyn ImmutableBlobStore>,
    blocks: Vec<HumanArtifactBlock>,
    index: usize,
    size: u64,
    hasher: Sha256,
    expected_size: u64,
    expected_digest: Sha256Digest,
}

fn artifact_body(
    objects: Arc<dyn ImmutableBlobStore>,
    blocks: Vec<HumanArtifactBlock>,
    expected_size: u64,
    expected_digest: Sha256Digest,
) -> Result<super::data::ArtifactBody, WebDataError> {
    if blocks.is_empty() {
        let digest = Sha256Digest::from_bytes(Sha256::digest([]).into());
        if expected_size != 0 || digest != expected_digest {
            return Err(WebDataError::Corrupt);
        }
    }
    let state = ArtifactStreamState {
        objects,
        blocks,
        index: 0,
        size: 0,
        hasher: Sha256::new(),
        expected_size,
        expected_digest,
    };
    Ok(Box::pin(stream::try_unfold(
        state,
        |mut state| async move {
            let Some(block) = state.blocks.get(state.index).cloned() else {
                return Ok(None);
            };
            let blob = state
                .objects
                .get_verified(&block.descriptor, block.descriptor.size())
                .await
                .map_err(map_blob_error)?;
            let bytes = blob.into_bytes();
            state.size = state
                .size
                .checked_add(u64::try_from(bytes.len()).map_err(|_| WebDataError::Corrupt)?)
                .ok_or(WebDataError::Corrupt)?;
            state.hasher.update(&bytes);
            state.index += 1;
            if state.index == state.blocks.len() {
                let actual_digest =
                    Sha256Digest::from_bytes(state.hasher.clone().finalize().into());
                if state.size != state.expected_size || actual_digest != state.expected_digest {
                    return Err(WebDataError::Corrupt);
                }
            }
            Ok(Some((bytes, state)))
        },
    )))
}

impl LiveWebData {
    async fn map_run_jobs(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        detail: &HumanRunDetail,
        request: &RunDetailRequest,
    ) -> Result<Option<RunJobPage>, WebDataError> {
        let jobs_allowed = self
            .allowed(
                context,
                tenant,
                repository,
                repository_read_permissions::JOB_READ,
                Some(detail.run.publication.effective_dashboard_visibility),
                SecretExposureClass::ReadableSecret,
            )
            .await?;
        if !jobs_allowed {
            return Ok(request.job_cursor.is_none().then_some(RunJobPage {
                visibility: CollectionVisibility::Restricted,
                jobs: Vec::new(),
                previous_cursor: None,
                next_cursor: None,
            }));
        }
        let cursor = match request.job_cursor.as_deref() {
            Some(cursor) => {
                let Some(cursor) = decode_job_cursor(cursor, tenant, repository.id, detail.run.id)
                else {
                    return Ok(None);
                };
                Some(cursor)
            }
            None => None,
        };
        let Some((start, end)) = run_job_page_bounds(&detail.jobs, request.limit, cursor) else {
            return Ok(None);
        };
        let mut jobs = Vec::with_capacity(end.saturating_sub(start));
        let mut log_access_cache = Vec::new();
        for job in &detail.jobs[start..end] {
            let log_visibility =
                durable_job_log_visibility(&detail.run, job.log_publication.as_ref())?;
            let logs_available = self
                .cached_log_access_allowed(
                    context,
                    tenant,
                    repository,
                    &mut log_access_cache,
                    log_visibility,
                )
                .await?;
            jobs.push(map_job(job, logs_available)?);
        }
        Ok(Some(RunJobPage {
            visibility: CollectionVisibility::Full,
            jobs,
            previous_cursor: (start > 0).then(|| {
                job_page_cursor(
                    tenant,
                    repository.id,
                    detail.run.id,
                    &detail.jobs[start],
                    NavigationPageDirection::Previous,
                )
            }),
            next_cursor: (end < detail.jobs.len()).then(|| {
                job_page_cursor(
                    tenant,
                    repository.id,
                    detail.run.id,
                    &detail.jobs[end - 1],
                    NavigationPageDirection::Next,
                )
            }),
        }))
    }

    async fn map_run_detail(
        &self,
        context: RequestContext,
        tenant: TenantScope,
        repository: HumanRepository,
        detail: HumanRunDetail,
        request: &RunDetailRequest,
    ) -> Result<Option<RunDetailPage>, WebDataError> {
        if detail.jobs.len() > MAX_DURABLE_RUN_JOBS
            || detail.artifacts.len() > MAX_RENDERED_ARTIFACTS
            || !run_jobs_are_canonical(&detail.jobs)
        {
            return Err(WebDataError::Corrupt);
        }
        let Some(job_page) = self
            .map_run_jobs(&context, &tenant, &repository, &detail, request)
            .await?
        else {
            return Ok(None);
        };

        let observed_at = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut decisions = Vec::with_capacity(detail.artifacts.len());
        let mut artifact_access_cache = Vec::new();
        for artifact in detail.artifacts.iter().filter(|artifact| {
            artifact
                .expires_at_seconds
                .is_none_or(|expires_at| expires_at > observed_at)
        }) {
            let access = self
                .cached_artifact_access(
                    &context,
                    &tenant,
                    &repository,
                    &mut artifact_access_cache,
                    &artifact.publication,
                )
                .await?;
            if !access.readable {
                decisions.push((None, true));
                continue;
            }
            decisions.push((Some(map_artifact(artifact, access.downloadable)), false));
        }
        let artifacts_restricted = decisions.iter().any(|(_, restricted)| *restricted);
        let artifacts = decisions
            .into_iter()
            .filter_map(|(artifact, _)| artifact)
            .collect();
        Ok(Some(RunDetailPage {
            repository: map_repository(
                &repository,
                self.settings_visible(&context, &tenant, &repository)
                    .await?,
            ),
            run: map_run(&detail.run)?,
            jobs: VisibleCollection {
                visibility: job_page.visibility,
                items: job_page.jobs,
            },
            job_previous_cursor: job_page.previous_cursor,
            job_next_cursor: job_page.next_cursor,
            artifacts: VisibleCollection {
                visibility: if artifacts_restricted {
                    CollectionVisibility::Restricted
                } else {
                    CollectionVisibility::Full
                },
                items: artifacts,
            },
        }))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn map_job_log(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
        scope: HumanJobScope,
        detail: HumanJobDetail,
        dashboard_metadata_allowed: bool,
        selected_log_access_allowed: bool,
        request: &JobLogRequest,
    ) -> Result<Option<JobLogPage>, WebDataError> {
        if detail.run.id != scope.run_id
            || detail.job.id != scope.job_id
            || detail.navigation.len() > MAX_DURABLE_RUN_JOBS
            || {
                let mut ids = HashSet::with_capacity(detail.navigation.len());
                !detail.navigation.iter().all(|job| ids.insert(job.id))
            }
            || detail.job.log_publication.as_ref()
                != detail.log_stream.as_ref().map(|stream| &stream.publication)
        {
            return Err(WebDataError::Corrupt);
        }
        if detail
            .log_stream
            .as_ref()
            .is_some_and(|stream| !log_stream_safety_is_valid(stream))
        {
            return Err(WebDataError::Corrupt);
        }
        let selected_job = map_job(&detail.job, selected_log_access_allowed)?;
        let mut selected_navigation_rows = detail
            .navigation
            .iter()
            .enumerate()
            .filter(|(_, job)| job.id == selected_job.id);
        let Some((selected_navigation_index, selected_navigation_row)) =
            selected_navigation_rows.next()
        else {
            return Err(WebDataError::Corrupt);
        };
        if selected_navigation_rows.next().is_some() {
            return Err(WebDataError::Corrupt);
        }
        // Navigation targets the stable job-detail capability. Log access is
        // represented independently by `selected_job.logs_available`.
        let selected_navigation = map_navigation(selected_navigation_row, true)?;
        if selected_navigation.name != selected_job.name
            || selected_navigation.status != selected_job.status
        {
            return Err(WebDataError::Corrupt);
        }
        let (jobs, previous_navigation_job_id, next_navigation_job_id) =
            if dashboard_metadata_allowed {
                let page_start = selected_navigation_index / MAX_RENDERED_JOBS * MAX_RENDERED_JOBS;
                let page_end = page_start
                    .saturating_add(MAX_RENDERED_JOBS)
                    .min(detail.navigation.len());
                let mut jobs = Vec::with_capacity(page_end.saturating_sub(page_start));
                for job in &detail.navigation[page_start..page_end] {
                    if job.id == selected_job.id {
                        jobs.push(selected_navigation.clone());
                        continue;
                    }
                    jobs.push(map_navigation(job, true)?);
                }
                let previous_navigation_job_id =
                    detail.navigation[..page_start].last().map(|job| job.id);
                let next_navigation_job_id =
                    detail.navigation[page_end..].first().map(|job| job.id);
                (jobs, previous_navigation_job_id, next_navigation_job_id)
            } else {
                (vec![selected_navigation], None, None)
            };
        if !selected_log_access_allowed || detail.log_stream.is_none() {
            if request.cursor.is_some() {
                return Ok(None);
            }
            let settings_visible = dashboard_metadata_allowed
                && self.settings_visible(context, tenant, repository).await?;
            return Ok(Some(JobLogPage {
                repository: map_repository(repository, settings_visible),
                run: map_run(&detail.run)?,
                jobs,
                previous_navigation_job_id,
                next_navigation_job_id,
                job: selected_job,
                log_visibility: if selected_log_access_allowed {
                    CollectionVisibility::Full
                } else {
                    CollectionVisibility::Restricted
                },
                lines: Vec::new(),
                previous_cursor: None,
                next_cursor: None,
                live: None,
            }));
        }
        let Some(log_stream) = detail.log_stream else {
            return Err(WebDataError::Corrupt);
        };
        let decoded_cursor = match request.cursor.as_deref() {
            None => None,
            Some(cursor) => match decode_log_cursor(
                cursor,
                tenant,
                repository.id,
                scope.run_id,
                scope.job_id,
                log_stream.id,
            ) {
                Some(cursor) => Some(cursor),
                None => return Ok(None),
            },
        };
        let run = map_run(&detail.run)?;
        let Some(attempt) = detail.job.latest_attempt.as_ref() else {
            return Err(WebDataError::Corrupt);
        };
        if log_stream.attempt_id != attempt.id {
            return Err(WebDataError::Corrupt);
        }
        let store_cursor = decoded_cursor.map(|cursor| HumanLogSegmentCursor {
            sequence: if cursor.direction == HumanLogSegmentPageDirection::Older
                && cursor.line_ordinal > 0
            {
                LogSequence::new(cursor.sequence.get() + 1)
            } else {
                cursor.sequence
            },
            direction: cursor.direction,
        });
        let page_size = HumanLogSegmentPageSize::new(LOG_SEGMENT_PAGE_SIZE)
            .map_err(|_| WebDataError::Corrupt)?;
        let query = HumanLogSegmentQuery {
            scope: scope.clone(),
            stream_id: log_stream.id,
            cursor: store_cursor,
            limit: page_size,
        };
        let Some(page) = self
            .reads
            .list_log_segments(&query)
            .await
            .map_err(map_store_error)?
        else {
            return Err(WebDataError::Corrupt);
        };
        if page.stream != log_stream {
            return Err(WebDataError::Corrupt);
        }

        let direction = decoded_cursor.map_or(HumanLogSegmentPageDirection::Newer, |cursor| {
            cursor.direction
        });
        let mut forward_lines = Vec::new();
        let mut reverse_lines = VecDeque::new();
        let mut decoded_bytes = 0_usize;
        let mut discarded_reverse_line = false;
        let mut next_exact = None;
        let mut saw_boundary = decoded_cursor.is_none();
        let mut forward_checkpoint =
            decoded_cursor.filter(|cursor| cursor.direction == HumanLogSegmentPageDirection::Newer);
        'segments: for segment in &page.segments {
            let blob = self
                .objects
                .get_verified(&segment.descriptor, segment.descriptor.size())
                .await
                .map_err(map_blob_error)?;
            let expectation = LogSegmentExpectation::new(
                log_stream.attempt_id,
                log_stream.id,
                segment.first_sequence,
                segment.last_sequence,
                segment.uncompressed_size,
                segment.end_of_stream,
            );
            let frames =
                tokio::task::spawn_blocking(move || decode_log_segment(&blob, expectation))
                    .await
                    .map_err(|_| WebDataError::Unavailable)?
                    .map_err(|_| WebDataError::Corrupt)?;
            for frame in frames {
                let candidates = render_frame_lines(&frame)?;
                if direction == HumanLogSegmentPageDirection::Newer && candidates.is_empty() {
                    forward_checkpoint = Some(DecodedLogCursor {
                        sequence: frame.sequence(),
                        line_ordinal: 0,
                        direction: HumanLogSegmentPageDirection::Newer,
                    });
                }
                if let Some(cursor) = decoded_cursor {
                    if direction == HumanLogSegmentPageDirection::Newer {
                        if frame.sequence() < cursor.sequence {
                            continue;
                        }
                        if frame.sequence() > cursor.sequence && !saw_boundary {
                            return Ok(None);
                        }
                    }
                    if frame.sequence() == cursor.sequence {
                        saw_boundary = true;
                        if usize::try_from(cursor.line_ordinal)
                            .ok()
                            .is_none_or(|ordinal| ordinal >= candidates.len())
                            && !(cursor.line_ordinal == 0 && frame.payload().is_empty())
                        {
                            return Ok(None);
                        }
                    }
                }
                for candidate in candidates {
                    if !candidate_is_on_requested_side(&candidate, decoded_cursor) {
                        continue;
                    }
                    if direction == HumanLogSegmentPageDirection::Older {
                        decoded_bytes = decoded_bytes
                            .checked_add(candidate.text.len())
                            .ok_or(WebDataError::Corrupt)?;
                        reverse_lines.push_back(candidate);
                        while reverse_lines.len() > request.limit
                            || decoded_bytes > request.maximum_decoded_bytes
                        {
                            let discarded = reverse_lines
                                .pop_front()
                                .expect("an over-limit reverse log page is non-empty");
                            decoded_bytes = decoded_bytes
                                .checked_sub(discarded.text.len())
                                .ok_or(WebDataError::Corrupt)?;
                            discarded_reverse_line = true;
                        }
                    } else {
                        let next_bytes = decoded_bytes
                            .checked_add(candidate.text.len())
                            .ok_or(WebDataError::Corrupt)?;
                        if forward_lines.len() == request.limit
                            || next_bytes > request.maximum_decoded_bytes
                        {
                            next_exact = Some(rendered_line_cursor(
                                &candidate,
                                HumanLogSegmentPageDirection::Newer,
                            ));
                            break 'segments;
                        }
                        decoded_bytes = next_bytes;
                        forward_checkpoint = Some(rendered_line_cursor(
                            &candidate,
                            HumanLogSegmentPageDirection::Newer,
                        ));
                        forward_lines.push(candidate);
                    }
                }
            }
        }
        if !cursor_boundary_is_valid(decoded_cursor, saw_boundary, &page) {
            return Ok(None);
        }

        let selected_lines = if direction == HumanLogSegmentPageDirection::Older {
            reverse_lines.into_iter().collect::<Vec<_>>()
        } else {
            forward_lines
        };
        let (previous_exact, next_exact) = log_page_cursors(
            decoded_cursor,
            &selected_lines,
            discarded_reverse_line,
            next_exact,
            &page,
        );
        let previous_cursor = previous_exact.map(|cursor| {
            encode_log_cursor(
                tenant,
                repository.id,
                scope.run_id,
                scope.job_id,
                log_stream.id,
                cursor,
            )
        });
        let next_cursor = next_exact.map(|cursor| {
            encode_log_cursor(
                tenant,
                repository.id,
                scope.run_id,
                scope.job_id,
                log_stream.id,
                cursor,
            )
        });
        let live = (direction == HumanLogSegmentPageDirection::Newer).then(|| JobLogLive {
            checkpoint: forward_checkpoint.map(|cursor| {
                encode_log_cursor(
                    tenant,
                    repository.id,
                    scope.run_id,
                    scope.job_id,
                    log_stream.id,
                    cursor,
                )
            }),
            stream_closed: log_stream.closed_at.is_some(),
            more_available: next_cursor.is_some(),
        });
        if log_stream.closed_at.is_some()
            && next_cursor.is_none()
            && page
                .segments
                .last()
                .is_some_and(|segment| !segment.end_of_stream)
        {
            return Err(WebDataError::Corrupt);
        }
        let settings_visible = dashboard_metadata_allowed
            && self.settings_visible(context, tenant, repository).await?;
        let lines = selected_lines.into_iter().map(visible_log_line).collect();
        Ok(Some(JobLogPage {
            repository: map_repository(repository, settings_visible),
            run,
            jobs,
            previous_navigation_job_id,
            next_navigation_job_id,
            job: selected_job,
            log_visibility: CollectionVisibility::Full,
            lines,
            previous_cursor,
            next_cursor,
            live,
        }))
    }
}

impl LiveWebData {
    fn repository_discovery_permissions(&self) -> Vec<Permission> {
        let mut permissions = vec![permission(repository_read_permissions::REPOSITORY_READ)];
        if self.repository_secrets.is_some() {
            permissions.push(permission(SECRET_METADATA_READ_PERMISSION));
        }
        permissions
    }

    async fn project_repository_directory_item(
        &self,
        context: &RequestContext,
        tenant: &TenantScope,
        repository: &HumanRepository,
    ) -> Result<Option<RepositoryDirectoryItem>, WebDataError> {
        let repository_visible = self
            .allowed(
                context,
                tenant,
                repository,
                repository_read_permissions::REPOSITORY_READ,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?;
        let actions_visible = if repository_visible {
            self.allowed(
                context,
                tenant,
                repository,
                repository_read_permissions::WORKFLOW_READ,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?
        } else {
            false
        };
        let access_visible = self.settings_visible(context, tenant, repository).await?;
        let secrets_visible = if self.repository_secrets.is_some() {
            self.allowed(
                context,
                tenant,
                repository,
                SECRET_METADATA_READ_PERMISSION,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?
        } else {
            false
        };
        let settings_destination = if access_visible {
            Some(RepositorySettingsDestination::Access)
        } else if secrets_visible {
            Some(RepositorySettingsDestination::Secrets)
        } else {
            None
        };
        if !repository_visible && settings_destination.is_none() {
            return Ok(None);
        }
        Ok(Some(RepositoryDirectoryItem {
            repository: map_repository(repository, access_visible),
            actions_visible,
            settings_destination,
        }))
    }
}

fn repository_directory_query(
    tenant: &TenantScope,
    request: &RepositoryDirectoryRequest,
) -> Result<HumanRepositoryListQuery, WebDataError> {
    let mut query = HumanRepositoryListQuery::new(tenant.clone());
    query.limit =
        HumanPageSize::new(u16::try_from(request.limit).map_err(|_| WebDataError::InvalidRequest)?)
            .map_err(|_| WebDataError::InvalidRequest)?;
    query.cursor = request
        .cursor
        .as_deref()
        .map(|cursor| decode_repository_cursor(cursor, tenant).ok_or(WebDataError::InvalidRequest))
        .transpose()?;
    Ok(query)
}

fn validate_repository_directory_page(
    context: &RequestContext,
    request: &RepositoryDirectoryRequest,
    page: &HumanRepositoryPage,
) -> Result<(), WebDataError> {
    if page.repositories.len() > request.limit {
        return Err(WebDataError::Corrupt);
    }
    if let Some(next_cursor) = page.next_cursor.as_ref() {
        let Some(last) = page.repositories.last() else {
            return Err(WebDataError::Corrupt);
        };
        if next_cursor.id != last.id
            || next_cursor.normalized_owner != last.owner.to_ascii_lowercase()
            || next_cursor.normalized_name != last.name.to_ascii_lowercase()
        {
            return Err(WebDataError::Corrupt);
        }
    }
    let mut seen = HashSet::with_capacity(page.repositories.len());
    for repository in &page.repositories {
        if repository.resource.tenant_id() != context.tenant_id()
            || repository.resource.repository_id().as_uuid() != repository.id.as_uuid()
            || repository.scm_provider != SCM_PROVIDER
            || RepositoryCoordinate::new(
                &repository.scm_provider,
                &repository.owner,
                &repository.name,
            )
            .is_err()
            || !valid_github_repository_identity(&repository.owner, &repository.name)
            || !seen.insert(repository.id)
        {
            return Err(WebDataError::Corrupt);
        }
    }
    Ok(())
}

fn repository_cursor(repository: &HumanRepository) -> HumanRepositoryCursor {
    HumanRepositoryCursor {
        normalized_owner: repository.owner.to_ascii_lowercase(),
        normalized_name: repository.name.to_ascii_lowercase(),
        id: repository.id,
    }
}

fn projected_repository_next_cursor(
    tenant: &TenantScope,
    store_next_cursor: Option<&HumanRepositoryCursor>,
    last_projected_cursor: Option<&HumanRepositoryCursor>,
) -> Result<Option<String>, WebDataError> {
    store_next_cursor
        .and(last_projected_cursor)
        .map(|cursor| encode_repository_cursor(tenant, cursor))
        .transpose()
}

#[async_trait]
impl WebData for LiveWebData {
    async fn repository_page(
        &self,
        context: &RequestContext,
        request: &RepositoryDirectoryRequest,
    ) -> Result<RepositoryDirectoryPage, WebDataError> {
        if request.limit != super::data::REPOSITORY_PAGE_SIZE {
            return Err(WebDataError::InvalidRequest);
        }
        let tenant = Self::tenant(context)?;
        let query = repository_directory_query(&tenant, request)?;
        let discovery_permissions = self.repository_discovery_permissions();
        let page = self
            .reads
            .list_repositories(&query, context.authorization(), &discovery_permissions)
            .await
            .map_err(map_store_error)?;
        validate_repository_directory_page(context, request, &page)?;
        let mut repositories = Vec::with_capacity(page.repositories.len());
        let mut last_projected_cursor = None;
        for repository in &page.repositories {
            if let Some(item) = self
                .project_repository_directory_item(context, &tenant, repository)
                .await?
            {
                last_projected_cursor = Some(repository_cursor(repository));
                repositories.push(item);
            }
        }
        let next_cursor = projected_repository_next_cursor(
            &tenant,
            page.next_cursor.as_ref(),
            last_projected_cursor.as_ref(),
        )?;
        Ok(RepositoryDirectoryPage {
            repositories,
            next_cursor,
        })
    }

    async fn list_runs(
        &self,
        context: &RequestContext,
        repository_path: &RepositoryPath,
        request: &RunListRequest,
    ) -> Result<Option<RunListPage>, WebDataError> {
        if request.limit == 0 || request.limit > super::data::RUN_PAGE_SIZE {
            return Ok(None);
        }
        let tenant = Self::tenant(context)?;
        let Some(repository) = self.repository(context, &tenant, repository_path).await? else {
            return Ok(None);
        };
        let Some(workflow_navigation) = self
            .workflows(context, &tenant, &repository, request)
            .await?
        else {
            return Ok(None);
        };

        let mut canonical_request = request.clone();
        let git_ref = match request.git_ref.as_deref() {
            Some(value) => match normalize_git_ref(value) {
                Some(git_ref) => {
                    canonical_request.git_ref = Some(git_ref.as_str().to_owned());
                    Some(git_ref)
                }
                None => return Ok(None),
            },
            None => None,
        };
        let decoded_cursor = match request.cursor.as_deref() {
            Some(cursor) => {
                match decode_run_cursor(cursor, &tenant, repository.id, &canonical_request) {
                    Some(cursor) => Some(cursor),
                    None => return Ok(None),
                }
            }
            None => None,
        };
        let mut query = HumanRunListQuery::new(tenant.clone(), repository.id);
        query.workflow_id = request.workflow_id;
        query.status = map_status_filter(request.status);
        query.git_ref = git_ref;
        query.cursor = decoded_cursor.map(|cursor| cursor.position);
        query.direction =
            decoded_cursor.map_or(HumanRunPageDirection::Older, |cursor| cursor.direction);
        query.limit =
            HumanPageSize::new(u16::try_from(request.limit).map_err(|_| WebDataError::Corrupt)?)
                .map_err(|_| WebDataError::Corrupt)?;
        let run_permission = permission(repository_read_permissions::RUN_READ);
        let Some(page) = self
            .reads
            .list_runs(&query, context.authorization(), &run_permission)
            .await
            .map_err(map_store_error)?
        else {
            return Ok(None);
        };
        if page.runs.len() > request.limit
            || page.runs.iter().any(|run| {
                request
                    .workflow_id
                    .is_some_and(|workflow_id| run.workflow_id != workflow_id)
                    || canonical_request
                        .git_ref
                        .as_ref()
                        .is_some_and(|git_ref| run.git_ref.as_ref() != Some(git_ref))
                    || !run_matches_status_filter(run, request.status)
            })
        {
            return Err(WebDataError::Corrupt);
        }
        let runs = page
            .runs
            .iter()
            .map(map_run)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(RunListPage {
            repository: map_repository(
                &repository,
                self.settings_visible(context, &tenant, &repository).await?,
            ),
            workflows: workflow_navigation.workflows,
            selected_workflow: workflow_navigation.selected_workflow,
            workflow_previous_cursor: workflow_navigation.previous_cursor,
            workflow_next_cursor: workflow_navigation.next_cursor,
            runs,
            previous_cursor: page.newer_cursor.map(|cursor| {
                encode_run_cursor(
                    &tenant,
                    repository.id,
                    &canonical_request,
                    cursor,
                    HumanRunPageDirection::Newer,
                )
            }),
            next_cursor: page.older_cursor.map(|cursor| {
                encode_run_cursor(
                    &tenant,
                    repository.id,
                    &canonical_request,
                    cursor,
                    HumanRunPageDirection::Older,
                )
            }),
        }))
    }

    async fn repository_settings(
        &self,
        context: &RequestContext,
        repository_path: &RepositoryPath,
    ) -> Result<Option<RepositorySettingsPage>, WebDataError> {
        if context.viewer().is_none() {
            return Ok(None);
        }
        let tenant = Self::tenant(context)?;
        let Ok(coordinate) =
            RepositoryCoordinate::new(SCM_PROVIDER, &repository_path.owner, &repository_path.name)
        else {
            return Ok(None);
        };
        let repository = self
            .reads
            .resolve_repository(&tenant, &coordinate)
            .await
            .map_err(map_store_error)?;
        let Some(repository) = repository else {
            return Ok(None);
        };
        if repository.scm_provider != SCM_PROVIDER
            || repository.owner != repository_path.owner
            || repository.name != repository_path.name
            || repository.resource.tenant_id() != context.tenant_id()
            || repository.resource.repository_id().as_uuid() != repository.id.as_uuid()
            || repository.publication_revision == 0
        {
            return Err(WebDataError::Corrupt);
        }
        let readable = self
            .allowed(
                context,
                &tenant,
                &repository,
                REPOSITORY_SETTINGS_READ_PERMISSION,
                Some(OutputVisibility::Private),
                SecretExposureClass::ReadableSecret,
            )
            .await?;
        if !readable {
            return Ok(None);
        }
        let editable = self
            .allowed(
                context,
                &tenant,
                &repository,
                REPOSITORY_SETTINGS_UPDATE_PERMISSION,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?;
        let secrets_visible = if self.repository_secrets.is_some() {
            self.allowed(
                context,
                &tenant,
                &repository,
                SECRET_METADATA_READ_PERMISSION,
                None,
                SecretExposureClass::ReadableSecret,
            )
            .await?
        } else {
            false
        };
        Ok(Some(RepositorySettingsPage {
            repository: map_repository(&repository, true),
            policy: repository.publication,
            revision: repository.publication_revision,
            editable,
            secrets_visible,
        }))
    }

    async fn repository_secrets(
        &self,
        snapshot: &automata_ci_auth::request_auth::AuthenticatedRequestSnapshot,
        repository: &RepositoryPath,
        request: RepositorySecretsPageRequest,
    ) -> Result<RepositorySecretsReadOutcome, WebDataError> {
        let Some(data) = self.repository_secrets.as_ref() else {
            return Ok(RepositorySecretsReadOutcome::NotFound);
        };
        data.page(snapshot, &repository.owner, &repository.name, request)
            .await
            .map_err(|error| match error {
                RepositorySecretWebError::Unavailable => WebDataError::Unavailable,
                RepositorySecretWebError::InvalidRequest | RepositorySecretWebError::Corrupt => {
                    WebDataError::Corrupt
                }
            })
    }

    async fn run_detail(
        &self,
        context: &RequestContext,
        repository_path: &RepositoryPath,
        run_id: RunId,
        request: &RunDetailRequest,
    ) -> Result<Option<RunDetailPage>, WebDataError> {
        if request.limit == 0 || request.limit > MAX_RENDERED_JOBS {
            return Ok(None);
        }
        let tenant = Self::tenant(context)?;
        let Some(repository) = self.repository(context, &tenant, repository_path).await? else {
            return Ok(None);
        };
        let scope = HumanRunScope::new(tenant.clone(), repository.id, run_id);
        let Some(detail) = self.reads.get_run(&scope).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        if detail.run.id != run_id {
            return Err(WebDataError::Corrupt);
        }
        if !self
            .allowed(
                context,
                &tenant,
                &repository,
                repository_read_permissions::WORKFLOW_READ,
                Some(detail.run.publication.effective_dashboard_visibility),
                SecretExposureClass::ReadableSecret,
            )
            .await?
            || !self
                .allowed(
                    context,
                    &tenant,
                    &repository,
                    repository_read_permissions::RUN_READ,
                    Some(detail.run.publication.effective_dashboard_visibility),
                    SecretExposureClass::ReadableSecret,
                )
                .await?
        {
            return Ok(None);
        }
        self.map_run_detail(context.clone(), tenant, repository, detail, request)
            .await
    }

    async fn job_log(
        &self,
        context: &RequestContext,
        repository_path: &RepositoryPath,
        run_id: RunId,
        job_id: JobId,
        request: &JobLogRequest,
    ) -> Result<Option<JobLogPage>, WebDataError> {
        if request.limit == 0
            || request.limit > super::data::LOG_PAGE_SIZE
            || request.maximum_decoded_bytes == 0
            || request.maximum_decoded_bytes > super::data::LOG_PAGE_DECODED_BYTES
        {
            return Ok(None);
        }
        let tenant = Self::tenant(context)?;
        let Some(repository) = self
            .resolve_repository_exact(&tenant, repository_path)
            .await?
        else {
            return Ok(None);
        };
        let scope = HumanJobScope::new(tenant.clone(), repository.id, run_id, job_id);
        let Some(detail) = self.reads.get_job(&scope).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        if detail.run.id != run_id || detail.job.id != job_id {
            return Err(WebDataError::Corrupt);
        }
        let dashboard_metadata_allowed = self
            .dashboard_job_metadata_allowed(
                context,
                &tenant,
                &repository,
                detail.run.publication.effective_dashboard_visibility,
            )
            .await?;
        let selected_log_visibility =
            durable_job_log_visibility(&detail.run, detail.job.log_publication.as_ref())?;
        if let Some(log_stream) = detail.log_stream.as_ref() {
            if detail.job.log_publication.as_ref() != Some(&log_stream.publication)
                || !log_stream_safety_is_valid(log_stream)
            {
                return Err(WebDataError::Corrupt);
            }
            let Some(attempt) = detail.job.latest_attempt.as_ref() else {
                return Err(WebDataError::Corrupt);
            };
            if log_stream.attempt_id != attempt.id {
                return Err(WebDataError::Corrupt);
            }
        }
        let selected_log_access_allowed = self
            .log_access_allowed(context, &tenant, &repository, selected_log_visibility)
            .await?;
        if !dashboard_metadata_allowed && !selected_log_access_allowed {
            return Ok(None);
        }
        self.map_job_log(
            context,
            &tenant,
            &repository,
            scope,
            detail,
            dashboard_metadata_allowed,
            selected_log_access_allowed,
            request,
        )
        .await
    }

    async fn authorize_live_log(
        &self,
        context: &RequestContext,
        repository_path: &RepositoryPath,
        run_id: RunId,
        job_id: JobId,
    ) -> Result<Option<AuthorizedLiveLog>, WebDataError> {
        let tenant = Self::tenant(context)?;
        let Some(repository) = self
            .resolve_repository_exact(&tenant, repository_path)
            .await?
        else {
            return Ok(None);
        };
        let job_scope = HumanJobScope::new(tenant.clone(), repository.id, run_id, job_id);
        let Some(detail) = self
            .reads
            .get_job(&job_scope)
            .await
            .map_err(map_store_error)?
        else {
            return Ok(None);
        };
        if detail.run.id != run_id || detail.job.id != job_id {
            return Err(WebDataError::Corrupt);
        }
        let Some(stream) = detail.log_stream.as_ref() else {
            return Ok(None);
        };
        let Some(attempt) = detail.job.latest_attempt.as_ref() else {
            return Err(WebDataError::Corrupt);
        };
        if detail.job.log_publication.as_ref() != Some(&stream.publication)
            || stream.attempt_id != attempt.id
            || !log_stream_safety_is_valid(stream)
        {
            return Err(WebDataError::Corrupt);
        }
        if !self
            .log_access_allowed(
                context,
                &tenant,
                &repository,
                durable_job_log_visibility(&detail.run, Some(&stream.publication))?,
            )
            .await?
        {
            return Ok(None);
        }
        let scope =
            HumanLiveLogScope::new(tenant, repository.id, run_id, job_id, attempt.id, stream.id)
                .map_err(|_| WebDataError::Corrupt)?;
        Ok(Some(AuthorizedLiveLog { scope }))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the bounded tail keeps checkpoint, segment, blob, and record validation contiguous"
    )]
    async fn read_live_log(
        &self,
        scope: &HumanLiveLogScope,
        checkpoint: Option<&str>,
        replay_checkpoint: bool,
    ) -> Result<Option<LiveLogBatch>, WebDataError> {
        let decoded_checkpoint = match checkpoint {
            None => None,
            Some(checkpoint) => {
                let Some(decoded) = decode_log_cursor(
                    checkpoint,
                    scope.tenant(),
                    scope.repository_id(),
                    scope.run_id(),
                    scope.job_id(),
                    scope.stream_id(),
                ) else {
                    return Ok(None);
                };
                if decoded.direction != HumanLogSegmentPageDirection::Newer {
                    return Ok(None);
                }
                Some(decoded)
            }
        };
        let query = HumanLogSegmentQuery {
            scope: HumanJobScope::new(
                scope.tenant().clone(),
                scope.repository_id(),
                scope.run_id(),
                scope.job_id(),
            ),
            stream_id: scope.stream_id(),
            cursor: decoded_checkpoint.map(|cursor| HumanLogSegmentCursor {
                sequence: cursor.sequence,
                direction: HumanLogSegmentPageDirection::Newer,
            }),
            limit: HumanLogSegmentPageSize::new(LOG_SEGMENT_PAGE_SIZE)
                .map_err(|_| WebDataError::Corrupt)?,
        };
        let Some(page) = self
            .reads
            .list_log_segments(&query)
            .await
            .map_err(map_store_error)?
        else {
            return Ok(None);
        };
        if page.stream.id != scope.stream_id()
            || page.stream.attempt_id != scope.attempt_id()
            || !log_stream_safety_is_valid(&page.stream)
        {
            return Err(WebDataError::Corrupt);
        }

        let mut records = Vec::new();
        let mut decoded_bytes = 0_usize;
        let mut checkpoint_cursor = decoded_checkpoint;
        let mut saw_boundary = decoded_checkpoint.is_none();
        let mut hit_limit = false;
        'segments: for segment in &page.segments {
            let blob = self
                .objects
                .get_verified(&segment.descriptor, segment.descriptor.size())
                .await
                .map_err(map_blob_error)?;
            let expectation = LogSegmentExpectation::new(
                scope.attempt_id(),
                scope.stream_id(),
                segment.first_sequence,
                segment.last_sequence,
                segment.uncompressed_size,
                segment.end_of_stream,
            );
            let frames =
                tokio::task::spawn_blocking(move || decode_log_segment(&blob, expectation))
                    .await
                    .map_err(|_| WebDataError::Unavailable)?
                    .map_err(|_| WebDataError::Corrupt)?;
            for frame in frames {
                let candidates = render_frame_lines(&frame)?;
                if candidates.is_empty() {
                    checkpoint_cursor = Some(DecodedLogCursor {
                        sequence: frame.sequence(),
                        line_ordinal: 0,
                        direction: HumanLogSegmentPageDirection::Newer,
                    });
                }
                if let Some(boundary) = decoded_checkpoint {
                    if frame.sequence() < boundary.sequence {
                        continue;
                    }
                    if frame.sequence() > boundary.sequence && !saw_boundary {
                        return Ok(None);
                    }
                    if frame.sequence() == boundary.sequence {
                        saw_boundary = true;
                        if usize::try_from(boundary.line_ordinal)
                            .ok()
                            .is_none_or(|ordinal| ordinal >= candidates.len())
                            && !(boundary.line_ordinal == 0 && frame.payload().is_empty())
                        {
                            return Ok(None);
                        }
                    }
                }
                for candidate in candidates {
                    let candidate_position = (candidate.sequence.get(), candidate.ordinal);
                    if let Some(boundary) = decoded_checkpoint {
                        let boundary_position = (boundary.sequence.get(), boundary.line_ordinal);
                        if candidate_position < boundary_position
                            || (!replay_checkpoint && candidate_position == boundary_position)
                        {
                            continue;
                        }
                    }
                    let next_bytes = decoded_bytes
                        .checked_add(candidate.text.len())
                        .ok_or(WebDataError::Corrupt)?;
                    if records.len() == super::data::LOG_PAGE_SIZE
                        || next_bytes > super::data::LOG_PAGE_DECODED_BYTES
                    {
                        hit_limit = true;
                        break 'segments;
                    }
                    decoded_bytes = next_bytes;
                    let cursor =
                        rendered_line_cursor(&candidate, HumanLogSegmentPageDirection::Newer);
                    let checkpoint = encode_log_cursor(
                        scope.tenant(),
                        scope.repository_id(),
                        scope.run_id(),
                        scope.job_id(),
                        scope.stream_id(),
                        cursor,
                    );
                    checkpoint_cursor = Some(cursor);
                    records.push(LiveLogRecord {
                        checkpoint,
                        line: visible_log_line(candidate),
                    });
                }
            }
        }
        if !cursor_boundary_is_valid(decoded_checkpoint, saw_boundary, &page) {
            return Ok(None);
        }
        let more_available = hit_limit || page.newer_cursor.is_some();
        let stream_closed = page.stream.closed_at.is_some() && !more_available;
        if stream_closed
            && page
                .segments
                .last()
                .is_some_and(|segment| !segment.end_of_stream)
        {
            return Err(WebDataError::Corrupt);
        }
        Ok(Some(LiveLogBatch {
            records,
            checkpoint: checkpoint_cursor.map(|cursor| {
                encode_log_cursor(
                    scope.tenant(),
                    scope.repository_id(),
                    scope.run_id(),
                    scope.job_id(),
                    scope.stream_id(),
                    cursor,
                )
            }),
            stream_closed,
            more_available,
        }))
    }

    async fn artifact(
        &self,
        context: &RequestContext,
        repository_path: &RepositoryPath,
        run_id: RunId,
        artifact_id: i64,
    ) -> Result<Option<ArtifactDownload>, WebDataError> {
        let Ok(artifact_id) = HumanArtifactId::new(artifact_id) else {
            return Ok(None);
        };
        let tenant = Self::tenant(context)?;
        let Some(repository) = self
            .resolve_repository_exact(&tenant, repository_path)
            .await?
        else {
            return Ok(None);
        };
        let run_scope = HumanRunScope::new(tenant.clone(), repository.id, run_id);
        let Some(run) = self
            .reads
            .get_run(&run_scope)
            .await
            .map_err(map_store_error)?
        else {
            return Ok(None);
        };
        if run.run.id != run_id {
            return Err(WebDataError::Corrupt);
        }
        let scope = HumanArtifactScope {
            tenant: tenant.clone(),
            repository_id: repository.id,
            run_id,
            artifact_id,
            observed_at_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
        };
        let Some(stored) = self
            .reads
            .get_artifact(&scope)
            .await
            .map_err(map_store_error)?
        else {
            return Ok(None);
        };
        if stored.artifact.id != artifact_id {
            return Err(WebDataError::Corrupt);
        }
        let (visibility, exposure) = publication_target(&stored.artifact.publication);
        if !self
            .allowed(
                context,
                &tenant,
                &repository,
                repository_read_permissions::ARTIFACT_READ,
                Some(visibility),
                exposure,
            )
            .await?
            || !self
                .allowed(
                    context,
                    &tenant,
                    &repository,
                    repository_read_permissions::ARTIFACT_DOWNLOAD,
                    Some(visibility),
                    exposure,
                )
                .await?
        {
            return Ok(None);
        }
        let manifest = self
            .objects
            .get_verified(&stored.manifest, MAXIMUM_ARTIFACT_MANIFEST_BYTES)
            .await
            .map_err(map_blob_error)?;
        validate_manifest(&stored, run_id, manifest.bytes())?;
        let body = artifact_body(
            Arc::clone(&self.objects),
            stored.blocks,
            stored.artifact.content_size,
            stored.artifact.content_digest,
        )?;
        Ok(Some(ArtifactDownload {
            file_name: stored.artifact.name,
            media_type: stored.artifact.mime_type,
            size: stored.artifact.content_size,
            digest: stored.artifact.content_digest.to_string(),
            body,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt::Write as _,
        io::Write as _,
        sync::{Arc, Mutex},
    };

    use automata_ci_auth::{
        authorization::{
            AuthorizationContext, OutputVisibility, Permission, RepositoryPublicationPolicy,
            RepositoryResource, RepositoryResourceId, SecretExposureClass,
            repository_read_permissions,
        },
        human::{PrincipalId, TenantId},
        request_auth::AuthenticatedRequestSnapshot,
    };
    use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore, MediaType, MemoryBlobStore};
    use automata_ci_core::{
        AttemptId, AttemptNumber, JobId, JobIrVersion, JobLifecycle, LogChannel as CoreLogChannel,
        LogFrame, LogSequence, LogStreamId, RunId, Sha256Digest, UnixMillis, WorkflowId,
    };
    use automata_ci_store::{
        DocumentSchema, HumanAuthorizationTarget, HumanGitCommitId, HumanJob, HumanJobAttempt,
        HumanJobDetail, HumanJobNavigation, HumanLogSegment, HumanLogSegmentPage, HumanLogStream,
        HumanOutputPublication, HumanRawLogDisposition, HumanRepository, HumanRepositoryCursor,
        HumanRepositoryPage, HumanRun, HumanRunConclusion, HumanRunCursor, HumanRunPageDirection,
        HumanRunPublication, HumanWorkflow, HumanWorkflowReadRepository, JobIrMetadata, ObjectKey,
        RepositoryCoordinate, RepositoryId, StoreError, TenantScope, WorkflowRunStatus,
    };

    use super::{
        CURSOR_VERSION, DecodedJobCursor, DecodedLogCursor, DecodedWorkflowCursor,
        JOB_CURSOR_BYTES, LOG_CURSOR_BYTES, LiveWebData, NavigationPageDirection,
        REPOSITORY_SETTINGS_READ_PERMISSION, REPOSITORY_SETTINGS_UPDATE_PERMISSION,
        RUN_CURSOR_BYTES, SECRET_METADATA_READ_PERMISSION, WORKFLOW_CURSOR_BYTES,
        conclusion_status, decode_job_cursor, decode_log_cursor, decode_repository_cursor,
        decode_run_cursor, decode_workflow_cursor, encode_job_cursor, encode_log_cursor,
        encode_repository_cursor, encode_run_cursor, encode_workflow_cursor, lifecycle_status,
        log_stream_safety_is_valid, map_job, map_navigation, map_run, map_workflow,
        must_escape_log_character, navigation_page_start, normalize_git_ref,
        projected_repository_next_cursor, render_frame_lines, valid_canonical_uuid,
    };
    use crate::app::repository_secrets::{
        RepositorySecretBrowserMutationOutcome, RepositorySecretWebData, RepositorySecretWebError,
        RepositorySecretsPageRequest, RepositorySecretsReadOutcome, VerifiedRepositorySecretForm,
    };
    use crate::app::web::data::{
        CollectionVisibility, JobLogPage, JobLogRequest, REPOSITORY_PAGE_SIZE,
        RepositoryDirectoryRequest, RepositoryPath, RepositorySettingsDestination, RequestContext,
        RunListRequest, Status, StatusFilter, Viewer, WebData, WebDataError,
    };

    #[test]
    fn workflow_enabled_state_survives_the_live_projection() {
        let id = WorkflowId::new();
        let workflow = map_workflow(&HumanWorkflow {
            id,
            path: ".ci/workflows/retired.yml".to_owned(),
            enabled: false,
            projected_name: None,
        });

        assert_eq!(workflow.id, id);
        assert_eq!(workflow.name, ".ci/workflows/retired.yml");
        assert!(!workflow.enabled);
    }

    #[test]
    fn bounded_navigation_reaches_251_workflows_and_all_4096_jobs() {
        assert_eq!(
            navigation_page_start(251, 250, 249, NavigationPageDirection::Next),
            Some(250)
        );
        assert_eq!(
            navigation_page_start(251, 250, 250, NavigationPageDirection::Previous),
            Some(0)
        );
        assert_eq!(
            navigation_page_start(4_096, 200, 3_999, NavigationPageDirection::Next),
            Some(4_000)
        );
        assert_eq!(
            navigation_page_start(4_096, 200, 4_000, NavigationPageDirection::Previous),
            Some(3_800)
        );
        assert_eq!(
            navigation_page_start(4_096, 200, 200, NavigationPageDirection::Next),
            None,
            "a forged non-boundary position must not create a page hole"
        );
    }

    #[test]
    fn navigation_cursors_are_canonical_and_scope_bound() {
        let tenant = tenant();
        let repository_id = RepositoryId::from_uuid(WorkflowId::new().as_uuid());
        let repository_position = HumanRepositoryCursor {
            normalized_owner: "automata-ci".to_owned(),
            normalized_name: "automata".to_owned(),
            id: repository_id,
        };
        let repository_cursor = encode_repository_cursor(&tenant, &repository_position)
            .expect("valid repository cursor");
        assert_eq!(
            decode_repository_cursor(&repository_cursor, &tenant),
            Some(repository_position.clone())
        );
        assert!(
            decode_repository_cursor(
                &repository_cursor,
                &TenantScope::from_authenticated_tenant_id("tenant-2").expect("other tenant"),
            )
            .is_none()
        );
        assert!(decode_repository_cursor(&format!("{repository_cursor}="), &tenant).is_none());
        let invalid_position = HumanRepositoryCursor {
            normalized_owner: "Automata-CI".to_owned(),
            ..repository_position.clone()
        };
        assert_eq!(
            encode_repository_cursor(&tenant, &invalid_position),
            Err(WebDataError::Corrupt)
        );
        let dropped_store_position = HumanRepositoryCursor {
            normalized_owner: "hidden".to_owned(),
            normalized_name: "repository".to_owned(),
            id: RepositoryId::from_uuid(WorkflowId::new().as_uuid()),
        };
        let safe_cursor = projected_repository_next_cursor(
            &tenant,
            Some(&dropped_store_position),
            Some(&repository_position),
        )
        .expect("visible projected cursor")
        .expect("next cursor");
        assert_eq!(
            decode_repository_cursor(&safe_cursor, &tenant),
            Some(repository_position.clone()),
            "a dropped Store row must never become the browser cursor"
        );
        assert_eq!(
            projected_repository_next_cursor(&tenant, Some(&dropped_store_position), None),
            Ok(None),
            "an empty projected page cannot safely advance through a hidden row"
        );

        let selected_workflow_id = WorkflowId::new();
        let workflow_position = WorkflowId::new();
        let workflow_cursor = encode_workflow_cursor(
            &tenant,
            repository_id,
            Some(selected_workflow_id),
            workflow_position,
            NavigationPageDirection::Next,
        );
        assert!(workflow_cursor.len() < WORKFLOW_CURSOR_BYTES * 2);
        assert_eq!(
            decode_workflow_cursor(
                &workflow_cursor,
                &tenant,
                repository_id,
                Some(selected_workflow_id),
            ),
            Some(DecodedWorkflowCursor {
                position: workflow_position,
                direction: NavigationPageDirection::Next,
            })
        );
        assert!(decode_workflow_cursor(&workflow_cursor, &tenant, repository_id, None).is_none());

        let run_id = RunId::new();
        let job_cursor = DecodedJobCursor {
            created_at: UnixMillis::new(4_000),
            position: JobId::new(),
            direction: NavigationPageDirection::Previous,
        };
        let encoded = encode_job_cursor(&tenant, repository_id, run_id, job_cursor);
        assert!(encoded.len() < JOB_CURSOR_BYTES * 2);
        assert_eq!(
            decode_job_cursor(&encoded, &tenant, repository_id, run_id),
            Some(job_cursor)
        );
        assert!(decode_job_cursor(&encoded, &tenant, repository_id, RunId::new()).is_none());
    }

    #[test]
    fn repository_cursor_reader_rejects_noncurrent_versions() {
        let tenant = tenant();
        let position = HumanRepositoryCursor {
            normalized_owner: "automata-ci".to_owned(),
            normalized_name: "automata".to_owned(),
            id: RepositoryId::from_uuid(WorkflowId::new().as_uuid()),
        };
        let current = encode_repository_cursor(&tenant, &position).expect("current cursor");
        let mut bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &current)
                .expect("cursor bytes");

        for version in [0, CURSOR_VERSION.checked_add(1).expect("test version")] {
            bytes[0] = version;
            let noncurrent =
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes);
            assert!(
                decode_repository_cursor(&noncurrent, &tenant).is_none(),
                "accepted cursor version {version}"
            );
        }
    }

    #[tokio::test]
    async fn repository_directory_preserves_the_authorized_store_page_without_link_overclaim() {
        let (data, context, _, _, _) = fake_live_data(true).await;
        let page = data
            .repository_page(
                &context,
                &RepositoryDirectoryRequest {
                    cursor: None,
                    limit: REPOSITORY_PAGE_SIZE,
                },
            )
            .await
            .expect("authorized repository page");

        assert_eq!(page.repositories.len(), 1);
        assert_eq!(page.repositories[0].repository.owner, "acme");
        assert_eq!(page.repositories[0].repository.name, "payments");
        assert!(page.repositories[0].actions_visible);
        assert!(!page.repositories[0].repository.settings_visible);
        assert!(page.next_cursor.is_none());
        assert_eq!(
            data.repository_page(
                &context,
                &RepositoryDirectoryRequest {
                    cursor: None,
                    limit: REPOSITORY_PAGE_SIZE + 1,
                },
            )
            .await,
            Err(WebDataError::InvalidRequest)
        );
        assert_eq!(
            data.repository_page(
                &context,
                &RepositoryDirectoryRequest {
                    cursor: Some("not-a-bound-cursor".to_owned()),
                    limit: REPOSITORY_PAGE_SIZE,
                },
            )
            .await,
            Err(WebDataError::InvalidRequest)
        );
    }

    #[derive(Debug)]
    struct ComposedRepositorySecretWebData;

    #[async_trait::async_trait]
    impl RepositorySecretWebData for ComposedRepositorySecretWebData {
        async fn page(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _owner: &str,
            _repository: &str,
            _request: RepositorySecretsPageRequest,
        ) -> Result<RepositorySecretsReadOutcome, RepositorySecretWebError> {
            unimplemented!("repository-directory discovery does not read secret rows")
        }

        async fn mutate(
            &self,
            _snapshot: &AuthenticatedRequestSnapshot,
            _owner: &str,
            _repository: &str,
            _form: VerifiedRepositorySecretForm,
        ) -> Result<RepositorySecretBrowserMutationOutcome, RepositorySecretWebError> {
            unimplemented!("repository-directory discovery does not mutate secrets")
        }
    }

    #[tokio::test]
    async fn repository_directory_exposes_secrets_without_overclaiming_repository_access() {
        let (data, _, _, _, _, _) = fake_live_data_with_policy(FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Private,
            log_visibility: OutputVisibility::Private,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: false,
            allow_logs: false,
            allow_settings_read: false,
            allow_settings_update: false,
        })
        .await;
        let data = data.with_repository_secrets(Arc::new(ComposedRepositorySecretWebData));
        let page = data
            .repository_page(
                &authenticated_request_context(),
                &RepositoryDirectoryRequest {
                    cursor: None,
                    limit: REPOSITORY_PAGE_SIZE,
                },
            )
            .await
            .expect("secret-metadata-authorized repository page");

        assert_eq!(page.repositories.len(), 1);
        assert!(!page.repositories[0].actions_visible);
        assert!(!page.repositories[0].repository.settings_visible);
        assert_eq!(
            page.repositories[0].settings_destination,
            Some(RepositorySettingsDestination::Secrets)
        );
    }

    #[tokio::test]
    async fn repository_directory_prefers_access_when_both_destinations_are_authorized() {
        let (data, _, _, _, _, _) = fake_live_data_with_policy(FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Private,
            log_visibility: OutputVisibility::Private,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: false,
            allow_logs: false,
            allow_settings_read: true,
            allow_settings_update: false,
        })
        .await;
        let data = data.with_repository_secrets(Arc::new(ComposedRepositorySecretWebData));
        let page = data
            .repository_page(
                &authenticated_request_context(),
                &RepositoryDirectoryRequest {
                    cursor: None,
                    limit: REPOSITORY_PAGE_SIZE,
                },
            )
            .await
            .expect("repository page with both settings destinations");

        assert_eq!(page.repositories.len(), 1);
        assert!(page.repositories[0].repository.settings_visible);
        assert_eq!(
            page.repositories[0].settings_destination,
            Some(RepositorySettingsDestination::Access)
        );
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Debug)]
    struct FakeReads {
        repository: HumanRepository,
        job: HumanJobDetail,
        log_page: HumanLogSegmentPage,
        allow_logs: bool,
        allow_dashboard: bool,
        allow_settings_read: bool,
        allow_settings_update: bool,
        authorization_calls: Arc<Mutex<Vec<HumanAuthorizationTarget>>>,
    }

    #[async_trait::async_trait]
    impl HumanWorkflowReadRepository for FakeReads {
        async fn resolve_repository(
            &self,
            _tenant: &TenantScope,
            _coordinate: &RepositoryCoordinate,
        ) -> Result<Option<HumanRepository>, StoreError> {
            Ok(Some(self.repository.clone()))
        }

        async fn list_repositories(
            &self,
            query: &automata_ci_store::HumanRepositoryListQuery,
            _context: &AuthorizationContext,
            permissions: &[Permission],
        ) -> Result<HumanRepositoryPage, StoreError> {
            assert_eq!(
                query.tenant.as_str(),
                self.repository.resource.tenant_id().as_str()
            );
            assert!(matches!(permissions.len(), 1 | 2));
            assert_eq!(
                permissions[0].as_str(),
                repository_read_permissions::REPOSITORY_READ
            );
            if let Some(permission) = permissions.get(1) {
                assert_eq!(permission.as_str(), SECRET_METADATA_READ_PERMISSION);
            }
            Ok(HumanRepositoryPage {
                repositories: vec![self.repository.clone()],
                next_cursor: None,
            })
        }

        async fn list_workflows(
            &self,
            _query: &automata_ci_store::HumanWorkflowListQuery,
            _context: &AuthorizationContext,
            _permission: &Permission,
        ) -> Result<Option<automata_ci_store::HumanWorkflowPage>, StoreError> {
            unimplemented!("not used by focused job-log tests")
        }

        async fn list_runs(
            &self,
            _query: &automata_ci_store::HumanRunListQuery,
            _context: &AuthorizationContext,
            _permission: &Permission,
        ) -> Result<Option<automata_ci_store::HumanRunPage>, StoreError> {
            unimplemented!("not used by focused job-log tests")
        }

        async fn get_run(
            &self,
            _scope: &automata_ci_store::HumanRunScope,
        ) -> Result<Option<automata_ci_store::HumanRunDetail>, StoreError> {
            unimplemented!("not used by focused job-log tests")
        }

        async fn get_job(
            &self,
            _scope: &automata_ci_store::HumanJobScope,
        ) -> Result<Option<HumanJobDetail>, StoreError> {
            Ok(Some(self.job.clone()))
        }

        async fn list_log_segments(
            &self,
            _query: &automata_ci_store::HumanLogSegmentQuery,
        ) -> Result<Option<automata_ci_store::HumanLogSegmentPage>, StoreError> {
            Ok(Some(self.log_page.clone()))
        }

        async fn get_artifact(
            &self,
            _scope: &automata_ci_store::HumanArtifactScope,
        ) -> Result<Option<automata_ci_store::HumanArtifactDownload>, StoreError> {
            unimplemented!("not used by focused job-log tests")
        }

        async fn is_repository_request_allowed(
            &self,
            _tenant: &TenantScope,
            _repository_id: RepositoryId,
            context: &AuthorizationContext,
            target: &HumanAuthorizationTarget,
        ) -> Result<bool, StoreError> {
            self.authorization_calls
                .lock()
                .expect("authorization call lock")
                .push(target.clone());
            let permission = target.request.permission().as_str();
            Ok(match permission {
                repository_read_permissions::LOG_READ => {
                    let visibility = target
                        .durable_visibility
                        .unwrap_or(self.repository.publication.logs());
                    let visibility = if target.request.secret_exposure()
                        == SecretExposureClass::ReadableSecret
                    {
                        OutputVisibility::Private
                    } else {
                        visibility
                    };
                    self.allow_logs && fake_audience_allows(context, visibility)
                }
                REPOSITORY_SETTINGS_UPDATE_PERMISSION => self.allow_settings_update,
                REPOSITORY_SETTINGS_READ_PERMISSION
                    if target.durable_visibility == Some(OutputVisibility::Private) =>
                {
                    self.allow_settings_read
                }
                SECRET_METADATA_READ_PERMISSION => true,
                repository_read_permissions::REPOSITORY_READ
                | repository_read_permissions::WORKFLOW_READ
                | repository_read_permissions::RUN_READ
                | repository_read_permissions::JOB_READ => {
                    let visibility = target
                        .durable_visibility
                        .unwrap_or(self.repository.publication.dashboard());
                    self.allow_dashboard && fake_audience_allows(context, visibility)
                }
                _ => false,
            })
        }
    }

    const fn fake_audience_allows(
        context: &AuthorizationContext,
        visibility: OutputVisibility,
    ) -> bool {
        match visibility {
            OutputVisibility::Public => true,
            OutputVisibility::Authenticated | OutputVisibility::Private => {
                context.tenant_id().is_some()
            }
        }
    }

    fn tenant() -> TenantScope {
        TenantScope::from_authenticated_tenant_id("tenant-1").expect("tenant")
    }

    fn request() -> RunListRequest {
        RunListRequest {
            workflow_id: Some(WorkflowId::new()),
            workflow_cursor: None,
            status: StatusFilter::Completed,
            git_ref: Some("refs/heads/main".to_owned()),
            cursor: None,
            limit: 25,
        }
    }

    async fn fake_live_data(
        allow_logs: bool,
    ) -> (LiveWebData, RequestContext, RepositoryPath, RunId, JobId) {
        fake_live_data_with_permissions(allow_logs, HumanRawLogDisposition::Persist, true, true)
            .await
    }

    async fn fake_live_data_with_settings_permissions(
        allow_read: bool,
        allow_update: bool,
    ) -> (LiveWebData, RequestContext, RepositoryPath, RunId, JobId) {
        fake_live_data_with_permissions(
            true,
            HumanRawLogDisposition::Persist,
            allow_read,
            allow_update,
        )
        .await
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Clone, Copy, Debug)]
    struct FakeLivePolicy {
        dashboard_visibility: OutputVisibility,
        log_visibility: OutputVisibility,
        log_exposure: SecretExposureClass,
        raw_log_disposition: HumanRawLogDisposition,
        allow_dashboard: bool,
        allow_logs: bool,
        allow_settings_read: bool,
        allow_settings_update: bool,
    }

    fn fixture_repository(tenant_id: &TenantId, repository_id: RepositoryId) -> HumanRepository {
        let resource_id = RepositoryResourceId::from_uuid(repository_id.as_uuid())
            .expect("repository resource ID");
        HumanRepository {
            id: repository_id,
            resource: RepositoryResource::new(tenant_id.clone(), resource_id),
            scm_provider: "github".to_owned(),
            provider_repository_id: "123".to_owned(),
            owner: "acme".to_owned(),
            name: "payments".to_owned(),
            publication: RepositoryPublicationPolicy::new(
                OutputVisibility::Public,
                OutputVisibility::Public,
                OutputVisibility::Public,
            ),
            publication_revision: 1,
        }
    }

    fn fixture_run(run_id: RunId, dashboard_visibility: OutputVisibility) -> HumanRun {
        HumanRun {
            id: run_id,
            workflow_id: WorkflowId::new(),
            workflow_path: ".ci/workflows/ci.yml".to_owned(),
            run_number: 42,
            run_attempt: 1,
            event_name: "push".to_owned(),
            head_commit: HumanGitCommitId::new(vec![7; 20]).expect("commit ID"),
            status: WorkflowRunStatus::Completed,
            conclusion: Some(HumanRunConclusion::Lost),
            workflow_name: "CI".to_owned(),
            git_ref: Some("refs/heads/main".to_owned()),
            actor: Some("octocat".to_owned()),
            display_title: Some("Validate checkout flow".to_owned()),
            commit_subject: Some("Validate checkout flow".to_owned()),
            created_at: UnixMillis::new(1_000),
            updated_at: UnixMillis::new(2_000),
            finished_at: Some(UnixMillis::new(2_000)),
            publication: HumanRunPublication {
                policy_revision: 1,
                requested_dashboard_visibility: dashboard_visibility,
                effective_dashboard_visibility: dashboard_visibility,
                requested_log_visibility: OutputVisibility::Public,
                requested_artifact_visibility: OutputVisibility::Public,
                safety_reason: "secretless".to_owned(),
                safety_schema: 2,
            },
        }
    }

    fn fixture_job_ir(job_id: JobId, run_id: RunId) -> JobIrMetadata {
        JobIrMetadata::new(
            job_id,
            run_id,
            JobIrVersion::new(1).expect("JobIR version"),
            1,
            Sha256Digest::from_bytes([7; 32]),
            ObjectKey::new(format!("tests/job-ir/{job_id}")).expect("JobIR object key"),
        )
        .expect("JobIR metadata")
    }

    fn fixture_output_publication(
        visibility: OutputVisibility,
        exposure: SecretExposureClass,
        reason: &str,
    ) -> HumanOutputPublication {
        HumanOutputPublication {
            secret_exposure: exposure,
            requested_visibility: visibility,
            effective_visibility: visibility,
            safety_reason: reason.to_owned(),
            safety_schema: u16::try_from(automata_ci_store::HUMAN_OUTPUT_PUBLICATION_SAFETY_SCHEMA)
                .expect("output publication schema fits u16"),
        }
    }

    fn fixture_job_detail(
        run: HumanRun,
        job_id: JobId,
        attempt_id: AttemptId,
        raw_log_disposition: HumanRawLogDisposition,
        log_publication: HumanOutputPublication,
    ) -> (HumanJobDetail, HumanLogStream) {
        let attempt = HumanJobAttempt {
            id: attempt_id,
            number: AttemptNumber::new(1).expect("attempt number"),
            lifecycle: JobLifecycle::Lost,
            queued_at: UnixMillis::new(1_100),
            changed_at: UnixMillis::new(1_500),
            started_at: Some(UnixMillis::new(1_200)),
            finished_at: Some(UnixMillis::new(1_900)),
            runner: None,
            terminal_result: None,
        };
        let log_stream = HumanLogStream {
            id: LogStreamId::new(),
            attempt_id,
            schema: DocumentSchema::new(1).expect("log schema"),
            opened_at: UnixMillis::new(1_200),
            closed_at: Some(UnixMillis::new(1_900)),
            raw_log_disposition,
            publication: log_publication,
        };
        let job = HumanJob {
            id: job_id,
            key: "build".to_owned(),
            display_name: "Build".to_owned(),
            created_at: UnixMillis::new(1_050),
            job_ir: fixture_job_ir(job_id, run.id),
            latest_attempt: Some(attempt),
            log_publication: Some(log_stream.publication.clone()),
        };
        let navigation = vec![
            HumanJobNavigation {
                id: job_id,
                display_name: "Build".to_owned(),
                lifecycle: Some(JobLifecycle::Lost),
                conclusion: Some(HumanRunConclusion::Lost),
                log_publication: Some(log_stream.publication.clone()),
            },
            HumanJobNavigation {
                id: JobId::new(),
                display_name: "Private logs".to_owned(),
                lifecycle: Some(JobLifecycle::Succeeded),
                conclusion: Some(HumanRunConclusion::Success),
                log_publication: Some(fixture_output_publication(
                    OutputVisibility::Private,
                    SecretExposureClass::Secretless,
                    "private",
                )),
            },
            HumanJobNavigation {
                id: JobId::new(),
                display_name: "Pending without a log stream".to_owned(),
                lifecycle: None,
                conclusion: None,
                log_publication: None,
            },
        ];
        (
            HumanJobDetail {
                run,
                navigation,
                job,
                log_stream: Some(log_stream.clone()),
            },
            log_stream,
        )
    }

    async fn fixture_log_storage(
        log_stream: &HumanLogStream,
    ) -> (Arc<MemoryBlobStore>, HumanLogSegment) {
        fixture_log_storage_with_payload(log_stream, b"checkout ok\n".to_vec()).await
    }

    async fn fixture_log_storage_with_payload(
        log_stream: &HumanLogStream,
        payload: Vec<u8>,
    ) -> (Arc<MemoryBlobStore>, HumanLogSegment) {
        let frames = vec![
            LogFrame::new(
                log_stream.id,
                log_stream.attempt_id,
                LogSequence::new(0),
                UnixMillis::new(1_300),
                CoreLogChannel::Stdout,
                payload,
                false,
            )
            .expect("log frame"),
            LogFrame::new(
                log_stream.id,
                log_stream.attempt_id,
                LogSequence::new(1),
                UnixMillis::new(1_900),
                CoreLogChannel::System,
                Vec::new(),
                true,
            )
            .expect("end frame"),
        ];
        let uncompressed = serde_json::to_vec(&frames).expect("log JSON");
        let mut encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(&uncompressed).expect("compress log");
        let compressed = encoder.finish().expect("finish log");
        let payload = BlobPayload::from_bytes(
            BlobKey::new("logs/test/segment.json.gz").expect("log key"),
            MediaType::new(automata_ci_control::runner_control::LOG_SEGMENT_MEDIA_TYPE)
                .expect("log media type"),
            bytes::Bytes::from(compressed),
        );
        let segment = HumanLogSegment {
            first_sequence: LogSequence::new(0),
            last_sequence: LogSequence::new(1),
            descriptor: payload.descriptor().clone(),
            uncompressed_size: u64::try_from(uncompressed.len()).expect("log size"),
            stored_at: UnixMillis::new(1_900),
            end_of_stream: true,
        };
        let objects = Arc::new(MemoryBlobStore::default());
        objects
            .put_if_absent(payload)
            .await
            .expect("store log segment");
        (objects, segment)
    }

    async fn fake_live_data_with_permissions(
        allow_logs: bool,
        raw_log_disposition: HumanRawLogDisposition,
        allow_settings_read: bool,
        allow_settings_update: bool,
    ) -> (LiveWebData, RequestContext, RepositoryPath, RunId, JobId) {
        let (log_visibility, log_exposure) =
            (OutputVisibility::Public, SecretExposureClass::Secretless);
        let (data, context, repository, run_id, job_id, _) =
            fake_live_data_with_policy(FakeLivePolicy {
                dashboard_visibility: OutputVisibility::Public,
                log_visibility,
                log_exposure,
                raw_log_disposition,
                allow_dashboard: true,
                allow_logs,
                allow_settings_read,
                allow_settings_update,
            })
            .await;
        (data, context, repository, run_id, job_id)
    }

    async fn fake_live_data_with_policy(
        policy: FakeLivePolicy,
    ) -> (
        LiveWebData,
        RequestContext,
        RepositoryPath,
        RunId,
        JobId,
        Arc<Mutex<Vec<HumanAuthorizationTarget>>>,
    ) {
        fake_live_data_with_policy_and_payload(policy, None).await
    }

    async fn fake_live_data_with_policy_and_payload(
        policy: FakeLivePolicy,
        payload: Option<Vec<u8>>,
    ) -> (
        LiveWebData,
        RequestContext,
        RepositoryPath,
        RunId,
        JobId,
        Arc<Mutex<Vec<HumanAuthorizationTarget>>>,
    ) {
        fake_live_data_with_policy_and_stream(policy, payload, true).await
    }

    async fn fake_live_data_with_policy_and_stream(
        policy: FakeLivePolicy,
        payload: Option<Vec<u8>>,
        has_log_stream: bool,
    ) -> (
        LiveWebData,
        RequestContext,
        RepositoryPath,
        RunId,
        JobId,
        Arc<Mutex<Vec<HumanAuthorizationTarget>>>,
    ) {
        let tenant_id = TenantId::new("tenant-1").expect("tenant ID");
        let repository_id = RepositoryId::from_uuid(RunId::new().as_uuid());
        let mut repository = fixture_repository(&tenant_id, repository_id);
        repository.publication = RepositoryPublicationPolicy::new(
            policy.dashboard_visibility,
            policy.log_visibility,
            OutputVisibility::Public,
        );
        let run_id = RunId::new();
        let job_id = JobId::new();
        let attempt_id = AttemptId::new();
        let log_publication = fixture_output_publication(
            policy.log_visibility,
            policy.log_exposure,
            if policy.log_exposure == SecretExposureClass::ReadableSecret {
                "secret_exposure"
            } else {
                "repository_policy"
            },
        );
        let mut run = fixture_run(run_id, policy.dashboard_visibility);
        run.publication.requested_log_visibility = policy.log_visibility;
        let (mut detail, log_stream) = fixture_job_detail(
            run,
            job_id,
            attempt_id,
            policy.raw_log_disposition,
            log_publication,
        );
        if !has_log_stream {
            detail.job.log_publication = None;
            detail.log_stream = None;
            let selected = detail
                .navigation
                .iter_mut()
                .find(|job| job.id == job_id)
                .expect("selected job navigation");
            selected.log_publication = None;
        }
        let (objects, segment) = match payload {
            Some(payload) => fixture_log_storage_with_payload(&log_stream, payload).await,
            None => fixture_log_storage(&log_stream).await,
        };
        let authorization_calls = Arc::new(Mutex::new(Vec::new()));
        let reads: Arc<dyn HumanWorkflowReadRepository> = Arc::new(FakeReads {
            repository,
            job: detail,
            log_page: HumanLogSegmentPage {
                stream: log_stream,
                segments: vec![segment],
                older_cursor: None,
                newer_cursor: None,
            },
            allow_logs: policy.allow_logs,
            allow_dashboard: policy.allow_dashboard,
            allow_settings_read: policy.allow_settings_read,
            allow_settings_update: policy.allow_settings_update,
            authorization_calls: Arc::clone(&authorization_calls),
        });
        let objects: Arc<dyn ImmutableBlobStore> = objects;
        (
            LiveWebData::new(reads, objects),
            RequestContext::anonymous(tenant_id),
            RepositoryPath {
                owner: "acme".to_owned(),
                name: "payments".to_owned(),
            },
            run_id,
            job_id,
            authorization_calls,
        )
    }

    fn first_log_page_request() -> JobLogRequest {
        JobLogRequest {
            cursor: None,
            limit: 200,
            maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
        }
    }

    async fn read_log_page(
        data: &LiveWebData,
        context: &RequestContext,
        repository: &RepositoryPath,
        run_id: RunId,
        job_id: JobId,
        cursor: Option<String>,
        limit: usize,
    ) -> JobLogPage {
        WebData::job_log(
            data,
            context,
            repository,
            run_id,
            job_id,
            &JobLogRequest {
                cursor,
                limit,
                maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
            },
        )
        .await
        .expect("log page read")
        .expect("authorized log page")
    }

    fn assert_log_texts(page: &JobLogPage, expected: &[&str]) {
        assert_eq!(
            page.lines
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            expected
        );
    }

    fn authenticated_request_context() -> RequestContext {
        let tenant_id = TenantId::new("tenant-1").expect("tenant ID");
        let authorization = AuthorizationContext::authenticated(
            tenant_id.clone(),
            PrincipalId::new("11111111-1111-4111-8111-111111111111").expect("principal ID"),
            std::collections::BTreeSet::default(),
        )
        .expect("authenticated context");
        RequestContext::new(
            tenant_id,
            authorization,
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("request context")
    }

    #[tokio::test]
    async fn invalid_cursors_are_hidden_and_log_denial_restricts_only_the_collection() {
        let (data, context, repository, run_id, job_id) = fake_live_data(true).await;
        let invalid_cursor = JobLogRequest {
            cursor: Some("not-a-canonical-cursor".to_owned()),
            limit: 200,
            maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
        };
        assert!(
            WebData::job_log(
                &data,
                &context,
                &repository,
                run_id,
                job_id,
                &invalid_cursor,
            )
            .await
            .expect("invalid cursors are hidden")
            .is_none()
        );

        let (data, context, repository, run_id, job_id) = fake_live_data(false).await;
        let first_page = JobLogRequest {
            cursor: None,
            limit: 200,
            maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
        };
        let page = WebData::job_log(&data, &context, &repository, run_id, job_id, &first_page)
            .await
            .expect("job detail lookup")
            .expect("dashboard-readable metadata remains visible");
        assert_eq!(page.log_visibility, CollectionVisibility::Restricted);
        assert!(page.lines.is_empty());
        assert!(page.previous_cursor.is_none());
        assert!(page.next_cursor.is_none());
        assert!(page.live.is_none());

        let denied_cursor = JobLogRequest {
            cursor: Some("not-a-canonical-cursor".to_owned()),
            ..first_page
        };
        assert!(
            WebData::job_log(&data, &context, &repository, run_id, job_id, &denied_cursor,)
                .await
                .expect("restricted log cursors are hidden")
                .is_none()
        );
    }

    #[tokio::test]
    async fn public_log_with_private_dashboard_omits_private_sibling_navigation() {
        let (data, context, repository, run_id, job_id, calls) =
            fake_live_data_with_policy(FakeLivePolicy {
                dashboard_visibility: OutputVisibility::Private,
                log_visibility: OutputVisibility::Public,
                log_exposure: SecretExposureClass::Secretless,
                raw_log_disposition: HumanRawLogDisposition::Persist,
                allow_dashboard: true,
                allow_logs: true,
                allow_settings_read: false,
                allow_settings_update: false,
            })
            .await;

        let page = WebData::job_log(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            &first_log_page_request(),
        )
        .await
        .expect("public log lookup")
        .expect("public log must not depend on dashboard publication");

        assert_eq!(page.jobs.len(), 1);
        assert_eq!(page.jobs[0].id, job_id);
        assert_eq!(page.jobs[0].name, page.job.name);
        assert!(page.jobs[0].logs_available);
        assert!(
            page.jobs
                .iter()
                .all(|navigation| navigation.name != "Private logs")
        );
        let calls = calls.lock().expect("authorization calls");
        assert_eq!(
            calls
                .iter()
                .filter(|target| {
                    target.request.permission().as_str() == repository_read_permissions::LOG_READ
                })
                .count(),
            1
        );
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0].request.permission().as_str(),
            repository_read_permissions::REPOSITORY_READ
        );
        let log_call = calls
            .iter()
            .find(|target| {
                target.request.permission().as_str() == repository_read_permissions::LOG_READ
            })
            .expect("selected-log authorization");
        assert_eq!(log_call.durable_visibility, Some(OutputVisibility::Public));
        assert_eq!(
            log_call.request.secret_exposure(),
            SecretExposureClass::Secretless
        );
    }

    #[tokio::test]
    async fn jobs_without_a_log_stream_still_advertise_a_job_detail_destination() {
        let (data, _, repository, run_id, job_id, calls) =
            fake_live_data_with_policy(FakeLivePolicy {
                dashboard_visibility: OutputVisibility::Public,
                log_visibility: OutputVisibility::Public,
                log_exposure: SecretExposureClass::Secretless,
                raw_log_disposition: HumanRawLogDisposition::Persist,
                allow_dashboard: true,
                allow_logs: true,
                allow_settings_read: false,
                allow_settings_update: false,
            })
            .await;
        let page = WebData::job_log(
            &data,
            &authenticated_request_context(),
            &repository,
            run_id,
            job_id,
            &first_log_page_request(),
        )
        .await
        .expect("job navigation read")
        .expect("authorized job log");

        let pending = page
            .jobs
            .iter()
            .find(|job| job.name == "Pending without a log stream")
            .expect("pending job navigation");
        assert!(pending.logs_available);
        assert_eq!(
            calls
                .lock()
                .expect("authorization calls")
                .iter()
                .filter(|target| {
                    target.request.permission().as_str() == repository_read_permissions::LOG_READ
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn dashboard_readable_job_renders_when_logs_are_denied() {
        let (data, context, repository, run_id, job_id, _) =
            fake_live_data_with_policy(FakeLivePolicy {
                dashboard_visibility: OutputVisibility::Public,
                log_visibility: OutputVisibility::Private,
                log_exposure: SecretExposureClass::Secretless,
                raw_log_disposition: HumanRawLogDisposition::Persist,
                allow_dashboard: true,
                allow_logs: false,
                allow_settings_read: false,
                allow_settings_update: false,
            })
            .await;

        let page = WebData::job_log(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            &first_log_page_request(),
        )
        .await
        .expect("job detail read")
        .expect("dashboard-readable job detail");

        assert_eq!(page.job.id, job_id);
        assert_eq!(page.log_visibility, CollectionVisibility::Restricted);
        assert!(page.lines.is_empty());
        assert!(page.previous_cursor.is_none());
        assert!(page.next_cursor.is_none());
        assert!(page.live.is_none());
    }

    #[tokio::test]
    async fn private_log_requires_authenticated_log_permission_with_exact_immutable_target() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Private,
            log_visibility: OutputVisibility::Private,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: false,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let (data, anonymous, repository, run_id, job_id, calls) =
            fake_live_data_with_policy(policy).await;
        let request = first_log_page_request();
        assert!(
            WebData::job_log(&data, &anonymous, &repository, run_id, job_id, &request,)
                .await
                .expect("anonymous private-log denial")
                .is_none()
        );
        {
            let mut calls = calls.lock().expect("authorization calls");
            assert_eq!(calls.len(), 2);
            assert_eq!(
                calls[0].request.permission().as_str(),
                repository_read_permissions::REPOSITORY_READ
            );
            let log_call = calls
                .iter()
                .find(|target| {
                    target.request.permission().as_str() == repository_read_permissions::LOG_READ
                })
                .expect("private-log authorization");
            assert_eq!(log_call.durable_visibility, Some(OutputVisibility::Private));
            assert_eq!(
                log_call.request.secret_exposure(),
                SecretExposureClass::Secretless
            );
            calls.clear();
        }

        let authenticated = authenticated_request_context();
        let page = WebData::job_log(&data, &authenticated, &repository, run_id, job_id, &request)
            .await
            .expect("authenticated private-log lookup")
            .expect("log-authorized viewer");
        assert_eq!(page.jobs.len(), 1);
        assert_eq!(page.lines.len(), 1);

        let (denied, _, repository, run_id, job_id, _) =
            fake_live_data_with_policy(FakeLivePolicy {
                allow_logs: false,
                ..policy
            })
            .await;
        assert!(
            WebData::job_log(
                &denied,
                &authenticated,
                &repository,
                run_id,
                job_id,
                &request,
            )
            .await
            .expect("authenticated log-permission denial")
            .is_none()
        );
    }

    #[tokio::test]
    async fn masked_readable_secret_logs_are_private_and_preserve_user_output() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Private,
            log_visibility: OutputVisibility::Private,
            log_exposure: SecretExposureClass::ReadableSecret,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: false,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let (data, anonymous, repository, run_id, job_id, _) =
            fake_live_data_with_policy(policy).await;
        let request = first_log_page_request();

        assert!(
            WebData::job_log(&data, &anonymous, &repository, run_id, job_id, &request,)
                .await
                .expect("anonymous readable-secret denial")
                .is_none()
        );
        let page = WebData::job_log(
            &data,
            &authenticated_request_context(),
            &repository,
            run_id,
            job_id,
            &request,
        )
        .await
        .expect("authenticated masked-log lookup")
        .expect("log-authorized viewer");

        assert_eq!(page.lines.len(), 1);
        assert_eq!(page.lines[0].text, "checkout ok");
    }

    #[tokio::test]
    async fn public_runner_redacted_logs_ignore_runtime_secret_exposure() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Public,
            log_visibility: OutputVisibility::Public,
            log_exposure: SecretExposureClass::ReadableSecret,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: true,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let (data, anonymous, repository, run_id, job_id, calls) =
            fake_live_data_with_policy(policy).await;
        let page = WebData::job_log(
            &data,
            &anonymous,
            &repository,
            run_id,
            job_id,
            &first_log_page_request(),
        )
        .await
        .expect("anonymous public runner-redacted log lookup")
        .expect("public runner-redacted log page");

        assert_eq!(page.log_visibility, CollectionVisibility::Full);
        assert_eq!(page.lines.len(), 1);
        assert_eq!(page.lines[0].text, "checkout ok");
        assert!(
            calls
                .lock()
                .expect("authorization calls")
                .iter()
                .any(|target| {
                    target.request.permission().as_str() == repository_read_permissions::LOG_READ
                        && target.request.secret_exposure() == SecretExposureClass::Secretless
                        && target.durable_visibility == Some(OutputVisibility::Public)
                })
        );
    }

    #[tokio::test]
    async fn anonymous_public_job_without_a_log_stream_has_visible_empty_logs() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Public,
            log_visibility: OutputVisibility::Public,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: true,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let (data, anonymous, repository, run_id, job_id, calls) =
            fake_live_data_with_policy_and_stream(policy, None, false).await;
        let page = WebData::job_log(
            &data,
            &anonymous,
            &repository,
            run_id,
            job_id,
            &first_log_page_request(),
        )
        .await
        .expect("anonymous public empty-log lookup")
        .expect("public empty-log page");

        assert_eq!(page.log_visibility, CollectionVisibility::Full);
        assert!(page.job.logs_available);
        assert!(page.lines.is_empty());
        assert!(page.previous_cursor.is_none());
        assert!(page.next_cursor.is_none());
        assert!(page.live.is_none());
        assert!(
            calls
                .lock()
                .expect("authorization calls")
                .iter()
                .any(|target| {
                    target.request.permission().as_str() == repository_read_permissions::LOG_READ
                        && target.request.secret_exposure() == SecretExposureClass::Secretless
                        && target.durable_visibility == Some(OutputVisibility::Public)
                })
        );
    }

    #[tokio::test]
    async fn job_log_parent_scope_mismatches_remain_closed() {
        let (data, context, repository, run_id, job_id) = fake_live_data(true).await;
        let request = first_log_page_request();
        assert_eq!(
            WebData::job_log(&data, &context, &repository, RunId::new(), job_id, &request,).await,
            Err(WebDataError::Corrupt)
        );
        assert_eq!(
            WebData::job_log(&data, &context, &repository, run_id, JobId::new(), &request,).await,
            Err(WebDataError::Corrupt)
        );
        let mismatched_repository = RepositoryPath {
            owner: "sibling".to_owned(),
            name: repository.name.clone(),
        };
        assert_eq!(
            WebData::job_log(
                &data,
                &context,
                &mismatched_repository,
                run_id,
                job_id,
                &request,
            )
            .await,
            Err(WebDataError::Corrupt)
        );
        let foreign_tenant =
            RequestContext::anonymous(TenantId::new("tenant-2").expect("foreign tenant"));
        assert_eq!(
            WebData::job_log(
                &data,
                &foreign_tenant,
                &repository,
                run_id,
                job_id,
                &request,
            )
            .await,
            Err(WebDataError::Corrupt)
        );
    }

    #[tokio::test]
    async fn repository_settings_require_an_authenticated_viewer_and_preserve_policy_revision() {
        let (data, anonymous, repository, _, _) = fake_live_data(true).await;
        assert!(
            WebData::repository_settings(&data, &anonymous, &repository)
                .await
                .expect("anonymous settings lookup must remain closed")
                .is_none()
        );

        let authenticated = RequestContext::new(
            TenantId::new("tenant-1").expect("tenant ID"),
            AuthorizationContext::anonymous(),
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("fixture request context");
        let settings = WebData::repository_settings(&data, &authenticated, &repository)
            .await
            .expect("settings lookup")
            .expect("authorized repository settings");
        assert_eq!(settings.repository.owner, "acme");
        assert_eq!(settings.repository.name, "payments");
        assert_eq!(settings.revision, 1);
        assert_eq!(settings.policy.dashboard(), OutputVisibility::Public);
        assert_eq!(settings.policy.logs(), OutputVisibility::Public);
        assert_eq!(settings.policy.artifacts(), OutputVisibility::Public);
        assert!(settings.editable);
        assert!(settings.repository.settings_visible);
    }

    #[tokio::test]
    async fn repository_settings_read_and_update_permissions_are_independent() {
        let authenticated = RequestContext::new(
            TenantId::new("tenant-1").expect("tenant ID"),
            AuthorizationContext::anonymous(),
            Some(Viewer {
                display_name: "Ada Lovelace".to_owned(),
            }),
            None,
        )
        .expect("fixture request context");

        let (denied, _, repository, _, _) =
            fake_live_data_with_settings_permissions(false, true).await;
        assert!(
            WebData::repository_settings(&denied, &authenticated, &repository)
                .await
                .expect("settings read denial")
                .is_none()
        );

        let (read_only, _, repository, _, _) =
            fake_live_data_with_settings_permissions(true, false).await;
        let settings = WebData::repository_settings(&read_only, &authenticated, &repository)
            .await
            .expect("settings read")
            .expect("read-authorized settings");
        assert!(settings.repository.settings_visible);
        assert!(!settings.editable);
    }

    #[test]
    fn run_cursor_is_canonical_directional_and_filter_bound() {
        let tenant = tenant();
        let repository_id = RepositoryId::from_uuid(RunId::new().as_uuid());
        let request = request();
        let position = HumanRunCursor {
            created_at: UnixMillis::new(1_725_000_000_123),
            id: RunId::new(),
        };
        let encoded = encode_run_cursor(
            &tenant,
            repository_id,
            &request,
            position,
            HumanRunPageDirection::Older,
        );
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &encoded)
                .expect("cursor")
                .len(),
            RUN_CURSOR_BYTES
        );
        let decoded =
            decode_run_cursor(&encoded, &tenant, repository_id, &request).expect("decode cursor");
        assert_eq!(decoded.position, position);
        assert_eq!(decoded.direction, HumanRunPageDirection::Older);

        let mut other_filter = request.clone();
        other_filter.status = StatusFilter::InProgress;
        assert!(decode_run_cursor(&encoded, &tenant, repository_id, &other_filter).is_none());
        assert!(
            decode_run_cursor(&format!("{encoded}="), &tenant, repository_id, &request).is_none()
        );
    }

    #[test]
    fn log_cursor_binds_every_parent_and_exact_fragment() {
        let tenant = tenant();
        let repository_id = RepositoryId::from_uuid(RunId::new().as_uuid());
        let run_id = RunId::new();
        let job_id = JobId::new();
        let stream_id = LogStreamId::new();
        let expected = DecodedLogCursor {
            sequence: LogSequence::new(41),
            line_ordinal: 3,
            direction: automata_ci_store::HumanLogSegmentPageDirection::Newer,
        };
        let encoded =
            encode_log_cursor(&tenant, repository_id, run_id, job_id, stream_id, expected);
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &encoded)
                .expect("cursor")
                .len(),
            LOG_CURSOR_BYTES
        );
        assert_eq!(
            decode_log_cursor(&encoded, &tenant, repository_id, run_id, job_id, stream_id,),
            Some(expected)
        );
        assert!(
            decode_log_cursor(
                &encoded,
                &tenant,
                repository_id,
                run_id,
                JobId::new(),
                stream_id,
            )
            .is_none()
        );
    }

    #[test]
    fn log_stream_reader_rejects_noncurrent_publication_safety_schema() {
        let run_id = RunId::new();
        let run = fixture_run(run_id, OutputVisibility::Private);
        let (_, mut stream) = fixture_job_detail(
            run,
            JobId::new(),
            AttemptId::new(),
            HumanRawLogDisposition::Persist,
            fixture_output_publication(
                OutputVisibility::Private,
                SecretExposureClass::Secretless,
                "fixture",
            ),
        );
        assert!(log_stream_safety_is_valid(&stream));
        for schema in [0, 1, 3] {
            stream.publication.safety_schema = schema;
            assert!(!log_stream_safety_is_valid(&stream));
        }
    }

    #[test]
    fn log_stream_reader_accepts_public_runner_redacted_logs() {
        let run_id = RunId::new();
        let run = fixture_run(run_id, OutputVisibility::Public);
        let (_, stream) = fixture_job_detail(
            run,
            JobId::new(),
            AttemptId::new(),
            HumanRawLogDisposition::Persist,
            fixture_output_publication(
                OutputVisibility::Public,
                SecretExposureClass::ReadableSecret,
                "repository_policy",
            ),
        );

        assert!(log_stream_safety_is_valid(&stream));
    }

    #[tokio::test]
    async fn live_job_log_decodes_verified_segments_and_omits_the_end_marker() {
        let (data, context, repository, run_id, job_id) = fake_live_data(true).await;
        let request = JobLogRequest {
            cursor: None,
            limit: 200,
            maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
        };
        let page = WebData::job_log(&data, &context, &repository, run_id, job_id, &request)
            .await
            .expect("read live log")
            .expect("authorized log page");
        assert_eq!(page.repository.scm_provider, "github");
        assert_eq!(page.job.attempt, Some(1));
        assert_eq!(page.lines.len(), 1);
        assert_eq!(page.lines[0].sequence, 0);
        assert_eq!(page.lines[0].text, "checkout ok");
        assert_eq!(page.job.status, Status::Lost);
        assert!(page.jobs[0].logs_available);
        assert!(page.jobs[1].logs_available);
        assert!(page.next_cursor.is_none());
        let live = page.live.expect("forward page live checkpoint");
        assert!(live.stream_closed);
        assert!(!live.more_available);
        let checkpoint = live.checkpoint.expect("terminal checkpoint");
        let replay = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            Some(checkpoint.clone()),
            200,
        )
        .await;
        assert!(replay.lines.is_empty());
        assert_eq!(
            replay.live.and_then(|live| live.checkpoint).as_deref(),
            Some(checkpoint.as_str())
        );
    }

    #[tokio::test]
    async fn transport_neutral_tail_authorizes_exact_scope_and_controls_replay() {
        let (data, context, repository, run_id, job_id) = fake_live_data(true).await;
        let authorized = WebData::authorize_live_log(&data, &context, &repository, run_id, job_id)
            .await
            .expect("authorize live log")
            .expect("authorized exact stream");

        let first = WebData::read_live_log(&data, &authorized.scope, None, true)
            .await
            .expect("initial durable tail")
            .expect("current stream");
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].line.text, "checkout ok");
        assert!(first.stream_closed);
        assert!(!first.more_available);
        let checkpoint = first.records[0].checkpoint.clone();

        let replay = WebData::read_live_log(&data, &authorized.scope, Some(&checkpoint), true)
            .await
            .expect("replay durable tail")
            .expect("same stream");
        assert_eq!(replay.records.len(), 1);
        assert_eq!(replay.records[0].checkpoint, checkpoint);

        let advanced = WebData::read_live_log(&data, &authorized.scope, Some(&checkpoint), false)
            .await
            .expect("advance durable tail")
            .expect("same stream");
        assert!(advanced.records.is_empty());
        assert_eq!(advanced.checkpoint, first.checkpoint);
        assert!(advanced.stream_closed);

        let (denied, denied_context, denied_repository, denied_run, denied_job) =
            fake_live_data(false).await;
        assert!(
            WebData::authorize_live_log(
                &denied,
                &denied_context,
                &denied_repository,
                denied_run,
                denied_job,
            )
            .await
            .expect("closed authorization decision")
            .is_none()
        );
    }

    #[tokio::test]
    async fn split_log_segment_pages_round_trip_at_exact_line_boundaries() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Public,
            log_visibility: OutputVisibility::Public,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: true,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let mut payload = String::new();
        for index in 0..5 {
            writeln!(payload, "line {index}").expect("writing to a String cannot fail");
        }
        let payload = payload.into_bytes();
        let (data, context, repository, run_id, job_id, _) =
            fake_live_data_with_policy_and_payload(policy, Some(payload)).await;
        let first = read_log_page(&data, &context, &repository, run_id, job_id, None, 2).await;
        assert_log_texts(&first, &["line 0", "line 1"]);
        assert!(first.previous_cursor.is_none());
        let first_live = first.live.as_ref().expect("first forward checkpoint");
        assert!(first_live.stream_closed);
        assert!(first_live.more_available);
        let first_next = first.next_cursor.expect("second-page cursor");

        let second = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            Some(first_next.clone()),
            2,
        )
        .await;
        assert_log_texts(&second, &["line 2", "line 3"]);
        let second_previous = second.previous_cursor.expect("first-page cursor");
        let second_next = second.next_cursor.expect("third-page cursor");

        let third = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            Some(second_next.clone()),
            2,
        )
        .await;
        assert_log_texts(&third, &["line 4"]);
        assert!(third.next_cursor.is_none());
        let third_live = third.live.as_ref().expect("terminal forward checkpoint");
        assert!(third_live.stream_closed);
        assert!(!third_live.more_available);

        let back_to_second = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            third.previous_cursor,
            2,
        )
        .await;
        assert_log_texts(&back_to_second, &["line 2", "line 3"]);
        assert!(back_to_second.live.is_none());
        assert_eq!(
            back_to_second.next_cursor.as_deref(),
            Some(second_next.as_str())
        );
        let back_to_first = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            back_to_second.previous_cursor,
            2,
        )
        .await;
        assert_log_texts(&back_to_first, &["line 0", "line 1"]);
        assert!(back_to_first.live.is_none());
        assert!(back_to_first.previous_cursor.is_none());
        assert_eq!(
            back_to_first.next_cursor.as_deref(),
            Some(first_next.as_str())
        );

        let direct_back_to_first = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            Some(second_previous),
            2,
        )
        .await;
        assert_eq!(direct_back_to_first.lines, back_to_first.lines);
    }

    #[tokio::test]
    async fn forward_log_checkpoint_replays_its_record_and_then_advances() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Public,
            log_visibility: OutputVisibility::Public,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: true,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let (data, context, repository, run_id, job_id, _) =
            fake_live_data_with_policy_and_payload(policy, Some(b"zero\none\ntwo\n".to_vec()))
                .await;
        let first = read_log_page(&data, &context, &repository, run_id, job_id, None, 2).await;
        let checkpoint = first
            .live
            .and_then(|live| live.checkpoint)
            .expect("first forward checkpoint");

        let replay = read_log_page(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            Some(checkpoint.clone()),
            2,
        )
        .await;

        assert_log_texts(&replay, &["one", "two"]);
        assert_ne!(
            replay.live.and_then(|live| live.checkpoint).as_deref(),
            Some(checkpoint.as_str())
        );
    }

    #[tokio::test]
    async fn forged_canonical_log_positions_are_non_enumerating() {
        let policy = FakeLivePolicy {
            dashboard_visibility: OutputVisibility::Public,
            log_visibility: OutputVisibility::Public,
            log_exposure: SecretExposureClass::Secretless,
            raw_log_disposition: HumanRawLogDisposition::Persist,
            allow_dashboard: true,
            allow_logs: true,
            allow_settings_read: false,
            allow_settings_update: false,
        };
        let (data, context, repository, run_id, job_id, _) =
            fake_live_data_with_policy_and_payload(policy, Some(b"one\ntwo\n".to_vec())).await;
        let first = WebData::job_log(
            &data,
            &context,
            &repository,
            run_id,
            job_id,
            &JobLogRequest {
                cursor: None,
                limit: 1,
                maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
            },
        )
        .await
        .expect("first log page")
        .expect("authorized first page");
        let cursor = first.next_cursor.expect("end-marker cursor");
        let cursor_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &cursor)
                .expect("decode cursor");

        for (range, replacement) in [
            (83..91, 99_u64.to_be_bytes().to_vec()),
            (91..95, u32::MAX.to_be_bytes().to_vec()),
        ] {
            let mut forged = cursor_bytes.clone();
            forged[range].copy_from_slice(&replacement);
            let forged =
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, forged);
            let result = WebData::job_log(
                &data,
                &context,
                &repository,
                run_id,
                job_id,
                &JobLogRequest {
                    cursor: Some(forged),
                    limit: 1,
                    maximum_decoded_bytes: super::super::data::LOG_PAGE_DECODED_BYTES,
                },
            )
            .await
            .expect("forged positions are hidden");
            assert!(result.is_none());
        }
    }

    #[test]
    fn branch_filters_are_normalized_without_rewriting_canonical_refs() {
        assert_eq!(
            normalize_git_ref("main").map(|value| value.as_str().to_owned()),
            Some("refs/heads/main".to_owned())
        );
        assert_eq!(
            normalize_git_ref("refs/tags/v1").map(|value| value.as_str().to_owned()),
            Some("refs/tags/v1".to_owned())
        );
        assert!(normalize_git_ref("").is_none());
    }

    #[test]
    fn log_frames_split_on_lines_and_utf8_boundaries_with_stable_ordinals() {
        let frame = LogFrame::new(
            LogStreamId::new(),
            AttemptId::new(),
            LogSequence::new(7),
            UnixMillis::new(10),
            CoreLogChannel::Stdout,
            b"first\n\nlast\n".to_vec(),
            false,
        )
        .expect("frame");
        let lines = render_frame_lines(&frame).expect("lines");
        assert_eq!(
            lines
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["first", "", "last"]
        );
        assert_eq!(
            lines.iter().map(|line| line.ordinal).collect::<Vec<_>>(),
            [0, 1, 2]
        );

        let oversized = "é".repeat(super::super::data::LOG_LINE_BYTES / 2 + 1);
        let frame = LogFrame::new(
            LogStreamId::new(),
            AttemptId::new(),
            LogSequence::new(8),
            UnixMillis::new(11),
            CoreLogChannel::Stderr,
            oversized.into_bytes(),
            false,
        )
        .expect("frame");
        let lines = render_frame_lines(&frame).expect("split lines");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text.len(), super::super::data::LOG_LINE_BYTES);
        assert_eq!(lines[1].text, "é");
    }

    #[test]
    fn log_rendering_exposes_controls_and_bidi_formatting_as_plain_text() {
        let frame = LogFrame::new(
            LogStreamId::new(),
            AttemptId::new(),
            LogSequence::new(9),
            UnixMillis::new(12),
            CoreLogChannel::Stdout,
            "safe\t\u{001b}[31m\u{202e}copy\r\n".as_bytes().to_vec(),
            false,
        )
        .expect("frame");
        let lines = render_frame_lines(&frame).expect("sanitized lines");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "safe\t\\u{001B}[31m\\u{202E}copy");
        assert!(
            lines[0]
                .text
                .chars()
                .all(|character| character == '\t' || !must_escape_log_character(character))
        );
    }

    #[test]
    fn pure_end_marker_is_not_rendered() {
        let frame = LogFrame::new(
            LogStreamId::new(),
            AttemptId::new(),
            LogSequence::new(9),
            UnixMillis::new(12),
            CoreLogChannel::System,
            Vec::new(),
            true,
        )
        .expect("end frame");
        assert!(render_frame_lines(&frame).expect("lines").is_empty());
    }

    #[test]
    fn status_mapping_preserves_lost_and_rejects_navigation_contradictions() {
        assert_eq!(lifecycle_status(JobLifecycle::Lost), Status::Lost);
        assert_eq!(
            conclusion_status(HumanRunConclusion::TimedOut),
            Status::TimedOut
        );
        let navigation = HumanJobNavigation {
            id: JobId::new(),
            display_name: "build".to_owned(),
            lifecycle: Some(JobLifecycle::Succeeded),
            conclusion: Some(HumanRunConclusion::Failure),
            log_publication: None,
        };
        assert_eq!(
            map_navigation(&navigation, false),
            Err(WebDataError::Corrupt)
        );
    }

    #[test]
    fn contributor_controlled_projection_copy_cannot_spoof_or_break_the_ui() {
        let run = HumanRun {
            id: RunId::new(),
            workflow_id: WorkflowId::new(),
            workflow_path: ".ci/workflows/ci.yml".to_owned(),
            run_number: 1,
            run_attempt: 1,
            event_name: "\u{202e}".to_owned(),
            head_commit: HumanGitCommitId::new(vec![7; 20]).expect("commit ID"),
            status: WorkflowRunStatus::Completed,
            conclusion: Some(HumanRunConclusion::Success),
            workflow_name: "\u{200b}".to_owned(),
            git_ref: Some("\u{202e}".to_owned()),
            actor: Some("\u{202e}octocat".to_owned()),
            display_title: Some(" \u{200b}".to_owned()),
            commit_subject: Some("spoof\u{202e}".to_owned()),
            created_at: UnixMillis::new(1),
            updated_at: UnixMillis::new(2),
            finished_at: Some(UnixMillis::new(2)),
            publication: HumanRunPublication {
                policy_revision: 1,
                requested_dashboard_visibility: OutputVisibility::Public,
                effective_dashboard_visibility: OutputVisibility::Public,
                requested_log_visibility: OutputVisibility::Public,
                requested_artifact_visibility: OutputVisibility::Public,
                safety_reason: "secretless".to_owned(),
                safety_schema: 2,
            },
        };
        let mapped = map_run(&run).expect("unsafe optional copy is omitted");
        assert_eq!(mapped.workflow.name, run.workflow_path);
        assert_eq!(mapped.event, "unknown");
        assert!(mapped.title.is_none());
        assert!(mapped.git_ref.is_none());
        assert!(mapped.actor.is_none());
        assert!(mapped.commit_subject.is_none());

        let job_id = JobId::new();
        let job = HumanJob {
            id: job_id,
            key: "build".to_owned(),
            display_name: "\u{200b}".to_owned(),
            created_at: UnixMillis::new(1),
            job_ir: fixture_job_ir(job_id, run.id),
            latest_attempt: None,
            log_publication: None,
        };
        assert_eq!(
            map_job(&job, false)
                .expect("unsafe job copy uses a neutral fallback")
                .name,
            "Workflow job"
        );
    }

    mod artifact_authorization {
        use std::{
            collections::BTreeSet,
            sync::{Arc, Mutex},
        };

        use automata_ci_auth::{
            authorization::{
                AuthorizationContext, OutputVisibility, Permission, RepositoryPublicationPolicy,
                SecretExposureClass, repository_read_permissions,
            },
            human::{PrincipalId, TenantId},
        };
        use automata_ci_blob::{
            BlobKey, BlobPayload, ImmutableBlobStore, MediaType, MemoryBlobStore,
        };
        use automata_ci_core::{AttemptId, JobId, RunId, Sha256Digest};
        use automata_ci_results_github::{
            ARTIFACT_MANIFEST_MEDIA_TYPE, ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactManifest,
        };
        use automata_ci_store::{
            self as store, HumanArtifactId, HumanAuthorizationTarget, HumanWorkflowReadRepository,
            RepositoryCoordinate, RepositoryId, StoreError, TenantScope,
        };
        use bytes::Bytes;
        use sha2::{Digest as _, Sha256};

        use super::{fixture_repository, fixture_run};
        use crate::app::web::{
            data::{
                RepositoryPath, RequestContext, RunDetailRequest, Viewer, WebData, WebDataError,
            },
            live::{LiveWebData, MAX_RENDERED_JOBS, block_list_digest, validate_manifest},
        };

        #[derive(Debug)]
        struct ArtifactReads {
            repository: store::HumanRepository,
            expected_run_id: RunId,
            expected_artifact_id: HumanArtifactId,
            run: Mutex<Option<store::HumanRunDetail>>,
            artifact: Mutex<Option<store::HumanArtifactDownload>>,
            explicit_permissions: BTreeSet<&'static str>,
            authorization_calls: Mutex<Vec<HumanAuthorizationTarget>>,
            run_scopes: Mutex<Vec<store::HumanRunScope>>,
            artifact_scopes: Mutex<Vec<store::HumanArtifactScope>>,
        }

        #[async_trait::async_trait]
        impl HumanWorkflowReadRepository for ArtifactReads {
            async fn resolve_repository(
                &self,
                tenant: &TenantScope,
                coordinate: &RepositoryCoordinate,
            ) -> Result<Option<store::HumanRepository>, StoreError> {
                if tenant.as_str() != self.repository.resource.tenant_id().as_str()
                    || coordinate.provider() != self.repository.scm_provider
                    || coordinate.owner() != self.repository.owner
                    || coordinate.name() != self.repository.name
                {
                    return Ok(None);
                }
                Ok(Some(self.repository.clone()))
            }

            async fn list_repositories(
                &self,
                _query: &store::HumanRepositoryListQuery,
                _context: &AuthorizationContext,
                _permissions: &[Permission],
            ) -> Result<store::HumanRepositoryPage, StoreError> {
                unimplemented!("not used by artifact authorization tests")
            }

            async fn list_workflows(
                &self,
                _query: &store::HumanWorkflowListQuery,
                _context: &AuthorizationContext,
                _permission: &Permission,
            ) -> Result<Option<store::HumanWorkflowPage>, StoreError> {
                unimplemented!("not used by artifact authorization tests")
            }

            async fn list_runs(
                &self,
                _query: &store::HumanRunListQuery,
                _context: &AuthorizationContext,
                _permission: &Permission,
            ) -> Result<Option<store::HumanRunPage>, StoreError> {
                unimplemented!("not used by artifact authorization tests")
            }

            async fn get_run(
                &self,
                scope: &store::HumanRunScope,
            ) -> Result<Option<store::HumanRunDetail>, StoreError> {
                self.run_scopes
                    .lock()
                    .expect("run-scope observations")
                    .push(scope.clone());
                if scope.tenant.as_str() != self.repository.resource.tenant_id().as_str()
                    || scope.repository_id != self.repository.id
                    || scope.run_id != self.expected_run_id
                {
                    return Ok(None);
                }
                Ok(self.run.lock().expect("artifact run fixture").clone())
            }

            async fn get_job(
                &self,
                _scope: &store::HumanJobScope,
            ) -> Result<Option<store::HumanJobDetail>, StoreError> {
                unimplemented!("not used by artifact authorization tests")
            }

            async fn list_log_segments(
                &self,
                _query: &store::HumanLogSegmentQuery,
            ) -> Result<Option<store::HumanLogSegmentPage>, StoreError> {
                unimplemented!("not used by artifact authorization tests")
            }

            async fn get_artifact(
                &self,
                scope: &store::HumanArtifactScope,
            ) -> Result<Option<store::HumanArtifactDownload>, StoreError> {
                self.artifact_scopes
                    .lock()
                    .expect("artifact-scope observations")
                    .push(scope.clone());
                if scope.tenant.as_str() != self.repository.resource.tenant_id().as_str()
                    || scope.repository_id != self.repository.id
                    || scope.run_id != self.expected_run_id
                    || scope.artifact_id != self.expected_artifact_id
                {
                    return Ok(None);
                }
                Ok(self
                    .artifact
                    .lock()
                    .expect("artifact download fixture")
                    .clone())
            }

            async fn is_repository_request_allowed(
                &self,
                tenant: &TenantScope,
                repository_id: RepositoryId,
                context: &AuthorizationContext,
                target: &HumanAuthorizationTarget,
            ) -> Result<bool, StoreError> {
                self.authorization_calls
                    .lock()
                    .expect("authorization observations")
                    .push(target.clone());
                let exact_scope = target
                    .request
                    .scope()
                    .repository_resource()
                    .is_some_and(|resource| resource == &self.repository.resource);
                if tenant.as_str() != self.repository.resource.tenant_id().as_str()
                    || repository_id != self.repository.id
                    || !exact_scope
                    || context
                        .tenant_id()
                        .is_some_and(|tenant_id| tenant_id != self.repository.resource.tenant_id())
                {
                    return Ok(false);
                }
                let permission = target.request.permission().as_str();
                if context.principal_id().is_some()
                    && self.explicit_permissions.contains(permission)
                {
                    return Ok(true);
                }
                if target.request.secret_exposure() == SecretExposureClass::ReadableSecret {
                    return Ok(false);
                }
                Ok(match target.durable_visibility {
                    Some(OutputVisibility::Public) => true,
                    Some(OutputVisibility::Authenticated) => context.principal_id().is_some(),
                    Some(OutputVisibility::Private) | None => false,
                })
            }
        }

        struct ArtifactFixture {
            data: LiveWebData,
            reads: Arc<ArtifactReads>,
            anonymous: RequestContext,
            authenticated: RequestContext,
            repository: RepositoryPath,
            run_id: RunId,
            artifact_id: HumanArtifactId,
        }

        async fn stored_artifact_fixture(
            run_id: RunId,
            artifact_id: HumanArtifactId,
            artifact_visibility: OutputVisibility,
            exposure: SecretExposureClass,
            manifest_schema: u16,
        ) -> (
            store::HumanArtifactSummary,
            store::HumanArtifactDownload,
            Arc<MemoryBlobStore>,
            ArtifactManifest,
        ) {
            let content_digest = Sha256Digest::from_bytes(Sha256::digest([]).into());
            let artifact = store::HumanArtifactSummary {
                id: artifact_id,
                name: "release.tar.zst".to_owned(),
                mime_type: "application/zstd".to_owned(),
                content_size: 0,
                content_digest,
                expires_at_seconds: None,
                finalized_at_seconds: 2_000,
                publication: store::HumanOutputPublication {
                    secret_exposure: exposure,
                    requested_visibility: artifact_visibility,
                    effective_visibility: artifact_visibility,
                    safety_reason: "fixture".to_owned(),
                    safety_schema: 2,
                },
            };
            let manifest = ArtifactManifest {
                schema: manifest_schema,
                artifact_id: artifact_id.get(),
                upload_id: RunId::new().to_string(),
                run_id: run_id.to_string(),
                job_id: JobId::new().to_string(),
                attempt_id: AttemptId::new().to_string(),
                fencing_token: 1,
                name: artifact.name.clone(),
                mime_type: artifact.mime_type.clone(),
                size: artifact.content_size,
                sha256: artifact.content_digest.to_string(),
                blocks: Vec::new(),
            };
            let manifest_payload = BlobPayload::from_bytes(
                BlobKey::new("artifacts/tests/release.manifest.json").expect("manifest key"),
                MediaType::new(ARTIFACT_MANIFEST_MEDIA_TYPE).expect("manifest media type"),
                Bytes::from(serde_json::to_vec(&manifest).expect("manifest JSON")),
            );
            let manifest_descriptor = manifest_payload.descriptor().clone();
            let objects = Arc::new(MemoryBlobStore::default());
            objects
                .put_if_absent(manifest_payload)
                .await
                .expect("store manifest");
            let stored = store::HumanArtifactDownload {
                artifact: artifact.clone(),
                manifest: manifest_descriptor,
                block_list_digest: block_list_digest(&[]),
                committed_at_seconds: 2_000,
                blocks: Vec::new(),
            };
            (artifact, stored, objects, manifest)
        }

        async fn artifact_fixture(
            dashboard_visibility: OutputVisibility,
            artifact_visibility: OutputVisibility,
            exposure: SecretExposureClass,
            explicit_permissions: &[&'static str],
        ) -> ArtifactFixture {
            let tenant_id = TenantId::new("tenant-1").expect("tenant ID");
            let repository_id = RepositoryId::from_uuid(RunId::new().as_uuid());
            let mut repository = fixture_repository(&tenant_id, repository_id);
            repository.publication = RepositoryPublicationPolicy::new(
                dashboard_visibility,
                OutputVisibility::Private,
                artifact_visibility,
            );
            let run_id = RunId::new();
            let mut run = fixture_run(run_id, dashboard_visibility);
            run.publication.requested_dashboard_visibility = dashboard_visibility;
            run.publication.effective_dashboard_visibility = dashboard_visibility;
            run.publication.requested_artifact_visibility = artifact_visibility;

            let artifact_id = HumanArtifactId::new(7).expect("artifact ID");
            let (artifact, stored, objects, _) = stored_artifact_fixture(
                run_id,
                artifact_id,
                artifact_visibility,
                exposure,
                ARTIFACT_MANIFEST_SCHEMA_VERSION,
            )
            .await;
            let reads = Arc::new(ArtifactReads {
                repository,
                expected_run_id: run_id,
                expected_artifact_id: artifact_id,
                run: Mutex::new(Some(store::HumanRunDetail {
                    run,
                    jobs: Vec::new(),
                    artifacts: vec![artifact],
                })),
                artifact: Mutex::new(Some(stored)),
                explicit_permissions: explicit_permissions.iter().copied().collect(),
                authorization_calls: Mutex::new(Vec::new()),
                run_scopes: Mutex::new(Vec::new()),
                artifact_scopes: Mutex::new(Vec::new()),
            });
            let read_port: Arc<dyn HumanWorkflowReadRepository> = reads.clone();
            let object_port: Arc<dyn ImmutableBlobStore> = objects;
            let authorization = AuthorizationContext::authenticated(
                tenant_id.clone(),
                PrincipalId::new("principal-1").expect("principal ID"),
                BTreeSet::new(),
            )
            .expect("authenticated context");
            ArtifactFixture {
                data: LiveWebData::new(read_port, object_port),
                reads,
                anonymous: RequestContext::anonymous(tenant_id.clone()),
                authenticated: RequestContext::new(
                    tenant_id,
                    authorization,
                    Some(Viewer {
                        display_name: "Ada Lovelace".to_owned(),
                    }),
                    None,
                )
                .expect("authenticated request context"),
                repository: RepositoryPath {
                    owner: "acme".to_owned(),
                    name: "payments".to_owned(),
                },
                run_id,
                artifact_id,
            }
        }

        async fn artifact_is_available(
            fixture: &ArtifactFixture,
            context: &RequestContext,
        ) -> Result<bool, WebDataError> {
            WebData::artifact(
                &fixture.data,
                context,
                &fixture.repository,
                fixture.run_id,
                fixture.artifact_id.get(),
            )
            .await
            .map(|artifact| artifact.is_some())
        }

        #[tokio::test]
        async fn artifact_download_reader_rejects_noncurrent_manifest_schema() {
            let run_id = RunId::new();
            let artifact_id = HumanArtifactId::new(7).expect("artifact ID");
            for schema in [
                0,
                ARTIFACT_MANIFEST_SCHEMA_VERSION
                    .checked_add(1)
                    .expect("forward manifest schema"),
            ] {
                let (_, stored, _, manifest) = stored_artifact_fixture(
                    run_id,
                    artifact_id,
                    OutputVisibility::Private,
                    SecretExposureClass::Secretless,
                    schema,
                )
                .await;
                let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
                assert_eq!(
                    validate_manifest(&stored, run_id, &bytes),
                    Err(WebDataError::Corrupt)
                );
            }
        }

        #[tokio::test]
        async fn run_detail_reuses_identical_immutable_artifact_authorization() {
            let fixture = artifact_fixture(
                OutputVisibility::Private,
                OutputVisibility::Private,
                SecretExposureClass::Secretless,
                &[
                    repository_read_permissions::REPOSITORY_READ,
                    repository_read_permissions::WORKFLOW_READ,
                    repository_read_permissions::RUN_READ,
                    repository_read_permissions::JOB_READ,
                    repository_read_permissions::ARTIFACT_READ,
                    repository_read_permissions::ARTIFACT_DOWNLOAD,
                ],
            )
            .await;
            {
                let mut run = fixture.reads.run.lock().expect("artifact run fixture");
                let detail = run.as_mut().expect("run detail fixture");
                let mut second = detail.artifacts[0].clone();
                second.id = HumanArtifactId::new(8).expect("second artifact ID");
                detail.artifacts.push(second);
            }

            let detail = WebData::run_detail(
                &fixture.data,
                &fixture.authenticated,
                &fixture.repository,
                fixture.run_id,
                &RunDetailRequest {
                    job_cursor: None,
                    limit: MAX_RENDERED_JOBS,
                },
            )
            .await
            .expect("run detail read")
            .expect("authorized run detail");
            assert_eq!(detail.artifacts.items.len(), 2);

            let artifact_permissions = fixture
                .reads
                .authorization_calls
                .lock()
                .expect("authorization observations")
                .iter()
                .map(|target| target.request.permission().as_str())
                .filter(|permission| {
                    matches!(
                        *permission,
                        repository_read_permissions::ARTIFACT_READ
                            | repository_read_permissions::ARTIFACT_DOWNLOAD
                    )
                })
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(
                artifact_permissions,
                vec![
                    repository_read_permissions::ARTIFACT_READ.to_owned(),
                    repository_read_permissions::ARTIFACT_DOWNLOAD.to_owned(),
                ]
            );
        }

        #[tokio::test]
        async fn public_artifact_direct_download_is_independent_from_private_dashboard() {
            let fixture = artifact_fixture(
                OutputVisibility::Private,
                OutputVisibility::Public,
                SecretExposureClass::Secretless,
                &[],
            )
            .await;
            let download = WebData::artifact(
                &fixture.data,
                &fixture.anonymous,
                &fixture.repository,
                fixture.run_id,
                fixture.artifact_id.get(),
            )
            .await
            .expect("public artifact lookup")
            .expect("public artifact download");
            assert_eq!(download.file_name, "release.tar.zst");
            assert_eq!(download.media_type, "application/zstd");
            assert_eq!(download.size, 0);

            let calls = fixture
                .reads
                .authorization_calls
                .lock()
                .expect("authorization observations");
            assert_eq!(calls.len(), 2);
            assert_eq!(
                calls
                    .iter()
                    .map(|target| target.request.permission().as_str())
                    .collect::<Vec<_>>(),
                [
                    repository_read_permissions::ARTIFACT_READ,
                    repository_read_permissions::ARTIFACT_DOWNLOAD,
                ]
            );
            assert!(calls.iter().all(|target| {
                target.durable_visibility == Some(OutputVisibility::Public)
                    && target.request.secret_exposure() == SecretExposureClass::Secretless
                    && target
                        .request
                        .scope()
                        .repository_resource()
                        .is_some_and(|resource| resource == &fixture.reads.repository.resource)
            }));
        }

        #[tokio::test]
        async fn authenticated_and_private_artifact_audiences_require_exact_authority() {
            let authenticated = artifact_fixture(
                OutputVisibility::Private,
                OutputVisibility::Authenticated,
                SecretExposureClass::CapabilityOnly,
                &[],
            )
            .await;
            assert!(
                !artifact_is_available(&authenticated, &authenticated.anonymous)
                    .await
                    .expect("anonymous authenticated-audience denial")
            );
            let authenticated = artifact_fixture(
                OutputVisibility::Private,
                OutputVisibility::Authenticated,
                SecretExposureClass::CapabilityOnly,
                &[],
            )
            .await;
            assert!(
                artifact_is_available(&authenticated, &authenticated.authenticated)
                    .await
                    .expect("authenticated-audience access")
            );

            for permissions in [
                &[][..],
                &[repository_read_permissions::ARTIFACT_READ][..],
                &[repository_read_permissions::ARTIFACT_DOWNLOAD][..],
            ] {
                let private = artifact_fixture(
                    OutputVisibility::Public,
                    OutputVisibility::Private,
                    SecretExposureClass::ReadableSecret,
                    permissions,
                )
                .await;
                assert!(
                    !artifact_is_available(&private, &private.authenticated)
                        .await
                        .expect("incomplete private artifact authority")
                );
            }
            let private = artifact_fixture(
                OutputVisibility::Public,
                OutputVisibility::Private,
                SecretExposureClass::ReadableSecret,
                &[
                    repository_read_permissions::ARTIFACT_READ,
                    repository_read_permissions::ARTIFACT_DOWNLOAD,
                ],
            )
            .await;
            assert!(
                !artifact_is_available(&private, &private.anonymous)
                    .await
                    .expect("anonymous private artifact denial")
            );
            assert!(
                artifact_is_available(&private, &private.authenticated)
                    .await
                    .expect("complete private artifact authority")
            );
        }

        #[tokio::test]
        async fn artifact_secret_exposure_is_part_of_immutable_authority() {
            let secret_bearing = artifact_fixture(
                OutputVisibility::Public,
                OutputVisibility::Public,
                SecretExposureClass::ReadableSecret,
                &[],
            )
            .await;
            assert!(
                !artifact_is_available(&secret_bearing, &secret_bearing.anonymous)
                    .await
                    .expect("secret-bearing public denial")
            );
            {
                let calls = secret_bearing
                    .reads
                    .authorization_calls
                    .lock()
                    .expect("authorization observations");
                assert_eq!(calls.len(), 1);
                assert_eq!(
                    calls[0].request.secret_exposure(),
                    SecretExposureClass::ReadableSecret
                );
            }
        }

        #[tokio::test]
        async fn artifact_parent_scopes_fail_closed_without_authorization() {
            let missing_run = artifact_fixture(
                OutputVisibility::Public,
                OutputVisibility::Public,
                SecretExposureClass::Secretless,
                &[],
            )
            .await;
            assert!(
                WebData::artifact(
                    &missing_run.data,
                    &missing_run.anonymous,
                    &missing_run.repository,
                    RunId::new(),
                    missing_run.artifact_id.get(),
                )
                .await
                .expect("cross-run artifact denial")
                .is_none()
            );
            assert!(
                missing_run
                    .reads
                    .artifact_scopes
                    .lock()
                    .expect("artifact scopes")
                    .is_empty()
            );
            assert!(
                missing_run
                    .reads
                    .authorization_calls
                    .lock()
                    .expect("authorization observations")
                    .is_empty()
            );

            let missing_artifact = artifact_fixture(
                OutputVisibility::Public,
                OutputVisibility::Public,
                SecretExposureClass::Secretless,
                &[],
            )
            .await;
            let other_artifact_id = missing_artifact.artifact_id.get() + 1;
            assert!(
                WebData::artifact(
                    &missing_artifact.data,
                    &missing_artifact.anonymous,
                    &missing_artifact.repository,
                    missing_artifact.run_id,
                    other_artifact_id,
                )
                .await
                .expect("cross-artifact denial")
                .is_none()
            );
            {
                let artifact_scopes = missing_artifact
                    .reads
                    .artifact_scopes
                    .lock()
                    .expect("artifact scopes");
                assert_eq!(artifact_scopes.len(), 1);
                assert_eq!(artifact_scopes[0].run_id, missing_artifact.run_id);
                assert_eq!(artifact_scopes[0].artifact_id.get(), other_artifact_id);
                assert!(artifact_scopes[0].observed_at_seconds > 0);
            }
            assert!(
                missing_artifact
                    .reads
                    .authorization_calls
                    .lock()
                    .expect("authorization observations")
                    .is_empty()
            );
        }

        #[tokio::test]
        async fn artifact_run_identity_mismatch_is_corrupt_before_authorization() {
            let corrupt_run = artifact_fixture(
                OutputVisibility::Public,
                OutputVisibility::Public,
                SecretExposureClass::Secretless,
                &[],
            )
            .await;
            corrupt_run
                .reads
                .run
                .lock()
                .expect("run fixture")
                .as_mut()
                .expect("run")
                .run
                .id = RunId::new();
            assert!(matches!(
                WebData::artifact(
                    &corrupt_run.data,
                    &corrupt_run.anonymous,
                    &corrupt_run.repository,
                    corrupt_run.run_id,
                    corrupt_run.artifact_id.get(),
                )
                .await,
                Err(WebDataError::Corrupt)
            ));
            assert!(
                corrupt_run
                    .reads
                    .artifact_scopes
                    .lock()
                    .expect("artifact scopes")
                    .is_empty()
            );
        }
    }

    #[test]
    fn manifest_uuid_shape_is_lowercase_non_nil_and_hyphenated() {
        let id = RunId::new().to_string();
        assert!(valid_canonical_uuid(&id));
        assert!(!valid_canonical_uuid(&id.to_uppercase()));
        assert!(!valid_canonical_uuid(
            "00000000-0000-0000-0000-000000000000"
        ));
    }
}
