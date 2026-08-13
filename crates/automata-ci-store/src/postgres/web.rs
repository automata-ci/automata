use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use automata_ci_auth::{
    authorization::{
        AuthorizationContext, AuthorizationRequest, AuthorizationScope,
        CompositeAuthorizationPolicy, OutputVisibility, Permission, RbacPolicy,
        RepositoryPublicationPolicy, RepositoryResource, RepositoryResourceId, RoleName,
        ScopedRoleGrant, SecretExposureClass, repository_read_permissions,
    },
    human::TenantId,
};
use automata_ci_core::{
    AttemptId, AttemptNumber, JobConclusion, JobId, JobIrVersion, JobLifecycle, LogSequence,
    LogStreamId, RunId, RunnerId, Sha256Digest, UnixMillis, WorkflowId,
};
use sqlx::{PgConnection, Postgres, Row as _, Transaction, postgres::PgRow};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    DocumentSchema, HUMAN_JOB_RESULT_MEDIA_TYPE, HUMAN_LOG_SEGMENT_MEDIA_TYPE, HumanArtifactBlock,
    HumanArtifactDownload, HumanArtifactId, HumanArtifactScope, HumanArtifactSummary,
    HumanAuthorizationTarget, HumanGitCommitId, HumanJob, HumanJobAttempt, HumanJobDetail,
    HumanJobNavigation, HumanJobScope, HumanLogSegment, HumanLogSegmentCursor, HumanLogSegmentPage,
    HumanLogSegmentPageDirection, HumanLogSegmentQuery, HumanLogStream, HumanOutputPublication,
    HumanRawLogDisposition, HumanRepository, HumanRepositoryCursor, HumanRepositoryListQuery,
    HumanRepositoryPage, HumanRun, HumanRunConclusion, HumanRunCursor, HumanRunDetail,
    HumanRunListQuery, HumanRunPage, HumanRunPageDirection, HumanRunPublication, HumanRunScope,
    HumanRunStatusFilter, HumanRunner, HumanTerminalResult, HumanWorkflow, HumanWorkflowCursor,
    HumanWorkflowListQuery, HumanWorkflowPage, HumanWorkflowProjectedName,
    HumanWorkflowReadRepository, JobIrMetadata, RepositoryCoordinate, RepositoryId, StoreError,
    TenantScope, WorkflowRunStatus, web::blob_descriptor,
};

use super::PostgresStore;

const MAX_RUN_DETAIL_JOBS: usize = 4_096;
const MAX_RUN_DETAIL_ARTIFACTS: usize = 500;
const MAX_ARTIFACT_BLOCKS: usize = 2_048;
const MAX_REPOSITORY_RBAC_ROLE_NAMES: usize = 4_096;
const MAX_REPOSITORY_RBAC_ROWS: usize = MAX_REPOSITORY_RBAC_ROLE_NAMES;
const MAX_REPOSITORY_DISCOVERY_SCOPES: usize = 4_096;
const MAX_REPOSITORY_DISCOVERY_PERMISSIONS: usize = 2;
const SECRET_METADATA_READ_PERMISSION: &str = "secrets:metadata:read";

#[async_trait]
impl HumanWorkflowReadRepository for PostgresStore {
    async fn resolve_repository(
        &self,
        tenant: &TenantScope,
        coordinate: &RepositoryCoordinate,
    ) -> Result<Option<HumanRepository>, StoreError> {
        let row = sqlx::query(
            r"
            SELECT repository.id, repository.tenant_id,
                   repository.scm_provider, repository.provider_repository_id,
                   repository.owner, repository.name,
                   policy.dashboard_audience, policy.log_audience,
                   policy.artifact_audience, policy.revision AS publication_revision
            FROM repositories AS repository
            LEFT JOIN repository_publication_policies AS policy
              ON policy.tenant_id = repository.tenant_id
             AND policy.repository_id = repository.id
            WHERE repository.tenant_id = $1
              AND repository.scm_provider = $2
              AND lower(repository.owner) = lower($3)
              AND lower(repository.name) = lower($4)
            ",
        )
        .bind(tenant.as_str())
        .bind(coordinate.provider())
        .bind(coordinate.owner())
        .bind(coordinate.name())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;

        row.as_ref().map(decode_repository).transpose()
    }

    async fn list_repositories(
        &self,
        query: &HumanRepositoryListQuery,
        context: &AuthorizationContext,
        permissions: &[Permission],
    ) -> Result<HumanRepositoryPage, StoreError> {
        list_authorized_repositories(self, query, context, permissions).await
    }

    async fn list_workflows(
        &self,
        query: &HumanWorkflowListQuery,
        context: &AuthorizationContext,
        permission: &Permission,
    ) -> Result<Option<HumanWorkflowPage>, StoreError> {
        if permission.as_str() != repository_read_permissions::WORKFLOW_READ {
            return Ok(None);
        }
        let mut transaction = begin_read(self).await?;
        let authorization = load_repository_authorization(
            &mut transaction,
            &query.tenant,
            query.repository_id,
            context,
            permission,
        )
        .await?;
        let Some(authorization) = authorization else {
            return Ok(None);
        };
        if !authorization.allows(context, permission, None) {
            return Ok(None);
        }
        let limit = i64::from(query.limit.get()) + 1;
        let rows = if let Some(cursor) = &query.cursor {
            sqlx::query(WORKFLOWS_AFTER_SQL)
                .bind(query.tenant.as_str())
                .bind(query.repository_id.as_uuid())
                .bind(&cursor.path)
                .bind(cursor.id.as_uuid())
                .bind(limit)
                .fetch_all(&mut *transaction)
                .await
                .map_err(operation_error)?
        } else {
            sqlx::query(WORKFLOWS_FIRST_SQL)
                .bind(query.tenant.as_str())
                .bind(query.repository_id.as_uuid())
                .bind(limit)
                .fetch_all(&mut *transaction)
                .await
                .map_err(operation_error)?
        };
        transaction.commit().await.map_err(operation_error)?;

        let has_more = rows.len() > usize::from(query.limit.get());
        let mut workflows = rows
            .iter()
            .take(usize::from(query.limit.get()))
            .map(decode_workflow)
            .collect::<Result<Vec<_>, _>>()?;
        for workflow in &mut workflows {
            if let Some(projected_name) = &workflow.projected_name
                && !authorization.allows(
                    context,
                    permission,
                    Some(projected_name.effective_visibility),
                )
            {
                workflow.projected_name = None;
            }
        }
        let next_cursor = if has_more {
            workflows.last().map(|workflow| HumanWorkflowCursor {
                path: workflow.path.clone(),
                id: workflow.id,
            })
        } else {
            None
        };
        workflows.shrink_to_fit();
        Ok(Some(HumanWorkflowPage {
            workflows,
            next_cursor,
        }))
    }

    async fn list_runs(
        &self,
        query: &HumanRunListQuery,
        context: &AuthorizationContext,
        permission: &Permission,
    ) -> Result<Option<HumanRunPage>, StoreError> {
        list_runs(self, query, context, permission).await
    }

    async fn get_run(&self, scope: &HumanRunScope) -> Result<Option<HumanRunDetail>, StoreError> {
        get_run(self, scope).await
    }

    async fn get_job(&self, scope: &HumanJobScope) -> Result<Option<HumanJobDetail>, StoreError> {
        get_job(self, scope).await
    }

    async fn list_log_segments(
        &self,
        query: &HumanLogSegmentQuery,
    ) -> Result<Option<HumanLogSegmentPage>, StoreError> {
        list_log_segments(self, query).await
    }

    async fn get_artifact(
        &self,
        scope: &HumanArtifactScope,
    ) -> Result<Option<HumanArtifactDownload>, StoreError> {
        get_artifact(self, scope).await
    }

    async fn is_repository_request_allowed(
        &self,
        tenant: &TenantScope,
        repository_id: RepositoryId,
        context: &AuthorizationContext,
        target: &HumanAuthorizationTarget,
    ) -> Result<bool, StoreError> {
        authorize_repository_request(self, tenant, repository_id, context, target).await
    }
}

const WORKFLOWS_FIRST_SQL: &str = r"
    SELECT workflow.id, workflow.path, workflow.enabled,
           projected.run_id AS projected_run_id,
           projected.workflow_name AS projected_workflow_name,
           projected.effective_dashboard_visibility AS projected_visibility
    FROM repositories AS repository
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = repository.id
    LEFT JOIN LATERAL (
        SELECT run.id AS run_id, run.workflow_name,
               run.effective_dashboard_visibility
        FROM workflow_runs AS run
        WHERE run.repository_id = repository.id
          AND run.workflow_id = workflow.id
        ORDER BY run.created_at_ms DESC, run.id DESC
        LIMIT 1
    ) AS projected ON TRUE
    WHERE repository.tenant_id = $1
      AND repository.id = $2
    ORDER BY workflow.path, workflow.id
    LIMIT $3
";

const WORKFLOWS_AFTER_SQL: &str = r"
    SELECT workflow.id, workflow.path, workflow.enabled,
           projected.run_id AS projected_run_id,
           projected.workflow_name AS projected_workflow_name,
           projected.effective_dashboard_visibility AS projected_visibility
    FROM repositories AS repository
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = repository.id
    LEFT JOIN LATERAL (
        SELECT run.id AS run_id, run.workflow_name,
               run.effective_dashboard_visibility
        FROM workflow_runs AS run
        WHERE run.repository_id = repository.id
          AND run.workflow_id = workflow.id
        ORDER BY run.created_at_ms DESC, run.id DESC
        LIMIT 1
    ) AS projected ON TRUE
    WHERE repository.tenant_id = $1
      AND repository.id = $2
      AND (workflow.path, workflow.id) > ($3, $4)
    ORDER BY workflow.path, workflow.id
    LIMIT $5
";

async fn workflow_exists(
    connection: &mut PgConnection,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    workflow_id: WorkflowId,
) -> Result<bool, StoreError> {
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM repositories AS repository
            JOIN workflow_definitions AS workflow
              ON workflow.repository_id = repository.id
            WHERE repository.tenant_id = $1
              AND repository.id = $2
              AND workflow.id = $3
        )
        ",
    )
    .bind(tenant.as_str())
    .bind(repository_id.as_uuid())
    .bind(workflow_id.as_uuid())
    .fetch_one(connection)
    .await
    .map_err(operation_error)
}

fn decode_repository(row: &PgRow) -> Result<HumanRepository, StoreError> {
    let id = RepositoryId::from_uuid(row.try_get("id").map_err(operation_error)?);
    let tenant_text: String = row.try_get("tenant_id").map_err(operation_error)?;
    let tenant_id = TenantId::new(tenant_text)
        .map_err(|_| StoreError::corrupt_data("repository tenant identity is invalid"))?;
    let resource_id = RepositoryResourceId::from_uuid(id.as_uuid())
        .map_err(|_| StoreError::corrupt_data("repository resource identity is invalid"))?;
    let dashboard = required_visibility(row, "dashboard_audience")?;
    let logs = required_visibility(row, "log_audience")?;
    let artifacts = required_visibility(row, "artifact_audience")?;
    let revision = positive_u64(
        row.try_get("publication_revision")
            .map_err(operation_error)?,
        "repository publication revision",
    )?;
    Ok(HumanRepository {
        id,
        resource: RepositoryResource::new(tenant_id, resource_id),
        scm_provider: row.try_get("scm_provider").map_err(operation_error)?,
        provider_repository_id: row
            .try_get("provider_repository_id")
            .map_err(operation_error)?,
        owner: row.try_get("owner").map_err(operation_error)?,
        name: row.try_get("name").map_err(operation_error)?,
        publication: RepositoryPublicationPolicy::new(dashboard, logs, artifacts),
        publication_revision: revision,
    })
}

fn decode_workflow(row: &PgRow) -> Result<HumanWorkflow, StoreError> {
    let projected_name: Option<String> = row
        .try_get("projected_workflow_name")
        .map_err(operation_error)?;
    let projected_run_id: Option<Uuid> =
        row.try_get("projected_run_id").map_err(operation_error)?;
    let projected_visibility: Option<String> = row
        .try_get("projected_visibility")
        .map_err(operation_error)?;
    let projected_name = match (projected_name, projected_run_id, projected_visibility) {
        (None, None, None) => None,
        (Some(name), Some(run_id), Some(visibility)) => Some(HumanWorkflowProjectedName {
            name,
            source_run_id: RunId::from_uuid(run_id),
            effective_visibility: parse_visibility(&visibility)?,
        }),
        _ => {
            return Err(StoreError::corrupt_data(
                "workflow name projection is incomplete",
            ));
        }
    };
    Ok(HumanWorkflow {
        id: WorkflowId::from_uuid(row.try_get("id").map_err(operation_error)?),
        path: row.try_get("path").map_err(operation_error)?,
        enabled: row.try_get("enabled").map_err(operation_error)?,
        projected_name,
    })
}

macro_rules! run_page_sql {
    ($comparison:literal, $order:literal) => {
        concat!(
            r"
            SELECT run.id, run.workflow_id, workflow.path AS workflow_path,
                   run.run_number, run.run_attempt, run.event_name, run.head_sha,
                   run.status, run.workflow_name, run.git_ref, run.actor,
                   run.display_title, run.commit_subject,
                   run.created_at_ms, run.updated_at_ms,
                   run.publication_policy_revision,
                   run.requested_dashboard_visibility,
                   run.effective_dashboard_visibility,
                   run.requested_log_visibility,
                   run.requested_artifact_visibility,
                   run.publication_safety_reason,
                   run.publication_safety_schema,
                   aggregate.job_count, aggregate.attempt_count,
                   aggregate.latest_lifecycles
            FROM repositories AS repository
            JOIN workflow_runs AS run
              ON run.repository_id = repository.id
            JOIN workflow_definitions AS workflow
              ON workflow.repository_id = repository.id
             AND workflow.id = run.workflow_id
            LEFT JOIN LATERAL (
                SELECT count(*) AS job_count,
                       count(latest.id) AS attempt_count,
                       array_agg(latest.lifecycle ORDER BY job.created_at_ms, job.id)
                           FILTER (WHERE latest.id IS NOT NULL) AS latest_lifecycles
                FROM jobs AS job
                LEFT JOIN LATERAL (
                    SELECT attempt.id, attempt.lifecycle
                    FROM job_attempts AS attempt
                    WHERE attempt.job_id = job.id
                    ORDER BY attempt.attempt_number DESC, attempt.id DESC
                    LIMIT 1
                ) AS latest ON TRUE
                WHERE job.run_id = run.id
            ) AS aggregate ON TRUE
            WHERE repository.tenant_id = $1
              AND repository.id = $2
              AND ($3::UUID IS NULL OR run.workflow_id = $3)
              AND (
                    $4::TEXT IS NULL
                    OR ($4 = 'completed' AND run.status IN ('completed', 'cancelled'))
                    OR ($4 <> 'completed' AND run.status = $4)
              )
              AND ($5::TEXT IS NULL OR run.git_ref = $5)
              AND ($6::BIGINT IS NULL OR (run.created_at_ms, run.id) ",
            $comparison,
            r" ($6, $7))
              AND (
                    $8::BOOLEAN
                    OR run.effective_dashboard_visibility = 'public'
                    OR ($9::BOOLEAN AND run.effective_dashboard_visibility = 'authenticated')
              )
            ORDER BY run.created_at_ms ",
            $order,
            r", run.id ",
            $order,
            r"
            LIMIT $10
            "
        )
    };
}

const RUNS_OLDER_SQL: &str = run_page_sql!("<", "DESC");
const RUNS_NEWER_SQL: &str = run_page_sql!(">", "ASC");

async fn list_runs(
    store: &PostgresStore,
    query: &HumanRunListQuery,
    context: &AuthorizationContext,
    permission: &Permission,
) -> Result<Option<HumanRunPage>, StoreError> {
    if permission.as_str() != repository_read_permissions::RUN_READ {
        return Ok(None);
    }
    let mut transaction = begin_read(store).await?;
    let Some(authorization) = load_repository_authorization(
        &mut transaction,
        &query.tenant,
        query.repository_id,
        context,
        permission,
    )
    .await?
    else {
        return Ok(None);
    };
    if !authorization.allows(context, permission, None) {
        return Ok(None);
    }
    if let Some(workflow_id) = query.workflow_id
        && !workflow_exists(
            &mut transaction,
            &query.tenant,
            query.repository_id,
            workflow_id,
        )
        .await?
    {
        return Ok(None);
    }
    let rbac_allowed = authorization.allows(context, permission, Some(OutputVisibility::Private));
    let authenticated =
        authorization.allows(context, permission, Some(OutputVisibility::Authenticated));

    let direction = if query.cursor.is_some() {
        query.direction
    } else {
        HumanRunPageDirection::Older
    };
    let sql = match direction {
        HumanRunPageDirection::Older => RUNS_OLDER_SQL,
        HumanRunPageDirection::Newer => RUNS_NEWER_SQL,
    };
    let cursor_created_at = query.cursor.map(|cursor| cursor.created_at.get());
    let cursor_id = query.cursor.map(|cursor| cursor.id.as_uuid());
    let workflow_id = query.workflow_id.map(WorkflowId::as_uuid);
    let status = query.status.map(run_status_filter_name);
    let git_ref = query.git_ref.as_ref().map(crate::HumanGitRef::as_str);
    let rows = sqlx::query(sql)
        .bind(query.tenant.as_str())
        .bind(query.repository_id.as_uuid())
        .bind(workflow_id)
        .bind(status)
        .bind(git_ref)
        .bind(cursor_created_at)
        .bind(cursor_id)
        .bind(rbac_allowed)
        .bind(authenticated)
        .bind(i64::from(query.limit.get()) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
    transaction.commit().await.map_err(operation_error)?;

    let has_more = rows.len() > usize::from(query.limit.get());
    let mut runs = rows
        .iter()
        .take(usize::from(query.limit.get()))
        .map(decode_run)
        .collect::<Result<Vec<_>, _>>()?;
    if direction == HumanRunPageDirection::Newer {
        runs.reverse();
    }

    let first_cursor = runs.first().map(run_cursor);
    let last_cursor = runs.last().map(run_cursor);
    let (older_cursor, newer_cursor) = match direction {
        HumanRunPageDirection::Older => (
            has_more.then_some(last_cursor).flatten(),
            query.cursor.and(first_cursor),
        ),
        HumanRunPageDirection::Newer => (
            query.cursor.and(last_cursor),
            has_more.then_some(first_cursor).flatten(),
        ),
    };
    Ok(Some(HumanRunPage {
        runs,
        older_cursor,
        newer_cursor,
    }))
}

const fn run_status_filter_name(filter: HumanRunStatusFilter) -> &'static str {
    match filter {
        HumanRunStatusFilter::Queued => "queued",
        HumanRunStatusFilter::InProgress => "in_progress",
        HumanRunStatusFilter::Completed => "completed",
    }
}

fn run_cursor(run: &HumanRun) -> HumanRunCursor {
    HumanRunCursor {
        created_at: run.created_at,
        id: run.id,
    }
}

fn decode_run(row: &PgRow) -> Result<HumanRun, StoreError> {
    let status_text: String = row.try_get("status").map_err(operation_error)?;
    let status = parse_run_status(&status_text)?;
    let job_count: i64 = row.try_get("job_count").map_err(operation_error)?;
    let attempt_count: i64 = row.try_get("attempt_count").map_err(operation_error)?;
    if job_count < 0 || attempt_count < 0 || attempt_count > job_count {
        return Err(StoreError::corrupt_data(
            "workflow run latest-attempt aggregate is invalid",
        ));
    }
    let lifecycle_names: Option<Vec<String>> =
        row.try_get("latest_lifecycles").map_err(operation_error)?;
    let lifecycles = lifecycle_names
        .unwrap_or_default()
        .iter()
        .map(|name| parse_lifecycle(name))
        .collect::<Result<Vec<_>, _>>()?;
    if i64::try_from(lifecycles.len()).ok() != Some(attempt_count) {
        return Err(StoreError::corrupt_data(
            "workflow run latest-attempt aggregate count is inconsistent",
        ));
    }
    let conclusion = if job_count == attempt_count && job_count > 0 {
        aggregate_conclusion(&lifecycles)
    } else {
        None
    };
    if status == WorkflowRunStatus::Completed && conclusion.is_none() {
        return Err(StoreError::corrupt_data(
            "completed workflow run lacks a terminal latest attempt for every job",
        ));
    }

    let run_number = positive_u64(
        row.try_get("run_number").map_err(operation_error)?,
        "workflow run number",
    )?;
    let run_attempt = positive_u32(
        row.try_get("run_attempt").map_err(operation_error)?,
        "workflow run attempt",
    )?;
    let updated_at = UnixMillis::new(row.try_get("updated_at_ms").map_err(operation_error)?);
    let finished_at = matches!(
        status,
        WorkflowRunStatus::Completed | WorkflowRunStatus::Cancelled
    )
    .then_some(updated_at);
    let policy_revision = positive_u64(
        row.try_get("publication_policy_revision")
            .map_err(operation_error)?,
        "workflow run publication revision",
    )?;
    let safety_schema = positive_u16(
        row.try_get("publication_safety_schema")
            .map_err(operation_error)?,
        "workflow run publication safety schema",
    )?;

    Ok(HumanRun {
        id: RunId::from_uuid(row.try_get("id").map_err(operation_error)?),
        workflow_id: WorkflowId::from_uuid(row.try_get("workflow_id").map_err(operation_error)?),
        workflow_path: row.try_get("workflow_path").map_err(operation_error)?,
        run_number,
        run_attempt,
        event_name: row.try_get("event_name").map_err(operation_error)?,
        head_commit: HumanGitCommitId::from_durable_bytes(
            row.try_get("head_sha").map_err(operation_error)?,
        )?,
        status,
        conclusion,
        workflow_name: row.try_get("workflow_name").map_err(operation_error)?,
        git_ref: row.try_get("git_ref").map_err(operation_error)?,
        actor: row.try_get("actor").map_err(operation_error)?,
        display_title: row.try_get("display_title").map_err(operation_error)?,
        commit_subject: row.try_get("commit_subject").map_err(operation_error)?,
        created_at: UnixMillis::new(row.try_get("created_at_ms").map_err(operation_error)?),
        updated_at,
        finished_at,
        publication: HumanRunPublication {
            policy_revision,
            requested_dashboard_visibility: required_visibility(
                row,
                "requested_dashboard_visibility",
            )?,
            effective_dashboard_visibility: required_visibility(
                row,
                "effective_dashboard_visibility",
            )?,
            requested_log_visibility: required_visibility(row, "requested_log_visibility")?,
            requested_artifact_visibility: required_visibility(
                row,
                "requested_artifact_visibility",
            )?,
            safety_reason: row
                .try_get("publication_safety_reason")
                .map_err(operation_error)?,
            safety_schema,
        },
    })
}

fn aggregate_conclusion(lifecycles: &[JobLifecycle]) -> Option<HumanRunConclusion> {
    if lifecycles.is_empty() || lifecycles.iter().any(|lifecycle| !lifecycle.is_terminal()) {
        return None;
    }
    if lifecycles.contains(&JobLifecycle::Failed) {
        Some(HumanRunConclusion::Failure)
    } else if lifecycles.contains(&JobLifecycle::TimedOut) {
        Some(HumanRunConclusion::TimedOut)
    } else if lifecycles.contains(&JobLifecycle::Cancelled) {
        Some(HumanRunConclusion::Cancelled)
    } else if lifecycles.contains(&JobLifecycle::Lost) {
        Some(HumanRunConclusion::Lost)
    } else if lifecycles
        .iter()
        .all(|lifecycle| *lifecycle == JobLifecycle::Skipped)
    {
        Some(HumanRunConclusion::Skipped)
    } else {
        Some(HumanRunConclusion::Success)
    }
}

fn parse_run_status(value: &str) -> Result<WorkflowRunStatus, StoreError> {
    match value {
        "queued" => Ok(WorkflowRunStatus::Queued),
        "in_progress" => Ok(WorkflowRunStatus::InProgress),
        "completed" => Ok(WorkflowRunStatus::Completed),
        "cancelled" => Ok(WorkflowRunStatus::Cancelled),
        _ => Err(StoreError::corrupt_data("workflow run status is unknown")),
    }
}

fn parse_lifecycle(value: &str) -> Result<JobLifecycle, StoreError> {
    match value {
        "queued" => Ok(JobLifecycle::Queued),
        "leased" => Ok(JobLifecycle::Leased),
        "preparing" => Ok(JobLifecycle::Preparing),
        "running" => Ok(JobLifecycle::Running),
        "cancelling" => Ok(JobLifecycle::Cancelling),
        "finalizing" => Ok(JobLifecycle::Finalizing),
        "succeeded" => Ok(JobLifecycle::Succeeded),
        "failed" => Ok(JobLifecycle::Failed),
        "cancelled" => Ok(JobLifecycle::Cancelled),
        "timed_out" => Ok(JobLifecycle::TimedOut),
        "skipped" => Ok(JobLifecycle::Skipped),
        "lost" => Ok(JobLifecycle::Lost),
        _ => Err(StoreError::corrupt_data("job attempt lifecycle is unknown")),
    }
}

const RUN_BY_ID_SQL: &str = r"
    SELECT run.id, run.workflow_id, workflow.path AS workflow_path,
           run.run_number, run.run_attempt, run.event_name, run.head_sha,
           run.status, run.workflow_name, run.git_ref, run.actor,
           run.display_title, run.commit_subject,
           run.created_at_ms, run.updated_at_ms,
           run.publication_policy_revision,
           run.requested_dashboard_visibility,
           run.effective_dashboard_visibility,
           run.requested_log_visibility,
           run.requested_artifact_visibility,
           run.publication_safety_reason,
           run.publication_safety_schema,
           aggregate.job_count, aggregate.attempt_count,
           aggregate.latest_lifecycles
    FROM repositories AS repository
    JOIN workflow_runs AS run
      ON run.repository_id = repository.id
    JOIN workflow_definitions AS workflow
      ON workflow.repository_id = repository.id
     AND workflow.id = run.workflow_id
    LEFT JOIN LATERAL (
        SELECT count(*) AS job_count,
               count(latest.id) AS attempt_count,
               array_agg(latest.lifecycle ORDER BY job.created_at_ms, job.id)
                   FILTER (WHERE latest.id IS NOT NULL) AS latest_lifecycles
        FROM jobs AS job
        LEFT JOIN LATERAL (
            SELECT attempt.id, attempt.lifecycle
            FROM job_attempts AS attempt
            WHERE attempt.job_id = job.id
            ORDER BY attempt.attempt_number DESC, attempt.id DESC
            LIMIT 1
        ) AS latest ON TRUE
        WHERE job.run_id = run.id
    ) AS aggregate ON TRUE
    WHERE repository.tenant_id = $1
      AND repository.id = $2
      AND run.id = $3
";

async fn get_run(
    store: &PostgresStore,
    scope: &HumanRunScope,
) -> Result<Option<HumanRunDetail>, StoreError> {
    let mut transaction = begin_read(store).await?;
    let Some(run) = load_run(&mut transaction, scope).await? else {
        return Ok(None);
    };
    let jobs = load_jobs(&mut transaction, scope).await?;
    let artifacts = load_artifact_summaries(&mut transaction, scope).await?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(HumanRunDetail {
        run,
        jobs,
        artifacts,
    }))
}

async fn begin_read(store: &PostgresStore) -> Result<Transaction<'_, Postgres>, StoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    Ok(transaction)
}

async fn load_run(
    connection: &mut PgConnection,
    scope: &HumanRunScope,
) -> Result<Option<HumanRun>, StoreError> {
    let row = sqlx::query(RUN_BY_ID_SQL)
        .bind(scope.tenant.as_str())
        .bind(scope.repository_id.as_uuid())
        .bind(scope.run_id.as_uuid())
        .fetch_optional(connection)
        .await
        .map_err(operation_error)?;
    row.as_ref().map(decode_run).transpose()
}

async fn load_jobs(
    connection: &mut PgConnection,
    scope: &HumanRunScope,
) -> Result<Vec<HumanJob>, StoreError> {
    let rows = sqlx::query(
        r"
        SELECT job.id AS job_id, job.job_key, job.display_name,
               job.created_at_ms AS job_created_at_ms,
               job.job_ir_schema, job.job_ir_size_bytes,
               job.job_ir_digest, job.job_ir_object_key,
               latest.id AS attempt_id,
               latest.attempt_number, latest.lifecycle,
               latest.queued_at_ms, latest.changed_at_ms,
               latest.started_at_ms,
               terminal.attempt_id AS terminal_attempt_id,
               terminal.terminal_authority,
               terminal.result_schema, terminal.result_size_bytes,
               terminal.result_digest, terminal.result_object_key,
               terminal.conclusion AS terminal_conclusion,
               terminal.completed_at_ms, terminal.committed_at_ms,
               coalesce(terminal.runner_id, latest.runner_id) AS selected_runner_id,
               runner.name AS runner_name,
               stream.id AS log_stream_id,
               stream.secret_exposure_class,
               stream.requested_visibility,
               stream.effective_visibility,
               stream.output_safety_reason,
               stream.output_safety_schema
        FROM repositories AS repository
        JOIN workflow_runs AS run
          ON run.repository_id = repository.id
        JOIN jobs AS job
          ON job.run_id = run.id
        LEFT JOIN LATERAL (
            SELECT attempt.id, attempt.attempt_number, attempt.lifecycle,
                   attempt.queued_at_ms, attempt.changed_at_ms,
                   attempt.started_at_ms, attempt.runner_id
            FROM job_attempts AS attempt
            WHERE attempt.job_id = job.id
            ORDER BY attempt.attempt_number DESC, attempt.id DESC
            LIMIT 1
        ) AS latest ON TRUE
        LEFT JOIN attempt_terminal_results AS terminal
          ON terminal.attempt_id = latest.id
        LEFT JOIN runners AS runner
          ON runner.tenant_id = repository.tenant_id
         AND runner.id = coalesce(terminal.runner_id, latest.runner_id)
        LEFT JOIN attempt_log_streams AS stream
          ON stream.attempt_id = latest.id
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND run.id = $3
        ORDER BY job.created_at_ms, job.id
        LIMIT $4
        ",
    )
    .bind(scope.tenant.as_str())
    .bind(scope.repository_id.as_uuid())
    .bind(scope.run_id.as_uuid())
    .bind(i64::try_from(MAX_RUN_DETAIL_JOBS + 1).expect("job read bound fits BIGINT"))
    .fetch_all(connection)
    .await
    .map_err(operation_error)?;
    if rows.len() > MAX_RUN_DETAIL_JOBS {
        return Err(StoreError::corrupt_data(
            "workflow run exceeds the human job read bound",
        ));
    }
    let jobs = rows
        .iter()
        .map(|row| decode_job(row, scope.run_id))
        .collect::<Result<Vec<_>, _>>()?;
    if jobs.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(StoreError::corrupt_data(
            "latest job attempt has multiple durable log streams",
        ));
    }
    Ok(jobs)
}

fn decode_job(row: &PgRow, run_id: RunId) -> Result<HumanJob, StoreError> {
    let job_id = JobId::from_uuid(row.try_get("job_id").map_err(operation_error)?);
    let version = JobIrVersion::new(positive_u16(
        row.try_get("job_ir_schema").map_err(operation_error)?,
        "JobIR schema",
    )?)
    .map_err(|_| StoreError::corrupt_data("JobIR schema is invalid"))?;
    let size = positive_u64(
        row.try_get("job_ir_size_bytes").map_err(operation_error)?,
        "JobIR encoded size",
    )?;
    let digest = decode_digest(
        row.try_get("job_ir_digest").map_err(operation_error)?,
        "JobIR digest",
    )?;
    let key = crate::ObjectKey::new(
        row.try_get::<String, _>("job_ir_object_key")
            .map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("JobIR object key is invalid"))?;
    let job_ir_metadata = JobIrMetadata::new(job_id, run_id, version, size, digest, key)
        .map_err(|_| StoreError::corrupt_data("JobIR descriptor is invalid"))?;

    let attempt_id: Option<Uuid> = row.try_get("attempt_id").map_err(operation_error)?;
    let latest_attempt = attempt_id
        .map(|attempt_id| decode_attempt(row, AttemptId::from_uuid(attempt_id)))
        .transpose()?;
    let log_stream_id: Option<Uuid> = row.try_get("log_stream_id").map_err(operation_error)?;
    let log_publication = log_stream_id
        .map(|_| decode_output_publication(row, "output_safety_reason", "output_safety_schema"))
        .transpose()?;
    Ok(HumanJob {
        id: job_id,
        key: row.try_get("job_key").map_err(operation_error)?,
        display_name: row.try_get("display_name").map_err(operation_error)?,
        created_at: UnixMillis::new(row.try_get("job_created_at_ms").map_err(operation_error)?),
        job_ir: job_ir_metadata,
        latest_attempt,
        log_publication,
    })
}

fn decode_attempt(row: &PgRow, attempt_id: AttemptId) -> Result<HumanJobAttempt, StoreError> {
    let lifecycle_text: String = row.try_get("lifecycle").map_err(operation_error)?;
    let lifecycle = parse_lifecycle(&lifecycle_text)?;
    let number = AttemptNumber::new(positive_u32(
        row.try_get("attempt_number").map_err(operation_error)?,
        "job attempt number",
    )?)
    .map_err(|_| StoreError::corrupt_data("job attempt number is invalid"))?;

    let selected_runner_id: Option<Uuid> =
        row.try_get("selected_runner_id").map_err(operation_error)?;
    let runner_name: Option<String> = row.try_get("runner_name").map_err(operation_error)?;
    let runner = match (selected_runner_id, runner_name) {
        (None, None) => None,
        (Some(id), Some(name)) => Some(HumanRunner {
            id: RunnerId::from_uuid(id),
            name,
        }),
        _ => {
            return Err(StoreError::corrupt_data(
                "job attempt runner does not belong to the repository tenant",
            ));
        }
    };

    let terminal_attempt_id: Option<Uuid> = row
        .try_get("terminal_attempt_id")
        .map_err(operation_error)?;
    let terminal_authority: Option<String> =
        row.try_get("terminal_authority").map_err(operation_error)?;
    let terminal_result = match (terminal_attempt_id, terminal_authority.as_deref()) {
        (Some(terminal_id), Some(authority)) => {
            if terminal_id != attempt_id.as_uuid() {
                return Err(StoreError::corrupt_data(
                    "terminal result references a different attempt",
                ));
            }
            match authority {
                "runner" => Some(decode_terminal_result(row, attempt_id, lifecycle)?),
                "server_cancellation" => {
                    validate_server_cancellation_terminal(row, lifecycle)?;
                    None
                }
                _ => {
                    return Err(StoreError::corrupt_data(
                        "terminal result authority is unknown",
                    ));
                }
            }
        }
        (None, None) => None,
        _ => {
            return Err(StoreError::corrupt_data(
                "terminal result authority is incomplete",
            ));
        }
    };
    let changed_at = UnixMillis::new(row.try_get("changed_at_ms").map_err(operation_error)?);
    let finished_at = terminal_result
        .as_ref()
        .map(|terminal| terminal.completed_at)
        .or_else(|| lifecycle.is_terminal().then_some(changed_at));
    Ok(HumanJobAttempt {
        id: attempt_id,
        number,
        lifecycle,
        queued_at: UnixMillis::new(row.try_get("queued_at_ms").map_err(operation_error)?),
        changed_at,
        started_at: row
            .try_get::<Option<i64>, _>("started_at_ms")
            .map_err(operation_error)?
            .map(UnixMillis::new),
        finished_at,
        runner,
        terminal_result,
    })
}

fn validate_server_cancellation_terminal(
    row: &PgRow,
    lifecycle: JobLifecycle,
) -> Result<(), StoreError> {
    let conclusion_text: String = row
        .try_get("terminal_conclusion")
        .map_err(operation_error)?;
    let conclusion = parse_job_conclusion(&conclusion_text)?;
    let completed_at: i64 = row.try_get("completed_at_ms").map_err(operation_error)?;
    let committed_at: i64 = row.try_get("committed_at_ms").map_err(operation_error)?;
    let result_fields_absent = row
        .try_get::<Option<i32>, _>("result_schema")
        .map_err(operation_error)?
        .is_none()
        && row
            .try_get::<Option<i64>, _>("result_size_bytes")
            .map_err(operation_error)?
            .is_none()
        && row
            .try_get::<Option<Vec<u8>>, _>("result_digest")
            .map_err(operation_error)?
            .is_none()
        && row
            .try_get::<Option<String>, _>("result_object_key")
            .map_err(operation_error)?
            .is_none();
    if lifecycle != JobLifecycle::Cancelled
        || conclusion != JobConclusion::Cancelled
        || completed_at < 0
        || committed_at < completed_at
        || !result_fields_absent
    {
        return Err(StoreError::corrupt_data(
            "server cancellation terminal evidence is invalid",
        ));
    }
    Ok(())
}

fn decode_terminal_result(
    row: &PgRow,
    attempt_id: AttemptId,
    lifecycle: JobLifecycle,
) -> Result<HumanTerminalResult, StoreError> {
    let conclusion_text: String = row
        .try_get("terminal_conclusion")
        .map_err(operation_error)?;
    let conclusion = parse_job_conclusion(&conclusion_text)?;
    if lifecycle_conclusion(lifecycle).and_then(run_to_job_conclusion) != Some(conclusion) {
        return Err(StoreError::corrupt_data(
            "terminal result conclusion contradicts the attempt lifecycle",
        ));
    }
    let schema = DocumentSchema::new(positive_u16(
        row.try_get("result_schema").map_err(operation_error)?,
        "terminal result schema",
    )?)
    .map_err(|_| StoreError::corrupt_data("terminal result schema is invalid"))?;
    let size = positive_u64(
        row.try_get("result_size_bytes").map_err(operation_error)?,
        "terminal result size",
    )?;
    let descriptor = blob_descriptor(
        row.try_get("result_object_key").map_err(operation_error)?,
        decode_digest(
            row.try_get("result_digest").map_err(operation_error)?,
            "terminal result digest",
        )?,
        size,
        HUMAN_JOB_RESULT_MEDIA_TYPE.to_owned(),
    )?;
    Ok(HumanTerminalResult {
        attempt_id,
        schema,
        descriptor,
        conclusion,
        completed_at: UnixMillis::new(row.try_get("completed_at_ms").map_err(operation_error)?),
        committed_at: UnixMillis::new(row.try_get("committed_at_ms").map_err(operation_error)?),
    })
}

async fn load_artifact_summaries(
    connection: &mut PgConnection,
    scope: &HumanRunScope,
) -> Result<Vec<HumanArtifactSummary>, StoreError> {
    let rows = sqlx::query(
        r"
        SELECT artifact.id, artifact.name, artifact.mime_type,
               artifact.content_size_bytes, artifact.content_digest,
               artifact.expires_at_seconds, artifact.finalized_at_seconds,
               artifact.secret_exposure_class,
               artifact.requested_visibility, artifact.effective_visibility,
               artifact.publication_safety_reason,
               artifact.publication_safety_schema
        FROM repositories AS repository
        JOIN workflow_runs AS run
          ON run.repository_id = repository.id
        JOIN workflow_artifacts AS artifact
          ON artifact.tenant_id = repository.tenant_id
         AND artifact.repository_id = repository.id
         AND artifact.run_id = run.id
        JOIN workflow_artifact_block_commits AS committed
          ON committed.artifact_id = artifact.id
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND run.id = $3
          AND artifact.state = 'finalized'
          AND artifact.manifest_state = 'ready'
        ORDER BY artifact.finalized_at_seconds DESC, artifact.id DESC
        LIMIT $4
        ",
    )
    .bind(scope.tenant.as_str())
    .bind(scope.repository_id.as_uuid())
    .bind(scope.run_id.as_uuid())
    .bind(i64::try_from(MAX_RUN_DETAIL_ARTIFACTS + 1).expect("artifact summary bound fits BIGINT"))
    .fetch_all(connection)
    .await
    .map_err(operation_error)?;
    if rows.len() > MAX_RUN_DETAIL_ARTIFACTS {
        return Err(StoreError::corrupt_data(
            "workflow run exceeds the human artifact summary bound",
        ));
    }
    rows.iter().map(decode_artifact_summary).collect()
}

fn decode_artifact_summary(row: &PgRow) -> Result<HumanArtifactSummary, StoreError> {
    Ok(HumanArtifactSummary {
        id: HumanArtifactId::new(row.try_get("id").map_err(operation_error)?)
            .map_err(|_| StoreError::corrupt_data("artifact identity is invalid"))?,
        name: row.try_get("name").map_err(operation_error)?,
        mime_type: row.try_get("mime_type").map_err(operation_error)?,
        content_size: nonnegative_u64(
            row.try_get("content_size_bytes").map_err(operation_error)?,
            "artifact content size",
        )?,
        content_digest: decode_digest(
            row.try_get("content_digest").map_err(operation_error)?,
            "artifact content digest",
        )?,
        expires_at_seconds: row.try_get("expires_at_seconds").map_err(operation_error)?,
        finalized_at_seconds: row
            .try_get("finalized_at_seconds")
            .map_err(operation_error)?,
        publication: decode_output_publication(
            row,
            "publication_safety_reason",
            "publication_safety_schema",
        )?,
    })
}

fn lifecycle_conclusion(lifecycle: JobLifecycle) -> Option<HumanRunConclusion> {
    match lifecycle {
        JobLifecycle::Succeeded => Some(HumanRunConclusion::Success),
        JobLifecycle::Failed => Some(HumanRunConclusion::Failure),
        JobLifecycle::Cancelled => Some(HumanRunConclusion::Cancelled),
        JobLifecycle::TimedOut => Some(HumanRunConclusion::TimedOut),
        JobLifecycle::Skipped => Some(HumanRunConclusion::Skipped),
        JobLifecycle::Lost => Some(HumanRunConclusion::Lost),
        JobLifecycle::Queued
        | JobLifecycle::Leased
        | JobLifecycle::Preparing
        | JobLifecycle::Running
        | JobLifecycle::Cancelling
        | JobLifecycle::Finalizing => None,
    }
}

const fn run_to_job_conclusion(conclusion: HumanRunConclusion) -> Option<JobConclusion> {
    match conclusion {
        HumanRunConclusion::Success => Some(JobConclusion::Success),
        HumanRunConclusion::Failure => Some(JobConclusion::Failure),
        HumanRunConclusion::Cancelled => Some(JobConclusion::Cancelled),
        HumanRunConclusion::TimedOut => Some(JobConclusion::TimedOut),
        HumanRunConclusion::Skipped => Some(JobConclusion::Skipped),
        HumanRunConclusion::Lost => None,
    }
}

fn parse_job_conclusion(value: &str) -> Result<JobConclusion, StoreError> {
    match value {
        "success" => Ok(JobConclusion::Success),
        "failure" => Ok(JobConclusion::Failure),
        "cancelled" => Ok(JobConclusion::Cancelled),
        "timed_out" => Ok(JobConclusion::TimedOut),
        "skipped" => Ok(JobConclusion::Skipped),
        _ => Err(StoreError::corrupt_data(
            "terminal result conclusion is unknown",
        )),
    }
}

async fn get_job(
    store: &PostgresStore,
    scope: &HumanJobScope,
) -> Result<Option<HumanJobDetail>, StoreError> {
    let run_scope = HumanRunScope::new(scope.tenant.clone(), scope.repository_id, scope.run_id);
    let mut transaction = begin_read(store).await?;
    let Some(run) = load_run(&mut transaction, &run_scope).await? else {
        return Ok(None);
    };
    let jobs = load_jobs(&mut transaction, &run_scope).await?;
    let Some(job) = jobs.iter().find(|job| job.id == scope.job_id).cloned() else {
        return Ok(None);
    };
    let navigation = jobs
        .iter()
        .map(|job| HumanJobNavigation {
            id: job.id,
            display_name: job.display_name.clone(),
            lifecycle: job.latest_attempt.as_ref().map(|attempt| attempt.lifecycle),
            conclusion: job
                .latest_attempt
                .as_ref()
                .and_then(|attempt| lifecycle_conclusion(attempt.lifecycle)),
            log_publication: job.log_publication.clone(),
        })
        .collect();
    let log_stream = load_log_stream(&mut transaction, scope, None).await?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(HumanJobDetail {
        run,
        navigation,
        job,
        log_stream,
    }))
}

async fn load_log_stream(
    connection: &mut PgConnection,
    scope: &HumanJobScope,
    exact_stream_id: Option<LogStreamId>,
) -> Result<Option<HumanLogStream>, StoreError> {
    let rows = sqlx::query(
        r"
        SELECT stream.id, stream.attempt_id, stream.log_schema,
               stream.opened_at_ms, stream.closed_at_ms,
               stream.secret_exposure_class, stream.raw_log_disposition,
               stream.requested_visibility, stream.effective_visibility,
               stream.output_safety_reason, stream.output_safety_schema,
               stats.segment_count, stats.first_sequence,
               stats.last_sequence, stats.terminal_count,
               stats.terminal_last_sequence, stats.has_gap,
               ($5::UUID IS NULL OR stream.id = $5) AS exact_match
        FROM repositories AS repository
        JOIN workflow_runs AS run
          ON run.repository_id = repository.id
        JOIN jobs AS job
          ON job.run_id = run.id
        JOIN LATERAL (
            SELECT attempt.id
            FROM job_attempts AS attempt
            WHERE attempt.job_id = job.id
            ORDER BY attempt.attempt_number DESC, attempt.id DESC
            LIMIT 1
        ) AS latest ON TRUE
        JOIN attempt_log_streams AS stream
          ON stream.attempt_id = latest.id
        LEFT JOIN LATERAL (
            SELECT count(*) AS segment_count,
                   min(ordered.first_sequence) AS first_sequence,
                   max(ordered.last_sequence) AS last_sequence,
                   count(*) FILTER (WHERE ordered.end_of_stream) AS terminal_count,
                   max(ordered.last_sequence) FILTER (WHERE ordered.end_of_stream)
                       AS terminal_last_sequence,
                   coalesce(bool_or(
                       ordered.previous_last IS NOT NULL
                       AND ordered.first_sequence - ordered.previous_last <> 1
                   ), FALSE) AS has_gap
            FROM (
                SELECT segment.first_sequence, segment.last_sequence,
                       segment.end_of_stream,
                       lag(segment.last_sequence) OVER (
                           ORDER BY segment.first_sequence
                       ) AS previous_last
                FROM attempt_log_segments AS segment
                WHERE segment.stream_id = stream.id
            ) AS ordered
        ) AS stats ON TRUE
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND run.id = $3
          AND job.id = $4
        ORDER BY stream.opened_at_ms, stream.id
        LIMIT 2
        ",
    )
    .bind(scope.tenant.as_str())
    .bind(scope.repository_id.as_uuid())
    .bind(scope.run_id.as_uuid())
    .bind(scope.job_id.as_uuid())
    .bind(exact_stream_id.map(LogStreamId::as_uuid))
    .fetch_all(connection)
    .await
    .map_err(operation_error)?;
    if rows.len() > 1 {
        return Err(StoreError::corrupt_data(
            "latest job attempt has multiple durable log streams",
        ));
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    if !row
        .try_get::<bool, _>("exact_match")
        .map_err(operation_error)?
    {
        return Ok(None);
    }
    decode_log_stream(row).map(Some)
}

fn decode_log_stream(row: &PgRow) -> Result<HumanLogStream, StoreError> {
    let segment_count: i64 = row.try_get("segment_count").map_err(operation_error)?;
    let first_sequence: Option<i64> = row.try_get("first_sequence").map_err(operation_error)?;
    let last_sequence: Option<i64> = row.try_get("last_sequence").map_err(operation_error)?;
    let terminal_count: i64 = row.try_get("terminal_count").map_err(operation_error)?;
    let terminal_last_sequence: Option<i64> = row
        .try_get("terminal_last_sequence")
        .map_err(operation_error)?;
    let has_gap: bool = row.try_get("has_gap").map_err(operation_error)?;
    let closed_at_ms: Option<i64> = row.try_get("closed_at_ms").map_err(operation_error)?;
    if segment_count < 0
        || !(0..=1).contains(&terminal_count)
        || has_gap
        || (segment_count == 0 && (first_sequence.is_some() || last_sequence.is_some()))
        || (segment_count > 0 && (first_sequence != Some(0) || last_sequence.is_none()))
        || (closed_at_ms.is_some()
            && (terminal_count != 1 || terminal_last_sequence != last_sequence))
        || (closed_at_ms.is_none() && terminal_count != 0)
    {
        return Err(StoreError::corrupt_data(
            "attempt log stream segment history is inconsistent",
        ));
    }
    let schema = DocumentSchema::new(positive_u16(
        row.try_get("log_schema").map_err(operation_error)?,
        "attempt log schema",
    )?)
    .map_err(|_| StoreError::corrupt_data("attempt log schema is invalid"))?;
    let raw_log_disposition = match row
        .try_get::<String, _>("raw_log_disposition")
        .map_err(operation_error)?
        .as_str()
    {
        "persist" => HumanRawLogDisposition::Persist,
        _ => {
            return Err(StoreError::corrupt_data(
                "attempt log raw-output disposition is unknown",
            ));
        }
    };
    Ok(HumanLogStream {
        id: LogStreamId::from_uuid(row.try_get("id").map_err(operation_error)?),
        attempt_id: AttemptId::from_uuid(row.try_get("attempt_id").map_err(operation_error)?),
        schema,
        opened_at: UnixMillis::new(row.try_get("opened_at_ms").map_err(operation_error)?),
        closed_at: closed_at_ms.map(UnixMillis::new),
        raw_log_disposition,
        publication: decode_output_publication(
            row,
            "output_safety_reason",
            "output_safety_schema",
        )?,
    })
}

async fn list_log_segments(
    store: &PostgresStore,
    query: &HumanLogSegmentQuery,
) -> Result<Option<HumanLogSegmentPage>, StoreError> {
    let mut transaction = begin_read(store).await?;
    let Some(stream) =
        load_log_stream(&mut transaction, &query.scope, Some(query.stream_id)).await?
    else {
        return Ok(None);
    };
    let direction = query
        .cursor
        .map_or(HumanLogSegmentPageDirection::Newer, |cursor| {
            cursor.direction
        });
    let boundary = query.cursor.map_or(0, |cursor| cursor.sequence.get());
    let boundary = i64::try_from(boundary)
        .map_err(|_| StoreError::corrupt_data("log sequence exceeds durable range"))?;
    let sql = match direction {
        HumanLogSegmentPageDirection::Newer => LOG_SEGMENTS_NEWER_SQL,
        HumanLogSegmentPageDirection::Older => LOG_SEGMENTS_OLDER_SQL,
    };
    let rows = sqlx::query(sql)
        .bind(query.scope.tenant.as_str())
        .bind(query.scope.repository_id.as_uuid())
        .bind(query.scope.run_id.as_uuid())
        .bind(query.scope.job_id.as_uuid())
        .bind(query.stream_id.as_uuid())
        .bind(boundary)
        .bind(i64::from(query.limit.get()) + 1)
        .fetch_all(&mut *transaction)
        .await
        .map_err(operation_error)?;
    transaction.commit().await.map_err(operation_error)?;

    let has_more = rows.len() > usize::from(query.limit.get());
    let mut segments = rows
        .iter()
        .take(usize::from(query.limit.get()))
        .map(decode_log_segment)
        .collect::<Result<Vec<_>, _>>()?;
    if direction == HumanLogSegmentPageDirection::Older {
        segments.reverse();
    }
    validate_segment_page(&segments)?;

    let first = segments.first();
    let last = segments.last();
    let (older_cursor, newer_cursor) = match direction {
        HumanLogSegmentPageDirection::Newer => {
            let older = first
                .filter(|segment| segment.first_sequence.get() > 0)
                .map(|segment| HumanLogSegmentCursor {
                    sequence: segment.first_sequence,
                    direction: HumanLogSegmentPageDirection::Older,
                });
            let newer = if has_more {
                last.map(next_segment_cursor).transpose()?
            } else {
                None
            };
            (older, newer)
        }
        HumanLogSegmentPageDirection::Older => {
            let older = if has_more {
                first.map(|segment| HumanLogSegmentCursor {
                    sequence: segment.first_sequence,
                    direction: HumanLogSegmentPageDirection::Older,
                })
            } else {
                None
            };
            let newer = query.cursor.and(last.map(next_segment_cursor).transpose()?);
            (older, newer)
        }
    };
    Ok(Some(HumanLogSegmentPage {
        stream,
        segments,
        older_cursor,
        newer_cursor,
    }))
}

macro_rules! log_segment_page_sql {
    ($predicate:literal, $order:literal) => {
        concat!(
            r"
            SELECT segment.first_sequence, segment.last_sequence,
                   segment.object_key, segment.object_digest,
                   segment.encoded_size_bytes, segment.uncompressed_size_bytes,
                   segment.stored_at_ms, segment.end_of_stream
            FROM repositories AS repository
            JOIN workflow_runs AS run
              ON run.repository_id = repository.id
            JOIN jobs AS job
              ON job.run_id = run.id
            JOIN LATERAL (
                SELECT attempt.id
                FROM job_attempts AS attempt
                WHERE attempt.job_id = job.id
                ORDER BY attempt.attempt_number DESC, attempt.id DESC
                LIMIT 1
            ) AS latest ON TRUE
            JOIN attempt_log_streams AS stream
              ON stream.attempt_id = latest.id
             AND stream.id = $5
            JOIN attempt_log_segments AS segment
              ON segment.stream_id = stream.id
            WHERE repository.tenant_id = $1
              AND repository.id = $2
              AND run.id = $3
              AND job.id = $4
              AND ",
            $predicate,
            r"
            ORDER BY segment.first_sequence ",
            $order,
            r"
            LIMIT $7
            "
        )
    };
}

const LOG_SEGMENTS_NEWER_SQL: &str = log_segment_page_sql!("segment.last_sequence >= $6", "ASC");
const LOG_SEGMENTS_OLDER_SQL: &str = log_segment_page_sql!("segment.first_sequence < $6", "DESC");

fn decode_log_segment(row: &PgRow) -> Result<HumanLogSegment, StoreError> {
    let first = nonnegative_u64(
        row.try_get("first_sequence").map_err(operation_error)?,
        "log segment first sequence",
    )?;
    let last = nonnegative_u64(
        row.try_get("last_sequence").map_err(operation_error)?,
        "log segment last sequence",
    )?;
    if last < first {
        return Err(StoreError::corrupt_data(
            "log segment sequence range is inverted",
        ));
    }
    let encoded_size = positive_u64(
        row.try_get("encoded_size_bytes").map_err(operation_error)?,
        "log segment encoded size",
    )?;
    Ok(HumanLogSegment {
        first_sequence: LogSequence::new(first),
        last_sequence: LogSequence::new(last),
        descriptor: blob_descriptor(
            row.try_get("object_key").map_err(operation_error)?,
            decode_digest(
                row.try_get("object_digest").map_err(operation_error)?,
                "log segment digest",
            )?,
            encoded_size,
            HUMAN_LOG_SEGMENT_MEDIA_TYPE.to_owned(),
        )?,
        uncompressed_size: positive_u64(
            row.try_get("uncompressed_size_bytes")
                .map_err(operation_error)?,
            "log segment uncompressed size",
        )?,
        stored_at: UnixMillis::new(row.try_get("stored_at_ms").map_err(operation_error)?),
        end_of_stream: row.try_get("end_of_stream").map_err(operation_error)?,
    })
}

fn validate_segment_page(segments: &[HumanLogSegment]) -> Result<(), StoreError> {
    for pair in segments.windows(2) {
        let expected = pair[0]
            .last_sequence
            .checked_next()
            .map_err(|_| StoreError::corrupt_data("log segment sequence is exhausted"))?;
        if pair[1].first_sequence != expected || pair[0].end_of_stream {
            return Err(StoreError::corrupt_data(
                "log segment page is non-contiguous",
            ));
        }
    }
    Ok(())
}

fn next_segment_cursor(segment: &HumanLogSegment) -> Result<HumanLogSegmentCursor, StoreError> {
    Ok(HumanLogSegmentCursor {
        sequence: segment
            .last_sequence
            .checked_next()
            .map_err(|_| StoreError::corrupt_data("log segment sequence is exhausted"))?,
        direction: HumanLogSegmentPageDirection::Newer,
    })
}

#[allow(clippy::too_many_lines)]
async fn get_artifact(
    store: &PostgresStore,
    scope: &HumanArtifactScope,
) -> Result<Option<HumanArtifactDownload>, StoreError> {
    let mut transaction = begin_read(store).await?;
    let row = sqlx::query(
        r"
        SELECT artifact.id, artifact.name, artifact.mime_type,
               artifact.content_size_bytes, artifact.content_digest,
               artifact.expires_at_seconds, artifact.finalized_at_seconds,
               artifact.secret_exposure_class,
               artifact.requested_visibility, artifact.effective_visibility,
               artifact.publication_safety_reason,
               artifact.publication_safety_schema,
               artifact.manifest_object_key, artifact.manifest_digest,
               artifact.manifest_size_bytes, artifact.manifest_media_type,
               committed.list_digest, committed.size_bytes AS committed_size_bytes,
               committed.committed_at_seconds,
               cardinality(committed.block_ids) AS committed_block_count
        FROM repositories AS repository
        JOIN workflow_runs AS run
          ON run.repository_id = repository.id
        JOIN workflow_artifacts AS artifact
          ON artifact.tenant_id = repository.tenant_id
         AND artifact.repository_id = repository.id
         AND artifact.run_id = run.id
        JOIN workflow_artifact_block_commits AS committed
          ON committed.artifact_id = artifact.id
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND run.id = $3
          AND artifact.id = $4
          AND artifact.state = 'finalized'
          AND artifact.manifest_state = 'ready'
          AND (
                artifact.expires_at_seconds IS NULL
                OR artifact.expires_at_seconds > $5
          )
        ",
    )
    .bind(scope.tenant.as_str())
    .bind(scope.repository_id.as_uuid())
    .bind(scope.run_id.as_uuid())
    .bind(scope.artifact_id.get())
    .bind(scope.observed_at_seconds)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let artifact = decode_artifact_summary(&row)?;
    let manifest_size = positive_u64(
        row.try_get("manifest_size_bytes")
            .map_err(operation_error)?,
        "artifact manifest size",
    )?;
    let manifest = blob_descriptor(
        row.try_get("manifest_object_key")
            .map_err(operation_error)?,
        decode_digest(
            row.try_get("manifest_digest").map_err(operation_error)?,
            "artifact manifest digest",
        )?,
        manifest_size,
        row.try_get("manifest_media_type")
            .map_err(operation_error)?,
    )?;
    let block_list_digest = decode_digest(
        row.try_get("list_digest").map_err(operation_error)?,
        "artifact block-list digest",
    )?;
    let committed_size = nonnegative_u64(
        row.try_get("committed_size_bytes")
            .map_err(operation_error)?,
        "committed artifact size",
    )?;
    if committed_size != artifact.content_size {
        return Err(StoreError::corrupt_data(
            "artifact commit size contradicts finalized content size",
        ));
    }
    let block_count: i32 = row
        .try_get("committed_block_count")
        .map_err(operation_error)?;
    let block_count = validated_artifact_block_count(block_count)?;

    let rows = sqlx::query(
        r"
        SELECT ordered.ordinal, ordered.block_id,
               block.object_key, block.digest,
               block.size_bytes, block.media_type
        FROM repositories AS repository
        JOIN workflow_runs AS run
          ON run.repository_id = repository.id
        JOIN workflow_artifacts AS artifact
          ON artifact.tenant_id = repository.tenant_id
         AND artifact.repository_id = repository.id
         AND artifact.run_id = run.id
        JOIN workflow_artifact_block_commits AS committed
          ON committed.artifact_id = artifact.id
        CROSS JOIN LATERAL unnest(committed.block_ids)
          WITH ORDINALITY AS ordered(block_id, ordinal)
        JOIN workflow_artifact_blocks AS block
          ON block.artifact_id = artifact.id
         AND block.block_id = ordered.block_id
         AND block.state = 'ready'
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND run.id = $3
          AND artifact.id = $4
          AND artifact.state = 'finalized'
          AND artifact.manifest_state = 'ready'
          AND (
                artifact.expires_at_seconds IS NULL
                OR artifact.expires_at_seconds > $5
          )
        ORDER BY ordered.ordinal
        LIMIT $6
        ",
    )
    .bind(scope.tenant.as_str())
    .bind(scope.repository_id.as_uuid())
    .bind(scope.run_id.as_uuid())
    .bind(scope.artifact_id.get())
    .bind(scope.observed_at_seconds)
    .bind(i64::try_from(MAX_ARTIFACT_BLOCKS + 1).expect("artifact block bound fits BIGINT"))
    .fetch_all(&mut *transaction)
    .await
    .map_err(operation_error)?;
    transaction.commit().await.map_err(operation_error)?;
    if rows.len() != block_count {
        return Err(StoreError::corrupt_data(
            "artifact commit references a missing or unreadied block",
        ));
    }
    let blocks = rows
        .iter()
        .map(decode_artifact_block)
        .collect::<Result<Vec<_>, _>>()?;
    let total_size = blocks.iter().try_fold(0_u64, |total, block| {
        total
            .checked_add(block.descriptor.size())
            .ok_or_else(|| StoreError::corrupt_data("artifact block size sum overflowed"))
    })?;
    if total_size != committed_size {
        return Err(StoreError::corrupt_data(
            "artifact ready blocks contradict the committed size",
        ));
    }
    Ok(Some(HumanArtifactDownload {
        artifact,
        manifest,
        block_list_digest,
        committed_at_seconds: row
            .try_get("committed_at_seconds")
            .map_err(operation_error)?,
        blocks,
    }))
}

fn decode_artifact_block(row: &PgRow) -> Result<HumanArtifactBlock, StoreError> {
    let ordinal: i64 = row.try_get("ordinal").map_err(operation_error)?;
    let ordinal = u32::try_from(ordinal)
        .ok()
        .filter(|ordinal| *ordinal > 0)
        .ok_or_else(|| StoreError::corrupt_data("artifact block ordinal is invalid"))?;
    let size = nonnegative_u64(
        row.try_get("size_bytes").map_err(operation_error)?,
        "artifact block size",
    )?;
    Ok(HumanArtifactBlock {
        ordinal,
        block_id: row.try_get("block_id").map_err(operation_error)?,
        descriptor: blob_descriptor(
            row.try_get("object_key").map_err(operation_error)?,
            decode_digest(
                row.try_get("digest").map_err(operation_error)?,
                "artifact block digest",
            )?,
            size,
            row.try_get("media_type").map_err(operation_error)?,
        )?,
    })
}

#[derive(Clone, Debug)]
struct RepositoryAuthorization {
    repository: HumanRepository,
    rbac: RbacPolicy,
    authorization_revision_current: bool,
}

impl RepositoryAuthorization {
    fn allows(
        &self,
        context: &AuthorizationContext,
        permission: &Permission,
        durable_visibility: Option<OutputVisibility>,
    ) -> bool {
        let request = AuthorizationRequest::new(
            AuthorizationScope::repository(self.repository.resource.clone()),
            permission.clone(),
        );
        self.allows_request(context, &request, durable_visibility)
    }

    fn allows_request(
        &self,
        context: &AuthorizationContext,
        request: &AuthorizationRequest,
        durable_visibility: Option<OutputVisibility>,
    ) -> bool {
        if !self.authorization_revision_current {
            return false;
        }
        let policy = publication_with_ceiling(
            self.repository.publication,
            request.permission(),
            durable_visibility,
        );
        let authorization = CompositeAuthorizationPolicy::new(
            self.rbac.clone(),
            BTreeMap::from([(self.repository.resource.clone(), policy)]),
        );
        authorization.allows(context, request)
    }
}

async fn authorize_repository_request(
    store: &PostgresStore,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    context: &AuthorizationContext,
    target: &HumanAuthorizationTarget,
) -> Result<bool, StoreError> {
    let Some(requested_repository) = target.request.scope().repository_resource() else {
        return Ok(false);
    };
    if requested_repository.tenant_id().as_str() != tenant.as_str()
        || requested_repository.repository_id().as_uuid() != repository_id.as_uuid()
    {
        return Ok(false);
    }
    let mut transaction = begin_read(store).await?;
    let Some(authorization) = load_repository_authorization(
        &mut transaction,
        tenant,
        repository_id,
        context,
        target.request.permission(),
    )
    .await?
    else {
        return Ok(false);
    };
    let allowed = authorization.allows_request(context, &target.request, target.durable_visibility);
    transaction.commit().await.map_err(operation_error)?;
    Ok(allowed)
}

async fn load_repository_authorization(
    connection: &mut PgConnection,
    tenant: &TenantScope,
    repository_id: RepositoryId,
    context: &AuthorizationContext,
    permission: &Permission,
) -> Result<Option<RepositoryAuthorization>, StoreError> {
    // Bound the authority carried by the request before observing whether the
    // target repository exists. Both existing and absent targets therefore
    // fail identically when the exact-resource role expansion is excessive.
    let role_names = context_repository_role_names(context, tenant, Some(repository_id.as_uuid()))?;
    let row = sqlx::query(
        r"
        SELECT repository.id, repository.tenant_id,
               repository.scm_provider, repository.provider_repository_id,
               repository.owner, repository.name,
               policy.dashboard_audience, policy.log_audience,
               policy.artifact_audience, policy.revision AS publication_revision
        FROM repositories AS repository
        LEFT JOIN repository_publication_policies AS policy
          ON policy.tenant_id = repository.tenant_id
         AND policy.repository_id = repository.id
        WHERE repository.tenant_id = $1 AND repository.id = $2
        ",
    )
    .bind(tenant.as_str())
    .bind(repository_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let repository = decode_repository(&row)?;
    let rbac = load_rbac_policy(
        connection,
        tenant,
        context,
        role_names.as_deref(),
        permission,
    )
    .await?;
    Ok(Some(RepositoryAuthorization {
        repository,
        rbac: rbac.policy,
        authorization_revision_current: rbac.authorization_revision_current,
    }))
}

struct LoadedRbacPolicy {
    policy: RbacPolicy,
    authorization_revision_current: bool,
}

impl LoadedRbacPolicy {
    fn current(policy: RbacPolicy) -> Self {
        Self {
            policy,
            authorization_revision_current: true,
        }
    }

    fn stale() -> Self {
        Self {
            policy: RbacPolicy::default(),
            authorization_revision_current: false,
        }
    }
}

const RBAC_POLICY_AT_REVISION_SQL: &str = r"
    SELECT role.id AS role_id, role.name AS role_name,
           permission_grant.permission_name
    FROM tenant_human_memberships AS membership
    JOIN human_principals AS principal
      ON principal.id = membership.principal_id
     AND principal.status = 'active'
    LEFT JOIN rbac_roles AS role
      ON role.tenant_id = membership.tenant_id
     AND role.name = ANY($4)
    LEFT JOIN rbac_role_permissions AS permission_grant
      ON permission_grant.tenant_id = role.tenant_id
     AND permission_grant.role_id = role.id
     AND permission_grant.permission_name = $5
    WHERE membership.tenant_id = $1
      AND membership.principal_id = $2
      AND membership.status = 'active'
      AND membership.authorization_revision = $3
    ORDER BY role.name, role.id, permission_grant.permission_name
    LIMIT $6
";

const RBAC_POLICY_SQL: &str = r"
    SELECT role.id AS role_id, role.name AS role_name,
           permission_grant.permission_name
    FROM rbac_roles AS role
    LEFT JOIN rbac_role_permissions AS permission_grant
      ON permission_grant.tenant_id = role.tenant_id
     AND permission_grant.role_id = role.id
     AND permission_grant.permission_name = $3
    WHERE role.tenant_id = $1
      AND role.name = ANY($2)
    ORDER BY role.name, role.id, permission_grant.permission_name
    LIMIT $4
";

fn enforce_repository_rbac_limit(
    count: usize,
    maximum: usize,
) -> Result<(), RepositoryRbacLoadExceeded> {
    if count > maximum {
        Err(RepositoryRbacLoadExceeded)
    } else {
        Ok(())
    }
}

fn repository_rbac_query_limit() -> Result<i64, StoreError> {
    MAX_REPOSITORY_RBAC_ROWS
        .checked_add(1)
        .and_then(|limit| i64::try_from(limit).ok())
        .ok_or_else(|| StoreError::operation(RepositoryRbacLoadExceeded))
}

fn repository_role_names(
    grants: &BTreeSet<ScopedRoleGrant>,
    tenant: &TenantScope,
    repository_id: Option<Uuid>,
) -> Result<Vec<String>, RepositoryRbacLoadExceeded> {
    // Repository reads can never consume runner-group grants. Exact reads also
    // discard sibling-repository grants before the role/permission SQL query;
    // listings retain repository grants because each scanned row is a candidate.
    let mut role_names = BTreeSet::new();
    for grant in grants {
        let applies = match grant.scope() {
            AuthorizationScope::Tenant { tenant_id } => tenant_id.as_str() == tenant.as_str(),
            AuthorizationScope::Repository {
                repository: granted,
            } => {
                granted.tenant_id().as_str() == tenant.as_str()
                    && repository_id.is_none_or(|requested_id| {
                        granted.repository_id().as_uuid() == requested_id
                    })
            }
            AuthorizationScope::RunnerGroup { .. } => false,
        };
        if applies && role_names.insert(grant.role().as_str().to_owned()) {
            enforce_repository_rbac_limit(role_names.len(), MAX_REPOSITORY_RBAC_ROLE_NAMES)?;
        }
    }
    Ok(role_names.into_iter().collect())
}

fn context_repository_role_names(
    context: &AuthorizationContext,
    tenant: &TenantScope,
    repository_id: Option<Uuid>,
) -> Result<Option<Vec<String>>, StoreError> {
    if context
        .tenant_id()
        .is_some_and(|context_tenant| context_tenant.as_str() != tenant.as_str())
    {
        return Ok(None);
    }
    let Some(grants) = context.role_grants() else {
        return Ok(None);
    };
    repository_role_names(grants, tenant, repository_id)
        .map(Some)
        .map_err(StoreError::operation)
}

#[derive(Clone, Debug)]
struct DurableRepositoryRbacRow {
    role_id: Option<Uuid>,
    role_name: Option<String>,
    permission_name: Option<String>,
}

fn assemble_repository_rbac_policy(
    rows: impl IntoIterator<Item = DurableRepositoryRbacRow>,
    expected_role_names: &[String],
    requested_permission: &Permission,
) -> Result<RbacPolicy, StoreError> {
    let expected_roles = expected_role_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected_roles.len() != expected_role_names.len() {
        return Err(StoreError::corrupt_data(
            "repository RBAC query contains duplicate requested role names",
        ));
    }

    // Authorization contexts intentionally carry stable role names rather
    // than durable database IDs. Bind the returned name to exactly one ID and
    // require one row per requested role so corrupt duplicate roles or
    // permission rows can never be folded into a broader policy.
    let mut durable_roles = BTreeMap::<RoleName, Uuid>::new();
    let mut durable_role_ids = BTreeSet::<Uuid>::new();
    let mut permissions = BTreeMap::<RoleName, BTreeSet<Permission>>::new();
    let mut membership_sentinel_seen = false;
    for row in rows {
        let (role_id, role_name) = match (row.role_id, row.role_name) {
            (None, None) if row.permission_name.is_none() => {
                if membership_sentinel_seen {
                    return Err(StoreError::corrupt_data(
                        "durable RBAC membership join returned duplicate sentinel rows",
                    ));
                }
                membership_sentinel_seen = true;
                continue;
            }
            (Some(role_id), Some(role_name)) if !role_id.is_nil() => (role_id, role_name),
            _ => {
                return Err(StoreError::corrupt_data(
                    "durable RBAC role and permission join is inconsistent",
                ));
            }
        };
        let role = RoleName::new(role_name)
            .map_err(|_| StoreError::corrupt_data("durable RBAC role name is invalid"))?;
        if !expected_roles.contains(role.as_str())
            || durable_roles.insert(role.clone(), role_id).is_some()
            || !durable_role_ids.insert(role_id)
        {
            return Err(StoreError::corrupt_data(
                "durable RBAC roles or permission grants are not unique",
            ));
        }
        let Some(permission_name) = row.permission_name else {
            continue;
        };
        let permission = Permission::new(permission_name)
            .map_err(|_| StoreError::corrupt_data("durable RBAC permission name is invalid"))?;
        if &permission != requested_permission {
            return Err(StoreError::corrupt_data(
                "durable RBAC permission does not match the requested permission",
            ));
        }
        permissions.entry(role).or_default().insert(permission);
    }
    if (membership_sentinel_seen && !durable_roles.is_empty())
        || durable_roles.len() != expected_roles.len()
    {
        return Err(StoreError::corrupt_data(
            "durable RBAC role set does not exactly match the requested roles",
        ));
    }
    Ok(RbacPolicy::new(permissions))
}

async fn load_rbac_policy(
    connection: &mut PgConnection,
    tenant: &TenantScope,
    context: &AuthorizationContext,
    role_names: Option<&[String]>,
    requested_permission: &Permission,
) -> Result<LoadedRbacPolicy, StoreError> {
    let Some(role_names) = role_names else {
        return Ok(LoadedRbacPolicy::current(RbacPolicy::default()));
    };
    let query_limit = repository_rbac_query_limit()?;
    let rows = if let Some(expected_revision) = context.authorization_revision() {
        let Some(principal_id) = context.principal_id() else {
            return Ok(LoadedRbacPolicy::stale());
        };
        let principal_id = Uuid::parse_str(principal_id.as_str())
            .map_err(|_| StoreError::corrupt_data("authenticated principal ID is not a UUID"))?;
        let expected_revision = i64::try_from(expected_revision).map_err(|_| {
            StoreError::corrupt_data("authenticated authorization revision exceeds BIGINT")
        })?;
        sqlx::query(RBAC_POLICY_AT_REVISION_SQL)
            .bind(tenant.as_str())
            .bind(principal_id)
            .bind(expected_revision)
            .bind(role_names)
            .bind(requested_permission.as_str())
            .bind(query_limit)
            .fetch_all(&mut *connection)
            .await
            .map_err(operation_error)?
    } else if role_names.is_empty() {
        return Ok(LoadedRbacPolicy::current(RbacPolicy::default()));
    } else {
        sqlx::query(RBAC_POLICY_SQL)
            .bind(tenant.as_str())
            .bind(role_names)
            .bind(requested_permission.as_str())
            .bind(query_limit)
            .fetch_all(&mut *connection)
            .await
            .map_err(operation_error)?
    };
    enforce_repository_rbac_limit(rows.len(), MAX_REPOSITORY_RBAC_ROWS)
        .map_err(StoreError::operation)?;
    if context.authorization_revision().is_some() && rows.is_empty() {
        return Ok(LoadedRbacPolicy::stale());
    }
    let durable_rows = rows
        .into_iter()
        .map(|row| {
            Ok(DurableRepositoryRbacRow {
                role_id: row
                    .try_get::<Option<Uuid>, _>("role_id")
                    .map_err(operation_error)?,
                role_name: row
                    .try_get::<Option<String>, _>("role_name")
                    .map_err(operation_error)?,
                permission_name: row
                    .try_get::<Option<String>, _>("permission_name")
                    .map_err(operation_error)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let policy = assemble_repository_rbac_policy(durable_rows, role_names, requested_permission)?;
    Ok(LoadedRbacPolicy::current(policy))
}

fn publication_with_ceiling(
    policy: RepositoryPublicationPolicy,
    permission: &Permission,
    ceiling: Option<OutputVisibility>,
) -> RepositoryPublicationPolicy {
    let Some(ceiling) = ceiling else {
        return policy;
    };
    match permission.as_str() {
        repository_read_permissions::REPOSITORY_READ
        | repository_read_permissions::WORKFLOW_READ
        | repository_read_permissions::RUN_READ
        | repository_read_permissions::JOB_READ => {
            RepositoryPublicationPolicy::new(ceiling, policy.logs(), policy.artifacts())
        }
        repository_read_permissions::LOG_READ => {
            RepositoryPublicationPolicy::new(policy.dashboard(), ceiling, policy.artifacts())
        }
        repository_read_permissions::ARTIFACT_READ
        | repository_read_permissions::ARTIFACT_DOWNLOAD => {
            RepositoryPublicationPolicy::new(policy.dashboard(), policy.logs(), ceiling)
        }
        _ => policy,
    }
}

async fn list_authorized_repositories(
    store: &PostgresStore,
    query: &HumanRepositoryListQuery,
    context: &AuthorizationContext,
    permissions: &[Permission],
) -> Result<HumanRepositoryPage, StoreError> {
    if !valid_repository_discovery_permissions(permissions) {
        return Ok(HumanRepositoryPage {
            repositories: Vec::new(),
            next_cursor: None,
        });
    }
    let role_names = context_repository_role_names(context, &query.tenant, None)?;
    let mut transaction = begin_read(store).await?;
    let mut policies = Vec::with_capacity(permissions.len());
    for permission in permissions {
        let policy = load_rbac_policy(
            &mut transaction,
            &query.tenant,
            context,
            role_names.as_deref(),
            permission,
        )
        .await?;
        policies.push((permission, policy));
    }
    let filter = repository_discovery_filter(context, &query.tenant, &policies)?;
    if filter.is_empty() {
        transaction.commit().await.map_err(operation_error)?;
        return Ok(HumanRepositoryPage {
            repositories: Vec::new(),
            next_cursor: None,
        });
    }
    let wanted = usize::from(query.limit.get()) + 1;
    let rows = fetch_authorized_repository_page(
        &mut transaction,
        &query.tenant,
        query.cursor.as_ref(),
        &filter,
        wanted,
    )
    .await?;
    let has_more = rows.len() > usize::from(query.limit.get());
    let authorized = rows
        .iter()
        .take(usize::from(query.limit.get()))
        .map(|row| Ok((decode_repository(row)?, decode_repository_cursor(row)?)))
        .collect::<Result<Vec<_>, StoreError>>()?;
    let next_cursor = if has_more {
        authorized.last().map(|(_, cursor)| cursor.clone())
    } else {
        None
    };
    let page = HumanRepositoryPage {
        repositories: authorized
            .into_iter()
            .map(|(repository, _)| repository)
            .collect(),
        next_cursor,
    };
    transaction.commit().await.map_err(operation_error)?;
    Ok(page)
}

fn valid_repository_discovery_permissions(permissions: &[Permission]) -> bool {
    if permissions.is_empty() || permissions.len() > MAX_REPOSITORY_DISCOVERY_PERMISSIONS {
        return false;
    }
    let mut seen = BTreeSet::new();
    permissions.iter().all(|permission| {
        matches!(
            permission.as_str(),
            repository_read_permissions::REPOSITORY_READ | SECRET_METADATA_READ_PERMISSION
        ) && seen.insert(permission.as_str())
    })
}

#[derive(Debug, Default, Eq, PartialEq)]
struct RepositoryDiscoveryFilter {
    publication_audience: Option<&'static str>,
    all_repositories: bool,
    repository_ids: Vec<Uuid>,
}

impl RepositoryDiscoveryFilter {
    const fn is_empty(&self) -> bool {
        self.publication_audience.is_none()
            && !self.all_repositories
            && self.repository_ids.is_empty()
    }
}

fn repository_discovery_filter(
    context: &AuthorizationContext,
    tenant: &TenantScope,
    policies: &[(&Permission, LoadedRbacPolicy)],
) -> Result<RepositoryDiscoveryFilter, StoreError> {
    if context
        .tenant_id()
        .is_some_and(|context_tenant| context_tenant.as_str() != tenant.as_str())
    {
        return Ok(RepositoryDiscoveryFilter::default());
    }
    let repository_read_current = policies.iter().any(|(permission, policy)| {
        permission.as_str() == repository_read_permissions::REPOSITORY_READ
            && policy.authorization_revision_current
    });
    let publication_audience =
        repository_read_current.then_some(if context.tenant_id().is_some() {
            "authenticated"
        } else {
            "public"
        });
    let Some(grants) = context.role_grants() else {
        return Ok(RepositoryDiscoveryFilter {
            publication_audience,
            ..RepositoryDiscoveryFilter::default()
        });
    };
    let all_repositories = policies.iter().any(|(permission, policy)| {
        policy.authorization_revision_current
            && grants.iter().any(|grant| {
                matches!(
                    grant.scope(),
                    AuthorizationScope::Tenant { tenant_id }
                        if tenant_id.as_str() == tenant.as_str()
                ) && policy.policy.allows([grant.role()], permission)
            })
    });
    if all_repositories {
        return Ok(RepositoryDiscoveryFilter {
            publication_audience,
            all_repositories,
            repository_ids: Vec::new(),
        });
    }
    let mut repository_ids = BTreeSet::new();
    for (permission, policy) in policies {
        if !policy.authorization_revision_current {
            continue;
        }
        for grant in grants {
            if !policy.policy.allows([grant.role()], permission) {
                continue;
            }
            if let AuthorizationScope::Repository { repository } = grant.scope()
                && repository.tenant_id().as_str() == tenant.as_str()
            {
                repository_ids.insert(repository.repository_id().as_uuid());
                enforce_repository_rbac_limit(
                    repository_ids.len(),
                    MAX_REPOSITORY_DISCOVERY_SCOPES,
                )
                .map_err(StoreError::operation)?;
            }
        }
    }
    Ok(RepositoryDiscoveryFilter {
        publication_audience,
        all_repositories,
        repository_ids: repository_ids.into_iter().collect(),
    })
}

async fn fetch_authorized_repository_page(
    connection: &mut PgConnection,
    tenant: &TenantScope,
    cursor: Option<&HumanRepositoryCursor>,
    filter: &RepositoryDiscoveryFilter,
    limit: usize,
) -> Result<Vec<PgRow>, StoreError> {
    let limit = i64::try_from(limit)
        .map_err(|_| StoreError::corrupt_data("repository page bound is invalid"))?;
    if let Some(cursor) = cursor {
        sqlx::query(REPOSITORIES_AFTER_SQL)
            .bind(tenant.as_str())
            .bind(filter.publication_audience)
            .bind(filter.all_repositories)
            .bind(filter.repository_ids.as_slice())
            .bind(&cursor.normalized_owner)
            .bind(&cursor.normalized_name)
            .bind(cursor.id.as_uuid())
            .bind(limit)
            .fetch_all(connection)
            .await
            .map_err(operation_error)
    } else {
        sqlx::query(REPOSITORIES_FIRST_SQL)
            .bind(tenant.as_str())
            .bind(filter.publication_audience)
            .bind(filter.all_repositories)
            .bind(filter.repository_ids.as_slice())
            .bind(limit)
            .fetch_all(connection)
            .await
            .map_err(operation_error)
    }
}

const REPOSITORIES_FIRST_SQL: &str = r"
    SELECT repository.id, repository.tenant_id,
           repository.scm_provider, repository.provider_repository_id,
           repository.owner, repository.name,
           lower(repository.owner) AS normalized_owner,
           lower(repository.name) AS normalized_name,
           policy.dashboard_audience, policy.log_audience,
           policy.artifact_audience, policy.revision AS publication_revision
    FROM repositories AS repository
    LEFT JOIN repository_publication_policies AS policy
      ON policy.tenant_id = repository.tenant_id
     AND policy.repository_id = repository.id
    WHERE repository.tenant_id = $1
      AND (
            ($2::TEXT = 'public' AND policy.dashboard_audience = 'public')
            OR (
                $2::TEXT = 'authenticated'
                AND policy.dashboard_audience IN ('public', 'authenticated')
            )
            OR $3::BOOLEAN
            OR repository.id = ANY($4::UUID[])
      )
    ORDER BY lower(repository.owner), lower(repository.name), repository.id
    LIMIT $5
";

const REPOSITORIES_AFTER_SQL: &str = r"
    SELECT repository.id, repository.tenant_id,
           repository.scm_provider, repository.provider_repository_id,
           repository.owner, repository.name,
           lower(repository.owner) AS normalized_owner,
           lower(repository.name) AS normalized_name,
           policy.dashboard_audience, policy.log_audience,
           policy.artifact_audience, policy.revision AS publication_revision
    FROM repositories AS repository
    LEFT JOIN repository_publication_policies AS policy
      ON policy.tenant_id = repository.tenant_id
     AND policy.repository_id = repository.id
    WHERE repository.tenant_id = $1
      AND (
            ($2::TEXT = 'public' AND policy.dashboard_audience = 'public')
            OR (
                $2::TEXT = 'authenticated'
                AND policy.dashboard_audience IN ('public', 'authenticated')
            )
            OR $3::BOOLEAN
            OR repository.id = ANY($4::UUID[])
      )
      AND (lower(repository.owner), lower(repository.name), repository.id) > ($5, $6, $7)
    ORDER BY lower(repository.owner), lower(repository.name), repository.id
    LIMIT $8
";

fn decode_repository_cursor(row: &PgRow) -> Result<HumanRepositoryCursor, StoreError> {
    Ok(HumanRepositoryCursor {
        normalized_owner: row.try_get("normalized_owner").map_err(operation_error)?,
        normalized_name: row.try_get("normalized_name").map_err(operation_error)?,
        id: RepositoryId::from_uuid(row.try_get("id").map_err(operation_error)?),
    })
}

#[derive(Debug, Error)]
#[error("repository RBAC load exceeded its hard bound")]
struct RepositoryRbacLoadExceeded;

fn decode_output_publication(
    row: &PgRow,
    reason_column: &str,
    schema_column: &str,
) -> Result<HumanOutputPublication, StoreError> {
    let exposure = row
        .try_get::<String, _>("secret_exposure_class")
        .map_err(operation_error)?;
    let secret_exposure = match exposure.as_str() {
        "secretless" => SecretExposureClass::Secretless,
        "capability_only" => SecretExposureClass::CapabilityOnly,
        "readable_secret" => SecretExposureClass::ReadableSecret,
        _ => {
            return Err(StoreError::corrupt_data(
                "durable secret exposure class is unknown",
            ));
        }
    };
    Ok(HumanOutputPublication {
        secret_exposure,
        requested_visibility: required_visibility(row, "requested_visibility")?,
        effective_visibility: required_visibility(row, "effective_visibility")?,
        safety_reason: row.try_get(reason_column).map_err(operation_error)?,
        safety_schema: positive_u16(
            row.try_get(schema_column).map_err(operation_error)?,
            "output publication safety schema",
        )?,
    })
}

fn required_visibility(row: &PgRow, column: &str) -> Result<OutputVisibility, StoreError> {
    let value: Option<String> = row.try_get(column).map_err(operation_error)?;
    value
        .as_deref()
        .ok_or_else(|| StoreError::corrupt_data("repository publication policy is missing"))
        .and_then(parse_visibility)
}

fn parse_visibility(value: &str) -> Result<OutputVisibility, StoreError> {
    match value {
        "private" => Ok(OutputVisibility::Private),
        "authenticated" => Ok(OutputVisibility::Authenticated),
        "public" => Ok(OutputVisibility::Public),
        _ => Err(StoreError::corrupt_data(
            "durable output visibility is unknown",
        )),
    }
}

fn decode_digest(bytes: Vec<u8>, field: &'static str) -> Result<Sha256Digest, StoreError> {
    let length = bytes.len();
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::corrupt_data(format!("{field} has {length} bytes")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn positive_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data(format!("{field} is not positive")))
}

fn nonnegative_u64(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::corrupt_data(format!("{field} is negative")))
}

fn positive_u32(value: i32, field: &'static str) -> Result<u32, StoreError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data(format!("{field} is not positive")))
}

fn positive_u16(value: i32, field: &'static str) -> Result<u16, StoreError> {
    u16::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| StoreError::corrupt_data(format!("{field} is outside the schema range")))
}

fn validated_artifact_block_count(value: i32) -> Result<usize, StoreError> {
    let value = usize::try_from(value)
        .map_err(|_| StoreError::corrupt_data("artifact block count is negative"))?;
    if value > MAX_ARTIFACT_BLOCKS {
        return Err(StoreError::corrupt_data(
            "artifact commit exceeds the product block bound",
        ));
    }
    Ok(value)
}

fn operation_error(error: sqlx::Error) -> StoreError {
    StoreError::operation(error)
}

#[cfg(test)]
mod tests {
    use super::{
        DurableRepositoryRbacRow, LoadedRbacPolicy, MAX_ARTIFACT_BLOCKS,
        MAX_REPOSITORY_DISCOVERY_SCOPES, MAX_REPOSITORY_RBAC_ROLE_NAMES, MAX_REPOSITORY_RBAC_ROWS,
        RBAC_POLICY_AT_REVISION_SQL, RBAC_POLICY_SQL, REPOSITORIES_AFTER_SQL,
        REPOSITORIES_FIRST_SQL, RepositoryDiscoveryFilter, assemble_repository_rbac_policy,
        enforce_repository_rbac_limit, repository_discovery_filter, repository_rbac_query_limit,
        repository_role_names, valid_repository_discovery_permissions,
        validated_artifact_block_count,
    };
    use crate::{StoreError, TenantScope};
    use automata_ci_auth::{
        authorization::{
            AuthorizationContext, AuthorizationScope, Permission, RbacPolicy, RepositoryResource,
            RepositoryResourceId, RoleName, RunnerGroupResource, RunnerGroupResourceId,
            ScopedRoleGrant,
        },
        human::{PrincipalId, TenantId},
    };
    use std::collections::{BTreeMap, BTreeSet};
    use uuid::Uuid;

    #[test]
    fn repository_discovery_accepts_only_the_bounded_exact_permission_union() {
        let repository_read = Permission::new("repositories:read").expect("repository read");
        let secret_metadata =
            Permission::new("secrets:metadata:read").expect("secret metadata read");

        assert!(valid_repository_discovery_permissions(
            std::slice::from_ref(&repository_read)
        ));
        assert!(valid_repository_discovery_permissions(
            std::slice::from_ref(&secret_metadata)
        ));
        assert!(valid_repository_discovery_permissions(&[
            repository_read.clone(),
            secret_metadata.clone(),
        ]));
        assert!(!valid_repository_discovery_permissions(&[]));
        assert!(!valid_repository_discovery_permissions(&[
            repository_read.clone(),
            repository_read,
        ]));
        assert!(!valid_repository_discovery_permissions(&[
            secret_metadata.clone(),
            secret_metadata,
        ]));
        assert!(!valid_repository_discovery_permissions(&[Permission::new(
            "runs:read"
        )
        .expect("unsupported discovery permission"),]));
    }

    #[test]
    fn repository_discovery_filters_authority_inside_each_keyset_query() {
        for sql in [REPOSITORIES_FIRST_SQL, REPOSITORIES_AFTER_SQL] {
            let authorization = sql
                .find("OR repository.id = ANY($4::UUID[])")
                .expect("exact repository authorization predicate");
            let ordering = sql
                .find("ORDER BY lower(repository.owner)")
                .expect("keyset ordering");
            let limit = sql.rfind("LIMIT $").expect("bounded lookahead");
            assert!(authorization < ordering);
            assert!(ordering < limit);
        }
    }

    #[test]
    fn repository_discovery_projects_publication_and_exact_scoped_grants() {
        let tenant = TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant");
        let tenant_id = TenantId::new("tenant-a").expect("tenant ID");
        let repository_id = Uuid::new_v4();
        let repository = RepositoryResource::new(
            tenant_id.clone(),
            RepositoryResourceId::from_uuid(repository_id).expect("repository ID"),
        );
        let repository_read = Permission::new("repositories:read").expect("repository read");
        let secret_metadata =
            Permission::new("secrets:metadata:read").expect("secret metadata read");
        let secret_reader = RoleName::new("secret-reader").expect("role");
        let secret_policy = RbacPolicy::new(BTreeMap::from([(
            secret_reader.clone(),
            BTreeSet::from([secret_metadata.clone()]),
        )]));
        let anonymous_policy = LoadedRbacPolicy::current(RbacPolicy::default());
        assert_eq!(
            repository_discovery_filter(
                &AuthorizationContext::anonymous(),
                &tenant,
                &[(&repository_read, anonymous_policy)],
            )
            .expect("anonymous discovery filter"),
            RepositoryDiscoveryFilter {
                publication_audience: Some("public"),
                ..RepositoryDiscoveryFilter::default()
            }
        );

        let exact_context = AuthorizationContext::authenticated(
            tenant_id.clone(),
            PrincipalId::new("principal-a").expect("principal"),
            BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::repository(repository),
                secret_reader.clone(),
            )]),
        )
        .expect("authorization context");
        let repository_policy = LoadedRbacPolicy::current(RbacPolicy::default());
        let secret_policy = LoadedRbacPolicy::current(secret_policy);
        assert_eq!(
            repository_discovery_filter(
                &exact_context,
                &tenant,
                &[
                    (&repository_read, repository_policy),
                    (&secret_metadata, secret_policy),
                ],
            )
            .expect("exact discovery filter"),
            RepositoryDiscoveryFilter {
                publication_audience: Some("authenticated"),
                all_repositories: false,
                repository_ids: vec![repository_id],
            }
        );

        let tenant_context = AuthorizationContext::authenticated(
            tenant_id.clone(),
            PrincipalId::new("principal-b").expect("principal"),
            BTreeSet::from([ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id),
                secret_reader,
            )]),
        )
        .expect("authorization context");
        assert_eq!(
            repository_discovery_filter(
                &tenant_context,
                &tenant,
                &[(
                    &secret_metadata,
                    LoadedRbacPolicy::current(RbacPolicy::new(BTreeMap::from([(
                        RoleName::new("secret-reader").expect("role"),
                        BTreeSet::from([secret_metadata.clone()]),
                    )]),))
                )],
            )
            .expect("tenant discovery filter"),
            RepositoryDiscoveryFilter {
                all_repositories: true,
                ..RepositoryDiscoveryFilter::default()
            }
        );
        assert!(
            repository_discovery_filter(
                &exact_context,
                &tenant,
                &[(&repository_read, LoadedRbacPolicy::stale())],
            )
            .expect("stale discovery filter")
            .is_empty()
        );
    }

    #[test]
    fn repository_discovery_bounds_exact_repository_scopes() {
        let tenant = TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant");
        let tenant_id = TenantId::new("tenant-a").expect("tenant ID");
        let secret_metadata =
            Permission::new("secrets:metadata:read").expect("secret metadata read");
        let role = RoleName::new("secret-reader").expect("role");
        let grants = (1..=MAX_REPOSITORY_DISCOVERY_SCOPES + 1)
            .map(|index| {
                ScopedRoleGrant::new(
                    AuthorizationScope::repository(RepositoryResource::new(
                        tenant_id.clone(),
                        RepositoryResourceId::from_uuid(Uuid::from_u128(
                            u128::try_from(index).expect("scope index fits in u128"),
                        ))
                        .expect("repository ID"),
                    )),
                    role.clone(),
                )
            })
            .collect();
        let context = AuthorizationContext::authenticated(
            tenant_id,
            PrincipalId::new("principal-a").expect("principal"),
            grants,
        )
        .expect("authorization context");
        let policy = LoadedRbacPolicy::current(RbacPolicy::new(BTreeMap::from([(
            role,
            BTreeSet::from([secret_metadata.clone()]),
        )])));

        assert!(
            repository_discovery_filter(&context, &tenant, &[(&secret_metadata, policy)]).is_err()
        );
    }

    #[test]
    fn artifact_block_descriptor_reads_enforce_the_product_cap() {
        assert_eq!(
            validated_artifact_block_count(
                i32::try_from(MAX_ARTIFACT_BLOCKS).expect("product cap fits i32")
            )
            .expect("the exact product cap is valid"),
            MAX_ARTIFACT_BLOCKS
        );
        assert!(matches!(
            validated_artifact_block_count(
                i32::try_from(MAX_ARTIFACT_BLOCKS + 1).expect("test value fits i32")
            ),
            Err(StoreError::CorruptData(_))
        ));
        assert!(matches!(
            validated_artifact_block_count(-1),
            Err(StoreError::CorruptData(_))
        ));
    }

    #[test]
    fn repository_rbac_reads_are_permission_scoped_and_fail_closed_at_one_over() {
        assert_eq!(MAX_REPOSITORY_RBAC_ROLE_NAMES, MAX_REPOSITORY_RBAC_ROWS);
        assert_eq!(
            repository_rbac_query_limit().expect("the fixed RBAC query limit fits BIGINT"),
            i64::try_from(MAX_REPOSITORY_RBAC_ROWS + 1).expect("the test limit fits BIGINT")
        );
        assert!(
            enforce_repository_rbac_limit(
                MAX_REPOSITORY_RBAC_ROLE_NAMES,
                MAX_REPOSITORY_RBAC_ROLE_NAMES
            )
            .is_ok()
        );
        assert!(
            enforce_repository_rbac_limit(
                MAX_REPOSITORY_RBAC_ROLE_NAMES + 1,
                MAX_REPOSITORY_RBAC_ROLE_NAMES
            )
            .is_err()
        );
        assert!(
            enforce_repository_rbac_limit(MAX_REPOSITORY_RBAC_ROWS, MAX_REPOSITORY_RBAC_ROWS)
                .is_ok()
        );
        assert!(
            enforce_repository_rbac_limit(MAX_REPOSITORY_RBAC_ROWS + 1, MAX_REPOSITORY_RBAC_ROWS)
                .is_err()
        );

        assert!(RBAC_POLICY_AT_REVISION_SQL.contains("FROM tenant_human_memberships"));
        assert!(RBAC_POLICY_AT_REVISION_SQL.contains("role.id AS role_id"));
        assert!(RBAC_POLICY_AT_REVISION_SQL.contains("LEFT JOIN rbac_roles"));
        assert!(RBAC_POLICY_AT_REVISION_SQL.contains("LEFT JOIN rbac_role_permissions"));
        assert!(RBAC_POLICY_AT_REVISION_SQL.contains("permission_grant.permission_name = $5"));
        assert!(RBAC_POLICY_AT_REVISION_SQL.contains("LIMIT $6"));
        assert!(RBAC_POLICY_SQL.contains("role.id AS role_id"));
        assert!(RBAC_POLICY_SQL.contains("LEFT JOIN rbac_role_permissions"));
        assert!(RBAC_POLICY_SQL.contains("permission_grant.permission_name = $3"));
        assert!(RBAC_POLICY_SQL.contains("LIMIT $4"));
    }

    #[test]
    fn repository_rbac_row_assembly_rejects_duplicate_or_incomplete_role_identity() {
        let requested = Permission::new("repositories:read").expect("permission");
        let role_id = Uuid::new_v4();
        let row = DurableRepositoryRbacRow {
            role_id: Some(role_id),
            role_name: Some("reader".to_owned()),
            permission_name: Some(requested.as_str().to_owned()),
        };
        assert!(
            assemble_repository_rbac_policy([row.clone()], &["reader".to_owned()], &requested,)
                .is_ok()
        );
        assert!(matches!(
            assemble_repository_rbac_policy(
                [row.clone(), row.clone()],
                &["reader".to_owned()],
                &requested,
            ),
            Err(StoreError::CorruptData(_))
        ));
        assert!(matches!(
            assemble_repository_rbac_policy(
                [
                    row.clone(),
                    DurableRepositoryRbacRow {
                        role_id: Some(Uuid::new_v4()),
                        ..row.clone()
                    },
                ],
                &["reader".to_owned()],
                &requested,
            ),
            Err(StoreError::CorruptData(_))
        ));
        assert!(matches!(
            assemble_repository_rbac_policy(
                [DurableRepositoryRbacRow {
                    permission_name: None,
                    ..row
                }],
                &["reader".to_owned(), "missing".to_owned()],
                &requested,
            ),
            Err(StoreError::CorruptData(_))
        ));
    }

    #[test]
    fn repository_role_expansion_keeps_only_applicable_scope() {
        let tenant = TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant");
        let tenant_id = TenantId::new("tenant-a").expect("tenant ID");
        let requested = RepositoryResource::new(
            tenant_id.clone(),
            RepositoryResourceId::from_uuid(Uuid::new_v4()).expect("repository ID"),
        );
        let sibling = RepositoryResource::new(
            tenant_id.clone(),
            RepositoryResourceId::from_uuid(Uuid::new_v4()).expect("repository ID"),
        );
        let runner_group = RunnerGroupResource::new(
            tenant_id.clone(),
            RunnerGroupResourceId::from_uuid(Uuid::new_v4()).expect("runner-group ID"),
        );
        let grants = BTreeSet::from([
            ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id),
                RoleName::new("tenant-role").expect("role"),
            ),
            ScopedRoleGrant::new(
                AuthorizationScope::repository(requested.clone()),
                RoleName::new("requested-role").expect("role"),
            ),
            ScopedRoleGrant::new(
                AuthorizationScope::repository(sibling),
                RoleName::new("sibling-role").expect("role"),
            ),
            ScopedRoleGrant::new(
                AuthorizationScope::runner_group(runner_group),
                RoleName::new("runner-role").expect("role"),
            ),
        ]);

        assert_eq!(
            repository_role_names(&grants, &tenant, Some(requested.repository_id().as_uuid()),)
                .expect("exact roles"),
            ["requested-role".to_owned(), "tenant-role".to_owned()]
        );
        assert_eq!(
            repository_role_names(&grants, &tenant, None).expect("listing roles"),
            [
                "requested-role".to_owned(),
                "sibling-role".to_owned(),
                "tenant-role".to_owned()
            ]
        );
    }

    #[test]
    fn repository_role_expansion_bounds_only_applicable_roles() {
        let tenant = TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant");
        let tenant_id = TenantId::new("tenant-a").expect("tenant ID");
        let requested = RepositoryResource::new(
            tenant_id.clone(),
            RepositoryResourceId::from_uuid(Uuid::new_v4()).expect("repository ID"),
        );
        let sibling = RepositoryResource::new(
            tenant_id.clone(),
            RepositoryResourceId::from_uuid(Uuid::new_v4()).expect("repository ID"),
        );
        let mut exact_limit = BTreeSet::new();
        for index in 0..MAX_REPOSITORY_RBAC_ROLE_NAMES {
            exact_limit.insert(ScopedRoleGrant::new(
                AuthorizationScope::tenant(tenant_id.clone()),
                RoleName::new(format!("role-{index}")).expect("role"),
            ));
        }
        assert_eq!(
            repository_role_names(
                &exact_limit,
                &tenant,
                Some(requested.repository_id().as_uuid()),
            )
            .expect("the exact role limit is accepted")
            .len(),
            MAX_REPOSITORY_RBAC_ROLE_NAMES
        );
        exact_limit.insert(ScopedRoleGrant::new(
            AuthorizationScope::tenant(tenant_id),
            RoleName::new("one-over-role").expect("role"),
        ));
        assert!(
            repository_role_names(
                &exact_limit,
                &tenant,
                Some(requested.repository_id().as_uuid()),
            )
            .is_err()
        );

        let mut unrelated = BTreeSet::new();
        for index in 0..=MAX_REPOSITORY_RBAC_ROLE_NAMES {
            unrelated.insert(ScopedRoleGrant::new(
                AuthorizationScope::repository(sibling.clone()),
                RoleName::new(format!("unrelated-{index}")).expect("role"),
            ));
        }
        unrelated.insert(ScopedRoleGrant::new(
            AuthorizationScope::repository(requested.clone()),
            RoleName::new("requested-role").expect("role"),
        ));
        assert_eq!(
            repository_role_names(
                &unrelated,
                &tenant,
                Some(requested.repository_id().as_uuid()),
            )
            .expect("unrelated roles do not consume the exact-resource budget"),
            ["requested-role".to_owned()]
        );
        assert!(repository_role_names(&unrelated, &tenant, None).is_err());
    }
}
