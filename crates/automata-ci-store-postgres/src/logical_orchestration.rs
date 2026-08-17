use async_trait::async_trait;
use automata_ci_auth::delegated_actor::RepositoryMutationActor;
use automata_ci_core::{
    JOB_RUNTIME_CONTEXT_SCHEMA_VERSION, OperationId, RUNNER_REQUIREMENTS_SCHEMA_VERSION, RunId,
    TRUST_SNAPSHOT_V1_MEDIA_TYPE, UnixMillis, WorkflowId,
};
use sha2::{Digest as _, Sha256};
use sqlx::{AssertSqlSafe, Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore,
    admission::{RunPublicationSnapshot, lock_repository_publication_snapshot},
    durable_schema::current_durable_schemas,
    event_subject::{
        load_event_subject_state_in_transaction, record_event_subject_progress_in_transaction,
        register_event_subject_in_transaction,
    },
    github_schedule::{
        record_github_scheduled_run_evidence_in_transaction,
        validate_github_schedule_selection_in_transaction,
        validate_github_scheduled_run_evidence_in_transaction,
    },
    github_subject_evidence::{
        record_github_workflow_run_subject_evidence_in_transaction,
        validate_github_workflow_run_subject_evidence_in_transaction,
        validate_github_workflow_selection_in_transaction,
    },
    secret_management::{
        AuthorizedWorkflowDispatchActor, AuthorizedWorkflowDispatchActorSource,
        authorize_workflow_dispatch_actor,
    },
};
use automata_ci_store::{
    AdmissionObject, AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim,
    AuthenticatedWorkflowDispatchClaim, AuthenticatedWorkflowDispatchSource,
    BeginWorkflowDispatchSourceResolution, CompleteWorkflowDispatchSourceResolution,
    EventControlSubject, EventControlSubjectId, EventSubjectId, EventSubjectOrigin,
    EventSubjectProgress, EventSubjectSelection, EventSubjectStoreError, EventSubjectTerminalKind,
    EventSubjectTerminalOutcome, GithubProviderManifestRevision, GithubScheduleFireClaim,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceClaimFence, GithubServerServiceRevision, GithubServerServiceWorkerId,
    GithubSubjectEvidenceStoreError, JobEnvironmentRequirement, LOGICAL_ORCHESTRATION_SCHEMA,
    LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionRepository,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowInvocationId, LogicalWorkflowJobKind,
    ObjectKey, ProviderConnectionId, RecordGithubWorkflowRunSubjectEvidence, RegisterEventSubject,
    RepositoryId, ResolveAuthenticatedWorkflowDispatchSource, Sha256Digest, StoreError,
    TenantScope, ValidateGithubWorkflowRunSubjectEvidenceReplay, WORKFLOW_ADMISSION_EPOCH,
    WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionIdempotency, WorkflowAdmissionStoreError,
    WorkflowDispatchSourceClaim, WorkflowDispatchSourceResolutionOutcome,
    WorkflowDispatchSourceResolutionRepository, WorkflowDispatchSourceResolutionStoreError,
    WorkflowSnapshotId,
};

enum SubjectEvidenceAdmission {
    AuthenticatedGithub {
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    },
    AuthenticatedWorkflowDispatch {
        claim: Box<AuthenticatedWorkflowDispatchClaim>,
    },
    ScheduledGithub {
        claim: GithubScheduleFireClaim,
    },
}

const WORKFLOW_DISPATCH_PERMISSION: &str = "runs:dispatch";
const WORKFLOW_DISPATCH_AUDIT_ACTION: &str = "workflow.dispatch";
const WORKFLOW_DISPATCH_AUDIT_RESOURCE_KIND: &str = "workflow_run";
const WORKFLOW_DISPATCH_AUDIT_ID_DOMAIN: &[u8] = b"automata.workflow-dispatch.audit.v1\0";
// SHA-256 prefix for `automata.logical-admission.idempotency-lock.v1`.
const LOGICAL_ADMISSION_IDEMPOTENCY_LOCK_NAMESPACE: i64 = 0x2fee_1fa8_b154_7857;
const WORKFLOW_DISPATCH_SOURCE_CLOCK_SKEW_MILLIS: i64 = 60_000;

#[async_trait]
impl WorkflowDispatchSourceResolutionRepository for PostgresStore {
    async fn begin_workflow_dispatch_source_resolution(
        &self,
        request: BeginWorkflowDispatchSourceResolution,
    ) -> Result<WorkflowDispatchSourceResolutionOutcome, WorkflowDispatchSourceResolutionStoreError>
    {
        begin_dispatch_source_resolution(self, request).await
    }

    async fn complete_workflow_dispatch_source_resolution(
        &self,
        request: CompleteWorkflowDispatchSourceResolution,
    ) -> Result<AuthenticatedWorkflowDispatchSource, WorkflowDispatchSourceResolutionStoreError>
    {
        complete_dispatch_source_resolution(self, request).await
    }

    async fn release_workflow_dispatch_source_resolution(
        &self,
        claim: WorkflowDispatchSourceClaim,
    ) -> Result<(), WorkflowDispatchSourceResolutionStoreError> {
        release_dispatch_source_resolution(self, claim).await
    }
}

const fn logical_workflow_job_kind_name(kind: LogicalWorkflowJobKind) -> &'static str {
    match kind {
        LogicalWorkflowJobKind::Steps => "steps",
        LogicalWorkflowJobKind::ReusableWorkflow => "reusable_workflow",
    }
}

const fn job_environment_requirement_name(requirement: JobEnvironmentRequirement) -> &'static str {
    match requirement {
        JobEnvironmentRequirement::None => "none",
        JobEnvironmentRequirement::Environment(_) => "environment",
    }
}

fn decode_commit_sha_bytes(value: &str) -> Result<Vec<u8>, LogicalWorkflowAdmissionStoreError> {
    if !matches!(value.len(), 40 | 64) {
        return Err(StoreError::corrupt_data("validated commit SHA has an invalid length").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            let high = digit(pair[0]);
            let low = digit(pair[1]);
            high.zip(low).map(|(high, low)| (high << 4) | low)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| StoreError::corrupt_data("validated commit SHA is not canonical").into())
}

const DISPATCH_SOURCE_RESOLUTION_COLUMNS: &str = r"
    tenant_id, operation_id, principal_id, repository_id, workflow_id,
    workflow_path, git_ref, scm_provider, provider_repository_id,
    repository_owner, repository_name, github_repository_owner_id,
    provider_connection_id, provider_manifest_revision, provider_manifest_digest,
    private_source_authority_id, private_source_authority_identity_digest,
    private_source_authority_app_configuration_revision,
    private_source_authority_policy_revision, state, claim_owner_id,
    claim_fence, claimed_at_ms, claim_expires_at_ms, commit_sha,
    source_digest, source_object_key, source_size_bytes, source_media_type,
    created_at_ms, resolved_at_ms
";

const DISPATCH_SOURCE_RESOLUTION_RETURNING_COLUMNS: &str = r"
    resolution.tenant_id, resolution.operation_id, resolution.principal_id,
    resolution.repository_id, resolution.workflow_id, resolution.workflow_path,
    resolution.git_ref, resolution.scm_provider, resolution.provider_repository_id,
    resolution.repository_owner, resolution.repository_name,
    resolution.github_repository_owner_id, resolution.provider_connection_id,
    resolution.provider_manifest_revision, resolution.provider_manifest_digest,
    resolution.private_source_authority_id,
    resolution.private_source_authority_identity_digest,
    resolution.private_source_authority_app_configuration_revision,
    resolution.private_source_authority_policy_revision, resolution.state,
    resolution.claim_owner_id, resolution.claim_fence, resolution.claimed_at_ms,
    resolution.claim_expires_at_ms, resolution.commit_sha, resolution.source_digest,
    resolution.source_object_key, resolution.source_size_bytes,
    resolution.source_media_type, resolution.created_at_ms, resolution.resolved_at_ms
";

#[allow(clippy::too_many_lines)] // Keep reauthorization, operation locking, and manifest pinning atomic.
async fn begin_dispatch_source_resolution(
    store: &PostgresStore,
    request: BeginWorkflowDispatchSourceResolution,
) -> Result<WorkflowDispatchSourceResolutionOutcome, WorkflowDispatchSourceResolutionStoreError> {
    let mut transaction = store.pool.begin().await.map_err(source_operation_error)?;
    let actor = authorize_workflow_dispatch_actor(
        &mut transaction,
        request.actor(),
        WORKFLOW_DISPATCH_PERMISSION,
        request.repository_id().as_uuid(),
    )
    .await
    .map_err(WorkflowDispatchSourceResolutionStoreError::Store)?
    .ok_or(WorkflowDispatchSourceResolutionStoreError::AuthorityRejected)?;
    if !authorized_dispatch_actor_matches(&actor, request.actor()) {
        return Err(WorkflowDispatchSourceResolutionStoreError::AuthorityRejected);
    }
    let now = dispatch_source_database_now(&mut transaction).await?;
    if now.get().abs_diff(request.observed_at().get())
        > u64::try_from(WORKFLOW_DISPATCH_SOURCE_CLOCK_SKEW_MILLIS).unwrap_or(u64::MAX)
    {
        return Err(WorkflowDispatchSourceResolutionStoreError::ClaimRejected);
    }

    let existing_query = format!(
        "SELECT {DISPATCH_SOURCE_RESOLUTION_COLUMNS} \
         FROM workflow_dispatch_source_resolutions \
         WHERE tenant_id = $1 AND operation_id = $2 FOR UPDATE"
    );
    if let Some(existing) = sqlx::query(AssertSqlSafe(existing_query))
        .bind(&actor.tenant_id)
        .bind(request.operation_id().as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(source_operation_error)?
    {
        validate_dispatch_source_operation(&existing, &actor, &request)?;
        let state = existing
            .try_get::<String, _>("state")
            .map_err(source_operation_error)?;
        if state == "resolved" {
            let source = resolved_dispatch_source_from_row(&existing)?;
            transaction.commit().await.map_err(source_operation_error)?;
            return Ok(WorkflowDispatchSourceResolutionOutcome::Resolved(source));
        }
        if state == "retryable"
            || existing
                .try_get::<Option<i64>, _>("claim_expires_at_ms")
                .map_err(source_operation_error)?
                .is_some_and(|expires_at| expires_at <= now.get())
        {
            ensure_dispatch_source_manifest_current(&mut transaction, &existing).await?;
            let expires_at = now
                .get()
                .checked_add(request.claim_millis())
                .ok_or(WorkflowDispatchSourceResolutionStoreError::ClaimRejected)?;
            let update_query = format!(
                "UPDATE workflow_dispatch_source_resolutions \
                 SET state = 'claimed', claim_owner_id = $3, claim_fence = claim_fence + 1, \
                     claimed_at_ms = $4, claim_expires_at_ms = $5 \
                 WHERE tenant_id = $1 AND operation_id = $2 \
                   AND state = ANY (ARRAY['claimed'::text, 'retryable'::text]) \
                   AND claim_fence < 9223372036854775807 \
                 RETURNING {DISPATCH_SOURCE_RESOLUTION_COLUMNS}"
            );
            let updated = sqlx::query(AssertSqlSafe(update_query))
                .bind(&actor.tenant_id)
                .bind(request.operation_id().as_uuid())
                .bind(request.worker_id().as_uuid())
                .bind(now.get())
                .bind(expires_at)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(source_operation_error)?
                .ok_or(WorkflowDispatchSourceResolutionStoreError::ClaimRejected)?;
            let claim = dispatch_source_claim_from_row(&updated)?;
            transaction.commit().await.map_err(source_operation_error)?;
            return Ok(WorkflowDispatchSourceResolutionOutcome::Claimed(claim));
        }
        let expires_at = existing
            .try_get::<Option<i64>, _>("claim_expires_at_ms")
            .map_err(source_operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("live dispatch source claim has no expiry"))?;
        let current_owner = existing
            .try_get::<Option<Uuid>, _>("claim_owner_id")
            .map_err(source_operation_error)?
            .ok_or_else(|| StoreError::corrupt_data("live dispatch source claim has no owner"))?;
        if expires_at > now.get() && current_owner != request.worker_id().as_uuid() {
            return Err(WorkflowDispatchSourceResolutionStoreError::ClaimRejected);
        }
        let claim = dispatch_source_claim_from_row(&existing)?;
        transaction.commit().await.map_err(source_operation_error)?;
        return Ok(WorkflowDispatchSourceResolutionOutcome::Claimed(claim));
    }

    let target = sqlx::query(
        r"
        SELECT repository.scm_provider, repository.provider_repository_id,
               repository.owner AS repository_owner,
               repository.name AS repository_name, workflow.path AS workflow_path,
               current_manifest.provider_connection_id,
               current_manifest.manifest_revision,
               current_manifest.manifest_digest,
               manifest.github_repository_owner_id,
               manifest.repository_visibility,
               authority.id AS private_source_authority_id,
               authority.identity_digest AS private_source_authority_identity_digest,
               authority.app_configuration_revision
                   AS private_source_authority_app_configuration_revision,
               authority.policy_revision AS private_source_authority_policy_revision
        FROM repositories AS repository
        JOIN workflow_definitions AS workflow
          ON workflow.repository_id = repository.id
         AND workflow.id = $3
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = repository.tenant_id
         AND current_manifest.repository_id = repository.id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = current_manifest.tenant_id
         AND manifest.repository_id = current_manifest.repository_id
         AND manifest.provider_connection_id = current_manifest.provider_connection_id
         AND manifest.manifest_revision = current_manifest.manifest_revision
         AND manifest.manifest_digest = current_manifest.manifest_digest
        LEFT JOIN github_server_service_authorities AS authority
          ON authority.tenant_id = manifest.tenant_id
         AND authority.repository_id = manifest.repository_id
         AND authority.provider_connection_id = manifest.provider_connection_id
         AND authority.provider_installation_id = manifest.provider_installation_id
         AND authority.github_app_id = manifest.github_app_id
         AND authority.github_repository_id = manifest.github_repository_id
         AND authority.github_repository_name = manifest.github_repository_name
         AND authority.app_configuration_revision = manifest.app_configuration_revision
         AND authority.policy_revision = manifest.policy_revision
         AND authority.service_scope = 'private_repository_source_read'
         AND authority.state = 'active'
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND repository.scm_provider = 'github'
          AND workflow.enabled = TRUE
          AND manifest.github_repository_owner_id IS NOT NULL
        ",
    )
    .bind(&actor.tenant_id)
    .bind(request.repository_id().as_uuid())
    .bind(request.workflow_id().as_uuid())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(source_operation_error)?
    .ok_or(WorkflowDispatchSourceResolutionStoreError::NotFound)?;
    let visibility = target
        .try_get::<String, _>("repository_visibility")
        .map_err(source_operation_error)?;
    let private_authority = target
        .try_get::<Option<Uuid>, _>("private_source_authority_id")
        .map_err(source_operation_error)?;
    if (visibility == "private") != private_authority.is_some()
        || !matches!(visibility.as_str(), "public" | "private")
    {
        return Err(WorkflowDispatchSourceResolutionStoreError::NotFound);
    }
    let expires_at = now
        .get()
        .checked_add(request.claim_millis())
        .ok_or(WorkflowDispatchSourceResolutionStoreError::ClaimRejected)?;
    let insert_query = format!(
        "INSERT INTO workflow_dispatch_source_resolutions (\
            tenant_id, operation_id, principal_id, repository_id, workflow_id,\
            workflow_path, git_ref, scm_provider, provider_repository_id,\
            repository_owner, repository_name, github_repository_owner_id,\
            provider_connection_id, provider_manifest_revision, provider_manifest_digest,\
            private_source_authority_id, private_source_authority_identity_digest,\
            private_source_authority_app_configuration_revision,\
            private_source_authority_policy_revision, state, claim_owner_id, claim_fence,\
            claimed_at_ms, claim_expires_at_ms, created_at_ms\
         ) VALUES (\
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,\
            $15, $16, $17, $18, $19, 'claimed', $20, 1, $21, $22, $21\
         ) RETURNING {DISPATCH_SOURCE_RESOLUTION_COLUMNS}"
    );
    let row = sqlx::query(AssertSqlSafe(insert_query))
        .bind(&actor.tenant_id)
        .bind(request.operation_id().as_uuid())
        .bind(actor.principal_id)
        .bind(request.repository_id().as_uuid())
        .bind(request.workflow_id().as_uuid())
        .bind(
            target
                .try_get::<String, _>("workflow_path")
                .map_err(source_operation_error)?,
        )
        .bind(request.git_ref())
        .bind(
            target
                .try_get::<String, _>("scm_provider")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<String, _>("provider_repository_id")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<String, _>("repository_owner")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<String, _>("repository_name")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<i64, _>("github_repository_owner_id")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<Uuid, _>("provider_connection_id")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<i64, _>("manifest_revision")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<Vec<u8>, _>("manifest_digest")
                .map_err(source_operation_error)?,
        )
        .bind(private_authority)
        .bind(
            target
                .try_get::<Option<Vec<u8>>, _>("private_source_authority_identity_digest")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<Option<i64>, _>("private_source_authority_app_configuration_revision")
                .map_err(source_operation_error)?,
        )
        .bind(
            target
                .try_get::<Option<i64>, _>("private_source_authority_policy_revision")
                .map_err(source_operation_error)?,
        )
        .bind(request.worker_id().as_uuid())
        .bind(now.get())
        .bind(expires_at)
        .fetch_one(&mut *transaction)
        .await
        .map_err(source_operation_error)?;
    let claim = dispatch_source_claim_from_row(&row)?;
    transaction.commit().await.map_err(source_operation_error)?;
    Ok(WorkflowDispatchSourceResolutionOutcome::Claimed(claim))
}

async fn complete_dispatch_source_resolution(
    store: &PostgresStore,
    request: CompleteWorkflowDispatchSourceResolution,
) -> Result<AuthenticatedWorkflowDispatchSource, WorkflowDispatchSourceResolutionStoreError> {
    let claim = request.claim();
    let mut transaction = store.pool.begin().await.map_err(source_operation_error)?;
    let now = dispatch_source_database_now(&mut transaction).await?;
    let update_query = format!(
        "UPDATE workflow_dispatch_source_resolutions AS resolution \
         SET state = 'resolved', claim_owner_id = NULL, claimed_at_ms = NULL,\
             claim_expires_at_ms = NULL, commit_sha = $18, source_digest = $19,\
             source_object_key = $20, source_size_bytes = $21, source_media_type = $22,\
             resolved_at_ms = $23 \
         FROM github_provider_manifest_current AS current_manifest \
         WHERE resolution.tenant_id = $1 AND resolution.operation_id = $2 \
           AND resolution.repository_id = $3 AND resolution.workflow_id = $4 \
           AND resolution.workflow_path = $5 AND resolution.git_ref = $6 \
           AND resolution.provider_connection_id = $7 \
           AND resolution.provider_manifest_revision = $8 \
           AND resolution.provider_manifest_digest = $9 \
           AND resolution.private_source_authority_id IS NOT DISTINCT FROM $10 \
           AND resolution.private_source_authority_identity_digest IS NOT DISTINCT FROM $11 \
           AND resolution.private_source_authority_app_configuration_revision \
               IS NOT DISTINCT FROM $12 \
           AND resolution.private_source_authority_policy_revision IS NOT DISTINCT FROM $13 \
           AND resolution.state = 'claimed' AND resolution.claim_owner_id = $14 \
           AND resolution.claim_fence = $15 AND resolution.claimed_at_ms = $16 \
           AND resolution.claim_expires_at_ms = $17 \
           AND resolution.claim_expires_at_ms > $23 \
           AND current_manifest.tenant_id = resolution.tenant_id \
           AND current_manifest.repository_id = resolution.repository_id \
           AND current_manifest.provider_connection_id = resolution.provider_connection_id \
           AND current_manifest.manifest_revision = resolution.provider_manifest_revision \
           AND current_manifest.manifest_digest = resolution.provider_manifest_digest \
         RETURNING {DISPATCH_SOURCE_RESOLUTION_RETURNING_COLUMNS}"
    );
    let commit_sha = decode_source_commit_sha_bytes(request.commit_sha())?;
    let size = i64::try_from(request.source().encoded_size())
        .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?;
    let private_authority = claim.private_source_authority();
    let row = sqlx::query(AssertSqlSafe(update_query))
        .bind(claim.tenant().as_str())
        .bind(claim.operation_id().as_uuid())
        .bind(claim.repository_id().as_uuid())
        .bind(claim.workflow_id().as_uuid())
        .bind(claim.workflow_path())
        .bind(claim.git_ref())
        .bind(claim.connection_id().as_uuid())
        .bind(
            i64::try_from(claim.manifest_revision().get())
                .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
        )
        .bind(claim.manifest_digest().as_bytes().as_slice())
        .bind(private_authority.map(|selector| selector.authority_id().as_uuid()))
        .bind(private_authority.map(|selector| selector.identity_digest().as_bytes().to_vec()))
        .bind(
            private_authority
                .map(|selector| i64::try_from(selector.app_configuration_revision().get()))
                .transpose()
                .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
        )
        .bind(
            private_authority
                .map(|selector| i64::try_from(selector.policy_revision().get()))
                .transpose()
                .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
        )
        .bind(claim.worker_id().as_uuid())
        .bind(
            i64::try_from(claim.fence().get())
                .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
        )
        .bind(claim.claimed_at().get())
        .bind(claim.expires_at().get())
        .bind(commit_sha)
        .bind(request.source().digest().as_bytes().as_slice())
        .bind(request.source().object_key().as_str())
        .bind(size)
        .bind(request.source().media_type())
        .bind(now.get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(source_operation_error)?
        .ok_or(WorkflowDispatchSourceResolutionStoreError::ClaimRejected)?;
    let source = resolved_dispatch_source_from_row(&row)?;
    transaction.commit().await.map_err(source_operation_error)?;
    Ok(source)
}

async fn release_dispatch_source_resolution(
    store: &PostgresStore,
    claim: WorkflowDispatchSourceClaim,
) -> Result<(), WorkflowDispatchSourceResolutionStoreError> {
    let released = sqlx::query(
        r"
        UPDATE workflow_dispatch_source_resolutions
        SET state = 'retryable', claim_owner_id = NULL,
            claimed_at_ms = NULL, claim_expires_at_ms = NULL
        WHERE tenant_id = $1 AND operation_id = $2 AND state = 'claimed'
          AND repository_id = $3 AND workflow_id = $4 AND workflow_path = $5
          AND git_ref = $6 AND provider_connection_id = $7
          AND provider_manifest_revision = $8 AND provider_manifest_digest = $9
          AND private_source_authority_id IS NOT DISTINCT FROM $10
          AND private_source_authority_identity_digest IS NOT DISTINCT FROM $11
          AND private_source_authority_app_configuration_revision IS NOT DISTINCT FROM $12
          AND private_source_authority_policy_revision IS NOT DISTINCT FROM $13
          AND claim_owner_id = $14 AND claim_fence = $15
          AND claimed_at_ms = $16 AND claim_expires_at_ms = $17
        ",
    )
    .bind(claim.tenant().as_str())
    .bind(claim.operation_id().as_uuid())
    .bind(claim.repository_id().as_uuid())
    .bind(claim.workflow_id().as_uuid())
    .bind(claim.workflow_path())
    .bind(claim.git_ref())
    .bind(claim.connection_id().as_uuid())
    .bind(
        i64::try_from(claim.manifest_revision().get())
            .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
    )
    .bind(claim.manifest_digest().as_bytes().as_slice())
    .bind(
        claim
            .private_source_authority()
            .map(|selector| selector.authority_id().as_uuid()),
    )
    .bind(
        claim
            .private_source_authority()
            .map(|selector| selector.identity_digest().as_bytes().to_vec()),
    )
    .bind(
        claim
            .private_source_authority()
            .map(|selector| i64::try_from(selector.app_configuration_revision().get()))
            .transpose()
            .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
    )
    .bind(
        claim
            .private_source_authority()
            .map(|selector| i64::try_from(selector.policy_revision().get()))
            .transpose()
            .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
    )
    .bind(claim.worker_id().as_uuid())
    .bind(
        i64::try_from(claim.fence().get())
            .map_err(|_| WorkflowDispatchSourceResolutionStoreError::Conflict)?,
    )
    .bind(claim.claimed_at().get())
    .bind(claim.expires_at().get())
    .execute(&store.pool)
    .await
    .map_err(source_operation_error)?;
    if released.rows_affected() != 1 {
        return Err(WorkflowDispatchSourceResolutionStoreError::ClaimRejected);
    }
    Ok(())
}

fn validate_dispatch_source_operation(
    row: &PgRow,
    actor: &AuthorizedWorkflowDispatchActor,
    request: &BeginWorkflowDispatchSourceResolution,
) -> Result<(), WorkflowDispatchSourceResolutionStoreError> {
    let exact = row
        .try_get::<String, _>("tenant_id")
        .map_err(source_operation_error)?
        == actor.tenant_id
        && row
            .try_get::<Uuid, _>("principal_id")
            .map_err(source_operation_error)?
            == actor.principal_id
        && row
            .try_get::<Uuid, _>("repository_id")
            .map_err(source_operation_error)?
            == request.repository_id().as_uuid()
        && row
            .try_get::<Uuid, _>("workflow_id")
            .map_err(source_operation_error)?
            == request.workflow_id().as_uuid()
        && row
            .try_get::<String, _>("git_ref")
            .map_err(source_operation_error)?
            == request.git_ref();
    if exact {
        Ok(())
    } else {
        Err(WorkflowDispatchSourceResolutionStoreError::Conflict)
    }
}

async fn ensure_dispatch_source_manifest_current(
    transaction: &mut Transaction<'_, Postgres>,
    row: &PgRow,
) -> Result<(), WorkflowDispatchSourceResolutionStoreError> {
    let current = sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1 FROM github_provider_manifest_current
            WHERE tenant_id = $1 AND repository_id = $2
              AND provider_connection_id = $3 AND manifest_revision = $4
              AND manifest_digest = $5
        )
        ",
    )
    .bind(
        row.try_get::<String, _>("tenant_id")
            .map_err(source_operation_error)?,
    )
    .bind(
        row.try_get::<Uuid, _>("repository_id")
            .map_err(source_operation_error)?,
    )
    .bind(
        row.try_get::<Uuid, _>("provider_connection_id")
            .map_err(source_operation_error)?,
    )
    .bind(
        row.try_get::<i64, _>("provider_manifest_revision")
            .map_err(source_operation_error)?,
    )
    .bind(
        row.try_get::<Vec<u8>, _>("provider_manifest_digest")
            .map_err(source_operation_error)?,
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(source_operation_error)?;
    if current {
        Ok(())
    } else {
        Err(WorkflowDispatchSourceResolutionStoreError::Conflict)
    }
}

fn dispatch_source_claim_from_row(
    row: &PgRow,
) -> Result<WorkflowDispatchSourceClaim, WorkflowDispatchSourceResolutionStoreError> {
    if row
        .try_get::<String, _>("state")
        .map_err(source_operation_error)?
        != "claimed"
    {
        return Err(source_corrupt("source-resolution row is not claimed"));
    }
    let tenant = TenantScope::from_authenticated_tenant_id(
        row.try_get::<String, _>("tenant_id")
            .map_err(source_operation_error)?,
    )
    .map_err(|_| source_corrupt("source-resolution tenant is invalid"))?;
    let authority_id = row
        .try_get::<Option<Uuid>, _>("private_source_authority_id")
        .map_err(source_operation_error)?;
    let authority_digest = row
        .try_get::<Option<Vec<u8>>, _>("private_source_authority_identity_digest")
        .map_err(source_operation_error)?;
    let authority_app_revision = row
        .try_get::<Option<i64>, _>("private_source_authority_app_configuration_revision")
        .map_err(source_operation_error)?;
    let authority_policy_revision = row
        .try_get::<Option<i64>, _>("private_source_authority_policy_revision")
        .map_err(source_operation_error)?;
    let private_source_authority = match (
        authority_id,
        authority_digest,
        authority_app_revision,
        authority_policy_revision,
    ) {
        (None, None, None, None) => None,
        (Some(id), Some(digest), Some(app_revision), Some(policy_revision)) => {
            Some(GithubServerServiceAuthoritySelector::from_durable_parts(
                tenant.clone(),
                GithubServerServiceAuthorityId::from_uuid(id)
                    .map_err(|_| source_corrupt("source authority ID is invalid"))?,
                source_digest(&digest)?,
                source_revision(app_revision)?,
                source_revision(policy_revision)?,
            ))
        }
        _ => return Err(source_corrupt("source authority selector is incomplete")),
    };
    WorkflowDispatchSourceClaim::from_durable_parts(
        tenant,
        RepositoryId::from_uuid(
            row.try_get("repository_id")
                .map_err(source_operation_error)?,
        ),
        WorkflowId::from_uuid(row.try_get("workflow_id").map_err(source_operation_error)?),
        row.try_get::<String, _>("workflow_path")
            .map_err(source_operation_error)?,
        row.try_get::<String, _>("git_ref")
            .map_err(source_operation_error)?,
        OperationId::from_uuid(
            row.try_get("operation_id")
                .map_err(source_operation_error)?,
        ),
        ProviderConnectionId::from_uuid(
            row.try_get("provider_connection_id")
                .map_err(source_operation_error)?,
        )
        .map_err(|_| source_corrupt("source connection ID is invalid"))?,
        GithubProviderManifestRevision::new(source_positive_u64(
            row,
            "provider_manifest_revision",
        )?)
        .map_err(|_| source_corrupt("source manifest revision is invalid"))?,
        source_digest(
            &row.try_get::<Vec<u8>, _>("provider_manifest_digest")
                .map_err(source_operation_error)?,
        )?,
        private_source_authority,
        GithubServerServiceWorkerId::from_uuid(
            row.try_get("claim_owner_id")
                .map_err(source_operation_error)?,
        )
        .map_err(|_| source_corrupt("source claim owner is invalid"))?,
        GithubServerServiceClaimFence::new(source_positive_u64(row, "claim_fence")?)
            .map_err(|_| source_corrupt("source claim fence is invalid"))?,
        UnixMillis::new(
            row.try_get("claimed_at_ms")
                .map_err(source_operation_error)?,
        ),
        UnixMillis::new(
            row.try_get("claim_expires_at_ms")
                .map_err(source_operation_error)?,
        ),
    )
    .map_err(|_| source_corrupt("source claim is invalid"))
}

fn resolved_dispatch_source_from_row(
    row: &PgRow,
) -> Result<AuthenticatedWorkflowDispatchSource, WorkflowDispatchSourceResolutionStoreError> {
    if row
        .try_get::<String, _>("state")
        .map_err(source_operation_error)?
        != "resolved"
    {
        return Err(source_corrupt("source-resolution row is not resolved"));
    }
    let provider = row
        .try_get::<String, _>("scm_provider")
        .map_err(source_operation_error)?;
    let repository = automata_ci_store::AdmissionRepository::new(
        RepositoryId::from_uuid(
            row.try_get("repository_id")
                .map_err(source_operation_error)?,
        ),
        provider,
        row.try_get::<String, _>("provider_repository_id")
            .map_err(source_operation_error)?,
        row.try_get::<String, _>("repository_owner")
            .map_err(source_operation_error)?,
        row.try_get::<String, _>("repository_name")
            .map_err(source_operation_error)?,
    )
    .map_err(|_| source_corrupt("resolved repository is invalid"))?;
    let digest = source_digest(
        &row.try_get::<Vec<u8>, _>("source_digest")
            .map_err(source_operation_error)?,
    )?;
    let size = source_positive_u64(row, "source_size_bytes")?;
    let object = AdmissionObject::new(
        digest,
        ObjectKey::new(
            row.try_get::<String, _>("source_object_key")
                .map_err(source_operation_error)?,
        )
        .map_err(|_| source_corrupt("resolved source object key is invalid"))?,
        size,
        &row.try_get::<String, _>("source_media_type")
            .map_err(source_operation_error)?,
    )
    .map_err(|_| source_corrupt("resolved source descriptor is invalid"))?;
    let commit = row
        .try_get::<Vec<u8>, _>("commit_sha")
        .map_err(source_operation_error)?;
    AuthenticatedWorkflowDispatchSource::new(
        repository,
        source_positive_u64(row, "github_repository_owner_id")?.to_string(),
        WorkflowId::from_uuid(row.try_get("workflow_id").map_err(source_operation_error)?),
        row.try_get::<String, _>("workflow_path")
            .map_err(source_operation_error)?,
        row.try_get::<String, _>("git_ref")
            .map_err(source_operation_error)?,
        lower_hex(&commit),
        object,
    )
    .map_err(|_| source_corrupt("resolved dispatch source is invalid"))
}

fn source_digest(bytes: &[u8]) -> Result<Sha256Digest, WorkflowDispatchSourceResolutionStoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| source_corrupt("source-resolution digest is invalid"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn source_revision(
    value: i64,
) -> Result<GithubServerServiceRevision, WorkflowDispatchSourceResolutionStoreError> {
    let value =
        u64::try_from(value).map_err(|_| source_corrupt("source authority revision is invalid"))?;
    GithubServerServiceRevision::new(value)
        .map_err(|_| source_corrupt("source authority revision is invalid"))
}

fn source_positive_u64(
    row: &PgRow,
    column: &str,
) -> Result<u64, WorkflowDispatchSourceResolutionStoreError> {
    row.try_get::<i64, _>(column)
        .map_err(source_operation_error)
        .and_then(|value| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| source_corrupt("source-resolution positive integer is invalid"))
        })
}

fn decode_source_commit_sha_bytes(
    value: &str,
) -> Result<Vec<u8>, WorkflowDispatchSourceResolutionStoreError> {
    if !matches!(value.len(), 40 | 64) {
        return Err(WorkflowDispatchSourceResolutionStoreError::Conflict);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            digit(pair[0])
                .zip(digit(pair[1]))
                .map(|(high, low)| (high << 4) | low)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(WorkflowDispatchSourceResolutionStoreError::Conflict)
}

async fn dispatch_source_database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<UnixMillis, WorkflowDispatchSourceResolutionStoreError> {
    let now = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(source_operation_error)?;
    Ok(UnixMillis::new(now))
}

fn source_corrupt(message: &'static str) -> WorkflowDispatchSourceResolutionStoreError {
    WorkflowDispatchSourceResolutionStoreError::Store(StoreError::corrupt_data(message))
}

fn source_operation_error(error: sqlx::Error) -> WorkflowDispatchSourceResolutionStoreError {
    WorkflowDispatchSourceResolutionStoreError::Store(StoreError::operation(error))
}

#[async_trait]
impl LogicalWorkflowAdmissionRepository for PostgresStore {
    async fn resolve_authenticated_workflow_dispatch_source(
        &self,
        request: ResolveAuthenticatedWorkflowDispatchSource,
    ) -> Result<Option<AuthenticatedWorkflowDispatchSource>, LogicalWorkflowAdmissionStoreError>
    {
        resolve_authenticated_dispatch_source(self, request).await
    }

    async fn admit_logical_workflow(
        &self,
        _command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    async fn admit_authenticated_github_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        admit_logical_workflow_transaction(
            self,
            command,
            SubjectEvidenceAdmission::AuthenticatedGithub {
                current_claim,
                observed_at,
            },
        )
        .await
    }

    async fn admit_scheduled_github_workflow(
        &self,
        command: AdmitLogicalWorkflowRun,
        claim: GithubScheduleFireClaim,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        admit_logical_workflow_transaction(
            self,
            command,
            SubjectEvidenceAdmission::ScheduledGithub { claim },
        )
        .await
    }

    async fn admit_authenticated_workflow_dispatch(
        &self,
        command: AdmitLogicalWorkflowRun,
        claim: AuthenticatedWorkflowDispatchClaim,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        admit_logical_workflow_transaction(
            self,
            command,
            SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch {
                claim: Box::new(claim),
            },
        )
        .await
    }
}

// One transaction reauthorizes the caller and decodes the complete immutable
// workflow source descriptor without exposing a partially validated record.
#[allow(clippy::too_many_lines)]
async fn resolve_authenticated_dispatch_source(
    store: &PostgresStore,
    request: ResolveAuthenticatedWorkflowDispatchSource,
) -> Result<Option<AuthenticatedWorkflowDispatchSource>, LogicalWorkflowAdmissionStoreError> {
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let actor = authorize_workflow_dispatch_actor(
        &mut transaction,
        request.actor(),
        WORKFLOW_DISPATCH_PERMISSION,
        request.repository_id().as_uuid(),
    )
    .await?;
    let Some(actor) = actor else {
        return Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected);
    };
    if !authorized_dispatch_actor_matches(&actor, request.actor()) {
        return Err(StoreError::corrupt_data(
            "reauthorized workflow dispatch source actor disagrees with its request",
        )
        .into());
    }

    // DISTINCT plus LIMIT 2 makes conflicting immutable descriptors at the
    // same exact repository/workflow/ref/commit identity a bounded fail-closed
    // corruption outcome rather than silently selecting one historical run.
    let rows = sqlx::query(
        r"
        SELECT DISTINCT repository.scm_provider,
               repository.provider_repository_id,
               manifest.github_repository_owner_id,
               repository.owner, repository.name, workflow.path,
               snapshot.source_digest, snapshot.source_object_key,
               snapshot.source_size_bytes, snapshot.source_media_type
        FROM repositories AS repository
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = repository.tenant_id
         AND current_manifest.repository_id = repository.id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = current_manifest.tenant_id
         AND manifest.repository_id = current_manifest.repository_id
         AND manifest.provider_connection_id = current_manifest.provider_connection_id
         AND manifest.manifest_revision = current_manifest.manifest_revision
         AND manifest.manifest_digest = current_manifest.manifest_digest
        JOIN workflow_definitions AS workflow
          ON workflow.repository_id = repository.id
        JOIN workflow_runs AS run
          ON run.repository_id = repository.id
         AND run.workflow_id = workflow.id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = workflow.id
        JOIN github_workflow_run_subject_evidence AS evidence
          ON evidence.tenant_id = repository.tenant_id
         AND evidence.repository_id = repository.id
         AND evidence.workflow_id = workflow.id
         AND evidence.snapshot_id = snapshot.id
         AND evidence.run_id = run.id
         AND evidence.workflow_path = workflow.path
         AND evidence.source_digest = snapshot.source_digest
         AND evidence.git_ref = run.git_ref
        WHERE repository.tenant_id = $1
          AND repository.id = $2
          AND workflow.id = $3
          AND run.git_ref = $4
          AND run.head_sha = $5
          AND run.admission_epoch = $6
          AND manifest.github_repository_owner_id IS NOT NULL
        LIMIT 2
        ",
    )
    .bind(&actor.tenant_id)
    .bind(request.repository_id().as_uuid())
    .bind(request.workflow_id().as_uuid())
    .bind(request.git_ref())
    .bind(decode_commit_sha_bytes(request.commit_sha())?)
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .fetch_all(&mut *transaction)
    .await
    .map_err(operation_error)?;
    let [row] = rows.as_slice() else {
        if rows.is_empty() {
            transaction.commit().await.map_err(operation_error)?;
            return Ok(None);
        }
        return Err(StoreError::corrupt_data(
            "signed GitHub admissions disagree on exact workflow source",
        )
        .into());
    };
    let source = dispatch_source_from_row(row, &request)?;
    transaction.commit().await.map_err(operation_error)?;
    Ok(Some(source))
}

fn dispatch_source_from_row(
    row: &PgRow,
    request: &ResolveAuthenticatedWorkflowDispatchSource,
) -> Result<AuthenticatedWorkflowDispatchSource, LogicalWorkflowAdmissionStoreError> {
    let provider = row
        .try_get::<String, _>("scm_provider")
        .map_err(operation_error)?;
    if provider != "github" {
        return Err(StoreError::corrupt_data(
            "signed GitHub workflow source belongs to a non-GitHub repository",
        )
        .into());
    }
    let digest = row
        .try_get::<Vec<u8>, _>("source_digest")
        .map_err(operation_error)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| StoreError::corrupt_data("signed GitHub workflow source digest is invalid"))?;
    let size = row
        .try_get::<Option<i64>, _>("source_size_bytes")
        .map_err(operation_error)?
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| StoreError::corrupt_data("signed GitHub workflow source size is invalid"))?;
    let media_type = row
        .try_get::<Option<String>, _>("source_media_type")
        .map_err(operation_error)?
        .ok_or_else(|| {
            StoreError::corrupt_data("signed GitHub workflow source media type is absent")
        })?;
    let source = AdmissionObject::new(
        Sha256Digest::from_bytes(digest),
        ObjectKey::new(
            row.try_get::<String, _>("source_object_key")
                .map_err(operation_error)?,
        )
        .map_err(|_| StoreError::corrupt_data("signed GitHub source object key is invalid"))?,
        size,
        &media_type,
    )
    .map_err(|_| StoreError::corrupt_data("signed GitHub source descriptor is invalid"))?;
    let repository = automata_ci_store::AdmissionRepository::new(
        request.repository_id(),
        provider,
        row.try_get::<String, _>("provider_repository_id")
            .map_err(operation_error)?,
        row.try_get::<String, _>("owner").map_err(operation_error)?,
        row.try_get::<String, _>("name").map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("signed GitHub repository identity is invalid"))?;
    let repository_owner_id = row
        .try_get::<i64, _>("github_repository_owner_id")
        .map_err(operation_error)?;
    if repository_owner_id <= 0 {
        return Err(
            StoreError::corrupt_data("signed GitHub repository owner identity is invalid").into(),
        );
    }
    AuthenticatedWorkflowDispatchSource::new(
        repository,
        repository_owner_id.to_string(),
        request.workflow_id(),
        row.try_get::<String, _>("path").map_err(operation_error)?,
        request.git_ref(),
        request.commit_sha(),
        source,
    )
    .map_err(|_| StoreError::corrupt_data("signed GitHub dispatch source is invalid").into())
}

#[allow(clippy::too_many_lines)] // One transaction seals every admission and event-subject invariant.
async fn admit_logical_workflow_transaction(
    store: &PostgresStore,
    command: AdmitLogicalWorkflowRun,
    subject_evidence: SubjectEvidenceAdmission,
) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
    validate_subject_evidence_boundary(&command, &subject_evidence)?;
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    // A waiter must observe the leader's commit in its next statement even
    // when the pool or session default uses a persistent snapshot.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
    // Disabled admissions intentionally have no receipt, so serialize the key
    // before deciding whether this transaction is a new admission or a replay.
    lock_logical_admission_idempotency(&mut transaction, &command).await?;
    let dispatch_actor =
        authorize_dispatch_subject(&mut transaction, &command, &subject_evidence).await?;
    let github_subject_evidence_required = matches!(
        &subject_evidence,
        SubjectEvidenceAdmission::AuthenticatedGithub { .. }
            | SubjectEvidenceAdmission::ScheduledGithub { .. }
    );

    let existing_receipt = admission_receipt_exists(&mut transaction, &command).await?;
    let publication = if existing_receipt {
        None
    } else {
        if matches!(
            &subject_evidence,
            SubjectEvidenceAdmission::AuthenticatedGithub { .. }
                | SubjectEvidenceAdmission::ScheduledGithub { .. }
        ) {
            resolve_repository(&mut transaction, &command).await?;
        }
        let publication = lock_repository_publication_snapshot(
            &mut transaction,
            command.tenant().as_str(),
            command.repository().id().as_uuid(),
        )
        .await?;
        resolve_workflow(&mut transaction, &command).await?;
        validate_subject_selection_authority(&mut transaction, &command, &subject_evidence).await?;
        if replay_disabled_event_subject(&mut transaction, &command, &subject_evidence).await? {
            transaction.commit().await.map_err(operation_error)?;
            return Err(LogicalWorkflowAdmissionStoreError::WorkflowDisabled);
        }
        if !require_workflow_enabled(&mut transaction, &command).await? {
            record_skipped_event_subject(
                &mut transaction,
                &command,
                &subject_evidence,
                command.admitted_at(),
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Err(LogicalWorkflowAdmissionStoreError::WorkflowDisabled);
        }
        Some(publication)
    };

    let claimed = if publication.is_some() {
        claim_idempotency_receipt(&mut transaction, &command, github_subject_evidence_required)
            .await?
    } else {
        false
    };
    if !claimed {
        let (receipt, admitted_at) =
            replay_receipt(&mut transaction, &command, github_subject_evidence_required).await?;
        validate_trust_snapshot_replay(&mut transaction, &command, admitted_at).await?;
        validate_replayed_subject_evidence(
            &mut transaction,
            &command,
            &subject_evidence,
            dispatch_actor.as_ref(),
            admitted_at,
        )
        .await?;
        super::reusable_workflow_admission::validate_reusable_workflow_expansion_replay(
            &mut transaction,
            &command,
        )
        .await?;
        record_admitted_event_subject(
            &mut transaction,
            &command,
            &subject_evidence,
            admitted_at,
            true,
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }
    let publication = publication.ok_or_else(|| {
        StoreError::corrupt_data("new logical admission lost its publication snapshot")
    })?;
    resolve_snapshot(&mut transaction, &command).await?;
    let run_number = allocate_run_number(&mut transaction, command.workflow_id()).await?;
    if let Some(concurrency) = command.concurrency() {
        super::admission::lock_concurrency_group(
            &mut transaction,
            command.repository().id(),
            command.admitted_at(),
            concurrency,
        )
        .await
        .map_err(map_concurrency_error)?;
    }
    insert_run(&mut transaction, &command, run_number, &publication).await?;
    insert_trust_snapshot(&mut transaction, &command).await?;
    insert_logical_run_and_invocation(&mut transaction, &command).await?;
    finalize_receipt(&mut transaction, &command).await?;
    record_new_subject_evidence(
        &mut transaction,
        &command,
        &subject_evidence,
        dispatch_actor.as_ref(),
    )
    .await?;
    record_admitted_event_subject(
        &mut transaction,
        &command,
        &subject_evidence,
        command.admitted_at(),
        false,
    )
    .await?;
    insert_logical_jobs(&mut transaction, &command).await?;
    seal_logical_graph(&mut transaction, &command).await?;
    if let Some(expansion) = command.reusable_workflows() {
        super::reusable_workflow_admission::insert_reusable_workflow_expansion(
            &mut transaction,
            &command,
            expansion,
        )
        .await?;
    }
    if let Some(concurrency) = command.concurrency() {
        super::admission::assign_concurrency_slot(
            &mut transaction,
            store.runner_payload_encryption.as_ref(),
            command.repository().id(),
            command.run_id(),
            command.admitted_at(),
            concurrency,
        )
        .await
        .map_err(map_concurrency_error)?;
    }
    transaction.commit().await.map_err(operation_error)?;

    Ok(LogicalWorkflowAdmissionReceipt::new(
        command.repository().id(),
        command.workflow_id(),
        command.snapshot_id(),
        command.run_id(),
        command.root_invocation_id(),
        run_number,
        false,
    ))
}

async fn record_admitted_event_subject(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
    admitted_at: UnixMillis,
    expected_replay: bool,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let outcome = EventSubjectTerminalOutcome::admitted(command.run_id())
        .map_err(event_subject_value_error)?;
    let (origin, control_id, registration_replay, progress_replay) =
        record_event_subject_terminal(transaction, command, subject_evidence, outcome, admitted_at)
            .await?;
    if progress_replay != expected_replay || (expected_replay && !registration_replay) {
        return Err(StoreError::corrupt_data(
            "generalized event-subject replay state disagrees with workflow admission",
        )
        .into());
    }
    link_github_check_event_control(
        transaction,
        command,
        origin,
        control_id,
        Some(command.run_id()),
    )
    .await
}

async fn record_skipped_event_subject(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
    recorded_at: UnixMillis,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let outcome = EventSubjectTerminalOutcome::skipped("workflow.disabled")
        .map_err(event_subject_value_error)?;
    let (origin, control_id, _, _) =
        record_event_subject_terminal(transaction, command, subject_evidence, outcome, recorded_at)
            .await?;
    link_github_check_event_control(transaction, command, origin, control_id, None).await
}

async fn replay_disabled_event_subject(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
) -> Result<bool, LogicalWorkflowAdmissionStoreError> {
    let origin = event_subject_origin(subject_evidence);
    let subject_id = EventSubjectId::derive(
        command.tenant(),
        command.repository().id(),
        origin,
        command.workflow_path(),
    )
    .map_err(event_subject_value_error)?;
    let Some((selection, control, progress)) =
        load_event_subject_state_in_transaction(transaction, subject_id)
            .await
            .map_err(event_subject_store_error)?
    else {
        return Ok(false);
    };
    if !event_selection_matches_command(&selection, command, origin) {
        return Err(StoreError::corrupt_data(
            "terminal event selection disagrees with admission coordinates",
        )
        .into());
    }
    let Some(progress) = progress else {
        return Ok(false);
    };
    if progress.outcome().kind() != EventSubjectTerminalKind::Skipped
        || progress.outcome().reason() != Some("workflow.disabled")
    {
        return Err(StoreError::corrupt_data(
            "terminal event subject has no matching logical admission receipt",
        )
        .into());
    }
    link_github_check_event_control(transaction, command, origin, control.id(), None).await?;
    Ok(true)
}

#[allow(clippy::too_many_lines)] // One exact mutation covers admitted and disabled projections.
async fn link_github_check_event_control(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    origin: EventSubjectOrigin,
    control_id: EventControlSubjectId,
    run_id: Option<RunId>,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    if matches!(origin, EventSubjectOrigin::ManualOperation(_)) {
        return Ok(());
    }
    let linked = if let Some(run_id) = run_id {
        sqlx::query(
            r"
            UPDATE github_check_subjects
               SET event_control_subject_id = $1
             WHERE tenant_id = $2
               AND repository_id = $3
               AND workflow_run_id = $4
               AND subject_kind = 'workflow'
               AND subject_key = $5
               AND (
                    (origin_kind = 'provider_delivery'
                     AND provider_delivery_id = $6)
                 OR (origin_kind = 'scheduled_fire'
                     AND schedule_fire_id = $6)
               )
               AND (event_control_subject_id IS NULL OR event_control_subject_id = $1)
            ",
        )
        .bind(control_id.as_uuid())
        .bind(command.tenant().as_str())
        .bind(command.repository().id().as_uuid())
        .bind(run_id.as_uuid())
        .bind(command.workflow_path())
        .bind(origin.as_uuid())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
    } else {
        // A disabled workflow is already terminal generalized progress. Keep
        // the optional GitHub projection subordinate to that control by
        // linking and terminalizing it in this same transaction. The second
        // arm is an exact no-op replay and cannot advance the revision again.
        sqlx::query(
            r"
            UPDATE github_check_subjects
               SET event_control_subject_id = $1,
                   desired_state = CASE
                       WHEN desired_state = 'queued' THEN 'completed'
                       ELSE desired_state
                   END,
                   desired_conclusion = CASE
                       WHEN desired_state = 'queued' THEN 'skipped'
                       ELSE desired_conclusion
                   END,
                   terminal_cause = CASE
                       WHEN desired_state = 'queued' THEN 'workflow_skipped'
                       ELSE terminal_cause
                   END,
                   desired_revision = CASE
                       WHEN desired_state = 'queued' THEN desired_revision + 1
                       ELSE desired_revision
                   END,
                   desired_updated_at_ms = CASE
                       WHEN desired_state = 'queued' THEN $6
                       ELSE desired_updated_at_ms
                   END
             WHERE tenant_id = $2
               AND repository_id = $3
               AND workflow_run_id IS NULL
               AND linked_at_ms IS NULL
               AND subject_kind = 'workflow'
               AND subject_key = $4
               AND (
                    (origin_kind = 'provider_delivery'
                     AND provider_delivery_id = $5)
                 OR (origin_kind = 'scheduled_fire'
                     AND schedule_fire_id = $5)
               )
               AND (
                    (event_control_subject_id IS NULL
                     AND desired_state = 'queued'
                     AND desired_conclusion IS NULL
                     AND terminal_cause IS NULL
                     AND desired_revision = 1
                     AND desired_updated_at_ms <= $6)
                 OR (event_control_subject_id = $1
                     AND desired_state = 'completed'
                     AND desired_conclusion = 'skipped'
                     AND terminal_cause = 'workflow_skipped'
                     AND desired_revision = 2
                     AND desired_updated_at_ms <= $6)
               )
            ",
        )
        .bind(control_id.as_uuid())
        .bind(command.tenant().as_str())
        .bind(command.repository().id().as_uuid())
        .bind(command.workflow_path())
        .bind(origin.as_uuid())
        .bind(command.admitted_at().get())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?
    };
    if linked.rows_affected() != 1 {
        return Err(StoreError::corrupt_data(
            "generalized event control does not match one Check projection",
        )
        .into());
    }
    Ok(())
}

async fn record_event_subject_terminal(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
    outcome: EventSubjectTerminalOutcome,
    recorded_at: UnixMillis,
) -> Result<
    (EventSubjectOrigin, EventControlSubjectId, bool, bool),
    LogicalWorkflowAdmissionStoreError,
> {
    let origin = event_subject_origin(subject_evidence);
    let subject_id = EventSubjectId::derive(
        command.tenant(),
        command.repository().id(),
        origin,
        command.workflow_path(),
    )
    .map_err(event_subject_value_error)?;
    let existing = load_event_subject_state_in_transaction(transaction, subject_id)
        .await
        .map_err(event_subject_store_error)?;
    let (selection, control_id, registration_replay, durable_progress) =
        if let Some((selection, control, progress)) = existing {
            if !event_selection_matches_command(&selection, command, origin) {
                return Err(StoreError::corrupt_data(
                    "generalized event selection disagrees with admission coordinates",
                )
                .into());
            }
            (selection, control.id(), true, progress)
        } else {
            let selection = EventSubjectSelection::new(
                subject_id,
                command.tenant().clone(),
                command.repository().id(),
                origin,
                command.event_name(),
                command.workflow_path(),
                lower_hex(command.head_sha()),
                command.source().digest(),
                command.request_digest(),
                recorded_at,
            )
            .map_err(event_subject_value_error)?;
            let control_id = EventControlSubjectId::derive(subject_id);
            let control = EventControlSubject::new(control_id, &selection, recorded_at)
                .map_err(event_subject_value_error)?;
            let request = RegisterEventSubject::new(selection.clone(), control)
                .map_err(event_subject_value_error)?;
            match register_event_subject_in_transaction(transaction, request).await {
                Ok(registration) => (selection, control_id, registration.is_replay(), None),
                Err(EventSubjectStoreError::Conflict) => {
                    let (durable_selection, durable_control, durable_progress) =
                        load_event_subject_state_in_transaction(transaction, subject_id)
                            .await
                            .map_err(event_subject_store_error)?
                            .ok_or_else(|| {
                                StoreError::corrupt_data(
                                    "concurrent generalized event registration lost durable state",
                                )
                            })?;
                    if !event_selection_matches_command(&durable_selection, command, origin) {
                        return Err(StoreError::corrupt_data(
                            "concurrent generalized event selection conflicts with admission",
                        )
                        .into());
                    }
                    (
                        durable_selection,
                        durable_control.id(),
                        true,
                        durable_progress,
                    )
                }
                Err(error) => return Err(event_subject_store_error(error)),
            }
        };
    if let Some(progress) = durable_progress {
        if progress.outcome() != &outcome {
            return Err(StoreError::corrupt_data(
                "terminal event-subject replay conflicts with durable progress",
            )
            .into());
        }
        return Ok((origin, control_id, registration_replay, true));
    }
    let progress = EventSubjectProgress::new(&selection, outcome, recorded_at)
        .map_err(event_subject_value_error)?;
    let progress = record_event_subject_progress_in_transaction(transaction, progress)
        .await
        .map_err(event_subject_store_error)?;
    Ok((
        origin,
        control_id,
        registration_replay,
        progress.is_replay(),
    ))
}

fn event_subject_origin(subject_evidence: &SubjectEvidenceAdmission) -> EventSubjectOrigin {
    match subject_evidence {
        SubjectEvidenceAdmission::AuthenticatedGithub { current_claim, .. } => {
            EventSubjectOrigin::ProviderDelivery(current_claim.claim().delivery_id())
        }
        SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } => {
            EventSubjectOrigin::ManualOperation(claim.operation_id())
        }
        SubjectEvidenceAdmission::ScheduledGithub { claim } => {
            EventSubjectOrigin::ScheduleFire(claim.fire_id())
        }
    }
}

fn event_selection_matches_command(
    selection: &EventSubjectSelection,
    command: &AdmitLogicalWorkflowRun,
    origin: EventSubjectOrigin,
) -> bool {
    selection.tenant() == command.tenant()
        && selection.repository_id() == command.repository().id()
        && selection.origin() == origin
        && selection.event_name() == command.event_name()
        && selection.workflow_path() == command.workflow_path()
        && selection.source_revision() == lower_hex(command.head_sha())
        && selection.source_digest() == command.source().digest()
        && selection.authority_digest() == command.request_digest()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn event_subject_value_error(
    _error: automata_ci_store::EventSubjectValueError,
) -> LogicalWorkflowAdmissionStoreError {
    StoreError::corrupt_data("generalized event-subject coordinates are invalid").into()
}

fn event_subject_store_error(error: EventSubjectStoreError) -> LogicalWorkflowAdmissionStoreError {
    match error {
        EventSubjectStoreError::Operation(error) => StoreError::Operation(error).into(),
        EventSubjectStoreError::Conflict => StoreError::corrupt_data(
            "generalized event-subject identity conflicts with durable admission",
        )
        .into(),
        EventSubjectStoreError::NotFound | EventSubjectStoreError::CorruptData => {
            StoreError::corrupt_data("durable generalized event-subject state is corrupt").into()
        }
    }
}

fn validate_subject_evidence_boundary(
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    match subject_evidence {
        SubjectEvidenceAdmission::AuthenticatedGithub {
            current_claim: _,
            observed_at,
        } => {
            let provider_delivery = matches!(
                command.idempotency(),
                WorkflowAdmissionIdempotency::ProviderDelivery(_)
            );
            if command.repository().provider() != "github"
                || !provider_delivery
                || command.admitted_at() != *observed_at
            {
                return Err(StoreError::corrupt_data(
                    "authenticated GitHub admission has an invalid provider boundary",
                )
                .into());
            }
        }
        SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } => {
            let operation_matches = matches!(
                command.idempotency(),
                WorkflowAdmissionIdempotency::Operation(operation_id)
                    if *operation_id == claim.operation_id()
            );
            let base_context_matches = command
                .base_context()
                .is_some_and(|context| context.digest() == claim.base_context_digest());
            if command.repository().provider() != "github"
                || command.event_name() != "workflow_dispatch"
                || claim.actor().tenant_id().as_str() != command.tenant().as_str()
                || claim.repository_id() != command.repository().id()
                || claim.workflow_id() != command.workflow_id()
                || claim.workflow_path() != command.workflow_path()
                || claim.git_ref() != command.git_ref()
                || claim.commit_sha() != lower_hex(command.head_sha())
                || claim.source() != command.source()
                || command.actor() != Some(claim.actor().principal_id().as_str())
                || claim.event_digest() != command.event().digest()
                || !base_context_matches
                || !operation_matches
            {
                return Err(StoreError::corrupt_data(
                    "authenticated workflow dispatch has an invalid exact-target boundary",
                )
                .into());
            }
        }
        SubjectEvidenceAdmission::ScheduledGithub { claim } => {
            let operation_matches = matches!(
                command.idempotency(),
                WorkflowAdmissionIdempotency::Operation(operation_id)
                    if *operation_id == OperationId::from_uuid(claim.fire_id().as_uuid())
            );
            if command.repository().provider() != "github"
                || command.event_name() != "schedule"
                || command.actor() != Some(automata_ci_store::GITHUB_SCHEDULE_SERVICE_ACTOR)
                || command.admitted_at() < claim.claimed_at()
                || command.admitted_at() >= claim.expires_at()
                || !operation_matches
            {
                return Err(StoreError::corrupt_data(
                    "scheduled GitHub admission has an invalid exact-fire boundary",
                )
                .into());
            }
        }
    }
    Ok(())
}

async fn validate_subject_selection_authority(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    match subject_evidence {
        SubjectEvidenceAdmission::AuthenticatedGithub { current_claim, .. } => {
            let request = RecordGithubWorkflowRunSubjectEvidence::from_logical_admission(
                *current_claim,
                command,
            )
            .map_err(|_| {
                StoreError::corrupt_data("invalid signed GitHub event selection evidence")
            })?;
            validate_github_workflow_selection_in_transaction(transaction, &request)
                .await
                .map_err(subject_evidence_error)
        }
        SubjectEvidenceAdmission::ScheduledGithub { claim } => {
            validate_github_schedule_selection_in_transaction(transaction, command, *claim).await
        }
        SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } => {
            validate_manual_dispatch_source_authority(transaction, command, claim).await
        }
    }
}

async fn validate_manual_dispatch_source_authority(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: &AuthenticatedWorkflowDispatchClaim,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let source_size = i64::try_from(claim.source().encoded_size()).map_err(|_| {
        StoreError::corrupt_data("workflow dispatch source size exceeds durable bounds")
    })?;
    if resolved_manual_dispatch_source_authorized(transaction, command, claim, source_size).await? {
        return Ok(());
    }

    // Retain the internal exact-source path for callers that already hold a
    // Core-authenticated historical admission. The public HTTP contract never
    // accepts a commit SHA and always uses the durable resolution above.
    let exact = sqlx::query_scalar::<_, bool>(
        r"
        SELECT TRUE
          FROM repositories AS repository
          JOIN workflow_definitions AS workflow
            ON workflow.repository_id = repository.id
           AND workflow.id = $3
           AND workflow.path = $4
          JOIN workflow_runs AS run
            ON run.repository_id = repository.id
           AND run.workflow_id = workflow.id
           AND run.git_ref = $5
           AND run.head_sha = $6
           AND run.admission_epoch = $11
          JOIN workflow_snapshots AS snapshot
            ON snapshot.id = run.snapshot_id
           AND snapshot.workflow_id = workflow.id
           AND snapshot.source_digest = $7
           AND snapshot.source_object_key = $8
           AND snapshot.source_size_bytes = $9
           AND snapshot.source_media_type = $10
          JOIN github_workflow_run_subject_evidence AS evidence
            ON evidence.tenant_id = repository.tenant_id
           AND evidence.repository_id = repository.id
           AND evidence.workflow_id = workflow.id
           AND evidence.snapshot_id = snapshot.id
           AND evidence.run_id = run.id
           AND evidence.workflow_path = workflow.path
           AND evidence.source_digest = snapshot.source_digest
           AND evidence.git_ref = run.git_ref
         WHERE repository.tenant_id = $1
           AND repository.id = $2
           AND repository.scm_provider = 'github'
         LIMIT 1
        FOR SHARE OF repository, workflow, run, snapshot, evidence
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(claim.workflow_id().as_uuid())
    .bind(claim.workflow_path())
    .bind(claim.git_ref())
    .bind(decode_commit_sha_bytes(claim.commit_sha())?)
    .bind(claim.source().digest().as_bytes().as_slice())
    .bind(claim.source().object_key().as_str())
    .bind(source_size)
    .bind(claim.source().media_type())
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if exact == Some(true) {
        Ok(())
    } else {
        Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected)
    }
}

async fn resolved_manual_dispatch_source_authorized(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: &AuthenticatedWorkflowDispatchClaim,
    source_size: i64,
) -> Result<bool, LogicalWorkflowAdmissionStoreError> {
    let principal_id = Uuid::parse_str(claim.actor().principal_id().as_str()).map_err(|_| {
        StoreError::corrupt_data("workflow dispatch principal identity is not a durable UUID")
    })?;
    let resolved = sqlx::query_scalar::<_, bool>(
        r"
        SELECT TRUE
        FROM workflow_dispatch_source_resolutions AS resolution
        WHERE resolution.tenant_id = $1
          AND resolution.repository_id = $2
          AND resolution.workflow_id = $3
          AND resolution.workflow_path = $4
          AND resolution.git_ref = $5
          AND resolution.commit_sha = $6
          AND resolution.source_digest = $7
          AND resolution.source_object_key = $8
          AND resolution.source_size_bytes = $9
          AND resolution.source_media_type = $10
          AND resolution.operation_id = $11
          AND resolution.principal_id = $12
          AND resolution.state = 'resolved'
        FOR SHARE OF resolution
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(claim.workflow_id().as_uuid())
    .bind(claim.workflow_path())
    .bind(claim.git_ref())
    .bind(decode_commit_sha_bytes(claim.commit_sha())?)
    .bind(claim.source().digest().as_bytes().as_slice())
    .bind(claim.source().object_key().as_str())
    .bind(source_size)
    .bind(claim.source().media_type())
    .bind(claim.operation_id().as_uuid())
    .bind(principal_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(resolved == Some(true))
}

async fn authorize_dispatch_subject(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
) -> Result<Option<AuthorizedWorkflowDispatchActor>, LogicalWorkflowAdmissionStoreError> {
    let SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } = subject_evidence else {
        return Ok(None);
    };
    require_existing_dispatch_repository(transaction, command).await?;
    let actor = authorize_workflow_dispatch_actor(
        transaction,
        claim.actor(),
        WORKFLOW_DISPATCH_PERMISSION,
        command.repository().id().as_uuid(),
    )
    .await?;
    let Some(actor) = actor else {
        return Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected);
    };
    if actor.tenant_id != command.tenant().as_str()
        || !authorized_dispatch_actor_matches(&actor, claim.actor())
    {
        return Err(StoreError::corrupt_data(
            "reauthorized workflow dispatch actor disagrees with its claim",
        )
        .into());
    }
    Ok(Some(actor))
}

async fn require_existing_dispatch_repository(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT scm_provider, provider_repository_id, owner, name
        FROM repositories
        WHERE tenant_id = $1 AND id = $2
        FOR SHARE
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected);
    };
    let repository = command.repository();
    let exact = row
        .try_get::<String, _>("scm_provider")
        .map_err(operation_error)?
        == repository.provider()
        && row
            .try_get::<String, _>("provider_repository_id")
            .map_err(operation_error)?
            == repository.provider_repository_id()
        && row.try_get::<String, _>("owner").map_err(operation_error)? == repository.owner()
        && row.try_get::<String, _>("name").map_err(operation_error)? == repository.name();
    if !exact {
        return Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected);
    }
    Ok(())
}

fn map_concurrency_error(error: WorkflowAdmissionStoreError) -> LogicalWorkflowAdmissionStoreError {
    match error {
        WorkflowAdmissionStoreError::Store(error) => error.into(),
        WorkflowAdmissionStoreError::ConcurrencyQueueFull => {
            LogicalWorkflowAdmissionStoreError::ConcurrencyQueueFull
        }
        WorkflowAdmissionStoreError::IdempotencyConflict
        | WorkflowAdmissionStoreError::IdentityConflict(_)
        | WorkflowAdmissionStoreError::RunNumberExhausted => StoreError::corrupt_data(
            "logical concurrency admission returned an unrelated legacy error",
        )
        .into(),
    }
}

async fn record_new_subject_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
    dispatch_actor: Option<&AuthorizedWorkflowDispatchActor>,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    match subject_evidence {
        SubjectEvidenceAdmission::AuthenticatedGithub {
            current_claim,
            observed_at: _,
        } => {
            let request = RecordGithubWorkflowRunSubjectEvidence::from_logical_admission(
                *current_claim,
                command,
            )
            .map_err(|_| {
                StoreError::corrupt_data("invalid signed GitHub logical-admission evidence")
            })?;
            record_github_workflow_run_subject_evidence_in_transaction(transaction, &request)
                .await
                .map_err(subject_evidence_error)?;
            Ok(())
        }
        SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } => {
            let actor = dispatch_actor.ok_or_else(|| {
                StoreError::corrupt_data(
                    "authenticated workflow dispatch lost its authorized actor",
                )
            })?;
            record_workflow_dispatch_audit(transaction, command, claim, actor).await
        }
        SubjectEvidenceAdmission::ScheduledGithub { claim } => {
            record_github_scheduled_run_evidence_in_transaction(transaction, command, *claim).await
        }
    }
}

async fn validate_replayed_subject_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
    dispatch_actor: Option<&AuthorizedWorkflowDispatchActor>,
    admitted_at: UnixMillis,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    match subject_evidence {
        SubjectEvidenceAdmission::AuthenticatedGithub {
            current_claim,
            observed_at,
        } => {
            let request = ValidateGithubWorkflowRunSubjectEvidenceReplay::from_logical_admission(
                *current_claim,
                *observed_at,
                admitted_at,
                command,
            )
            .map_err(|_| {
                StoreError::corrupt_data("invalid signed GitHub logical-admission replay")
            })?;
            validate_github_workflow_run_subject_evidence_in_transaction(transaction, &request)
                .await
                .map_err(subject_evidence_error)?;
            Ok(())
        }
        SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } => {
            let actor = dispatch_actor.ok_or_else(|| {
                StoreError::corrupt_data("workflow dispatch replay lost its authorized actor")
            })?;
            validate_workflow_dispatch_audit(transaction, command, claim, actor, admitted_at).await
        }
        SubjectEvidenceAdmission::ScheduledGithub { claim } => {
            validate_github_scheduled_run_evidence_in_transaction(
                transaction,
                command,
                *claim,
                admitted_at,
            )
            .await
        }
    }
}

async fn record_workflow_dispatch_audit(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: &AuthenticatedWorkflowDispatchClaim,
    actor: &AuthorizedWorkflowDispatchActor,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let event_id = workflow_dispatch_audit_event_id(command.request_digest());
    let (session_id, request_id) = match &actor.source {
        AuthorizedWorkflowDispatchActorSource::CoreSession {
            session_id,
            request_id,
        } => (Some(*session_id), request_id.as_deref()),
        AuthorizedWorkflowDispatchActorSource::Delegated { .. } => (None, None),
    };
    sqlx::query(
        r"
        INSERT INTO security_audit_events (
            event_id, tenant_id, occurred_at_ms, actor_kind,
            actor_principal_id, actor_session_id, authorization_revision,
            action, outcome, resource_kind, resource_id, request_id
        ) VALUES (
            $1,$2,$3,'human',$4,$5,$6,$7,'succeeded',$8,$9,$10
        )
        ON CONFLICT (event_id) DO NOTHING
        ",
    )
    .bind(event_id)
    .bind(&actor.tenant_id)
    .bind(command.admitted_at().get())
    .bind(actor.principal_id)
    .bind(session_id)
    .bind(actor.authorization_revision)
    .bind(WORKFLOW_DISPATCH_AUDIT_ACTION)
    .bind(WORKFLOW_DISPATCH_AUDIT_RESOURCE_KIND)
    .bind(command.run_id().to_string())
    .bind(request_id)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if let AuthorizedWorkflowDispatchActorSource::Delegated {
        issuer,
        subject,
        external_session_id,
        assertion_id,
        authenticated_at_seconds,
        issued_at_seconds,
        expires_at_seconds,
    } = &actor.source
    {
        let authenticated_at_ms = seconds_to_millis(*authenticated_at_seconds)?;
        let issued_at_ms = seconds_to_millis(*issued_at_seconds)?;
        let expires_at_ms = seconds_to_millis(*expires_at_seconds)?;
        if command.admitted_at().get() < issued_at_ms
            || command.admitted_at().get() >= expires_at_ms
        {
            return Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected);
        }
        sqlx::query(
            r"
            INSERT INTO delegated_actor_audit_evidence (
                event_id, tenant_id, principal_id, issuer, subject,
                external_session_id, assertion_id, authenticated_at_ms,
                issued_at_ms, expires_at_ms
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT (event_id) DO NOTHING
            ",
        )
        .bind(event_id)
        .bind(&actor.tenant_id)
        .bind(actor.principal_id)
        .bind(issuer)
        .bind(subject)
        .bind(external_session_id)
        .bind(assertion_id)
        .bind(authenticated_at_ms)
        .bind(issued_at_ms)
        .bind(expires_at_ms)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }
    validate_workflow_dispatch_audit(transaction, command, claim, actor, command.admitted_at())
        .await?;
    pin_workflow_dispatch_runtime_policy(transaction, command).await
}

async fn pin_workflow_dispatch_runtime_policy(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO logical_workflow_runtime_policy_pins (
            run_id, tenant_id, repository_id, policy_revision,
            policy_digest, pinned_at_ms
        )
        SELECT $1, $2, $3, manifest.runtime_policy_revision,
               manifest.runtime_policy_digest, $4
        FROM github_provider_manifest_current AS current_manifest
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = current_manifest.tenant_id
         AND manifest.repository_id = current_manifest.repository_id
         AND manifest.provider_connection_id = current_manifest.provider_connection_id
         AND manifest.manifest_revision = current_manifest.manifest_revision
         AND manifest.manifest_digest = current_manifest.manifest_digest
        JOIN workflow_runtime_policy_revisions AS policy
          ON policy.tenant_id = manifest.tenant_id
         AND policy.repository_id = manifest.repository_id
         AND policy.policy_revision = manifest.runtime_policy_revision
         AND policy.policy_digest = manifest.runtime_policy_digest
         AND policy.state = 'sealed'
        WHERE current_manifest.tenant_id = $2
          AND current_manifest.repository_id = $3
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if inserted.rows_affected() != 1 {
        return Err(StoreError::corrupt_data(
            "workflow dispatch lacks one exact current runtime policy",
        )
        .into());
    }
    Ok(())
}

async fn validate_workflow_dispatch_audit(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: &AuthenticatedWorkflowDispatchClaim,
    actor: &AuthorizedWorkflowDispatchActor,
    admitted_at: UnixMillis,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT tenant_id, occurred_at_ms, actor_kind, actor_principal_id,
               actor_session_id, authorization_revision, action, outcome,
               resource_kind, resource_id
        FROM security_audit_events
        WHERE event_id = $1
        FOR UPDATE
        ",
    )
    .bind(workflow_dispatch_audit_event_id(command.request_digest()))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let Some(row) = row else {
        return Err(StoreError::corrupt_data(
            "workflow dispatch admission audit evidence is absent",
        )
        .into());
    };
    let resource_id = command.run_id().to_string();
    let audit_session_id = row
        .try_get::<Option<Uuid>, _>("actor_session_id")
        .map_err(operation_error)?;
    let event_id = workflow_dispatch_audit_event_id(command.request_digest());
    let actor_evidence_exact = validate_dispatch_actor_audit_evidence(
        transaction,
        event_id,
        actor,
        audit_session_id,
        admitted_at,
    )
    .await?;
    let exact = actor_evidence_exact
        && authorized_dispatch_actor_matches(actor, claim.actor())
        && row
            .try_get::<String, _>("tenant_id")
            .map_err(operation_error)?
            == actor.tenant_id
        && row
            .try_get::<i64, _>("occurred_at_ms")
            .map_err(operation_error)?
            == admitted_at.get()
        && row
            .try_get::<String, _>("actor_kind")
            .map_err(operation_error)?
            == "human"
        && row
            .try_get::<Option<Uuid>, _>("actor_principal_id")
            .map_err(operation_error)?
            == Some(actor.principal_id)
        && row
            .try_get::<Option<i64>, _>("authorization_revision")
            .map_err(operation_error)?
            == Some(actor.authorization_revision)
        && row
            .try_get::<String, _>("action")
            .map_err(operation_error)?
            == WORKFLOW_DISPATCH_AUDIT_ACTION
        && row
            .try_get::<String, _>("outcome")
            .map_err(operation_error)?
            == "succeeded"
        && row
            .try_get::<String, _>("resource_kind")
            .map_err(operation_error)?
            == WORKFLOW_DISPATCH_AUDIT_RESOURCE_KIND
        && row
            .try_get::<Option<String>, _>("resource_id")
            .map_err(operation_error)?
            .as_deref()
            == Some(resource_id.as_str());
    if !exact {
        return Err(StoreError::corrupt_data(
            "workflow dispatch admission audit evidence is inconsistent",
        )
        .into());
    }
    Ok(())
}

async fn validate_dispatch_actor_audit_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: Uuid,
    actor: &AuthorizedWorkflowDispatchActor,
    audit_session_id: Option<Uuid>,
    admitted_at: UnixMillis,
) -> Result<bool, LogicalWorkflowAdmissionStoreError> {
    let evidence = sqlx::query(
        r"
        SELECT tenant_id, principal_id, issuer, subject, external_session_id,
               issued_at_ms, expires_at_ms
        FROM delegated_actor_audit_evidence
        WHERE event_id = $1
        FOR SHARE
        ",
    )
    .bind(event_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    match (&actor.source, audit_session_id, evidence) {
        (
            AuthorizedWorkflowDispatchActorSource::CoreSession { session_id, .. },
            Some(audit_session_id),
            None,
        ) => Ok(*session_id == audit_session_id),
        (
            AuthorizedWorkflowDispatchActorSource::Delegated {
                issuer,
                subject,
                external_session_id,
                ..
            },
            None,
            Some(evidence),
        ) => {
            // A replay can carry a freshly signed assertion for the same
            // external session. The current assertion was reauthorized above;
            // this row intentionally preserves the assertion that first
            // admitted the run.
            let issued_at_ms = evidence
                .try_get::<i64, _>("issued_at_ms")
                .map_err(operation_error)?;
            let expires_at_ms = evidence
                .try_get::<i64, _>("expires_at_ms")
                .map_err(operation_error)?;
            Ok(evidence
                .try_get::<String, _>("tenant_id")
                .map_err(operation_error)?
                == actor.tenant_id
                && evidence
                    .try_get::<Uuid, _>("principal_id")
                    .map_err(operation_error)?
                    == actor.principal_id
                && evidence
                    .try_get::<String, _>("issuer")
                    .map_err(operation_error)?
                    == *issuer
                && evidence
                    .try_get::<Uuid, _>("subject")
                    .map_err(operation_error)?
                    == *subject
                && evidence
                    .try_get::<Uuid, _>("external_session_id")
                    .map_err(operation_error)?
                    == *external_session_id
                && admitted_at.get() >= issued_at_ms
                && admitted_at.get() < expires_at_ms)
        }
        _ => Ok(false),
    }
}

fn authorized_dispatch_actor_matches(
    authorized: &AuthorizedWorkflowDispatchActor,
    requested: &RepositoryMutationActor,
) -> bool {
    if requested.tenant_id().as_str() != authorized.tenant_id
        || requested.principal_id().as_str() != authorized.principal_id.hyphenated().to_string()
        || i64::try_from(requested.authorization_revision()).ok()
            != Some(authorized.authorization_revision)
    {
        return false;
    }
    match (&authorized.source, requested) {
        (
            AuthorizedWorkflowDispatchActorSource::CoreSession { session_id, .. },
            RepositoryMutationActor::CoreSession(requested),
        ) => requested.session_id().as_str() == session_id.hyphenated().to_string(),
        (
            AuthorizedWorkflowDispatchActorSource::Delegated {
                issuer,
                subject,
                external_session_id,
                assertion_id,
                authenticated_at_seconds,
                issued_at_seconds,
                expires_at_seconds,
            },
            RepositoryMutationActor::Delegated(requested),
        ) => {
            let assertion = requested.assertion();
            assertion.issuer() == issuer
                && assertion.subject() == *subject
                && assertion.session_id() == *external_session_id
                && assertion.assertion_id() == *assertion_id
                && assertion.authenticated_at().as_seconds() == *authenticated_at_seconds
                && assertion.issued_at().as_seconds() == *issued_at_seconds
                && assertion.expires_at().as_seconds() == *expires_at_seconds
        }
        _ => false,
    }
}

fn seconds_to_millis(seconds: u64) -> Result<i64, LogicalWorkflowAdmissionStoreError> {
    seconds
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| {
            StoreError::corrupt_data("delegated actor time is outside PostgreSQL").into()
        })
}

fn workflow_dispatch_audit_event_id(request_digest: Sha256Digest) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(WORKFLOW_DISPATCH_AUDIT_ID_DOMAIN);
    digest.update(request_digest.as_bytes());
    let digest: [u8; 32] = digest.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn subject_evidence_error(
    error: GithubSubjectEvidenceStoreError,
) -> LogicalWorkflowAdmissionStoreError {
    match error {
        GithubSubjectEvidenceStoreError::Operation(error) => StoreError::Operation(error).into(),
        GithubSubjectEvidenceStoreError::CorruptData => {
            StoreError::corrupt_data("durable signed GitHub subject evidence is corrupt").into()
        }
        GithubSubjectEvidenceStoreError::AuthorityRejected
        | GithubSubjectEvidenceStoreError::ReplayConflict
        | GithubSubjectEvidenceStoreError::NotFound => {
            StoreError::corrupt_data("signed GitHub subject evidence rejected admission").into()
        }
    }
}

async fn lock_logical_admission_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let tenant = command.tenant().as_str();
    let kind = command.idempotency().kind();
    let key = command.idempotency().key();
    // Byte-length framing keeps delimiter-bearing identities distinct. A hash
    // collision can only serialize unrelated admissions; it cannot split one key.
    let lock_identity = format!(
        "{}:{tenant}|{}:{kind}|{}:{key}",
        tenant.len(),
        kind.len(),
        key.len(),
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
        .bind(lock_identity)
        .bind(LOGICAL_ADMISSION_IDEMPOTENCY_LOCK_NAMESPACE)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn admission_receipt_exists(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<bool, LogicalWorkflowAdmissionStoreError> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM workflow_admission_receipts
            WHERE tenant_id = $1
              AND idempotency_kind = $2
              AND idempotency_key = $3
        )
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)
}

async fn claim_idempotency_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    github_subject_evidence_required: bool,
) -> Result<bool, LogicalWorkflowAdmissionStoreError> {
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_admission_receipts (
            tenant_id, idempotency_kind, idempotency_key, request_digest,
            github_subject_evidence_required
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .bind(command.request_digest().as_bytes().as_slice())
    .bind(github_subject_evidence_required)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    Ok(rows == 1)
}

#[allow(clippy::too_many_lines)] // Exact replay decodes and checks every linked current descriptor.
async fn replay_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    github_subject_evidence_required: bool,
) -> Result<(LogicalWorkflowAdmissionReceipt, UnixMillis), LogicalWorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT receipt.request_digest, receipt.repository_id, receipt.run_id,
               receipt.github_subject_evidence_required,
               receipt.committed_at_ms, run.workflow_id, run.snapshot_id,
               run.repository_id AS run_repository_id,
               run.run_number, run.admission_epoch, run.plan_schema,
               run.created_at_ms AS run_created_at_ms,
               run.publication_policy_revision,
               run.requested_dashboard_visibility,
               run.effective_dashboard_visibility,
               run.requested_log_visibility,
               run.requested_artifact_visibility,
               run.publication_safety_reason, run.publication_safety_schema,
               marker.root_invocation_id, marker.orchestration_schema,
               marker.admission_digest,
               marker.base_context_digest, marker.base_context_object_key,
               marker.base_context_size_bytes, marker.base_context_media_type,
               marker.base_context_schema,
               marker.admitted_at_ms AS marker_admitted_at_ms,
               invocation.id AS invocation_id
        FROM workflow_admission_receipts AS receipt
        LEFT JOIN workflow_runs AS run ON run.id = receipt.run_id
        LEFT JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        LEFT JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = marker.run_id
         AND invocation.id = marker.root_invocation_id
        WHERE receipt.tenant_id = $1
          AND receipt.idempotency_kind = $2
          AND receipt.idempotency_key = $3
        FOR UPDATE OF receipt
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| {
        StoreError::corrupt_data("logical admission conflict lost its durable receipt")
    })?;

    let request_digest: Vec<u8> = row.try_get("request_digest").map_err(operation_error)?;
    if request_digest.as_slice() != command.request_digest().as_bytes() {
        return Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict);
    }
    let durable_github_subject_evidence_required: bool = row
        .try_get("github_subject_evidence_required")
        .map_err(operation_error)?;
    if durable_github_subject_evidence_required != github_subject_evidence_required {
        return Err(StoreError::corrupt_data(
            "logical admission receipt has a different subject-evidence mode",
        )
        .into());
    }

    let repository_id = row
        .try_get::<Option<Uuid>, _>("repository_id")
        .map_err(operation_error)?;
    let run_id = row
        .try_get::<Option<Uuid>, _>("run_id")
        .map_err(operation_error)?;
    let run_repository_id = row
        .try_get::<Option<Uuid>, _>("run_repository_id")
        .map_err(operation_error)?;
    let workflow_id = row
        .try_get::<Option<Uuid>, _>("workflow_id")
        .map_err(operation_error)?;
    let snapshot_id = row
        .try_get::<Option<Uuid>, _>("snapshot_id")
        .map_err(operation_error)?;
    let run_number = row
        .try_get::<Option<i64>, _>("run_number")
        .map_err(operation_error)?;
    let admission_epoch = row
        .try_get::<Option<i32>, _>("admission_epoch")
        .map_err(operation_error)?;
    let plan_schema = row
        .try_get::<Option<i32>, _>("plan_schema")
        .map_err(operation_error)?;
    let root_invocation_id = row
        .try_get::<Option<Uuid>, _>("root_invocation_id")
        .map_err(operation_error)?;
    let invocation_id = row
        .try_get::<Option<Uuid>, _>("invocation_id")
        .map_err(operation_error)?;
    let orchestration_schema = row
        .try_get::<Option<i16>, _>("orchestration_schema")
        .map_err(operation_error)?;
    let admission_digest = row
        .try_get::<Option<Vec<u8>>, _>("admission_digest")
        .map_err(operation_error)?;
    let base_context_digest = row
        .try_get::<Option<Vec<u8>>, _>("base_context_digest")
        .map_err(operation_error)?;
    let base_context_object_key = row
        .try_get::<Option<String>, _>("base_context_object_key")
        .map_err(operation_error)?;
    let base_context_size = row
        .try_get::<Option<i64>, _>("base_context_size_bytes")
        .map_err(operation_error)?;
    let base_context_media_type = row
        .try_get::<Option<String>, _>("base_context_media_type")
        .map_err(operation_error)?;
    let base_context_schema = row
        .try_get::<Option<i16>, _>("base_context_schema")
        .map_err(operation_error)?;
    let committed_at = row
        .try_get::<Option<i64>, _>("committed_at_ms")
        .map_err(operation_error)?;
    let run_created_at = row
        .try_get::<Option<i64>, _>("run_created_at_ms")
        .map_err(operation_error)?;
    let marker_admitted_at = row
        .try_get::<Option<i64>, _>("marker_admitted_at_ms")
        .map_err(operation_error)?;

    let (
        Some(repository_id),
        Some(run_id),
        Some(run_repository_id),
        Some(workflow_id),
        Some(snapshot_id),
        Some(run_number),
        Some(admission_epoch),
        Some(plan_schema),
        Some(root_invocation_id),
        Some(invocation_id),
        Some(orchestration_schema),
        Some(admission_digest),
        Some(committed_at),
        Some(run_created_at),
        Some(marker_admitted_at),
    ) = (
        repository_id,
        run_id,
        run_repository_id,
        workflow_id,
        snapshot_id,
        run_number,
        admission_epoch,
        plan_schema,
        root_invocation_id,
        invocation_id,
        orchestration_schema,
        admission_digest,
        committed_at,
        run_created_at,
        marker_admitted_at,
    )
    else {
        return Err(
            StoreError::corrupt_data("current logical admission receipt is incomplete").into(),
        );
    };

    let base_context_exact = match command.base_context() {
        Some(context) => {
            base_context_digest.as_deref() == Some(context.digest().as_bytes().as_slice())
                && base_context_object_key.as_deref() == Some(context.object_key().as_str())
                && base_context_size.and_then(|size| u64::try_from(size).ok())
                    == Some(context.encoded_size())
                && base_context_media_type.as_deref() == Some(context.media_type())
                && base_context_schema == i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).ok()
        }
        None => {
            base_context_digest.is_none()
                && base_context_object_key.is_none()
                && base_context_size.is_none()
                && base_context_media_type.is_none()
                && base_context_schema.is_none()
        }
    };

    if repository_id != command.repository().id().as_uuid()
        || run_repository_id != repository_id
        || run_id != command.run_id().as_uuid()
        || workflow_id != command.workflow_id().as_uuid()
        || snapshot_id != command.snapshot_id().as_uuid()
        || root_invocation_id != command.root_invocation_id().as_uuid()
        || invocation_id != root_invocation_id
        || admission_epoch != i32::from(WORKFLOW_ADMISSION_EPOCH)
        || plan_schema != i32::from(WORKFLOW_PLAN_SCHEMA)
        || orchestration_schema != i16::try_from(LOGICAL_ORCHESTRATION_SCHEMA).unwrap_or(i16::MAX)
        || admission_digest.as_slice() != command.request_digest().as_bytes()
        || !base_context_exact
        || run_created_at < 0
        || committed_at != run_created_at
        || marker_admitted_at != run_created_at
    {
        return Err(StoreError::corrupt_data(
            "current logical admission receipt disagrees with immutable evidence",
        )
        .into());
    }
    let publication = RunPublicationSnapshot::from_durable_run(
        row.try_get("publication_policy_revision")
            .map_err(operation_error)?,
        row.try_get("requested_dashboard_visibility")
            .map_err(operation_error)?,
        row.try_get::<Option<String>, _>("effective_dashboard_visibility")
            .map_err(operation_error)?
            .as_deref(),
        row.try_get("requested_log_visibility")
            .map_err(operation_error)?,
        row.try_get("requested_artifact_visibility")
            .map_err(operation_error)?,
        row.try_get::<Option<String>, _>("publication_safety_reason")
            .map_err(operation_error)?
            .as_deref(),
        row.try_get("publication_safety_schema")
            .map_err(operation_error)?,
    )?;
    let current = lock_repository_publication_snapshot(
        transaction,
        command.tenant().as_str(),
        command.repository().id().as_uuid(),
    )
    .await?;
    publication.revalidate_against_current(&current)?;

    let run_number = u64::try_from(run_number)
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| StoreError::corrupt_data("invalid durable workflow run number"))?;
    let root_invocation_id = LogicalWorkflowInvocationId::from_uuid(root_invocation_id)
        .map_err(|_| StoreError::corrupt_data("invalid durable root invocation identity"))?;
    Ok((
        LogicalWorkflowAdmissionReceipt::new(
            RepositoryId::from_uuid(repository_id),
            WorkflowId::from_uuid(workflow_id),
            WorkflowSnapshotId::from_uuid(snapshot_id),
            RunId::from_uuid(run_id),
            root_invocation_id,
            run_number,
            true,
        ),
        UnixMillis::new(run_created_at),
    ))
}

async fn resolve_repository(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let repository = command.repository();
    let id: Uuid = sqlx::query_scalar(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
        ON CONFLICT (tenant_id, scm_provider, provider_repository_id)
        DO UPDATE SET owner = EXCLUDED.owner, name = EXCLUDED.name,
                      updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING id
        ",
    )
    .bind(repository.id().as_uuid())
    .bind(command.tenant().as_str())
    .bind(repository.provider())
    .bind(repository.provider_repository_id())
    .bind(repository.owner())
    .bind(repository.name())
    .bind(command.admitted_at().get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if id != repository.id().as_uuid() {
        return Err(LogicalWorkflowAdmissionStoreError::IdentityConflict(
            "repository",
        ));
    }
    Ok(())
}

async fn resolve_workflow(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let id: Uuid = sqlx::query_scalar(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$4)
        ON CONFLICT (repository_id, path)
        DO UPDATE SET updated_at_ms = EXCLUDED.updated_at_ms
        RETURNING id
        ",
    )
    .bind(command.workflow_id().as_uuid())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_path())
    .bind(command.admitted_at().get())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if id != command.workflow_id().as_uuid() {
        return Err(LogicalWorkflowAdmissionStoreError::IdentityConflict(
            "workflow",
        ));
    }
    Ok(())
}

async fn require_workflow_enabled(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<bool, LogicalWorkflowAdmissionStoreError> {
    sqlx::query(
        r"
        INSERT INTO workflow_enable_state_revisions (
            tenant_id, repository_id, workflow_id, workflow_path,
            state_revision, enable_state, changed_at_ms
        )
        SELECT $1,$2,$3,$4,1,
               CASE WHEN workflow.enabled THEN 'enabled' ELSE 'disabled' END,
               $5
        FROM workflow_definitions AS workflow
        JOIN repositories AS repository
          ON repository.id = workflow.repository_id
         AND repository.tenant_id = $1
        WHERE workflow.repository_id = $2
          AND workflow.id = $3
          AND workflow.path = $4
          AND NOT EXISTS (
              SELECT 1
              FROM workflow_enable_state_current AS current
              WHERE current.tenant_id = $1
                AND current.repository_id = $2
                AND current.workflow_id = $3
          )
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(command.workflow_path())
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    sqlx::query(
        r"
        INSERT INTO workflow_enable_state_current (
            tenant_id, repository_id, workflow_id, state_revision
        )
        SELECT $1,$2,$3,1
        WHERE NOT EXISTS (
            SELECT 1
            FROM workflow_enable_state_current AS current
            WHERE current.tenant_id = $1
              AND current.repository_id = $2
              AND current.workflow_id = $3
        )
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let row = sqlx::query(
        r"
        SELECT revision.workflow_path, revision.enable_state
        FROM workflow_enable_state_current AS current
        JOIN workflow_enable_state_revisions AS revision
          ON revision.tenant_id = current.tenant_id
         AND revision.repository_id = current.repository_id
         AND revision.workflow_id = current.workflow_id
         AND revision.state_revision = current.state_revision
        WHERE current.tenant_id = $1
          AND current.repository_id = $2
          AND current.workflow_id = $3
        FOR SHARE OF current
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("workflow enable state is missing"))?;
    if row
        .try_get::<String, _>("workflow_path")
        .map_err(operation_error)?
        != command.workflow_path()
    {
        return Err(StoreError::corrupt_data("workflow enable-state identity changed").into());
    }
    match row
        .try_get::<String, _>("enable_state")
        .map_err(operation_error)?
        .as_str()
    {
        "enabled" => Ok(true),
        "disabled" => Ok(false),
        _ => Err(StoreError::corrupt_data("workflow enable state is invalid").into()),
    }
}

async fn resolve_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let source = command.source();
    let schemas = current_durable_schemas();
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key, frontend_schema,
            created_at_ms, admission_epoch, source_size_bytes, source_media_type
        ) VALUES ($1,$2,$3,$4,$9,$5,$6,$7,$8)
        ON CONFLICT (workflow_id, source_digest) DO NOTHING
        ",
    )
    .bind(command.snapshot_id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(source.digest().as_bytes().as_slice())
    .bind(source.object_key().as_str())
    .bind(command.admitted_at().get())
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(size_i64(source)?)
    .bind(source.media_type())
    .bind(schemas.workflow_plan_i16)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    let row = sqlx::query(
        r"
        SELECT id, source_object_key, frontend_schema, admission_epoch,
               source_size_bytes, source_media_type
        FROM workflow_snapshots
        WHERE workflow_id = $1 AND source_digest = $2
        FOR UPDATE
        ",
    )
    .bind(command.workflow_id().as_uuid())
    .bind(source.digest().as_bytes().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let exact = row.try_get::<Uuid, _>("id").map_err(operation_error)?
        == command.snapshot_id().as_uuid()
        && row
            .try_get::<String, _>("source_object_key")
            .map_err(operation_error)?
            == source.object_key().as_str()
        && row
            .try_get::<i16, _>("frontend_schema")
            .map_err(operation_error)?
            == schemas.workflow_plan_i16
        && row
            .try_get::<i32, _>("admission_epoch")
            .map_err(operation_error)?
            == i32::from(WORKFLOW_ADMISSION_EPOCH)
        && row
            .try_get::<Option<i64>, _>("source_size_bytes")
            .map_err(operation_error)?
            == Some(size_i64(source)?)
        && row
            .try_get::<Option<String>, _>("source_media_type")
            .map_err(operation_error)?
            .as_deref()
            == Some(source.media_type());
    if !exact {
        return Err(LogicalWorkflowAdmissionStoreError::IdentityConflict(
            "workflow snapshot",
        ));
    }
    Ok(())
}

async fn allocate_run_number(
    transaction: &mut Transaction<'_, Postgres>,
    workflow_id: WorkflowId,
) -> Result<u64, LogicalWorkflowAdmissionStoreError> {
    let number: Option<i64> = sqlx::query_scalar(
        r"
        INSERT INTO workflow_run_number_counters (workflow_id, next_run_number)
        VALUES ($1, 2)
        ON CONFLICT (workflow_id) DO UPDATE
        SET next_run_number = workflow_run_number_counters.next_run_number + 1
        WHERE workflow_run_number_counters.next_run_number < 9223372036854775807
        RETURNING next_run_number - 1
        ",
    )
    .bind(workflow_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    let number = number.ok_or(LogicalWorkflowAdmissionStoreError::RunNumberExhausted)?;
    u64::try_from(number)
        .ok()
        .filter(|number| *number > 0)
        .ok_or(LogicalWorkflowAdmissionStoreError::RunNumberExhausted)
}

async fn insert_run(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    run_number: u64,
    publication: &RunPublicationSnapshot,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let schemas = current_durable_schemas();
    let event = command.event();
    let plan = command.plan();
    let run_number = i64::try_from(run_number)
        .map_err(|_| LogicalWorkflowAdmissionStoreError::RunNumberExhausted)?;
    let run_attempt = i32::try_from(command.run_attempt())
        .map_err(|_| StoreError::corrupt_data("workflow run attempt exceeds INTEGER"))?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, run_attempt,
            event_name, event_object_key, head_sha, status, workflow_name,
            git_ref, actor, display_title, commit_subject,
            created_at_ms, updated_at_ms, concurrency_group_key,
            concurrency_queue_policy, concurrency_cancel_in_progress,
            admission_epoch, event_digest, event_size_bytes, event_media_type,
            plan_digest, plan_object_key, plan_size_bytes, plan_media_type, plan_schema,
            publication_policy_revision, requested_dashboard_visibility,
            effective_dashboard_visibility, requested_log_visibility,
            requested_artifact_visibility, publication_safety_reason,
            publication_safety_schema, runner_requirements_schema
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',$10,
            $11,$12,$13,$14,$15,$15,$16,$17,$18,
            $19,$20,$21,$22,$23,$24,$25,$26,$27,
            $28,$29,$29,$30,$31,'repository_policy',$33,$32
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING id
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(command.repository().id().as_uuid())
    .bind(command.workflow_id().as_uuid())
    .bind(command.snapshot_id().as_uuid())
    .bind(run_number)
    .bind(run_attempt)
    .bind(command.event_name())
    .bind(event.object_key().as_str())
    .bind(command.head_sha())
    .bind(command.workflow_name())
    .bind(command.git_ref())
    .bind(command.actor())
    .bind(command.display_title())
    .bind(command.commit_subject())
    .bind(command.admitted_at().get())
    .bind(
        command
            .concurrency()
            .map(automata_ci_store::WorkflowConcurrency::normalized_key),
    )
    .bind(
        command
            .concurrency()
            .map(|concurrency| super::admission::queue_policy_name(concurrency.queue_policy())),
    )
    .bind(
        command
            .concurrency()
            .map(automata_ci_store::WorkflowConcurrency::cancel_in_progress),
    )
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(event.digest().as_bytes().as_slice())
    .bind(size_i64(event)?)
    .bind(event.media_type())
    .bind(plan.digest().as_bytes().as_slice())
    .bind(plan.object_key().as_str())
    .bind(size_i64(plan)?)
    .bind(plan.media_type())
    .bind(i32::from(WORKFLOW_PLAN_SCHEMA))
    .bind(publication.revision())
    .bind(publication.dashboard())
    .bind(publication.logs())
    .bind(publication.artifacts())
    .bind(i16::try_from(RUNNER_REQUIREMENTS_SCHEMA_VERSION).unwrap_or(i16::MAX))
    .bind(schemas.publication_safety_i32)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    if inserted.is_none() {
        return Err(LogicalWorkflowAdmissionStoreError::IdentityConflict(
            "workflow run",
        ));
    }
    Ok(())
}

async fn insert_trust_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let snapshot = command.trust_snapshot();
    if snapshot.is_construction_placeholder() {
        return Err(
            StoreError::corrupt_data("workflow admission lacks sealed trust evidence").into(),
        );
    }
    let snapshot_schema = i16::try_from(snapshot.schema())
        .map_err(|_| StoreError::corrupt_data("trust snapshot schema exceeds SMALLINT"))?;
    let policy_revision = i64::try_from(snapshot.policy_revision().get())
        .map_err(|_| StoreError::corrupt_data("trust policy revision exceeds BIGINT"))?;
    let rows = sqlx::query(
        r"
        INSERT INTO workflow_run_trust_snapshots (
            run_id, snapshot_schema, policy_revision, policy_digest,
            snapshot_digest, snapshot_bytes, media_type, created_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(snapshot_schema)
    .bind(policy_revision)
    .bind(snapshot.policy_digest().as_bytes().as_slice())
    .bind(snapshot.digest().as_bytes().as_slice())
    .bind(snapshot.canonical_bytes())
    .bind(TRUST_SNAPSHOT_V1_MEDIA_TYPE)
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data("workflow trust snapshot was not sealed").into());
    }
    Ok(())
}

async fn validate_trust_snapshot_replay(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    durable_admitted_at: UnixMillis,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let row = sqlx::query(
        r"
        SELECT snapshot_schema, policy_revision, policy_digest,
               snapshot_digest, snapshot_bytes, media_type, created_at_ms
        FROM workflow_run_trust_snapshots
        WHERE run_id = $1
        FOR KEY SHARE
        ",
    )
    .bind(command.run_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("workflow run lacks its trust snapshot"))?;
    let snapshot = command.trust_snapshot();
    let exact = row
        .try_get::<i16, _>("snapshot_schema")
        .map_err(operation_error)?
        == i16::try_from(snapshot.schema()).unwrap_or(i16::MAX)
        && row
            .try_get::<i64, _>("policy_revision")
            .map_err(operation_error)?
            == i64::try_from(snapshot.policy_revision().get()).unwrap_or(i64::MAX)
        && row
            .try_get::<Vec<u8>, _>("policy_digest")
            .map_err(operation_error)?
            .as_slice()
            == snapshot.policy_digest().as_bytes()
        && row
            .try_get::<Vec<u8>, _>("snapshot_digest")
            .map_err(operation_error)?
            .as_slice()
            == snapshot.digest().as_bytes()
        && row
            .try_get::<Vec<u8>, _>("snapshot_bytes")
            .map_err(operation_error)?
            .as_slice()
            == snapshot.canonical_bytes()
        && row
            .try_get::<String, _>("media_type")
            .map_err(operation_error)?
            == TRUST_SNAPSHOT_V1_MEDIA_TYPE
        && row
            .try_get::<i64, _>("created_at_ms")
            .map_err(operation_error)?
            == durable_admitted_at.get();
    if !exact {
        return Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict);
    }
    Ok(())
}

async fn insert_logical_run_and_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let base_context = command.base_context();
    sqlx::query(
        r"
        INSERT INTO logical_workflow_runs (
            run_id, root_invocation_id, orchestration_schema,
            admission_digest, state, revision, admitted_at_ms, updated_at_ms,
            base_context_digest, base_context_object_key,
            base_context_size_bytes, base_context_media_type, base_context_schema,
            runner_requirements_schema
        ) VALUES ($1,$2,$3,$4,'pending',1,$5,$5,$6,$7,$8,$9,$10,$11)
        ",
    )
    .bind(command.run_id().as_uuid())
    .bind(command.root_invocation_id().as_uuid())
    .bind(
        i16::try_from(LOGICAL_ORCHESTRATION_SCHEMA).map_err(|_| {
            StoreError::corrupt_data("logical orchestration schema exceeds SMALLINT")
        })?,
    )
    .bind(command.request_digest().as_bytes().as_slice())
    .bind(command.admitted_at().get())
    .bind(base_context.map(|context| context.digest().as_bytes().to_vec()))
    .bind(base_context.map(|context| context.object_key().as_str()))
    .bind(base_context.map(size_i64).transpose()?)
    .bind(base_context.map(AdmissionObject::media_type))
    .bind(
        base_context.map(|_| i16::try_from(JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(i16::MAX)),
    )
    .bind(i16::try_from(RUNNER_REQUIREMENTS_SCHEMA_VERSION).unwrap_or(i16::MAX))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    let plan = command.plan();
    sqlx::query(
        r"
        INSERT INTO logical_workflow_invocations (
            id, run_id, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, state, revision,
            created_at_ms, updated_at_ms
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',1,$8,$8)
        ",
    )
    .bind(command.root_invocation_id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(plan.digest().as_bytes().as_slice())
    .bind(plan.object_key().as_str())
    .bind(size_i64(plan)?)
    .bind(plan.media_type())
    .bind(
        i16::try_from(WORKFLOW_PLAN_SCHEMA)
            .map_err(|_| StoreError::corrupt_data("workflow plan schema exceeds SMALLINT"))?,
    )
    .bind(command.admitted_at().get())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    Ok(())
}

async fn insert_logical_jobs(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let schemas = current_durable_schemas();
    let pin = sqlx::query(
        r"
        SELECT policy_revision, policy_digest
        FROM logical_workflow_runtime_policy_pins
        WHERE run_id = $1
        FOR KEY SHARE
        ",
    )
    .bind(command.run_id().as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?
    .ok_or_else(|| StoreError::corrupt_data("authenticated admission lacks runtime policy pin"))?;
    let runtime_policy_revision: i64 = pin.try_get("policy_revision").map_err(operation_error)?;
    let runtime_policy_digest: Vec<u8> = pin.try_get("policy_digest").map_err(operation_error)?;

    for job in command.jobs() {
        sqlx::query(
            r"
            INSERT INTO logical_workflow_jobs (
                id, run_id, invocation_id, logical_key, source_order,
                execution_kind, state, activation_fence,
                created_at_ms, updated_at_ms,
                runtime_policy_revision, runtime_policy_digest,
                environment_requirement_kind, environment_template_digest,
                secret_reference_names, variable_reference_names,
                credential_requirements_schema
            ) VALUES (
                $1,$2,$3,$4,$5,$6,'pending',0,$7,$7,$8,$9,
                $10,$11,$12,$13,$14
            )
            ",
        )
        .bind(job.id().as_uuid())
        .bind(command.run_id().as_uuid())
        .bind(command.root_invocation_id().as_uuid())
        .bind(job.key().as_str())
        .bind(i32::from(job.source_order()))
        .bind(logical_workflow_job_kind_name(job.kind()))
        .bind(command.admitted_at().get())
        .bind(runtime_policy_revision)
        .bind(runtime_policy_digest.as_slice())
        .bind(job_environment_requirement_name(
            job.credential_requirements().environment(),
        ))
        .bind(
            job.credential_requirements()
                .environment()
                .template_digest()
                .map(|digest| digest.as_bytes().as_slice().to_vec()),
        )
        .bind(job.credential_requirements().secret_names())
        .bind(job.credential_requirements().variable_names())
        .bind(schemas.runner_requirements_i16)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }

    for job in command.jobs() {
        for prerequisite in job.prerequisites() {
            sqlx::query(
                r"
                INSERT INTO logical_workflow_dependencies (
                    run_id, invocation_id, logical_job_id, prerequisite_job_id
                ) VALUES ($1,$2,$3,$4)
                ",
            )
            .bind(command.run_id().as_uuid())
            .bind(command.root_invocation_id().as_uuid())
            .bind(job.id().as_uuid())
            .bind(prerequisite.as_uuid())
            .execute(&mut **transaction)
            .await
            .map_err(operation_error)?;
        }
    }
    Ok(())
}

async fn seal_logical_graph(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE logical_workflow_runs
        SET admission_graph_sealed_at_ms = database_clock.now_ms,
            updated_at_ms = database_clock.now_ms
        FROM (
            SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT AS now_ms
        ) AS database_clock
        WHERE run_id = $1 AND admission_graph_sealed_at_ms IS NULL
        ",
    )
    .bind(command.run_id().as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data("logical admission graph was not sealed").into());
    }
    Ok(())
}

async fn finalize_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let rows = sqlx::query(
        r"
        UPDATE workflow_admission_receipts
        SET repository_id = $4, run_id = $5, committed_at_ms = $6
        WHERE tenant_id = $1 AND idempotency_kind = $2 AND idempotency_key = $3
          AND request_digest = $7 AND run_id IS NULL
        ",
    )
    .bind(command.tenant().as_str())
    .bind(command.idempotency().kind())
    .bind(command.idempotency().key())
    .bind(command.repository().id().as_uuid())
    .bind(command.run_id().as_uuid())
    .bind(command.admitted_at().get())
    .bind(command.request_digest().as_bytes().as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?
    .rows_affected();
    if rows != 1 {
        return Err(StoreError::corrupt_data(
            "logical admission receipt finalization lost ownership",
        )
        .into());
    }
    Ok(())
}

fn size_i64(object: &AdmissionObject) -> Result<i64, LogicalWorkflowAdmissionStoreError> {
    i64::try_from(object.encoded_size()).map_err(|_| {
        StoreError::corrupt_data("immutable object size exceeds PostgreSQL BIGINT").into()
    })
}

fn operation_error(error: sqlx::Error) -> LogicalWorkflowAdmissionStoreError {
    StoreError::operation(error).into()
}
