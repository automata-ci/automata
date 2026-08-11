use async_trait::async_trait;
use automata_ci_core::{OperationId, RunId, UnixMillis, WorkflowId};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row as _, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    PostgresStore,
    admission::{RunPublicationSnapshot, lock_repository_publication_snapshot},
    github_schedule::{
        record_github_scheduled_run_evidence_in_transaction,
        validate_github_scheduled_run_evidence_in_transaction,
    },
    github_subject_evidence::{
        record_github_workflow_run_subject_evidence_in_transaction,
        validate_github_workflow_run_subject_evidence_in_transaction,
    },
    secret_management::{AuthorizedHumanRepositoryAction, authorize_human_repository_action},
};
use crate::{
    AdmissionObject, AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim,
    AuthenticatedWorkflowDispatchClaim, AuthenticatedWorkflowDispatchSource,
    GithubScheduleFireClaim, GithubSubjectEvidenceStoreError, LOGICAL_ORCHESTRATION_SCHEMA,
    LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionRepository,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowInvocationId, ObjectKey,
    RecordGithubWorkflowRunSubjectEvidence, RepositoryId,
    ResolveAuthenticatedWorkflowDispatchSource, Sha256Digest, StoreError,
    ValidateGithubWorkflowRunSubjectEvidenceReplay, WORKFLOW_ADMISSION_EPOCH, WORKFLOW_PLAN_SCHEMA,
    WorkflowAdmissionIdempotency, WorkflowAdmissionStoreError, WorkflowSnapshotId,
};

enum SubjectEvidenceAdmission {
    AuthenticatedGithub {
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    },
    AuthenticatedWorkflowDispatch {
        claim: AuthenticatedWorkflowDispatchClaim,
    },
    ScheduledGithub {
        claim: GithubScheduleFireClaim,
    },
}

const WORKFLOW_DISPATCH_PERMISSION: &str = "runs:dispatch";
const WORKFLOW_DISPATCH_AUDIT_ACTION: &str = "workflow.dispatch";
const WORKFLOW_DISPATCH_AUDIT_RESOURCE_KIND: &str = "workflow_run";
const WORKFLOW_DISPATCH_AUDIT_ID_DOMAIN: &[u8] = b"automata.workflow-dispatch.audit.v1\0";

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
            SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim },
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
    let actor = authorize_human_repository_action(
        &mut transaction,
        request.actor(),
        WORKFLOW_DISPATCH_PERMISSION,
        request.repository_id().as_uuid(),
    )
    .await?;
    let Some(actor) = actor else {
        return Err(LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected);
    };
    if actor.tenant_id != request.actor().tenant_id().as_str()
        || actor.authorization_revision
            != i64::try_from(request.actor().authorization_revision().value()).unwrap_or(i64::MAX)
        || actor.principal_id.hyphenated().to_string() != request.actor().principal_id().as_str()
        || actor.session_id.hyphenated().to_string() != request.actor().session_id().as_str()
    {
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
               repository.owner, repository.name, workflow.path,
               snapshot.source_digest, snapshot.source_object_key,
               snapshot.source_size_bytes, snapshot.source_media_type
        FROM repositories AS repository
        JOIN github_provider_manifest_current AS current_manifest
          ON current_manifest.tenant_id = repository.tenant_id
         AND current_manifest.repository_id = repository.id
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
        LIMIT 2
        ",
    )
    .bind(&actor.tenant_id)
    .bind(request.repository_id().as_uuid())
    .bind(request.workflow_id().as_uuid())
    .bind(request.git_ref())
    .bind(request.commit_sha_bytes())
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
    let repository = crate::AdmissionRepository::new(
        request.repository_id(),
        provider,
        row.try_get::<String, _>("provider_repository_id")
            .map_err(operation_error)?,
        row.try_get::<String, _>("owner").map_err(operation_error)?,
        row.try_get::<String, _>("name").map_err(operation_error)?,
    )
    .map_err(|_| StoreError::corrupt_data("signed GitHub repository identity is invalid"))?;
    AuthenticatedWorkflowDispatchSource::new(
        repository,
        request.workflow_id(),
        row.try_get::<String, _>("path").map_err(operation_error)?,
        request.git_ref(),
        request.commit_sha(),
        source,
    )
    .map_err(|_| StoreError::corrupt_data("signed GitHub dispatch source is invalid").into())
}

async fn admit_logical_workflow_transaction(
    store: &PostgresStore,
    command: AdmitLogicalWorkflowRun,
    subject_evidence: SubjectEvidenceAdmission,
) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
    validate_subject_evidence_boundary(&command, &subject_evidence)?;
    let mut transaction = store.pool.begin().await.map_err(operation_error)?;
    let dispatch_actor =
        authorize_dispatch_subject(&mut transaction, &command, &subject_evidence).await?;
    let github_subject_evidence_required = matches!(
        &subject_evidence,
        SubjectEvidenceAdmission::AuthenticatedGithub { .. }
            | SubjectEvidenceAdmission::ScheduledGithub { .. }
    );

    if !claim_idempotency_receipt(&mut transaction, &command, github_subject_evidence_required)
        .await?
    {
        let (receipt, admitted_at) =
            replay_receipt(&mut transaction, &command, github_subject_evidence_required).await?;
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
        transaction.commit().await.map_err(operation_error)?;
        return Ok(receipt);
    }

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
    insert_logical_run_and_invocation(&mut transaction, &command).await?;
    finalize_receipt(&mut transaction, &command).await?;
    record_new_subject_evidence(
        &mut transaction,
        &command,
        &subject_evidence,
        dispatch_actor.as_ref(),
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

fn validate_subject_evidence_boundary(
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    match subject_evidence {
        SubjectEvidenceAdmission::AuthenticatedGithub { observed_at, .. } => {
            if command.repository().provider() != "github"
                || !matches!(
                    command.idempotency(),
                    WorkflowAdmissionIdempotency::ProviderDelivery(_)
                )
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
                || command.actor() != Some(crate::GITHUB_SCHEDULE_SERVICE_ACTOR)
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

async fn authorize_dispatch_subject(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    subject_evidence: &SubjectEvidenceAdmission,
) -> Result<Option<AuthorizedHumanRepositoryAction>, LogicalWorkflowAdmissionStoreError> {
    let SubjectEvidenceAdmission::AuthenticatedWorkflowDispatch { claim } = subject_evidence else {
        return Ok(None);
    };
    require_existing_dispatch_repository(transaction, command).await?;
    let actor = authorize_human_repository_action(
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
        || actor.authorization_revision
            != i64::try_from(claim.actor().authorization_revision().value()).unwrap_or(i64::MAX)
        || actor.principal_id.hyphenated().to_string() != claim.actor().principal_id().as_str()
        || actor.session_id.hyphenated().to_string() != claim.actor().session_id().as_str()
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
    dispatch_actor: Option<&AuthorizedHumanRepositoryAction>,
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
    dispatch_actor: Option<&AuthorizedHumanRepositoryAction>,
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
    actor: &AuthorizedHumanRepositoryAction,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let event_id = workflow_dispatch_audit_event_id(command.request_digest());
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
    .bind(actor.session_id)
    .bind(actor.authorization_revision)
    .bind(WORKFLOW_DISPATCH_AUDIT_ACTION)
    .bind(WORKFLOW_DISPATCH_AUDIT_RESOURCE_KIND)
    .bind(command.run_id().to_string())
    .bind(actor.request_id.as_deref())
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    validate_workflow_dispatch_audit(transaction, command, claim, actor, command.admitted_at())
        .await
}

async fn validate_workflow_dispatch_audit(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
    claim: &AuthenticatedWorkflowDispatchClaim,
    actor: &AuthorizedHumanRepositoryAction,
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
    let exact = row
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
            .try_get::<Option<Uuid>, _>("actor_session_id")
            .map_err(operation_error)?
            == Some(actor.session_id)
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
            == Some(resource_id.as_str())
        && claim.actor().tenant_id().as_str() == actor.tenant_id
        && claim.actor().principal_id().as_str() == actor.principal_id.hyphenated().to_string()
        && claim.actor().session_id().as_str() == actor.session_id.hyphenated().to_string()
        && i64::try_from(claim.actor().authorization_revision().value()).ok()
            == Some(actor.authorization_revision);
    if !exact {
        return Err(StoreError::corrupt_data(
            "workflow dispatch admission audit evidence is inconsistent",
        )
        .into());
    }
    Ok(())
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
        LEFT JOIN workflow_plan_v2_runs AS marker ON marker.run_id = run.id
        LEFT JOIN workflow_plan_v2_invocations AS invocation
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
                && base_context_schema == Some(2)
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

async fn resolve_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let source = command.source();
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key, frontend_schema,
            created_at_ms, admission_epoch, source_size_bytes, source_media_type
        ) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8)
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
            == 1
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
            publication_safety_schema
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',$10,
            $11,$12,$13,$14,$15,$15,$16,$17,$18,
            $19,$20,$21,$22,$23,$24,$25,$26,$27,
            $28,$29,$29,$30,$31,'repository_policy',1
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
            .map(crate::WorkflowConcurrency::normalized_key),
    )
    .bind(
        command
            .concurrency()
            .map(|concurrency| super::admission::queue_policy_name(concurrency.queue_policy())),
    )
    .bind(
        command
            .concurrency()
            .map(crate::WorkflowConcurrency::cancel_in_progress),
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

async fn insert_logical_run_and_invocation(
    transaction: &mut Transaction<'_, Postgres>,
    command: &AdmitLogicalWorkflowRun,
) -> Result<(), LogicalWorkflowAdmissionStoreError> {
    let base_context = command.base_context();
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_runs (
            run_id, root_invocation_id, orchestration_schema,
            admission_digest, state, revision, admitted_at_ms, updated_at_ms,
            base_context_digest, base_context_object_key,
            base_context_size_bytes, base_context_media_type, base_context_schema
        ) VALUES ($1,$2,$3,$4,'pending',1,$5,$5,$6,$7,$8,$9,$10)
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
    .bind(base_context.map(|_| {
        i16::try_from(automata_ci_core::JOB_RUNTIME_CONTEXT_SCHEMA_VERSION).unwrap_or(i16::MAX)
    }))
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;

    let plan = command.plan();
    sqlx::query(
        r"
        INSERT INTO workflow_plan_v2_invocations (
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
    let pin = sqlx::query(
        r"
        SELECT policy_revision, policy_digest
        FROM workflow_plan_v2_runtime_policy_pins
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
            INSERT INTO workflow_plan_v2_jobs (
                id, run_id, invocation_id, logical_key, source_order,
                execution_kind, state, activation_fence,
                created_at_ms, updated_at_ms,
                runtime_policy_revision, runtime_policy_digest,
                environment_requirement_kind, environment_template_digest,
                secret_reference_names, variable_reference_names,
                credential_requirements_schema
            ) VALUES (
                $1,$2,$3,$4,$5,$6,'pending',0,$7,$7,$8,$9,
                $10,$11,$12,$13,1
            )
            ",
        )
        .bind(job.id().as_uuid())
        .bind(command.run_id().as_uuid())
        .bind(command.root_invocation_id().as_uuid())
        .bind(job.key().as_str())
        .bind(i32::from(job.source_order()))
        .bind(job.kind().as_str())
        .bind(command.admitted_at().get())
        .bind(runtime_policy_revision)
        .bind(runtime_policy_digest.as_slice())
        .bind(job.credential_requirements().environment().kind())
        .bind(
            job.credential_requirements()
                .environment()
                .template_digest()
                .map(|digest| digest.as_bytes().as_slice().to_vec()),
        )
        .bind(job.credential_requirements().secret_names())
        .bind(job.credential_requirements().variable_names())
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    }

    for job in command.jobs() {
        for prerequisite in job.prerequisites() {
            sqlx::query(
                r"
                INSERT INTO workflow_plan_v2_dependencies (
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
        UPDATE workflow_plan_v2_runs
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
