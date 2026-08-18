use async_trait::async_trait;
use automata_ci_blob::{BlobDescriptor, BlobKey, MediaType};
use automata_ci_core::{AttemptId, GitObjectId, JobId, RunId, Sha256Digest, UnixMillis};
use sqlx::{AssertSqlSafe, PgConnection, Postgres, Row as _, Transaction};
use uuid::Uuid;

use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    AdvanceGithubCheckAnnotations, AttemptStoreError, BeginGithubCheckAnnotationBatch,
    BeginGithubCheckRunCreate, BindGithubCheckRun, BindGithubCheckSuite,
    BlockGithubCheckAnnotationMismatch, BlockGithubCheckProjectionForCredentialRejection,
    ClaimGithubCheckProjection, ClaimedGithubCheckProjection,
    ClearGithubCheckAnnotationUncertainty, CompleteGithubCheckProjection,
    GithubCheckAnnotationProgress, GithubCheckAppId, GithubCheckConclusion,
    GithubCheckCreateReconciliation, GithubCheckDesiredProjection, GithubCheckDetailsTarget,
    GithubCheckName, GithubCheckProjectionAction, GithubCheckProjectionClaimFence,
    GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId, GithubCheckRunBindingFence,
    GithubCheckRunCreateFence, GithubCheckRunId, GithubCheckStoreError, GithubCheckSubjectIdentity,
    GithubCheckSubjectKey, GithubCheckSubjectOrigin, GithubCheckSubjectReceipt, GithubCheckSuiteId,
    GithubCheckTerminalCause, GithubRepositoryName, GithubScheduleFireId,
    GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceRevision, HUMAN_JOB_RESULT_MEDIA_TYPE, InitializeGithubCheckPresentation,
    MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS, MAX_TERMINAL_RESULT_BYTES, ProviderDeliveryId,
    ProviderInstallationId, ProviderRepositoryId, ReleaseUnissuedGithubCheckAnnotationBatch,
    ReleaseUnissuedGithubCheckRunCreate, RepositoryId, ResolveGithubCheckRunCreate,
    RetryGithubCheckProjection, RetryUncertainGithubCheckAnnotations, StoreError, TenantScope,
};

use super::{PostgresStore, pg_bigint};

// A caller clock is useful only as bounded admission evidence. Durable claim
// eligibility and every absolute fence time are issued from PostgreSQL after
// any preceding lock wait.
const MAX_GITHUB_CHECK_PROJECTION_CLOCK_SKEW_MILLIS: i64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionSubjectOrigin {
    ProviderDelivery,
    ScheduledFire,
    WorkflowRerun,
}

pub(super) const fn github_check_conclusion_name(value: GithubCheckConclusion) -> &'static str {
    match value {
        GithubCheckConclusion::ActionRequired => "action_required",
        GithubCheckConclusion::Cancelled => "cancelled",
        GithubCheckConclusion::Failure => "failure",
        GithubCheckConclusion::Success => "success",
        GithubCheckConclusion::Skipped => "skipped",
        GithubCheckConclusion::TimedOut => "timed_out",
    }
}

pub(super) const fn github_check_terminal_cause_name(
    value: GithubCheckTerminalCause,
) -> &'static str {
    match value {
        GithubCheckTerminalCause::WorkflowSuccess => "workflow_success",
        GithubCheckTerminalCause::WorkflowSkipped => "workflow_skipped",
        GithubCheckTerminalCause::WorkflowFailure => "workflow_failure",
        GithubCheckTerminalCause::WorkflowCancelled => "workflow_cancelled",
        GithubCheckTerminalCause::WorkflowTimedOut => "workflow_timed_out",
        GithubCheckTerminalCause::ProviderUnknown => "provider_unknown",
        GithubCheckTerminalCause::SystemUnknown => "system_unknown",
    }
}

pub(super) enum GithubJobCheckInsertError {
    Operation(sqlx::Error),
    CorruptData(&'static str),
}

impl GithubJobCheckInsertError {
    pub(super) fn into_store_error(self) -> StoreError {
        match self {
            Self::Operation(error) => StoreError::operation(error),
            Self::CorruptData(message) => StoreError::corrupt_data(message),
        }
    }

    pub(super) fn into_attempt_error(self) -> AttemptStoreError {
        match self {
            Self::Operation(error) => AttemptStoreError::operation(error),
            Self::CorruptData(message) => AttemptStoreError::corrupt_data(message),
        }
    }
}

pub(super) async fn insert_github_job_check_subject(
    transaction: &mut Transaction<'_, Postgres>,
    job_id: JobId,
    attempt_id: AttemptId,
    queued_at: UnixMillis,
) -> Result<(), GithubJobCheckInsertError> {
    let job = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, Option<String>)>(
        r"
        SELECT job.run_id, job.display_name,
               authority.github_check_subject_id, authority.aggregate_check_name
        FROM jobs AS job
        LEFT JOIN LATERAL (
            SELECT origin.github_check_subject_id,
                   manifest.check_name AS aggregate_check_name
            FROM github_workflow_run_manifest_origins AS origin
            JOIN github_provider_manifest_revisions AS manifest
              ON manifest.tenant_id = origin.tenant_id
             AND manifest.repository_id = origin.repository_id
             AND manifest.provider_connection_id = origin.provider_connection_id
             AND manifest.manifest_revision = origin.provider_manifest_revision
             AND manifest.manifest_digest = origin.provider_manifest_digest
            WHERE origin.run_id = job.run_id
        ) AS authority ON TRUE
        WHERE job.id = $1
        FOR KEY SHARE OF job
        ",
    )
    .bind(job_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(GithubJobCheckInsertError::Operation)?
    .ok_or(GithubJobCheckInsertError::CorruptData(
        "GitHub job Check has no durable job",
    ))?;
    let Some(parent_id) = job.2 else {
        return Ok(());
    };
    let check_name = GithubCheckName::from_job_display_name(&job.1).map_err(|_| {
        GithubJobCheckInsertError::CorruptData("job display name is not Check-safe")
    })?;
    let Some(aggregate_check_name) = job.3.as_deref() else {
        return Err(GithubJobCheckInsertError::CorruptData(
            "GitHub job Check has no aggregate-name authority",
        ));
    };
    if aggregate_check_name == check_name.as_str() {
        return Err(GithubJobCheckInsertError::CorruptData(
            "job display name collides with the reserved aggregate Check name",
        ));
    }
    let subject_id = Uuid::new_v4();
    let subject_key = format!("job/{}/attempt/{}", job_id.as_uuid(), attempt_id.as_uuid());
    let external_id = format!("automata-check:{subject_id}");
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r"
        INSERT INTO github_check_subjects (
            id, tenant_id, repository_id, provider_delivery_id, subject_key,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_repository_name, github_app_id,
            head_sha, check_name, external_id, created_at_ms,
            desired_updated_at_ms, origin_kind, schedule_fire_id,
            workflow_rerun_run_id, subject_kind, parent_subject_id,
            job_id, job_attempt_id, workflow_run_id, linked_at_ms
        )
        SELECT $1, parent.tenant_id, parent.repository_id,
               parent.provider_delivery_id, $2,
               parent.provider_connection_id, parent.provider_installation_id,
               parent.github_repository_id, parent.github_repository_name,
               parent.github_app_id, parent.head_sha, $3, $4, $5, $5,
               parent.origin_kind, parent.schedule_fire_id,
               parent.workflow_rerun_run_id, 'job', parent.id, $6, $7, $9, $5
        FROM github_check_subjects AS parent
        WHERE parent.id = $8
          AND parent.subject_kind = 'workflow'
        RETURNING id
        ",
    )
    .bind(subject_id)
    .bind(subject_key)
    .bind(check_name.as_str())
    .bind(external_id)
    .bind(queued_at.get())
    .bind(job_id.as_uuid())
    .bind(attempt_id.as_uuid())
    .bind(parent_id)
    .bind(job.0)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(GithubJobCheckInsertError::Operation)?;

    let Some(inserted) = inserted else {
        return Ok(());
    };
    if inserted != subject_id {
        return Err(GithubJobCheckInsertError::CorruptData(
            "GitHub job Check identity changed on insert",
        ));
    }
    Ok(())
}

pub(super) const SUBJECT_COLUMNS: &str = r"
    subject.id, subject.tenant_id, subject.repository_id,
    subject.origin_kind, subject.provider_delivery_id, subject.schedule_fire_id,
    subject.workflow_rerun_run_id,
    subject.subject_key, subject.subject_kind, subject.parent_subject_id,
    subject.job_id, subject.job_attempt_id,
    subject.provider_connection_id, subject.provider_installation_id,
    subject.github_repository_id, subject.github_repository_name,
    subject.github_app_id, subject.head_sha,
    subject.check_name, subject.external_id, subject.workflow_run_id,
    subject.linked_at_ms,
    subject.desired_state, subject.desired_conclusion, subject.terminal_cause,
    subject.desired_revision, subject.created_at_ms, subject.desired_updated_at_ms
";

#[rustfmt::skip]
macro_rules! projection_origin_authority_sql {
    ($prefix:literal, $indent:literal, $schedule_connection_indent:literal, $suffix:literal $(,)?) => {
        concat!(
            $prefix,
            $indent, "AND CASE subject.origin_kind\n",
            $indent, "  WHEN 'provider_delivery' THEN EXISTS (\n",
            $indent, "      SELECT 1\n",
            $indent, "      FROM github_provider_delivery_evidence AS delivery_evidence\n",
            $indent, "      WHERE delivery_evidence.provider_delivery_id = subject.provider_delivery_id\n",
            $indent, "        AND delivery_evidence.tenant_id = subject.tenant_id\n",
            $indent, "        AND delivery_evidence.repository_id = subject.repository_id\n",
            $indent, "        AND (\n",
            $indent, "          delivery_evidence.github_check_subject_id =\n",
            $indent, "              COALESCE(subject.parent_subject_id, subject.id)\n",
            $indent, "          OR EXISTS (\n",
            $indent, "              SELECT 1\n",
            $indent, "              FROM github_workflow_run_subject_evidence AS run_evidence\n",
            $indent, "              WHERE run_evidence.github_check_subject_id =\n",
            $indent, "                        COALESCE(subject.parent_subject_id, subject.id)\n",
            $indent, "                AND run_evidence.provider_delivery_id =\n",
            $indent, "                    subject.provider_delivery_id\n",
            $indent, "                AND run_evidence.tenant_id = subject.tenant_id\n",
            $indent, "                AND run_evidence.repository_id = subject.repository_id\n",
            $indent, "                AND (\n",
            $indent, "                    subject.parent_subject_id IS NOT NULL\n",
            $indent, "                    OR run_evidence.workflow_path = subject.subject_key\n",
            $indent, "                )\n",
            $indent, "                AND run_evidence.run_id = subject.workflow_run_id\n",
            $indent, "          )\n",
            $indent, "          OR EXISTS (\n",
            $indent, "              SELECT 1\n",
            $indent, "              FROM provider_delivery_workflow_progress AS progress\n",
            $indent, "              WHERE progress.inbox_id = subject.provider_delivery_id\n",
            $indent, "                AND progress.tenant_id = subject.tenant_id\n",
            $indent, "                AND progress.workflow_path = subject.subject_key\n",
            $indent, "                AND progress.outcome_kind = 'failed'\n",
            $indent, "                AND subject.workflow_run_id IS NULL\n",
            $indent, "          )\n",
            $indent, "        )\n",
            $indent, "  )\n",
            $indent, "  WHEN 'scheduled_fire' THEN EXISTS (\n",
            $indent, "      SELECT 1\n",
            $indent, "      FROM github_schedule_check_evidence AS schedule_evidence\n",
            $indent, "      WHERE schedule_evidence.github_check_subject_id =\n",
            $indent, "                COALESCE(subject.parent_subject_id, subject.id)\n",
            $indent, "        AND schedule_evidence.schedule_fire_id = subject.schedule_fire_id\n",
            $indent, "        AND schedule_evidence.tenant_id = subject.tenant_id\n",
            $indent, "        AND schedule_evidence.repository_id = subject.repository_id\n",
            $indent, "        AND schedule_evidence.provider_connection_id =\n",
            $indent, $schedule_connection_indent, "subject.provider_connection_id\n",
            $indent, "  )\n",
            $indent, "  WHEN 'workflow_rerun' THEN EXISTS (\n",
            $indent, "      SELECT 1\n",
            $indent, "      FROM workflow_rerun_check_evidence AS rerun_evidence\n",
            $indent, "      WHERE rerun_evidence.github_check_subject_id =\n",
            $indent, "                COALESCE(subject.parent_subject_id, subject.id)\n",
            $indent, "        AND rerun_evidence.run_id = subject.workflow_rerun_run_id\n",
            $indent, "        AND rerun_evidence.tenant_id = subject.tenant_id\n",
            $indent, "        AND rerun_evidence.repository_id = subject.repository_id\n",
            $indent, "        AND rerun_evidence.provider_connection_id =\n",
            $indent, "            subject.provider_connection_id\n",
            $indent, "  )\n",
            $indent, "  ELSE FALSE\n",
            $indent, "END\n",
            $suffix,
        )
    };
}

macro_rules! claim_locked_projection_sql {
    ($origin_authority:literal) => {
        concat!(
            r"
    UPDATE github_check_projection_outbox AS outbox
    SET state = 'claimed',
        attempted_revision = subject.desired_revision,
        attempt_count = CASE
            WHEN outbox.attempted_revision IS DISTINCT FROM subject.desired_revision
                THEN 1
            ELSE outbox.attempt_count + 1
        END,
        claim_fence = outbox.claim_fence + 1,
        claim_owner_id = $3,
        claim_action = CASE
            WHEN outbox.external_suite_id IS NULL THEN 'ensure_suite'
            WHEN outbox.external_run_id IS NULL
                 AND outbox.create_started_at_ms IS NULL THEN 'prepare_run_create'
            WHEN outbox.external_run_id IS NULL THEN 'reconcile_run_create'
            ELSE 'publish'
        END,
        claimed_desired_revision = subject.desired_revision,
        claimed_desired_state = subject.desired_state,
        claimed_desired_conclusion = subject.desired_conclusion,
        claimed_at_ms = $4,
        claim_expires_at_ms = $5,
        next_attempt_at_ms = NULL,
        last_failure_kind = NULL,
        blocked_reason = NULL,
        state_updated_at_ms = $4
",
            $origin_authority,
            r"      AND outbox.claim_fence < 9223372036854775807
      AND (
        outbox.attempted_revision IS DISTINCT FROM subject.desired_revision
        OR outbox.attempt_count < 64
      )
      AND (
        outbox.state = 'pending'
        OR outbox.state = 'retry' AND outbox.next_attempt_at_ms <= $4
        OR outbox.state = 'create_indeterminate'
           AND outbox.next_reconcile_at_ms <= $4
        OR outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $4
      )
    RETURNING
        outbox.subject_id, outbox.attempt_count, outbox.claim_fence,
        outbox.claim_action, outbox.external_suite_id, outbox.external_run_id,
        outbox.claimed_at_ms, outbox.claim_expires_at_ms,
        subject.id, subject.tenant_id, subject.repository_id,
        subject.origin_kind, subject.provider_delivery_id,
        subject.schedule_fire_id, subject.workflow_rerun_run_id,
        subject.subject_key, subject.subject_kind, subject.parent_subject_id,
        subject.job_id, subject.job_attempt_id,
        subject.provider_connection_id, subject.provider_installation_id,
        subject.github_repository_id, subject.github_repository_name,
        subject.github_app_id, subject.head_sha,
        subject.check_name, subject.external_id, subject.workflow_run_id,
        subject.linked_at_ms,
        subject.desired_state, subject.desired_conclusion, subject.terminal_cause,
        subject.desired_revision, subject.created_at_ms,
        subject.desired_updated_at_ms,
        (SELECT attempt.started_at_ms
           FROM job_attempts AS attempt
          WHERE attempt.id = subject.job_attempt_id) AS job_started_at_ms,
        (SELECT terminal.completed_at_ms
           FROM attempt_terminal_results AS terminal
          WHERE terminal.attempt_id = subject.job_attempt_id) AS job_completed_at_ms,
        (SELECT terminal.result_schema
           FROM attempt_terminal_results AS terminal
          WHERE terminal.attempt_id = subject.job_attempt_id) AS job_result_schema,
        (SELECT terminal.result_size_bytes
           FROM attempt_terminal_results AS terminal
          WHERE terminal.attempt_id = subject.job_attempt_id) AS job_result_size_bytes,
        (SELECT terminal.result_digest
           FROM attempt_terminal_results AS terminal
          WHERE terminal.attempt_id = subject.job_attempt_id) AS job_result_digest,
        (SELECT terminal.result_object_key
           FROM attempt_terminal_results AS terminal
          WHERE terminal.attempt_id = subject.job_attempt_id) AS job_result_object_key,
        (SELECT progress.presentation_digest
           FROM github_check_annotation_progress AS progress
          WHERE progress.subject_id = subject.id) AS annotation_presentation_digest,
        (SELECT progress.annotation_total
           FROM github_check_annotation_progress AS progress
          WHERE progress.subject_id = subject.id) AS annotation_total,
        (SELECT progress.annotation_next
           FROM github_check_annotation_progress AS progress
          WHERE progress.subject_id = subject.id) AS annotation_next,
        (SELECT progress.uncertain_batch_size
           FROM github_check_annotation_progress AS progress
          WHERE progress.subject_id = subject.id) AS annotation_uncertain_batch_size,
        evidence.checks_authority_id,
        evidence.checks_authority_identity_digest,
        evidence.checks_authority_app_configuration_revision,
        evidence.checks_authority_policy_revision
",
        )
    };
}

const LOCK_PROJECTION_CANDIDATE_SQL: &str = projection_origin_authority_sql!(
    r"
    SELECT outbox.subject_id, subject.origin_kind
    FROM github_check_projection_outbox AS outbox
    JOIN github_check_subjects AS subject
      ON subject.id = outbox.subject_id
    WHERE subject.provider_connection_id = $1
",
    "      ",
    "          ",
    r"      AND outbox.claim_fence < 9223372036854775807
      AND (
        outbox.attempted_revision IS DISTINCT FROM subject.desired_revision
        OR outbox.attempt_count < 64
      )
      AND (
        outbox.state = 'pending'
        OR outbox.state = 'retry' AND outbox.next_attempt_at_ms <= $2
        OR outbox.state = 'create_indeterminate'
           AND outbox.next_reconcile_at_ms <= $2
        OR outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $2
      )
    ORDER BY
        CASE outbox.state
            WHEN 'pending' THEN outbox.state_updated_at_ms
            WHEN 'retry' THEN outbox.next_attempt_at_ms
            WHEN 'create_indeterminate' THEN outbox.next_reconcile_at_ms
            ELSE outbox.claim_expires_at_ms
        END,
        outbox.subject_id
    FOR UPDATE OF outbox SKIP LOCKED
    LIMIT 1
",
);

const CLAIM_LOCKED_DELIVERY_PROJECTION_SQL: &str = claim_locked_projection_sql!(
    r"    FROM github_check_subjects AS subject,
         github_provider_delivery_evidence AS evidence
    WHERE outbox.subject_id = $1
      AND subject.id = outbox.subject_id
      AND subject.origin_kind = 'provider_delivery'
      AND subject.schedule_fire_id IS NULL
      AND subject.provider_connection_id = $2
      AND evidence.provider_delivery_id = subject.provider_delivery_id
      AND evidence.tenant_id = subject.tenant_id
      AND evidence.repository_id = subject.repository_id
      AND (
        evidence.github_check_subject_id = COALESCE(subject.parent_subject_id, subject.id)
        OR EXISTS (
            SELECT 1
            FROM github_workflow_run_subject_evidence AS run_evidence
            WHERE run_evidence.github_check_subject_id =
                      COALESCE(subject.parent_subject_id, subject.id)
              AND run_evidence.provider_delivery_id = subject.provider_delivery_id
              AND run_evidence.tenant_id = subject.tenant_id
              AND run_evidence.repository_id = subject.repository_id
              AND (
                  subject.parent_subject_id IS NOT NULL
                  OR run_evidence.workflow_path = subject.subject_key
              )
              AND run_evidence.run_id = subject.workflow_run_id
        )
        OR EXISTS (
            SELECT 1
            FROM provider_delivery_workflow_progress AS progress
            WHERE progress.inbox_id = subject.provider_delivery_id
              AND progress.tenant_id = subject.tenant_id
              AND progress.workflow_path = subject.subject_key
              AND progress.outcome_kind = 'failed'
              AND subject.workflow_run_id IS NULL
        )
      )
"
);

const CLAIM_LOCKED_SCHEDULE_PROJECTION_SQL: &str = claim_locked_projection_sql!(
    r"    FROM github_check_subjects AS subject,
         github_schedule_check_evidence AS evidence
    WHERE outbox.subject_id = $1
      AND subject.id = outbox.subject_id
      AND subject.origin_kind = 'scheduled_fire'
      AND subject.provider_delivery_id IS NULL
      AND subject.provider_connection_id = $2
      AND evidence.github_check_subject_id = COALESCE(subject.parent_subject_id, subject.id)
      AND evidence.schedule_fire_id = subject.schedule_fire_id
      AND evidence.tenant_id = subject.tenant_id
      AND evidence.repository_id = subject.repository_id
      AND evidence.provider_connection_id = subject.provider_connection_id
"
);

const CLAIM_LOCKED_RERUN_PROJECTION_SQL: &str = claim_locked_projection_sql!(
    r"    FROM github_check_subjects AS subject,
         workflow_rerun_check_evidence AS evidence
    WHERE outbox.subject_id = $1
      AND subject.id = outbox.subject_id
      AND subject.origin_kind = 'workflow_rerun'
      AND subject.provider_delivery_id IS NULL
      AND subject.schedule_fire_id IS NULL
      AND subject.provider_connection_id = $2
      AND evidence.github_check_subject_id = COALESCE(subject.parent_subject_id, subject.id)
      AND evidence.run_id = subject.workflow_rerun_run_id
      AND evidence.tenant_id = subject.tenant_id
      AND evidence.repository_id = subject.repository_id
      AND evidence.provider_connection_id = subject.provider_connection_id
"
);

const PROJECTION_FENCE_EXHAUSTED_SQL: &str = projection_origin_authority_sql!(
    r"
        SELECT EXISTS (
            SELECT 1
            FROM github_check_projection_outbox AS outbox
            JOIN github_check_subjects AS subject ON subject.id = outbox.subject_id
            WHERE subject.provider_connection_id = $1
",
    "              ",
    "            ",
    r"              AND outbox.claim_fence = 9223372036854775807
              AND (
                outbox.state = 'pending'
                OR outbox.state = 'retry' AND outbox.next_attempt_at_ms <= $2
                OR outbox.state = 'create_indeterminate'
                   AND outbox.next_reconcile_at_ms <= $2
                OR outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $2
              )
        )
        ",
);

const BLOCK_EXHAUSTED_CANDIDATES_SQL: &str = projection_origin_authority_sql!(
    r"
        UPDATE github_check_projection_outbox AS outbox
        SET state = 'blocked',
            next_attempt_at_ms = NULL,
            last_failure_kind = NULL,
            blocked_reason = 'attempt_limit',
            claim_owner_id = NULL, claim_action = NULL,
            claimed_desired_revision = NULL, claimed_desired_state = NULL,
            claimed_desired_conclusion = NULL,
            claimed_at_ms = NULL, claim_expires_at_ms = NULL,
            state_updated_at_ms = $2
        FROM github_check_subjects AS subject
        WHERE subject.id = outbox.subject_id
          AND subject.provider_connection_id = $1
",
    "          ",
    "            ",
    r"          AND outbox.attempted_revision = subject.desired_revision
          AND outbox.attempt_count >= 64
          AND (
            outbox.state = 'pending'
            OR outbox.state = 'retry' AND outbox.next_attempt_at_ms <= $2
            OR outbox.state = 'create_indeterminate'
               AND outbox.next_reconcile_at_ms <= $2
            OR outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $2
          )
        ",
);

#[async_trait]
impl GithubCheckProjectionOutbox for PostgresStore {
    async fn claim_github_check_projection(
        &self,
        request: ClaimGithubCheckProjection,
    ) -> Result<Option<ClaimedGithubCheckProjection>, GithubCheckStoreError> {
        let claim_duration = requested_claim_duration(request)?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        let selection_now = database_now_ms(&mut transaction).await?;
        validate_caller_clock(request.observed_at(), selection_now)?;
        block_exhausted_candidates(&mut transaction, request.connection_id(), selection_now)
            .await?;
        // The exhaustion update can wait behind a row owner. Re-read and
        // revalidate PostgreSQL time before it can select a due row, take over
        // an expired fence, or issue a new absolute interval.
        let lock_observed_at = database_now_ms(&mut transaction).await?;
        if lock_observed_at < selection_now {
            return Err(GithubCheckStoreError::CorruptData);
        }
        validate_caller_clock(request.observed_at(), lock_observed_at)?;
        let candidate = sqlx::query(LOCK_PROJECTION_CANDIDATE_SQL)
            .bind(request.connection_id().as_uuid())
            .bind(lock_observed_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?;
        if let Some(candidate) = candidate {
            let candidate_id: Uuid = candidate.try_get("subject_id").map_err(operation_error)?;
            let origin = decode_projection_origin(&candidate)?;
            let claimed = claim_locked_projection(
                &mut transaction,
                request,
                candidate_id,
                origin,
                lock_observed_at,
                claim_duration,
            )
            .await?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(Some(claimed));
        }
        let idle_now = database_now_ms(&mut transaction).await?;
        if idle_now < lock_observed_at {
            return Err(GithubCheckStoreError::CorruptData);
        }
        validate_caller_clock(request.observed_at(), idle_now)?;
        let fence_exhausted =
            projection_fence_exhausted(&mut transaction, request.connection_id(), idle_now).await?;
        transaction.commit().await.map_err(operation_error)?;
        if fence_exhausted {
            Err(GithubCheckStoreError::FenceExhausted)
        } else {
            Ok(None)
        }
    }

    async fn bind_github_check_suite(
        &self,
        request: BindGithubCheckSuite,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = 'pending',
                external_suite_id = $4,
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $5
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claim_action = 'ensure_suite'
              AND outbox.external_suite_id IS NULL
              AND outbox.claimed_at_ms <= $5
              AND outbox.claim_expires_at_ms > $5
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(pg_bigint(request.claim().fence()))
            .bind(pg_bigint(request.suite_id().get()))
            .bind(request.observed_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        exact_external_replay(
            &self.pool,
            request.claim().subject_id(),
            Some(request.suite_id()),
            None,
        )
        .await
    }

    async fn begin_github_check_run_create(
        &self,
        request: BeginGithubCheckRunCreate,
    ) -> Result<GithubCheckRunCreateFence, GithubCheckStoreError> {
        let changed = sqlx::query(
            r"
            UPDATE github_check_projection_outbox
            SET state = 'create_indeterminate',
                create_owner_id = $2,
                create_fence = $3,
                create_started_at_ms = $4,
                create_issue_expires_at_ms = $5,
                reconcile_not_before_ms = $6,
                next_reconcile_at_ms = $6,
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $4
            WHERE subject_id = $1
              AND state = 'claimed'
              AND claim_owner_id = $2
              AND claim_fence = $3
              AND claim_action = 'prepare_run_create'
              AND claimed_at_ms <= $4
              AND claim_expires_at_ms > $4
              AND claim_expires_at_ms = $5
            RETURNING subject_id
            ",
        )
        .bind(request.claim().subject_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.started_at().get())
        .bind(request.issue_expires_at().get())
        .bind(request.reconcile_not_before().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;
        if changed.is_some() {
            return Ok(request.fence());
        }
        let exact: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1 FROM github_check_projection_outbox
                WHERE subject_id = $1
                  AND state = 'create_indeterminate'
                  AND create_owner_id = $2
                  AND create_fence = $3
                  AND create_started_at_ms = $4
                  AND create_issue_expires_at_ms = $5
                  AND reconcile_not_before_ms = $6
                  AND next_reconcile_at_ms = $6
            )
            ",
        )
        .bind(request.claim().subject_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.started_at().get())
        .bind(request.issue_expires_at().get())
        .bind(request.reconcile_not_before().get())
        .fetch_one(&self.pool)
        .await
        .map_err(operation_error)?;
        if exact {
            Ok(request.fence())
        } else {
            Err(GithubCheckStoreError::ClaimRejected)
        }
    }

    async fn release_unissued_github_check_run_create(
        &self,
        request: ReleaseUnissuedGithubCheckRunCreate,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let fence = request.fence();
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = CASE WHEN attempt_count >= 64 THEN 'blocked' ELSE 'retry' END,
                next_attempt_at_ms = CASE WHEN attempt_count >= 64 THEN NULL ELSE $7 END,
                last_failure_kind = CASE
                    WHEN attempt_count >= 64 THEN NULL ELSE 'create_not_issued'
                END,
                blocked_reason = CASE
                    WHEN attempt_count >= 64 THEN 'attempt_limit' ELSE NULL
                END,
                create_owner_id = NULL, create_fence = NULL,
                create_started_at_ms = NULL, create_issue_expires_at_ms = NULL,
                reconcile_not_before_ms = NULL,
                next_reconcile_at_ms = NULL,
                state_updated_at_ms = $6
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.state = 'create_indeterminate'
              AND outbox.create_owner_id = $2
              AND outbox.create_fence = $3
              AND outbox.create_started_at_ms = $4
              AND outbox.create_issue_expires_at_ms = $5
              AND outbox.reconcile_not_before_ms = $8
              AND outbox.next_reconcile_at_ms = outbox.reconcile_not_before_ms
              AND outbox.external_run_id IS NULL
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(fence.claim().subject_id().as_uuid())
            .bind(fence.claim().owner().as_uuid())
            .bind(pg_bigint(fence.claim().fence()))
            .bind(fence.started_at().get())
            .bind(fence.issue_expires_at().get())
            .bind(request.released_at().get())
            .bind(request.retry_at().get())
            .bind(fence.reconcile_not_before().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        exact_unissued_release_replay(&self.pool, request).await
    }

    async fn bind_github_check_run(
        &self,
        request: BindGithubCheckRun,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let (claim, binding_kind, create_fence) = match request.fence() {
            GithubCheckRunBindingFence::Create(fence) => (fence.claim(), "create", Some(fence)),
            GithubCheckRunBindingFence::Reconciliation(claim) => (claim, "reconciliation", None),
        };
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = CASE
                    WHEN subject.desired_state = 'queued' THEN 'delivered'
                    ELSE 'pending'
                END,
                external_run_id = $5,
                external_bound_at_ms = $6,
                provider_state = 'queued', provider_conclusion = NULL,
                provider_observed_at_ms = $6,
                projected_revision = CASE
                    WHEN subject.desired_state = 'queued' THEN subject.desired_revision
                    ELSE outbox.projected_revision
                END,
                create_owner_id = NULL, create_fence = NULL,
                create_started_at_ms = NULL, create_issue_expires_at_ms = NULL,
                reconcile_not_before_ms = NULL,
                next_reconcile_at_ms = NULL,
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $6
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.external_suite_id = $4
              AND outbox.external_run_id IS NULL
              AND (
                $7 = 'create'
                AND outbox.create_owner_id = $2
                AND outbox.create_fence = $3
                AND outbox.create_started_at_ms = $8
                AND outbox.create_issue_expires_at_ms = $9
                AND outbox.reconcile_not_before_ms = $10
                AND outbox.create_started_at_ms <= $6
                AND (
                    outbox.state = 'create_indeterminate'
                    OR outbox.state = 'claimed'
                       AND outbox.claim_action = 'reconcile_run_create'
                )
                OR $7 = 'reconciliation'
                AND outbox.state = 'claimed'
                AND outbox.claim_owner_id = $2
                AND outbox.claim_fence = $3
                AND outbox.claim_action = 'reconcile_run_create'
                AND outbox.claimed_at_ms <= $6
                AND outbox.claim_expires_at_ms > $6
              )
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(claim.subject_id().as_uuid())
            .bind(claim.owner().as_uuid())
            .bind(pg_bigint(claim.fence()))
            .bind(pg_bigint(request.suite_id().get()))
            .bind(pg_bigint(request.run_id().get()))
            .bind(request.observed_at().get())
            .bind(binding_kind)
            .bind(
                create_fence
                    .map(GithubCheckRunCreateFence::started_at)
                    .map(UnixMillis::get),
            )
            .bind(
                create_fence
                    .map(GithubCheckRunCreateFence::issue_expires_at)
                    .map(UnixMillis::get),
            )
            .bind(
                create_fence
                    .map(GithubCheckRunCreateFence::reconcile_not_before)
                    .map(UnixMillis::get),
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        exact_external_replay(
            &self.pool,
            claim.subject_id(),
            Some(request.suite_id()),
            Some(request.run_id()),
        )
        .await
    }

    async fn resolve_github_check_run_create(
        &self,
        request: ResolveGithubCheckRunCreate,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let (query, retry_at) = match request.outcome() {
            GithubCheckCreateReconciliation::Missing => {
                let retry_at = request
                    .retry_at()
                    .ok_or(GithubCheckStoreError::CorruptData)?;
                (
                    format!(
                        r"
                    UPDATE github_check_projection_outbox AS outbox
                    SET state = CASE
                            WHEN attempt_count >= 64 THEN 'blocked'
                            ELSE 'create_indeterminate'
                        END,
                        next_reconcile_at_ms = $5,
                        blocked_reason = CASE
                            WHEN attempt_count >= 64 THEN 'attempt_limit'
                            ELSE NULL
                        END,
                        claim_owner_id = NULL, claim_action = NULL,
                        claimed_desired_revision = NULL, claimed_desired_state = NULL,
                        claimed_desired_conclusion = NULL,
                        claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                        state_updated_at_ms = $4
                    FROM github_check_subjects AS subject
                    WHERE outbox.subject_id = $1
                      AND subject.id = outbox.subject_id
                      AND outbox.state = 'claimed'
                      AND outbox.claim_owner_id = $2
                      AND outbox.claim_fence = $3
                      AND outbox.claim_action = 'reconcile_run_create'
                      AND outbox.create_started_at_ms IS NOT NULL
                      AND outbox.external_run_id IS NULL
                      AND outbox.claimed_at_ms <= $4
                      AND outbox.claim_expires_at_ms > $4
                    RETURNING {SUBJECT_COLUMNS}
                        "
                    ),
                    Some(retry_at),
                )
            }
            GithubCheckCreateReconciliation::Ambiguous => (
                format!(
                    r"
                UPDATE github_check_projection_outbox AS outbox
                SET state = 'blocked',
                    blocked_reason = 'ambiguous_create',
                    claim_owner_id = NULL, claim_action = NULL,
                    claimed_desired_revision = NULL, claimed_desired_state = NULL,
                    claimed_desired_conclusion = NULL,
                    claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                    state_updated_at_ms = $4
                FROM github_check_subjects AS subject
                WHERE outbox.subject_id = $1
                  AND subject.id = outbox.subject_id
                  AND outbox.state = 'claimed'
                  AND outbox.claim_owner_id = $2
                  AND outbox.claim_fence = $3
                  AND outbox.claim_action = 'reconcile_run_create'
                  AND outbox.create_started_at_ms IS NOT NULL
                  AND outbox.external_run_id IS NULL
                  AND outbox.claimed_at_ms <= $4
                  AND outbox.claim_expires_at_ms > $4
                RETURNING {SUBJECT_COLUMNS}
                    "
                ),
                None,
            ),
        };
        let mut sql = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(pg_bigint(request.claim().fence()))
            .bind(request.observed_at().get());
        if let Some(retry_at) = retry_at {
            sql = sql.bind(retry_at.get());
        }
        let row = sql
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        exact_create_reconciliation_replay(&self.pool, request).await
    }

    async fn initialize_github_check_presentation(
        &self,
        request: InitializeGithubCheckPresentation,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError> {
        sqlx::query(
            r"
            INSERT INTO github_check_annotation_progress (
                subject_id, presentation_digest, annotation_total,
                annotation_next, uncertain_batch_size, updated_at_ms
            )
            SELECT outbox.subject_id, $4, $5, 0, NULL, $6
            FROM github_check_projection_outbox AS outbox
            JOIN github_check_subjects AS subject ON subject.id = outbox.subject_id
            WHERE outbox.subject_id = $1
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claim_action = 'publish'
              AND outbox.claimed_desired_state = 'completed'
              AND subject.subject_kind = 'job'
              AND outbox.claimed_at_ms <= $6
              AND outbox.claim_expires_at_ms > $6
            ON CONFLICT (subject_id) DO NOTHING
            ",
        )
        .bind(request.claim().subject_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.digest().as_bytes().as_slice())
        .bind(i32::from(request.annotation_count()))
        .bind(request.initialized_at().get())
        .execute(&self.pool)
        .await
        .map_err(operation_error)?;

        let row = sqlx::query(
            r"
            SELECT progress.presentation_digest AS annotation_presentation_digest,
                   progress.annotation_total,
                   progress.annotation_next,
                   progress.uncertain_batch_size AS annotation_uncertain_batch_size
            FROM github_check_annotation_progress AS progress
            JOIN github_check_projection_outbox AS outbox
              ON outbox.subject_id = progress.subject_id
            WHERE progress.subject_id = $1
              AND progress.presentation_digest = $4
              AND progress.annotation_total = $5
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claim_action = 'publish'
              AND outbox.claimed_at_ms <= $6
              AND outbox.claim_expires_at_ms > $6
            ",
        )
        .bind(request.claim().subject_id().as_uuid())
        .bind(request.claim().owner().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.digest().as_bytes().as_slice())
        .bind(i32::from(request.annotation_count()))
        .bind(request.initialized_at().get())
        .fetch_optional(&self.pool)
        .await
        .map_err(operation_error)?;
        row.map(|row| decode_annotation_progress(&row))
            .transpose()?
            .ok_or(GithubCheckStoreError::ProjectionMismatch)
    }

    async fn begin_github_check_annotation_batch(
        &self,
        request: BeginGithubCheckAnnotationBatch,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        let claim = request.claim();
        lock_live_annotation_publish_claim(&mut transaction, claim, request.started_at()).await?;

        let row = sqlx::query(
            r"
            UPDATE github_check_annotation_progress
            SET uncertain_batch_size = $4,
                updated_at_ms = $5
            WHERE subject_id = $1
              AND presentation_digest = $2
              AND annotation_next = $3
              AND uncertain_batch_size IS NULL
              AND annotation_next + $4 <= annotation_total
            RETURNING presentation_digest AS annotation_presentation_digest,
                      annotation_total,
                      annotation_next,
                      uncertain_batch_size AS annotation_uncertain_batch_size
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(request.digest().as_bytes().as_slice())
        .bind(i32::from(request.from()))
        .bind(i16::from(request.batch_size()))
        .bind(request.started_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let progress = row
            .map(|row| decode_annotation_progress(&row))
            .transpose()?
            .ok_or(GithubCheckStoreError::ProjectionMismatch)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(progress)
    }

    async fn advance_github_check_annotations(
        &self,
        request: AdvanceGithubCheckAnnotations,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        let claim = request.claim();
        lock_live_annotation_publish_claim(&mut transaction, claim, request.observed_at()).await?;
        let batch_size = request
            .to()
            .checked_sub(request.from())
            .and_then(|size| u8::try_from(size).ok())
            .ok_or(GithubCheckStoreError::ProjectionMismatch)?;
        lock_exact_annotation_batch(
            &mut transaction,
            claim,
            request.digest(),
            request.from(),
            batch_size,
        )
        .await?;

        let row = sqlx::query(
            r"
            UPDATE github_check_annotation_progress
            SET annotation_next = $4,
                uncertain_batch_size = NULL,
                updated_at_ms = $6
            WHERE subject_id = $1
              AND presentation_digest = $2
              AND annotation_next = $3
              AND annotation_total >= $4
              AND uncertain_batch_size = $5
            RETURNING presentation_digest AS annotation_presentation_digest,
                      annotation_total,
                      annotation_next,
                      uncertain_batch_size AS annotation_uncertain_batch_size
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(request.digest().as_bytes().as_slice())
        .bind(i32::from(request.from()))
        .bind(i32::from(request.to()))
        .bind(i16::from(batch_size))
        .bind(request.observed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let progress = row
            .map(|row| decode_annotation_progress(&row))
            .transpose()?
            .ok_or(GithubCheckStoreError::ProjectionMismatch)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(progress)
    }

    async fn retry_uncertain_github_check_annotations(
        &self,
        request: RetryUncertainGithubCheckAnnotations,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        let claim = request.claim();
        lock_live_annotation_publish_claim(&mut transaction, claim, request.failed_at()).await?;
        lock_exact_annotation_batch(
            &mut transaction,
            claim,
            request.digest(),
            request.from(),
            request.batch_size(),
        )
        .await?;

        let receipt = retry_live_annotation_publish_claim(
            &mut transaction,
            claim,
            request.failed_at(),
            request.retry_at(),
            "github_annotation_ambiguous",
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn release_unissued_github_check_annotation_batch(
        &self,
        request: ReleaseUnissuedGithubCheckAnnotationBatch,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        let claim = request.claim();
        lock_live_annotation_publish_claim(&mut transaction, claim, request.released_at()).await?;
        lock_exact_annotation_batch(
            &mut transaction,
            claim,
            request.digest(),
            request.from(),
            request.batch_size(),
        )
        .await?;

        let cleared = sqlx::query(
            r"
            UPDATE github_check_annotation_progress
            SET uncertain_batch_size = NULL,
                updated_at_ms = $6
            WHERE subject_id = $1
              AND presentation_digest = $2
              AND annotation_next = $3
              AND uncertain_batch_size = $4
              AND updated_at_ms = $5
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(request.digest().as_bytes().as_slice())
        .bind(i32::from(request.from()))
        .bind(i16::from(request.batch_size()))
        .bind(request.started_at().get())
        .bind(request.released_at().get())
        .execute(&mut *transaction)
        .await
        .map_err(operation_error)?;
        if cleared.rows_affected() != 1 {
            return Err(GithubCheckStoreError::ProjectionMismatch);
        }

        let receipt = retry_live_annotation_publish_claim(
            &mut transaction,
            claim,
            request.released_at(),
            request.retry_at(),
            "github_annotation_not_issued",
        )
        .await?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(receipt)
    }

    async fn clear_github_check_annotation_uncertainty(
        &self,
        request: ClearGithubCheckAnnotationUncertainty,
    ) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError> {
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        pin_read_committed(&mut transaction).await?;
        let claim = request.claim();
        lock_live_annotation_publish_claim(&mut transaction, claim, request.observed_at()).await?;
        lock_exact_annotation_batch(
            &mut transaction,
            claim,
            request.digest(),
            request.from(),
            request.batch_size(),
        )
        .await?;

        let row = sqlx::query(
            r"
            UPDATE github_check_annotation_progress
            SET uncertain_batch_size = NULL, updated_at_ms = $5
            WHERE subject_id = $1
              AND presentation_digest = $2
              AND annotation_next = $3
              AND uncertain_batch_size = $4
            RETURNING presentation_digest AS annotation_presentation_digest,
                      annotation_total,
                      annotation_next,
                      uncertain_batch_size AS annotation_uncertain_batch_size
            ",
        )
        .bind(claim.subject_id().as_uuid())
        .bind(request.digest().as_bytes().as_slice())
        .bind(i32::from(request.from()))
        .bind(i16::from(request.batch_size()))
        .bind(request.observed_at().get())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(operation_error)?;
        let progress = row
            .map(|row| decode_annotation_progress(&row))
            .transpose()?
            .ok_or(GithubCheckStoreError::ProjectionMismatch)?;
        transaction.commit().await.map_err(operation_error)?;
        Ok(progress)
    }

    async fn block_github_check_annotation_mismatch(
        &self,
        request: BlockGithubCheckAnnotationMismatch,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = 'blocked', next_attempt_at_ms = NULL,
                last_failure_kind = NULL, blocked_reason = 'annotation_mismatch',
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $4
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claim_action = 'publish'
              AND outbox.claimed_at_ms <= $4
              AND outbox.claim_expires_at_ms > $4
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(pg_bigint(request.claim().fence()))
            .bind(request.blocked_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        row.map(|row| decode_subject(&row).map(|subject| subject.receipt))
            .transpose()?
            .ok_or(GithubCheckStoreError::ClaimRejected)
    }

    async fn complete_github_check_projection(
        &self,
        request: CompleteGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let (provider_state, provider_conclusion) = projection_columns(request.observed());
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = CASE
                    WHEN subject.desired_revision = outbox.claimed_desired_revision
                     AND subject.desired_state = outbox.claimed_desired_state
                     AND subject.desired_conclusion IS NOT DISTINCT FROM outbox.claimed_desired_conclusion
                    THEN 'delivered'
                    ELSE 'pending'
                END,
                projected_revision = outbox.claimed_desired_revision,
                provider_state = $4, provider_conclusion = $5,
                provider_observed_at_ms = $6,
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $6
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claim_action = 'publish'
              AND outbox.external_run_id IS NOT NULL
              AND outbox.claimed_desired_state = $4
              AND outbox.claimed_desired_conclusion IS NOT DISTINCT FROM $5
              AND outbox.claimed_at_ms <= $6
              AND outbox.claim_expires_at_ms > $6
              AND (
                    subject.subject_kind <> 'job'
                    OR outbox.claimed_desired_state <> 'completed'
                    OR NOT EXISTS (
                        SELECT 1
                        FROM attempt_terminal_results AS terminal
                        WHERE terminal.attempt_id = subject.job_attempt_id
                          AND terminal.result_object_key IS NOT NULL
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM github_check_annotation_progress AS progress
                        WHERE progress.subject_id = outbox.subject_id
                          AND progress.annotation_next = progress.annotation_total
                          AND progress.uncertain_batch_size IS NULL
                    )
                  )
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(pg_bigint(request.claim().fence()))
            .bind(provider_state)
            .bind(provider_conclusion)
            .bind(request.observed_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        let exact = load_projection_replay(
            &self.pool,
            request.claim().subject_id(),
            provider_state,
            provider_conclusion,
        )
        .await?;
        match exact {
            Some(receipt) => Ok(receipt),
            None => Err(GithubCheckStoreError::ProjectionMismatch),
        }
    }

    async fn block_github_check_projection_for_credential_rejection(
        &self,
        request: BlockGithubCheckProjectionForCredentialRejection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = 'blocked',
                next_attempt_at_ms = NULL,
                last_failure_kind = NULL,
                blocked_reason = 'credential_rejected',
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $4
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claimed_at_ms <= $4
              AND outbox.claim_expires_at_ms > $4
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(pg_bigint(request.claim().fence()))
            .bind(request.blocked_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        row.map(|row| decode_subject(&row).map(|subject| subject.receipt))
            .transpose()?
            .ok_or(GithubCheckStoreError::ClaimRejected)
    }

    async fn retry_github_check_projection(
        &self,
        request: RetryGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            UPDATE github_check_projection_outbox AS outbox
            SET state = CASE WHEN attempt_count >= 64 THEN 'blocked' ELSE 'retry' END,
                next_attempt_at_ms = CASE WHEN attempt_count >= 64 THEN NULL ELSE $5 END,
                last_failure_kind = CASE WHEN attempt_count >= 64 THEN NULL ELSE $4 END,
                blocked_reason = CASE WHEN attempt_count >= 64 THEN 'attempt_limit' ELSE NULL END,
                claim_owner_id = NULL, claim_action = NULL,
                claimed_desired_revision = NULL, claimed_desired_state = NULL,
                claimed_desired_conclusion = NULL,
                claimed_at_ms = NULL, claim_expires_at_ms = NULL,
                state_updated_at_ms = $6
            FROM github_check_subjects AS subject
            WHERE outbox.subject_id = $1
              AND subject.id = outbox.subject_id
              AND outbox.state = 'claimed'
              AND outbox.claim_owner_id = $2
              AND outbox.claim_fence = $3
              AND outbox.claimed_at_ms <= $6
              AND outbox.claim_expires_at_ms > $6
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(pg_bigint(request.claim().fence()))
            .bind(request.failure_kind())
            .bind(request.retry_at().get())
            .bind(request.failed_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        row.map(|row| decode_subject(&row).map(|subject| subject.receipt))
            .transpose()?
            .ok_or(GithubCheckStoreError::ClaimRejected)
    }
}

pub(super) struct DecodedSubject {
    pub(super) identity: GithubCheckSubjectIdentity,
    pub(super) receipt: GithubCheckSubjectReceipt,
    pub(super) created_at: UnixMillis,
    pub(super) desired_updated_at: UnixMillis,
    pub(super) details_target: GithubCheckDetailsTarget,
}

pub(super) fn decode_subject(
    row: &sqlx::postgres::PgRow,
) -> Result<DecodedSubject, GithubCheckStoreError> {
    let subject_id = automata_ci_store::GithubCheckSubjectId::from_uuid(uuid_column(row, "id")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let identity = decode_subject_identity(row)?;
    let workflow_run_id = optional_uuid_column(row, "workflow_run_id")?.map(RunId::from_uuid);
    let subject_kind = string_column(row, "subject_kind")?;
    let parent_subject_id = optional_uuid_column(row, "parent_subject_id")?;
    let job_id = optional_uuid_column(row, "job_id")?.map(JobId::from_uuid);
    let job_attempt_id = optional_uuid_column(row, "job_attempt_id")?;
    let details_target = match (
        subject_kind.as_str(),
        parent_subject_id,
        job_id,
        job_attempt_id,
        workflow_run_id,
    ) {
        // The required delivery aggregate is externally claimable before
        // logical admission and therefore retains its repository target.
        // Schedule and rerun roots are internal lifecycle authority; their
        // target is decoded only for durable receipts because no outbox row
        // projects them to GitHub.
        ("workflow", None, None, None, workflow_run_id) => match identity.origin() {
            GithubCheckSubjectOrigin::ScheduledFire(_) => GithubCheckDetailsTarget::Repository,
            GithubCheckSubjectOrigin::ProviderDelivery(_)
                if identity.subject_key().as_str()
                    == automata_ci_store::GITHUB_PROVIDER_ALL_DIRECT_WORKFLOWS_KEY =>
            {
                GithubCheckDetailsTarget::Repository
            }
            GithubCheckSubjectOrigin::ProviderDelivery(_)
            | GithubCheckSubjectOrigin::WorkflowRerun(_) => workflow_run_id.map_or(
                GithubCheckDetailsTarget::Repository,
                GithubCheckDetailsTarget::WorkflowRun,
            ),
        },
        ("job", Some(parent_id), Some(job_id), Some(attempt_id), Some(run_id))
            if !parent_id.is_nil() && !attempt_id.is_nil() =>
        {
            GithubCheckDetailsTarget::Job { run_id, job_id }
        }
        _ => return Err(GithubCheckStoreError::CorruptData),
    };
    let desired = decode_desired(row)?;
    let desired_revision = positive_u64_column(row, "desired_revision")?;
    let external_id = string_column(row, "external_id")?;
    let receipt = GithubCheckSubjectReceipt::from_durable_parts(
        subject_id,
        external_id,
        workflow_run_id,
        desired,
        desired_revision,
    )
    .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let created_at = unix_millis_column(row, "created_at_ms")?;
    optional_unix_millis_column(row, "linked_at_ms")?;
    let desired_updated_at = unix_millis_column(row, "desired_updated_at_ms")?;
    Ok(DecodedSubject {
        identity,
        receipt,
        created_at,
        desired_updated_at,
        details_target,
    })
}

fn decode_subject_identity(
    row: &sqlx::postgres::PgRow,
) -> Result<GithubCheckSubjectIdentity, GithubCheckStoreError> {
    let tenant = TenantScope::from_authenticated_tenant_id(string_column(row, "tenant_id")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let repository_uuid = uuid_column(row, "repository_id")?;
    if repository_uuid.is_nil() {
        return Err(GithubCheckStoreError::CorruptData);
    }
    let origin_kind = string_column(row, "origin_kind")?;
    let delivery_id = optional_uuid_column(row, "provider_delivery_id")?
        .map(ProviderDeliveryId::from_uuid)
        .transpose()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let schedule_fire_id = optional_uuid_column(row, "schedule_fire_id")?
        .map(GithubScheduleFireId::from_uuid)
        .transpose()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let rerun_run_id = optional_uuid_column(row, "workflow_rerun_run_id")?.map(RunId::from_uuid);
    let subject_key = GithubCheckSubjectKey::new(string_column(row, "subject_key")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let connection_id =
        ProviderConnectionId::from_uuid(uuid_column(row, "provider_connection_id")?)
            .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let installation_id =
        ProviderInstallationId::new(positive_u64_column(row, "provider_installation_id")?)
            .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let github_repository_id =
        ProviderRepositoryId::new(positive_u64_column(row, "github_repository_id")?)
            .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let github_repository_name =
        GithubRepositoryName::new(string_column(row, "github_repository_name")?)
            .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let app_id = GithubCheckAppId::new(positive_u64_column(row, "github_app_id")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let head_sha = GitObjectId::from_durable_bytes(&bytes_column(row, "head_sha")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let name = GithubCheckName::new(string_column(row, "check_name")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    match (
        origin_kind.as_str(),
        delivery_id,
        schedule_fire_id,
        rerun_run_id,
    ) {
        ("provider_delivery", Some(delivery_id), None, None) => GithubCheckSubjectIdentity::new(
            tenant,
            RepositoryId::from_uuid(repository_uuid),
            delivery_id,
            subject_key,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            app_id,
            head_sha,
            name,
        ),
        ("scheduled_fire", None, Some(fire_id), None) => GithubCheckSubjectIdentity::new_scheduled(
            tenant,
            RepositoryId::from_uuid(repository_uuid),
            fire_id,
            subject_key,
            connection_id,
            installation_id,
            github_repository_id,
            github_repository_name,
            app_id,
            head_sha,
            name,
        ),
        ("workflow_rerun", None, None, Some(rerun_run_id)) => {
            GithubCheckSubjectIdentity::new_rerun(
                tenant,
                RepositoryId::from_uuid(repository_uuid),
                rerun_run_id,
                subject_key,
                connection_id,
                installation_id,
                github_repository_id,
                github_repository_name,
                app_id,
                head_sha,
                name,
            )
        }
        _ => return Err(GithubCheckStoreError::CorruptData),
    }
    .map_err(|_| GithubCheckStoreError::CorruptData)
}

fn decode_claimed(
    row: &sqlx::postgres::PgRow,
    owner: GithubCheckProjectionWorkerId,
) -> Result<ClaimedGithubCheckProjection, GithubCheckStoreError> {
    let subject = decode_subject(row)?;
    let fence = positive_u64_column(row, "claim_fence")?;
    let claim = GithubCheckProjectionClaimFence::from_durable_parts(
        subject.receipt.subject_id(),
        owner,
        fence,
    )
    .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let action = match string_column(row, "claim_action")?.as_str() {
        "ensure_suite" => GithubCheckProjectionAction::EnsureSuite,
        "prepare_run_create" => GithubCheckProjectionAction::PrepareRunCreate,
        "reconcile_run_create" => GithubCheckProjectionAction::ReconcileRunCreate,
        "publish" => GithubCheckProjectionAction::Publish,
        _ => return Err(GithubCheckStoreError::CorruptData),
    };
    let checks_authority = GithubServerServiceAuthoritySelector::from_durable_parts(
        subject.identity.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(uuid_column(row, "checks_authority_id")?)
            .map_err(|_| GithubCheckStoreError::CorruptData)?,
        sha256_column(row, "checks_authority_identity_digest")?,
        GithubServerServiceRevision::new(positive_u64_column(
            row,
            "checks_authority_app_configuration_revision",
        )?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?,
        GithubServerServiceRevision::new(positive_u64_column(
            row,
            "checks_authority_policy_revision",
        )?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?,
    );
    let attempts = positive_u16_column(row, "attempt_count")?;
    let suite_id = optional_positive_u64_column(row, "external_suite_id")?
        .map(GithubCheckSuiteId::new)
        .transpose()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let run_id = optional_positive_u64_column(row, "external_run_id")?
        .map(GithubCheckRunId::new)
        .transpose()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let job_started_at = optional_unix_millis_column(row, "job_started_at_ms")?;
    let job_completed_at = optional_unix_millis_column(row, "job_completed_at_ms")?;
    let terminal_result = optional_job_result_descriptor(row)?;
    let annotation_progress = decode_annotation_progress(row)?;
    let (started_at, completed_at) = match subject.receipt.desired() {
        GithubCheckDesiredProjection::Queued => (None, None),
        GithubCheckDesiredProjection::InProgress => (
            Some(job_started_at.unwrap_or(subject.desired_updated_at)),
            None,
        ),
        GithubCheckDesiredProjection::Terminal(_) => (
            Some(job_started_at.unwrap_or(subject.created_at)),
            Some(job_completed_at.unwrap_or(subject.desired_updated_at)),
        ),
    };
    ClaimedGithubCheckProjection::from_durable_parts(
        claim,
        action,
        attempts,
        subject.identity,
        subject.details_target,
        checks_authority,
        subject.receipt.external_id().to_owned(),
        subject.receipt.desired(),
        subject.receipt.desired_revision(),
        suite_id,
        run_id,
        subject.created_at,
        subject.desired_updated_at,
        terminal_result,
        annotation_progress,
        started_at,
        completed_at,
        unix_millis_column(row, "claimed_at_ms")?,
        unix_millis_column(row, "claim_expires_at_ms")?,
    )
    .map_err(|_| GithubCheckStoreError::CorruptData)
}

fn decode_desired(
    row: &sqlx::postgres::PgRow,
) -> Result<GithubCheckDesiredProjection, GithubCheckStoreError> {
    let state = string_column(row, "desired_state")?;
    let conclusion: Option<String> = row.try_get("desired_conclusion").map_err(operation_error)?;
    let cause: Option<String> = row.try_get("terminal_cause").map_err(operation_error)?;
    match (state.as_str(), conclusion.as_deref(), cause.as_deref()) {
        ("queued", None, None) => Ok(GithubCheckDesiredProjection::Queued),
        ("in_progress", None, None) => Ok(GithubCheckDesiredProjection::InProgress),
        ("completed", Some(conclusion), Some(cause)) => {
            let cause = decode_cause(cause)?;
            if github_check_conclusion_name(cause.conclusion()) != conclusion {
                return Err(GithubCheckStoreError::CorruptData);
            }
            Ok(GithubCheckDesiredProjection::terminal(cause))
        }
        _ => Err(GithubCheckStoreError::CorruptData),
    }
}

fn decode_cause(value: &str) -> Result<GithubCheckTerminalCause, GithubCheckStoreError> {
    match value {
        "workflow_success" => Ok(GithubCheckTerminalCause::WorkflowSuccess),
        "workflow_skipped" => Ok(GithubCheckTerminalCause::WorkflowSkipped),
        "workflow_failure" => Ok(GithubCheckTerminalCause::WorkflowFailure),
        "workflow_cancelled" => Ok(GithubCheckTerminalCause::WorkflowCancelled),
        "workflow_timed_out" => Ok(GithubCheckTerminalCause::WorkflowTimedOut),
        "provider_unknown" => Ok(GithubCheckTerminalCause::ProviderUnknown),
        "system_unknown" => Ok(GithubCheckTerminalCause::SystemUnknown),
        _ => Err(GithubCheckStoreError::CorruptData),
    }
}

fn projection_columns(
    projection: GithubCheckDesiredProjection,
) -> (&'static str, Option<&'static str>) {
    match projection {
        GithubCheckDesiredProjection::Queued => ("queued", None),
        GithubCheckDesiredProjection::InProgress => ("in_progress", None),
        GithubCheckDesiredProjection::Terminal(cause) => (
            "completed",
            Some(github_check_conclusion_name(cause.conclusion())),
        ),
    }
}

async fn exact_external_replay(
    pool: &sqlx::PgPool,
    subject_id: automata_ci_store::GithubCheckSubjectId,
    expected_suite: Option<GithubCheckSuiteId>,
    expected_run: Option<GithubCheckRunId>,
) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
    let query = format!(
        r"
        SELECT {SUBJECT_COLUMNS}, outbox.external_suite_id, outbox.external_run_id
        FROM github_check_subjects AS subject
        JOIN github_check_projection_outbox AS outbox ON outbox.subject_id = subject.id
        WHERE subject.id = $1
        "
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(subject_id.as_uuid())
        .fetch_optional(pool)
        .await
        .map_err(operation_error)?
        .ok_or(GithubCheckStoreError::ClaimRejected)?;
    let suite = optional_positive_u64_column(&row, "external_suite_id")?
        .map(GithubCheckSuiteId::new)
        .transpose()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let run = optional_positive_u64_column(&row, "external_run_id")?
        .map(GithubCheckRunId::new)
        .transpose()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    if suite == expected_suite && run == expected_run {
        Ok(decode_subject(&row)?.receipt)
    } else if suite.is_some() || run.is_some() {
        Err(GithubCheckStoreError::ExternalIdentityConflict)
    } else {
        Err(GithubCheckStoreError::ClaimRejected)
    }
}

async fn exact_unissued_release_replay(
    pool: &sqlx::PgPool,
    request: ReleaseUnissuedGithubCheckRunCreate,
) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
    let query = format!(
        r"
        SELECT {SUBJECT_COLUMNS}
        FROM github_check_subjects AS subject
        JOIN github_check_projection_outbox AS outbox ON outbox.subject_id = subject.id
        WHERE subject.id = $1
          AND outbox.create_owner_id IS NULL
          AND outbox.create_fence IS NULL
          AND outbox.create_started_at_ms IS NULL
          AND outbox.create_issue_expires_at_ms IS NULL
          AND outbox.reconcile_not_before_ms IS NULL
          AND outbox.next_reconcile_at_ms IS NULL
          AND outbox.claim_fence = $4
          AND outbox.state_updated_at_ms = $2
          AND (
            outbox.state = 'retry'
            AND outbox.last_failure_kind = 'create_not_issued'
            AND outbox.next_attempt_at_ms = $3
            OR outbox.state = 'blocked'
            AND outbox.blocked_reason = 'attempt_limit'
            AND outbox.attempt_count >= 64
            AND outbox.last_failure_kind IS NULL
            AND outbox.next_attempt_at_ms IS NULL
          )
        "
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(request.fence().claim().subject_id().as_uuid())
        .bind(request.released_at().get())
        .bind(request.retry_at().get())
        .bind(pg_bigint(request.fence().claim().fence()))
        .fetch_optional(pool)
        .await
        .map_err(operation_error)?
        .ok_or(GithubCheckStoreError::ClaimRejected)?;
    Ok(decode_subject(&row)?.receipt)
}

async fn exact_create_reconciliation_replay(
    pool: &sqlx::PgPool,
    request: ResolveGithubCheckRunCreate,
) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
    let (outcome, retry_at) = match request.outcome() {
        GithubCheckCreateReconciliation::Missing => (
            "missing",
            Some(
                request
                    .retry_at()
                    .ok_or(GithubCheckStoreError::CorruptData)?
                    .get(),
            ),
        ),
        GithubCheckCreateReconciliation::Ambiguous => ("ambiguous", None),
    };
    let query = format!(
        r"
        SELECT {SUBJECT_COLUMNS}
        FROM github_check_subjects AS subject
        JOIN github_check_projection_outbox AS outbox ON outbox.subject_id = subject.id
        WHERE subject.id = $1
          AND outbox.claim_fence = $2
          AND outbox.state_updated_at_ms = $3
          AND outbox.create_started_at_ms IS NOT NULL
          AND outbox.external_run_id IS NULL
          AND (
            $4 = 'missing'
            AND outbox.next_reconcile_at_ms = $5
            AND (
                outbox.state = 'create_indeterminate'
                AND outbox.blocked_reason IS NULL
                OR outbox.state = 'blocked'
                AND outbox.blocked_reason = 'attempt_limit'
                AND outbox.attempt_count >= 64
            )
            OR $4 = 'ambiguous'
            AND outbox.state = 'blocked'
            AND outbox.blocked_reason = 'ambiguous_create'
          )
        "
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(request.claim().subject_id().as_uuid())
        .bind(pg_bigint(request.claim().fence()))
        .bind(request.observed_at().get())
        .bind(outcome)
        .bind(retry_at)
        .fetch_optional(pool)
        .await
        .map_err(operation_error)?
        .ok_or(GithubCheckStoreError::ClaimRejected)?;
    Ok(decode_subject(&row)?.receipt)
}

async fn load_projection_replay(
    pool: &sqlx::PgPool,
    subject_id: automata_ci_store::GithubCheckSubjectId,
    expected_state: &str,
    expected_conclusion: Option<&str>,
) -> Result<Option<GithubCheckSubjectReceipt>, GithubCheckStoreError> {
    let query = format!(
        r"
        SELECT {SUBJECT_COLUMNS}, outbox.state AS outbox_state,
               outbox.provider_state, outbox.provider_conclusion
        FROM github_check_subjects AS subject
        JOIN github_check_projection_outbox AS outbox ON outbox.subject_id = subject.id
        WHERE subject.id = $1
        "
    );
    let Some(row) = sqlx::query(AssertSqlSafe(query))
        .bind(subject_id.as_uuid())
        .fetch_optional(pool)
        .await
        .map_err(operation_error)?
    else {
        return Ok(None);
    };
    let state: String = row.try_get("outbox_state").map_err(operation_error)?;
    let provider_state: Option<String> = row.try_get("provider_state").map_err(operation_error)?;
    let provider_conclusion: Option<String> = row
        .try_get("provider_conclusion")
        .map_err(operation_error)?;
    if state == "delivered"
        && provider_state.as_deref() == Some(expected_state)
        && provider_conclusion.as_deref() == expected_conclusion
    {
        Ok(Some(decode_subject(&row)?.receipt))
    } else {
        Ok(None)
    }
}

fn decode_projection_origin(
    row: &sqlx::postgres::PgRow,
) -> Result<ProjectionSubjectOrigin, GithubCheckStoreError> {
    match row
        .try_get::<String, _>("origin_kind")
        .map_err(operation_error)?
        .as_str()
    {
        "provider_delivery" => Ok(ProjectionSubjectOrigin::ProviderDelivery),
        "scheduled_fire" => Ok(ProjectionSubjectOrigin::ScheduledFire),
        "workflow_rerun" => Ok(ProjectionSubjectOrigin::WorkflowRerun),
        _ => Err(GithubCheckStoreError::CorruptData),
    }
}

async fn claim_locked_projection(
    transaction: &mut Transaction<'_, Postgres>,
    request: ClaimGithubCheckProjection,
    candidate_id: Uuid,
    origin: ProjectionSubjectOrigin,
    lock_observed_at: i64,
    claim_duration: i64,
) -> Result<ClaimedGithubCheckProjection, GithubCheckStoreError> {
    // Issue the interval after locking the exact row, then recheck caller
    // admission and due/takeover eligibility in the fenced update.
    let claimed_at = database_now_ms(&mut *transaction).await?;
    if claimed_at < lock_observed_at {
        return Err(GithubCheckStoreError::CorruptData);
    }
    validate_caller_clock(request.observed_at(), claimed_at)?;
    let expires_at = claimed_at
        .checked_add(claim_duration)
        .ok_or(GithubCheckStoreError::CorruptData)?;
    let claim_sql = match origin {
        ProjectionSubjectOrigin::ProviderDelivery => CLAIM_LOCKED_DELIVERY_PROJECTION_SQL,
        ProjectionSubjectOrigin::ScheduledFire => CLAIM_LOCKED_SCHEDULE_PROJECTION_SQL,
        ProjectionSubjectOrigin::WorkflowRerun => CLAIM_LOCKED_RERUN_PROJECTION_SQL,
    };
    let row = sqlx::query(claim_sql)
        .bind(candidate_id)
        .bind(request.connection_id().as_uuid())
        .bind(request.owner().as_uuid())
        .bind(claimed_at)
        .bind(expires_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .ok_or(GithubCheckStoreError::CorruptData)?;
    decode_claimed(&row, request.owner())
}

async fn projection_fence_exhausted(
    transaction: &mut Transaction<'_, Postgres>,
    connection_id: ProviderConnectionId,
    database_now: i64,
) -> Result<bool, GithubCheckStoreError> {
    sqlx::query_scalar(PROJECTION_FENCE_EXHAUSTED_SQL)
        .bind(connection_id.as_uuid())
        .bind(database_now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(operation_error)
}

async fn block_exhausted_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    connection_id: ProviderConnectionId,
    database_now: i64,
) -> Result<(), GithubCheckStoreError> {
    sqlx::query(BLOCK_EXHAUSTED_CANDIDATES_SQL)
        .bind(connection_id.as_uuid())
        .bind(database_now)
        .execute(&mut **transaction)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn lock_live_annotation_publish_claim(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubCheckProjectionClaimFence,
    observed_at: UnixMillis,
) -> Result<(), GithubCheckStoreError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT subject_id
        FROM github_check_projection_outbox
        WHERE subject_id = $1
          AND state = 'claimed'
          AND claim_owner_id = $2
          AND claim_fence = $3
          AND claim_action = 'publish'
          AND claimed_at_ms <= $4
          AND claim_expires_at_ms > $4
        FOR UPDATE
        ",
    )
    .bind(claim.subject_id().as_uuid())
    .bind(claim.owner().as_uuid())
    .bind(pg_bigint(claim.fence()))
    .bind(observed_at.get())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    locked
        .map(|_| ())
        .ok_or(GithubCheckStoreError::ClaimRejected)
}

async fn lock_exact_annotation_batch(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubCheckProjectionClaimFence,
    digest: Sha256Digest,
    from: u16,
    batch_size: u8,
) -> Result<(), GithubCheckStoreError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        r"
        SELECT subject_id
        FROM github_check_annotation_progress
        WHERE subject_id = $1
          AND presentation_digest = $2
          AND annotation_next = $3
          AND uncertain_batch_size = $4
        FOR UPDATE
        ",
    )
    .bind(claim.subject_id().as_uuid())
    .bind(digest.as_bytes().as_slice())
    .bind(i32::from(from))
    .bind(i16::from(batch_size))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(operation_error)?;
    locked
        .map(|_| ())
        .ok_or(GithubCheckStoreError::ProjectionMismatch)
}

async fn retry_live_annotation_publish_claim(
    transaction: &mut Transaction<'_, Postgres>,
    claim: GithubCheckProjectionClaimFence,
    observed_at: UnixMillis,
    retry_at: UnixMillis,
    failure_kind: &str,
) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
    let query = format!(
        r"
        UPDATE github_check_projection_outbox AS outbox
        SET state = CASE WHEN attempt_count >= 64 THEN 'blocked' ELSE 'retry' END,
            next_attempt_at_ms = CASE WHEN attempt_count >= 64 THEN NULL ELSE $5 END,
            last_failure_kind = CASE WHEN attempt_count >= 64 THEN NULL ELSE $6 END,
            blocked_reason = CASE WHEN attempt_count >= 64 THEN 'attempt_limit' ELSE NULL END,
            claim_owner_id = NULL, claim_action = NULL,
            claimed_desired_revision = NULL, claimed_desired_state = NULL,
            claimed_desired_conclusion = NULL,
            claimed_at_ms = NULL, claim_expires_at_ms = NULL,
            state_updated_at_ms = $4
        FROM github_check_subjects AS subject
        WHERE outbox.subject_id = $1
          AND subject.id = outbox.subject_id
          AND outbox.state = 'claimed'
          AND outbox.claim_owner_id = $2
          AND outbox.claim_fence = $3
          AND outbox.claim_action = 'publish'
          AND outbox.claimed_at_ms <= $4
          AND outbox.claim_expires_at_ms > $4
        RETURNING {SUBJECT_COLUMNS}
        "
    );
    let row = sqlx::query(AssertSqlSafe(query))
        .bind(claim.subject_id().as_uuid())
        .bind(claim.owner().as_uuid())
        .bind(pg_bigint(claim.fence()))
        .bind(observed_at.get())
        .bind(retry_at.get())
        .bind(failure_kind)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?;
    row.map(|row| decode_subject(&row).map(|subject| subject.receipt))
        .transpose()?
        .ok_or(GithubCheckStoreError::ClaimRejected)
}

async fn pin_read_committed(connection: &mut PgConnection) -> Result<(), GithubCheckStoreError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(connection)
        .await
        .map_err(operation_error)?;
    Ok(())
}

async fn database_now_ms(connection: &mut PgConnection) -> Result<i64, GithubCheckStoreError> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(connection)
            .await
            .map_err(operation_error)?;
    if database_now < 0 {
        return Err(GithubCheckStoreError::CorruptData);
    }
    Ok(database_now)
}

fn validate_caller_clock(
    observed_at: UnixMillis,
    database_now: i64,
) -> Result<(), GithubCheckStoreError> {
    if observed_at.get()
        < database_now.saturating_sub(MAX_GITHUB_CHECK_PROJECTION_CLOCK_SKEW_MILLIS)
        || observed_at.get()
            > database_now.saturating_add(MAX_GITHUB_CHECK_PROJECTION_CLOCK_SKEW_MILLIS)
    {
        return Err(GithubCheckStoreError::ClaimRejected);
    }
    Ok(())
}

fn requested_claim_duration(
    request: ClaimGithubCheckProjection,
) -> Result<i64, GithubCheckStoreError> {
    request
        .expires_at()
        .get()
        .checked_sub(request.observed_at().get())
        .filter(|duration| *duration > 0)
        .ok_or(GithubCheckStoreError::ClaimRejected)
}

fn uuid_column(row: &sqlx::postgres::PgRow, column: &str) -> Result<Uuid, GithubCheckStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn optional_uuid_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Option<Uuid>, GithubCheckStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn string_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<String, GithubCheckStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn bytes_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Vec<u8>, GithubCheckStoreError> {
    row.try_get(column).map_err(operation_error)
}

fn sha256_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Sha256Digest, GithubCheckStoreError> {
    let bytes: [u8; 32] = bytes_column(row, column)?
        .try_into()
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_job_result_descriptor(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<BlobDescriptor>, GithubCheckStoreError> {
    let schema: Option<i32> = row.try_get("job_result_schema").map_err(operation_error)?;
    let size: Option<i64> = row
        .try_get("job_result_size_bytes")
        .map_err(operation_error)?;
    let digest: Option<Vec<u8>> = row.try_get("job_result_digest").map_err(operation_error)?;
    let object_key: Option<String> = row
        .try_get("job_result_object_key")
        .map_err(operation_error)?;
    match (schema, size, digest, object_key) {
        (None, None, None, None) => Ok(None),
        (Some(1), Some(size), Some(digest), Some(object_key)) => {
            let size = u64::try_from(size)
                .ok()
                .filter(|size| (1..=MAX_TERMINAL_RESULT_BYTES).contains(size))
                .ok_or(GithubCheckStoreError::CorruptData)?;
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| GithubCheckStoreError::CorruptData)?;
            let key = BlobKey::new(object_key).map_err(|_| GithubCheckStoreError::CorruptData)?;
            let media_type = MediaType::new(HUMAN_JOB_RESULT_MEDIA_TYPE)
                .map_err(|_| GithubCheckStoreError::CorruptData)?;
            Ok(Some(BlobDescriptor::new(
                key,
                Sha256Digest::from_bytes(digest),
                size,
                media_type,
            )))
        }
        _ => Err(GithubCheckStoreError::CorruptData),
    }
}

fn decode_annotation_progress(
    row: &sqlx::postgres::PgRow,
) -> Result<GithubCheckAnnotationProgress, GithubCheckStoreError> {
    let digest: Option<Vec<u8>> = row
        .try_get("annotation_presentation_digest")
        .map_err(operation_error)?;
    let total: Option<i32> = row.try_get("annotation_total").map_err(operation_error)?;
    let next: Option<i32> = row.try_get("annotation_next").map_err(operation_error)?;
    let uncertain: Option<i16> = row
        .try_get("annotation_uncertain_batch_size")
        .map_err(operation_error)?;
    match (digest, total, next) {
        (None, None, None) if uncertain.is_none() => Ok(GithubCheckAnnotationProgress::default()),
        (Some(digest), Some(total), Some(next)) => {
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| GithubCheckStoreError::CorruptData)?;
            GithubCheckAnnotationProgress::from_durable_parts(
                Some(Sha256Digest::from_bytes(digest)),
                u16::try_from(total).map_err(|_| GithubCheckStoreError::CorruptData)?,
                u16::try_from(next).map_err(|_| GithubCheckStoreError::CorruptData)?,
                uncertain
                    .map(u8::try_from)
                    .transpose()
                    .map_err(|_| GithubCheckStoreError::CorruptData)?,
            )
            .map_err(|_| GithubCheckStoreError::CorruptData)
        }
        _ => Err(GithubCheckStoreError::CorruptData),
    }
}

fn positive_u64_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<u64, GithubCheckStoreError> {
    let value: i64 = row.try_get(column).map_err(operation_error)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubCheckStoreError::CorruptData)
}

fn optional_positive_u64_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Option<u64>, GithubCheckStoreError> {
    let value: Option<i64> = row.try_get(column).map_err(operation_error)?;
    value
        .map(|value| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or(GithubCheckStoreError::CorruptData)
        })
        .transpose()
}

fn positive_u16_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<u16, GithubCheckStoreError> {
    let value: i16 = row.try_get(column).map_err(operation_error)?;
    u16::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS).contains(value))
        .ok_or(GithubCheckStoreError::CorruptData)
}

fn unix_millis_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<UnixMillis, GithubCheckStoreError> {
    let value: i64 = row.try_get(column).map_err(operation_error)?;
    if value < 0 {
        return Err(GithubCheckStoreError::CorruptData);
    }
    Ok(UnixMillis::new(value))
}

fn optional_unix_millis_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> Result<Option<UnixMillis>, GithubCheckStoreError> {
    let value: Option<i64> = row.try_get(column).map_err(operation_error)?;
    value
        .map(|value| {
            if value < 0 {
                Err(GithubCheckStoreError::CorruptData)
            } else {
                Ok(UnixMillis::new(value))
            }
        })
        .transpose()
}

fn operation_error(error: sqlx::Error) -> GithubCheckStoreError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        == Some("github_check_projection_external_run_unique")
    {
        return GithubCheckStoreError::ExternalIdentityConflict;
    }
    GithubCheckStoreError::operation(error)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[rustfmt::skip]
    const PROJECTION_SQL: [&str; 6] = [LOCK_PROJECTION_CANDIDATE_SQL, CLAIM_LOCKED_DELIVERY_PROJECTION_SQL, CLAIM_LOCKED_SCHEDULE_PROJECTION_SQL, CLAIM_LOCKED_RERUN_PROJECTION_SQL, PROJECTION_FENCE_EXHAUSTED_SQL, BLOCK_EXHAUSTED_CANDIDATES_SQL];
    #[rustfmt::skip]
    const FINGERPRINTS: [(usize, &str, usize, &str); 6] = [
        (4159, "691859128cd03244c477255920adc51ea2c649cf06f9040d1fa0f14f1d5e7e5c", 2992, "3210a2469eb3f703ab710fea0013c58bb79ec9ae9f536f3c74a561803ca77bcb"),
        (6285, "bace26ab71eddd1fd8a26bfae37e7254e5fd20d468abf4d4f8930d0eb2596a38", 5118, "6b2fecb3ad8d196f5539467fc0fdda38e2265568351272fe1099729ec8dde866"),
        (5241, "b8fdd9e95c5856d800e80eb88f154ba13c2ccef7d2ee307049d648f4e709917d", 4384, "73737d04020eec9ac84c84d57f5ef7e40f6a393810451720e3405fbe31beefa5"),
        (5278, "c3d9e042cca7c7183d7398087cd873aa7a353e1d1deff98f9b529cb3337d62c3", 4415, "743b5543234e7e8c898976c9a7ad8dc1a359afe3041b8deb67495f8811040fad"),
        (4244, "40d9d6a2235070d9ee8d005649f82be97a89cfd8a6694cd7ae918b34c65b8602", 2593, "e9f89a3d82dbe3739d4562daad4bb3d736fc47fa8df77a2fe961ea8f0ed0a251"),
        (4402, "fa051bb08fde7acb32390dc421db6d14ca07b651b9df8ef5e02ac11bd9512bc8", 2939, "e926232caf0c5ca982cd0281d572418864d3c4a61cb70cb427808f4c225122a6"),
    ];

    #[test]
    fn projection_sql_fingerprints_are_stable() {
        for (index, sql) in PROJECTION_SQL.into_iter().enumerate() {
            let (raw_len, raw_sha, canonical_len, canonical_sha) = FINGERPRINTS[index];
            assert_eq!((sql.len(), sha256(sql)), (raw_len, raw_sha.to_owned()));
            let canonical = canonical_sql(sql);
            assert_eq!(
                (canonical.len(), sha256(&canonical)),
                (canonical_len, canonical_sha.to_owned())
            );
        }
    }

    #[rustfmt::skip]
    #[test]
    fn projection_origin_authority_is_shared() {
        let canonical = [LOCK_PROJECTION_CANDIDATE_SQL, PROJECTION_FENCE_EXHAUSTED_SQL, BLOCK_EXHAUSTED_CANDIDATES_SQL]
            .map(|sql| canonical_sql(origin_authority(sql)));
        assert!(canonical.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!((canonical[0].len(), sha256(&canonical[0])),
            (2118, "793e9a4664128465995c1c1957f4f2e73dce82a8bda586468474caf2800330c2".to_owned()));
    }

    #[test]
    fn placeholders_and_returning_projection_are_preserved() {
        #[rustfmt::skip]
        let expected: [&[u8]; 6] = [
            &[1, 2, 2, 2][..], &[3, 4, 5, 4, 1, 2, 4, 4, 4], &[3, 4, 5, 4, 1, 2, 4, 4, 4],
            &[3, 4, 5, 4, 1, 2, 4, 4, 4], &[1, 2, 2, 2], &[2, 1, 2, 2, 2],
        ];
        for (sql, expected) in PROJECTION_SQL.into_iter().zip(expected) {
            assert_eq!(placeholder_sequence(sql), expected);
        }
        let returning = [
            CLAIM_LOCKED_DELIVERY_PROJECTION_SQL,
            CLAIM_LOCKED_SCHEDULE_PROJECTION_SQL,
            CLAIM_LOCKED_RERUN_PROJECTION_SQL,
        ]
        .map(|sql| {
            sql.split_once("    RETURNING\n")
                .expect("claim RETURNING")
                .1
        });
        assert!(returning.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(returning[0].split(',').count(), 50);
    }

    #[test]
    fn claims_keep_closed_origin_evidence_and_null_guards() {
        #[rustfmt::skip]
        let cases = [
            (CLAIM_LOCKED_DELIVERY_PROJECTION_SQL, "provider_delivery", "github_provider_delivery_evidence", &["schedule_fire_id"][..], &["provider_delivery_id", "workflow_rerun_run_id"][..]),
            (CLAIM_LOCKED_SCHEDULE_PROJECTION_SQL, "scheduled_fire", "github_schedule_check_evidence", &["provider_delivery_id"][..], &["schedule_fire_id", "workflow_rerun_run_id"][..]),
            (CLAIM_LOCKED_RERUN_PROJECTION_SQL, "workflow_rerun", "workflow_rerun_check_evidence", &["provider_delivery_id", "schedule_fire_id"][..], &["workflow_rerun_run_id"][..]),
        ];
        for (sql, origin, evidence, required_nulls, forbidden_nulls) in cases {
            assert!(sql.contains(&format!("subject.origin_kind = '{origin}'")));
            assert!(sql.contains(&format!("{evidence} AS evidence")));
            assert!(
                required_nulls
                    .iter()
                    .all(|field| sql.contains(&format!("subject.{field} IS NULL")))
            );
            assert!(
                forbidden_nulls
                    .iter()
                    .all(|field| !sql.contains(&format!("subject.{field} IS NULL")))
            );
        }
    }

    fn sha256(value: &str) -> String {
        Sha256Digest::from_bytes(Sha256::digest(value.as_bytes()).into()).to_string()
    }

    fn canonical_sql(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn origin_authority(sql: &str) -> &str {
        let start = sql.find("CASE subject.origin_kind").expect("origin CASE");
        let end = sql[start..].find("ELSE FALSE").expect("closed origin CASE") + start;
        let end = sql[end..].find("END").expect("origin CASE end") + end + "END".len();
        &sql[start..end]
    }

    #[rustfmt::skip]
    fn placeholder_sequence(sql: &str) -> Vec<u8> {
        sql.as_bytes().windows(2).filter(|pair| pair[0] == b'$' && pair[1].is_ascii_digit()).map(|pair| pair[1] - b'0').collect()
    }
}
