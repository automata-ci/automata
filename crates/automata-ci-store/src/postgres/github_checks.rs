use async_trait::async_trait;
use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use sqlx::{AssertSqlSafe, PgConnection, Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::{
    BeginGithubCheckRunCreate, BindGithubCheckRun, BindGithubCheckSuite,
    ClaimGithubCheckProjection, ClaimedGithubCheckProjection, CompleteGithubCheckProjection,
    GithubCheckAppId, GithubCheckCreateReconciliation, GithubCheckDesiredProjection,
    GithubCheckHeadSha, GithubCheckName, GithubCheckProjectionAction,
    GithubCheckProjectionClaimFence, GithubCheckProjectionOutbox, GithubCheckProjectionWorkerId,
    GithubCheckRunBindingFence, GithubCheckRunCreateFence, GithubCheckRunId, GithubCheckStoreError,
    GithubCheckSubjectIdentity, GithubCheckSubjectKey, GithubCheckSubjectReceipt,
    GithubCheckSubjectRepository, GithubCheckSubjectTarget, GithubCheckSuiteId,
    GithubCheckTerminalCause, GithubCheckTerminalizationRepository, GithubRepositoryName,
    GithubScheduleFireId, GithubServerServiceAuthorityId, GithubServerServiceAuthoritySelector,
    GithubServerServiceRevision, LinkGithubCheckWorkflowRun, MAX_GITHUB_CHECK_PROJECTION_ATTEMPTS,
    ProviderConnectionId, ProviderDeliveryId, ProviderInstallationId, ProviderRepositoryId,
    RegisterGithubCheckSubject, ReleaseUnissuedGithubCheckRunCreate, RepositoryId,
    ResolveGithubCheckRunCreate, RetryGithubCheckProjection, StartGithubCheckProjection,
    TenantScope, TerminalizeGithubCheck,
};

use super::PostgresStore;

// A caller clock is useful only as bounded admission evidence. Durable claim
// eligibility and every absolute fence time are issued from PostgreSQL after
// any preceding lock wait.
const MAX_GITHUB_CHECK_PROJECTION_CLOCK_SKEW_MILLIS: i64 = 60_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProjectionSubjectOrigin {
    ProviderDelivery,
    ScheduledFire,
}

pub(super) const SUBJECT_COLUMNS: &str = r"
    subject.id, subject.tenant_id, subject.repository_id,
    subject.origin_kind, subject.provider_delivery_id, subject.schedule_fire_id,
    subject.subject_key,
    subject.provider_connection_id, subject.provider_installation_id,
    subject.github_repository_id, subject.github_repository_name,
    subject.github_app_id, subject.head_sha,
    subject.check_name, subject.external_id, subject.workflow_run_id,
    subject.linked_at_ms,
    subject.desired_state, subject.desired_conclusion, subject.terminal_cause,
    subject.desired_revision, subject.created_at_ms, subject.desired_updated_at_ms
";

const LOCK_PROJECTION_CANDIDATE_SQL: &str = r"
    SELECT outbox.subject_id, subject.origin_kind
    FROM github_check_projection_outbox AS outbox
    JOIN github_check_subjects AS subject
      ON subject.id = outbox.subject_id
    WHERE subject.provider_connection_id = $1
      AND CASE subject.origin_kind
        WHEN 'provider_delivery' THEN EXISTS (
            SELECT 1
            FROM github_provider_delivery_evidence AS delivery_evidence
            WHERE delivery_evidence.github_check_subject_id = subject.id
              AND delivery_evidence.provider_delivery_id = subject.provider_delivery_id
              AND delivery_evidence.tenant_id = subject.tenant_id
              AND delivery_evidence.repository_id = subject.repository_id
        )
        WHEN 'scheduled_fire' THEN EXISTS (
            SELECT 1
            FROM github_schedule_check_evidence AS schedule_evidence
            WHERE schedule_evidence.github_check_subject_id = subject.id
              AND schedule_evidence.schedule_fire_id = subject.schedule_fire_id
              AND schedule_evidence.tenant_id = subject.tenant_id
              AND schedule_evidence.repository_id = subject.repository_id
              AND schedule_evidence.provider_connection_id =
                  subject.provider_connection_id
        )
        ELSE FALSE
      END
      AND outbox.claim_fence < 9223372036854775807
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
";

const CLAIM_LOCKED_DELIVERY_PROJECTION_SQL: &str = r"
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
    FROM github_check_subjects AS subject,
         github_provider_delivery_evidence AS evidence
    WHERE outbox.subject_id = $1
      AND subject.id = outbox.subject_id
      AND subject.origin_kind = 'provider_delivery'
      AND subject.schedule_fire_id IS NULL
      AND subject.provider_connection_id = $2
      AND evidence.github_check_subject_id = subject.id
      AND evidence.provider_delivery_id = subject.provider_delivery_id
      AND evidence.tenant_id = subject.tenant_id
      AND evidence.repository_id = subject.repository_id
      AND outbox.claim_fence < 9223372036854775807
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
        subject.schedule_fire_id, subject.subject_key,
        subject.provider_connection_id, subject.provider_installation_id,
        subject.github_repository_id, subject.github_repository_name,
        subject.github_app_id, subject.head_sha,
        subject.check_name, subject.external_id, subject.workflow_run_id,
        subject.linked_at_ms,
        subject.desired_state, subject.desired_conclusion, subject.terminal_cause,
        subject.desired_revision, subject.created_at_ms,
        subject.desired_updated_at_ms,
        evidence.checks_authority_id,
        evidence.checks_authority_identity_digest,
        evidence.checks_authority_app_configuration_revision,
        evidence.checks_authority_policy_revision
";

const CLAIM_LOCKED_SCHEDULE_PROJECTION_SQL: &str = r"
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
    FROM github_check_subjects AS subject,
         github_schedule_check_evidence AS evidence
    WHERE outbox.subject_id = $1
      AND subject.id = outbox.subject_id
      AND subject.origin_kind = 'scheduled_fire'
      AND subject.provider_delivery_id IS NULL
      AND subject.provider_connection_id = $2
      AND evidence.github_check_subject_id = subject.id
      AND evidence.schedule_fire_id = subject.schedule_fire_id
      AND evidence.tenant_id = subject.tenant_id
      AND evidence.repository_id = subject.repository_id
      AND evidence.provider_connection_id = subject.provider_connection_id
      AND outbox.claim_fence < 9223372036854775807
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
        subject.schedule_fire_id, subject.subject_key,
        subject.provider_connection_id, subject.provider_installation_id,
        subject.github_repository_id, subject.github_repository_name,
        subject.github_app_id, subject.head_sha,
        subject.check_name, subject.external_id, subject.workflow_run_id,
        subject.linked_at_ms,
        subject.desired_state, subject.desired_conclusion, subject.terminal_cause,
        subject.desired_revision, subject.created_at_ms,
        subject.desired_updated_at_ms,
        evidence.checks_authority_id,
        evidence.checks_authority_identity_digest,
        evidence.checks_authority_app_configuration_revision,
        evidence.checks_authority_policy_revision
";

#[async_trait]
impl GithubCheckSubjectRepository for PostgresStore {
    async fn register_github_check_subject(
        &self,
        request: RegisterGithubCheckSubject,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let delivery_id = request
            .identity()
            .delivery_id()
            .ok_or(GithubCheckStoreError::AuthorityRejected)?;
        let mut transaction = self.pool.begin().await.map_err(operation_error)?;
        let proposed_id = Uuid::new_v4();
        let external_id = format!("automata-check:{proposed_id}");
        let query = format!(
            r"
            INSERT INTO github_check_subjects AS subject (
                id, tenant_id, repository_id, provider_delivery_id, subject_key,
                provider_connection_id, provider_installation_id,
                github_repository_id, github_app_id, head_sha, check_name,
                external_id, created_at_ms, desired_updated_at_ms
            )
            SELECT
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13
            FROM provider_delivery_inbox AS delivery
            JOIN repositories AS repository
              ON repository.id = $3
             AND repository.tenant_id = $2
             AND repository.scm_provider = 'github'
             AND repository.provider_repository_id = $8::TEXT
            WHERE delivery.id = $4
              AND delivery.tenant_id = $2
              AND delivery.provider = 'github'
              AND delivery.connection_id = $6
              AND delivery.installation_id = $7
              AND delivery.provider_repository_id = $8
              AND delivery.repository_identity = $14
              AND repository.owner || '/' || repository.name = $14
            ON CONFLICT (provider_delivery_id, subject_key) DO NOTHING
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let inserted = sqlx::query(AssertSqlSafe(query))
            .bind(proposed_id)
            .bind(request.identity().tenant().as_str())
            .bind(request.identity().repository_id().as_uuid())
            .bind(delivery_id.as_uuid())
            .bind(request.identity().subject_key().as_str())
            .bind(request.identity().connection_id().as_uuid())
            .bind(request.identity().installation_id().as_i64())
            .bind(request.identity().github_repository_id().as_i64())
            .bind(request.identity().app_id().as_i64())
            .bind(request.identity().head_sha().as_bytes().as_slice())
            .bind(request.identity().name().as_str())
            .bind(&external_id)
            .bind(request.created_at().get())
            .bind(request.identity().github_repository_name().as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(operation_error)?;

        if let Some(row) = inserted {
            let durable = decode_subject(&row)?;
            transaction.commit().await.map_err(operation_error)?;
            return Ok(durable.receipt);
        }

        let existing = load_subject_by_replay_key(
            &mut transaction,
            delivery_id,
            request.identity().subject_key(),
        )
        .await?;
        let Some(existing) = existing else {
            return Err(GithubCheckStoreError::AuthorityRejected);
        };
        if existing.identity != *request.identity() || existing.created_at != request.created_at() {
            return Err(GithubCheckStoreError::ReplayConflict);
        }
        transaction.commit().await.map_err(operation_error)?;
        Ok(existing.receipt)
    }

    async fn link_github_check_workflow_run(
        &self,
        request: LinkGithubCheckWorkflowRun,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            WITH locked_run AS MATERIALIZED (
                SELECT id, repository_id, head_sha
                FROM workflow_runs
                WHERE id = $3 AND status IN ('queued', 'in_progress')
                FOR UPDATE
            )
            UPDATE github_check_subjects AS subject
            SET workflow_run_id = $3, linked_at_ms = $4
            FROM locked_run AS run
            WHERE subject.id = $1
              AND subject.tenant_id = $2
              AND subject.workflow_run_id IS NULL
              AND run.id = $3
              AND run.repository_id = subject.repository_id
              AND run.head_sha = subject.head_sha
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.target().subject_id().as_uuid())
            .bind(request.target().tenant().as_str())
            .bind(request.run_id().as_uuid())
            .bind(request.linked_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        let existing = load_subject(&self.pool, request.target()).await?;
        match existing {
            Some(existing)
                if existing.receipt.workflow_run_id() == Some(request.run_id())
                    && existing.linked_at == Some(request.linked_at()) =>
            {
                Ok(existing.receipt)
            }
            Some(existing) if existing.receipt.workflow_run_id().is_none() => {
                Err(GithubCheckStoreError::AuthorityRejected)
            }
            Some(_) => Err(GithubCheckStoreError::TransitionConflict),
            None => Err(GithubCheckStoreError::NotFound),
        }
    }

    async fn start_github_check_projection(
        &self,
        request: StartGithubCheckProjection,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            UPDATE github_check_subjects AS subject
            SET desired_state = 'in_progress',
                desired_revision = desired_revision + 1,
                desired_updated_at_ms = $3
            WHERE id = $1
              AND tenant_id = $2
              AND desired_state = 'queued'
              AND desired_updated_at_ms <= $3
              AND desired_revision < 9223372036854775807
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.target().subject_id().as_uuid())
            .bind(request.target().tenant().as_str())
            .bind(request.started_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        exact_desired_replay(
            &self.pool,
            request.target(),
            GithubCheckDesiredProjection::InProgress,
            request.started_at(),
        )
        .await
    }
}

#[async_trait]
impl GithubCheckTerminalizationRepository for PostgresStore {
    async fn terminalize_github_check(
        &self,
        request: TerminalizeGithubCheck,
    ) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
        let query = format!(
            r"
            UPDATE github_check_subjects AS subject
            SET desired_state = 'completed',
                desired_conclusion = $3,
                terminal_cause = $4,
                desired_revision = desired_revision + 1,
                desired_updated_at_ms = $5
            WHERE id = $1
              AND tenant_id = $2
              AND desired_state IN ('queued', 'in_progress')
              AND desired_updated_at_ms <= $5
              AND desired_revision < 9223372036854775807
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.target().subject_id().as_uuid())
            .bind(request.target().tenant().as_str())
            .bind(request.conclusion().as_str())
            .bind(request.cause().as_str())
            .bind(request.terminal_at().get())
            .fetch_optional(&self.pool)
            .await
            .map_err(operation_error)?;
        if let Some(row) = row {
            return Ok(decode_subject(&row)?.receipt);
        }
        exact_desired_replay(
            &self.pool,
            request.target(),
            GithubCheckDesiredProjection::terminal(request.cause()),
            request.terminal_at(),
        )
        .await
    }
}

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
            .bind(request.claim().fence_i64())
            .bind(request.suite_id().as_i64())
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
        .bind(request.claim().fence_i64())
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
        .bind(request.claim().fence_i64())
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
            .bind(fence.claim().fence_i64())
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
            .bind(claim.fence_i64())
            .bind(request.suite_id().as_i64())
            .bind(request.run_id().as_i64())
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
            .bind(request.claim().fence_i64())
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
            RETURNING {SUBJECT_COLUMNS}
            "
        );
        let row = sqlx::query(AssertSqlSafe(query))
            .bind(request.claim().subject_id().as_uuid())
            .bind(request.claim().owner().as_uuid())
            .bind(request.claim().fence_i64())
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
            .bind(request.claim().fence_i64())
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
    pub(super) linked_at: Option<UnixMillis>,
    pub(super) desired_updated_at: UnixMillis,
}

pub(super) fn decode_subject(
    row: &sqlx::postgres::PgRow,
) -> Result<DecodedSubject, GithubCheckStoreError> {
    let subject_id = crate::GithubCheckSubjectId::from_uuid(uuid_column(row, "id")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
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
    let head_sha = GithubCheckHeadSha::try_from_slice(&bytes_column(row, "head_sha")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let name = GithubCheckName::new(string_column(row, "check_name")?)
        .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let identity = match (origin_kind.as_str(), delivery_id, schedule_fire_id) {
        ("provider_delivery", Some(delivery_id), None) => GithubCheckSubjectIdentity::new(
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
        ("scheduled_fire", None, Some(fire_id)) => GithubCheckSubjectIdentity::new_scheduled(
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
        _ => return Err(GithubCheckStoreError::CorruptData),
    }
    .map_err(|_| GithubCheckStoreError::CorruptData)?;
    let workflow_run_id = optional_uuid_column(row, "workflow_run_id")?.map(RunId::from_uuid);
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
    let linked_at = optional_unix_millis_column(row, "linked_at_ms")?;
    let desired_updated_at = unix_millis_column(row, "desired_updated_at_ms")?;
    Ok(DecodedSubject {
        identity,
        receipt,
        created_at,
        linked_at,
        desired_updated_at,
    })
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
    ClaimedGithubCheckProjection::from_durable_parts(
        claim,
        action,
        attempts,
        subject.identity,
        checks_authority,
        subject.receipt.external_id().to_owned(),
        subject.receipt.desired(),
        subject.receipt.desired_revision(),
        suite_id,
        run_id,
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
            if cause.conclusion().as_str() != conclusion {
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
        GithubCheckDesiredProjection::Terminal(cause) => {
            ("completed", Some(cause.conclusion().as_str()))
        }
    }
}

async fn load_subject(
    pool: &sqlx::PgPool,
    target: &GithubCheckSubjectTarget,
) -> Result<Option<DecodedSubject>, GithubCheckStoreError> {
    let query = format!(
        "SELECT {SUBJECT_COLUMNS} FROM github_check_subjects AS subject WHERE subject.id = $1 AND subject.tenant_id = $2"
    );
    sqlx::query(AssertSqlSafe(query))
        .bind(target.subject_id().as_uuid())
        .bind(target.tenant().as_str())
        .fetch_optional(pool)
        .await
        .map_err(operation_error)?
        .map(|row| decode_subject(&row))
        .transpose()
}

async fn load_subject_by_replay_key(
    transaction: &mut Transaction<'_, Postgres>,
    delivery_id: ProviderDeliveryId,
    subject_key: &GithubCheckSubjectKey,
) -> Result<Option<DecodedSubject>, GithubCheckStoreError> {
    let query = format!(
        "SELECT {SUBJECT_COLUMNS} FROM github_check_subjects AS subject WHERE subject.provider_delivery_id = $1 AND subject.subject_key = $2 FOR UPDATE"
    );
    sqlx::query(AssertSqlSafe(query))
        .bind(delivery_id.as_uuid())
        .bind(subject_key.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(operation_error)?
        .map(|row| decode_subject(&row))
        .transpose()
}

async fn exact_desired_replay(
    pool: &sqlx::PgPool,
    target: &GithubCheckSubjectTarget,
    expected: GithubCheckDesiredProjection,
    expected_at: UnixMillis,
) -> Result<GithubCheckSubjectReceipt, GithubCheckStoreError> {
    let existing = load_subject(pool, target).await?;
    match existing {
        Some(existing)
            if existing.receipt.desired() == expected
                && existing.desired_updated_at == expected_at =>
        {
            Ok(existing.receipt)
        }
        Some(_) => Err(GithubCheckStoreError::TransitionConflict),
        None => Err(GithubCheckStoreError::NotFound),
    }
}

async fn exact_external_replay(
    pool: &sqlx::PgPool,
    subject_id: crate::GithubCheckSubjectId,
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
        .bind(request.fence().claim().fence_i64())
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
        .bind(request.claim().fence_i64())
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
    subject_id: crate::GithubCheckSubjectId,
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
    sqlx::query_scalar(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM github_check_projection_outbox AS outbox
            JOIN github_check_subjects AS subject ON subject.id = outbox.subject_id
            WHERE subject.provider_connection_id = $1
              AND CASE subject.origin_kind
                WHEN 'provider_delivery' THEN EXISTS (
                    SELECT 1
                    FROM github_provider_delivery_evidence AS delivery_evidence
                    WHERE delivery_evidence.github_check_subject_id = subject.id
                      AND delivery_evidence.provider_delivery_id = subject.provider_delivery_id
                      AND delivery_evidence.tenant_id = subject.tenant_id
                      AND delivery_evidence.repository_id = subject.repository_id
                )
                WHEN 'scheduled_fire' THEN EXISTS (
                    SELECT 1
                    FROM github_schedule_check_evidence AS schedule_evidence
                    WHERE schedule_evidence.github_check_subject_id = subject.id
                      AND schedule_evidence.schedule_fire_id = subject.schedule_fire_id
                      AND schedule_evidence.tenant_id = subject.tenant_id
                      AND schedule_evidence.repository_id = subject.repository_id
                      AND schedule_evidence.provider_connection_id =
                          subject.provider_connection_id
                )
                ELSE FALSE
              END
              AND outbox.claim_fence = 9223372036854775807
              AND (
                outbox.state = 'pending'
                OR outbox.state = 'retry' AND outbox.next_attempt_at_ms <= $2
                OR outbox.state = 'create_indeterminate'
                   AND outbox.next_reconcile_at_ms <= $2
                OR outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $2
              )
        )
        ",
    )
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
    sqlx::query(
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
          AND CASE subject.origin_kind
            WHEN 'provider_delivery' THEN EXISTS (
                SELECT 1
                FROM github_provider_delivery_evidence AS delivery_evidence
                WHERE delivery_evidence.github_check_subject_id = subject.id
                  AND delivery_evidence.provider_delivery_id = subject.provider_delivery_id
                  AND delivery_evidence.tenant_id = subject.tenant_id
                  AND delivery_evidence.repository_id = subject.repository_id
            )
            WHEN 'scheduled_fire' THEN EXISTS (
                SELECT 1
                FROM github_schedule_check_evidence AS schedule_evidence
                WHERE schedule_evidence.github_check_subject_id = subject.id
                  AND schedule_evidence.schedule_fire_id = subject.schedule_fire_id
                  AND schedule_evidence.tenant_id = subject.tenant_id
                  AND schedule_evidence.repository_id = subject.repository_id
                  AND schedule_evidence.provider_connection_id =
                      subject.provider_connection_id
            )
            ELSE FALSE
          END
          AND outbox.attempted_revision = subject.desired_revision
          AND outbox.attempt_count >= 64
          AND (
            outbox.state = 'pending'
            OR outbox.state = 'retry' AND outbox.next_attempt_at_ms <= $2
            OR outbox.state = 'create_indeterminate'
               AND outbox.next_reconcile_at_ms <= $2
            OR outbox.state = 'claimed' AND outbox.claim_expires_at_ms <= $2
          )
        ",
    )
    .bind(connection_id.as_uuid())
    .bind(database_now)
    .execute(&mut **transaction)
    .await
    .map_err(operation_error)?;
    Ok(())
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
