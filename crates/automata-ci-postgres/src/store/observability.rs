use async_trait::async_trait;
use automata_ci_control::observability::{
    ArtifactCounts, ArtifactReservationKind, ArtifactReservations, ArtifactState,
    BuiltinSecretCleanupCounts, BuiltinSecretCleanupStatus, ControlPlaneCapacityCandidate,
    ControlPlaneCapacityRunner, ControlPlaneStateRepository, ControlPlaneStateSnapshot,
    ControlPlaneStateSnapshotRequest, DatabasePoolSnapshot, JobAttemptCounts, LeaseCounts,
    LeaseState, LogicalActivationCounts, LogicalActivationState, LogicalJobCounts, LogicalJobState,
    LogicalWorkflowRunCounts, LogicalWorkflowRunState, MAX_CONTROL_PLANE_CAPACITY_CANDIDATES,
    MAX_CONTROL_PLANE_CAPACITY_RUNNERS, MAX_CONTROL_PLANE_CAPACITY_SLOTS_PER_RUNNER, RunnerCounts,
    RunnerDesiredState, RunnerObservedState, RunnerSessionCounts, RunnerSessionState,
    WorkflowRunCounts,
};
use automata_ci_core::{
    AttemptId, JOB_IR_SCHEMA_VERSION, JobId, JobLifecycle, RunnerCapabilities, RunnerId,
    RunnerRequirements, RunnerSessionId, UnixMillis,
};
use sqlx::{Postgres, Row as _, postgres::PgRow};
use uuid::Uuid;

use super::PostgresStore;
use automata_ci_store::{
    RoutingLabel, RunnerGeneration, RunnerSessionFence, RunnerSlotCount, SessionEpoch,
    StableRunnerSlot, StoreError, WORKFLOW_ADMISSION_EPOCH, WorkflowRunStatus,
};

const STATE_TRANSACTION_MODE: &str = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY";
const STATE_STATEMENT_TIMEOUT: &str = "SET LOCAL statement_timeout = '2000ms'";
const POOL_SNAPSHOT_ATTEMPTS: u8 = 4;

const CONTROL_PLANE_STATE_QUERY: &str = r"
WITH
workflow AS (
    SELECT
        count(*) FILTER (WHERE status = 'queued')::BIGINT AS queued,
        count(*) FILTER (WHERE status = 'in_progress')::BIGINT AS in_progress,
        count(*) FILTER (WHERE status = 'completed')::BIGINT AS completed,
        count(*) FILTER (WHERE status = 'cancelled')::BIGINT AS cancelled
    FROM workflow_runs
),
logical_run AS (
    SELECT
        count(*) FILTER (WHERE state = 'pending')::BIGINT AS pending,
        count(*) FILTER (WHERE state = 'active')::BIGINT AS active,
        count(*) FILTER (WHERE state = 'completed')::BIGINT AS completed,
        count(*) FILTER (WHERE state = 'cancelled')::BIGINT AS cancelled,
        count(*) FILTER (WHERE state = 'failed')::BIGINT AS failed
    FROM logical_workflow_runs
),
logical_job AS (
    SELECT
        count(*) FILTER (WHERE state = 'pending')::BIGINT AS pending,
        count(*) FILTER (WHERE state = 'activating')::BIGINT AS activating,
        count(*) FILTER (WHERE state = 'activated')::BIGINT AS activated,
        count(*) FILTER (WHERE state = 'completed')::BIGINT AS completed,
        count(*) FILTER (WHERE state = 'skipped')::BIGINT AS skipped,
        count(*) FILTER (WHERE state = 'cancelled')::BIGINT AS cancelled,
        count(*) FILTER (WHERE state = 'failed')::BIGINT AS failed,
        min(created_at_ms) FILTER (WHERE state = 'pending')::BIGINT AS pending_oldest_at_ms,
        min(activation_claimed_at_ms) FILTER (
            WHERE state = 'activating'
        )::BIGINT AS activating_oldest_at_ms,
        count(*) FILTER (
            WHERE state = 'activating' AND activation_expires_at_ms <= $1
        )::BIGINT AS expired,
        min(activation_expires_at_ms) FILTER (
            WHERE state = 'activating' AND activation_expires_at_ms <= $1
        )::BIGINT AS expired_oldest_at_ms
    FROM logical_workflow_jobs
),
logical_publication AS (
    SELECT count(*)::BIGINT AS publications
    FROM logical_workflow_activation_publications
),
logical_instance AS (
    SELECT count(*)::BIGINT AS instances
    FROM logical_workflow_instances
),
attempt AS (
    SELECT
        count(*) FILTER (WHERE lifecycle = 'queued')::BIGINT AS queued,
        count(*) FILTER (WHERE lifecycle = 'leased')::BIGINT AS leased,
        count(*) FILTER (WHERE lifecycle = 'preparing')::BIGINT AS preparing,
        count(*) FILTER (WHERE lifecycle = 'running')::BIGINT AS running,
        count(*) FILTER (WHERE lifecycle = 'cancelling')::BIGINT AS cancelling,
        count(*) FILTER (WHERE lifecycle = 'finalizing')::BIGINT AS finalizing,
        count(*) FILTER (WHERE lifecycle = 'succeeded')::BIGINT AS succeeded,
        count(*) FILTER (WHERE lifecycle = 'failed')::BIGINT AS failed,
        count(*) FILTER (WHERE lifecycle = 'cancelled')::BIGINT AS cancelled,
        count(*) FILTER (WHERE lifecycle = 'timed_out')::BIGINT AS timed_out,
        count(*) FILTER (WHERE lifecycle = 'skipped')::BIGINT AS skipped,
        count(*) FILTER (WHERE lifecycle = 'lost')::BIGINT AS lost
    FROM job_attempts
),
runner AS (
    SELECT
        count(*) FILTER (WHERE status = 'offline' AND desired_state = 'active')::BIGINT
            AS offline_active,
        count(*) FILTER (WHERE status = 'offline' AND desired_state = 'draining')::BIGINT
            AS offline_draining,
        count(*) FILTER (WHERE status = 'offline' AND desired_state = 'disabled')::BIGINT
            AS offline_disabled,
        count(*) FILTER (WHERE status = 'online' AND desired_state = 'active')::BIGINT
            AS online_active,
        count(*) FILTER (WHERE status = 'online' AND desired_state = 'draining')::BIGINT
            AS online_draining,
        count(*) FILTER (WHERE status = 'online' AND desired_state = 'disabled')::BIGINT
            AS online_disabled
    FROM runners
),
session_state AS (
    SELECT
        count(*) FILTER (WHERE disconnected_at_ms IS NULL)::BIGINT AS live,
        count(*) FILTER (WHERE disconnected_at_ms IS NOT NULL)::BIGINT AS disconnected
    FROM runner_sessions
),
queue AS (
    SELECT count(*)::BIGINT AS depth, min(queued_at_ms)::BIGINT AS oldest_at_ms
    FROM job_attempts
    WHERE lifecycle = 'queued'
),
eligible_queue AS (
    SELECT count(*)::BIGINT AS depth, min(attempt.queued_at_ms)::BIGINT AS oldest_at_ms
    FROM job_attempts AS attempt
    JOIN jobs AS job ON job.id = attempt.job_id
    JOIN workflow_runs AS run ON run.id = job.run_id
    WHERE job.admission_epoch = $3
      AND job.job_ir_schema = $4
      AND attempt.lifecycle = 'queued'
      AND attempt.queued_at_ms <= $1
      AND run.status IN ('queued', 'in_progress')
      AND NOT EXISTS (
          SELECT 1 FROM attempt_cancellation_intents AS cancellation
          WHERE cancellation.attempt_id = attempt.id
      )
      AND (
          run.concurrency_group_key IS NULL
          OR EXISTS (
              SELECT 1 FROM concurrency_groups AS concurrency
              WHERE concurrency.repository_id = run.repository_id
                AND concurrency.normalized_key = run.concurrency_group_key
                AND concurrency.running_run_id = run.id
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM job_dependencies AS dependency
          WHERE dependency.run_id = job.run_id
            AND dependency.job_id = job.id
            AND coalesce((
                SELECT prerequisite_attempt.lifecycle
                FROM job_attempts AS prerequisite_attempt
                WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
                ORDER BY prerequisite_attempt.attempt_number DESC
                LIMIT 1
            ), '') <> 'succeeded'
      )
),
lease AS (
    SELECT
        count(*) FILTER (WHERE lease_expires_at_ms > $2)::BIGINT AS active,
        count(*) FILTER (
            WHERE lease_expires_at_ms > $1 AND lease_expires_at_ms <= $2
        )::BIGINT AS near_expiry,
        count(*) FILTER (WHERE lease_expires_at_ms <= $1)::BIGINT AS expired
    FROM job_attempts
    WHERE lifecycle IN ('leased', 'preparing', 'running', 'cancelling', 'finalizing')
),
pending_command AS (
    SELECT count(*)::BIGINT AS depth, min(command.created_at_ms)::BIGINT AS oldest_at_ms
    FROM runner_command_outbox AS command
    JOIN runner_sessions AS session ON session.id = command.runner_session_id
    WHERE command.payload_tombstone_reason IS NULL
      AND command.command_sequence > session.acknowledged_command_sequence
),
pending_cancellation AS (
    SELECT count(*)::BIGINT AS depth, min(requested_at_ms)::BIGINT AS oldest_at_ms
    FROM attempt_cancellation_intents
    WHERE acknowledged_at_ms IS NULL
),
builtin_secret_cleanup AS (
    SELECT
        count(*) FILTER (WHERE status = 'pending')::BIGINT AS pending,
        min(created_at_ms) FILTER (
            WHERE status = 'pending'
        )::BIGINT AS pending_oldest_created_at_ms,
        count(*) FILTER (WHERE status = 'in_progress')::BIGINT AS in_progress,
        min(created_at_ms) FILTER (
            WHERE status = 'in_progress'
        )::BIGINT AS in_progress_oldest_created_at_ms,
        count(*) FILTER (WHERE status = 'dead_letter')::BIGINT AS dead_letter,
        min(created_at_ms) FILTER (
            WHERE status = 'dead_letter'
        )::BIGINT AS dead_letter_oldest_created_at_ms
    FROM secret_cleanup_outbox
    WHERE provider_id = 'builtin'
      AND cleanup_kind = 'destroy_secret_version'
      AND status IN ('pending', 'in_progress', 'dead_letter')
),
artifact AS (
    SELECT
        count(*) FILTER (
            WHERE state = 'pending' AND manifest_state IS NULL
        )::BIGINT AS pending_upload,
        count(*) FILTER (
            WHERE state = 'pending' AND manifest_state = 'reserved'
        )::BIGINT AS publication_reserved,
        count(*) FILTER (
            WHERE state = 'finalized' AND manifest_state = 'ready'
        )::BIGINT AS finalized
    FROM workflow_artifacts
),
block_reservation AS (
    SELECT count(*)::BIGINT AS depth, min(staged_at_seconds)::BIGINT AS oldest_at_seconds
    FROM workflow_artifact_blocks
    WHERE state = 'reserved'
),
manifest_reservation AS (
    SELECT
        count(*)::BIGINT AS depth,
        min(manifest_reserved_at_seconds)::BIGINT AS oldest_at_seconds
    FROM workflow_artifacts
    WHERE state = 'pending' AND manifest_state = 'reserved'
)
SELECT
    workflow.queued AS workflow_queued,
    workflow.in_progress AS workflow_in_progress,
    workflow.completed AS workflow_completed,
    workflow.cancelled AS workflow_cancelled,
    logical_run.pending AS logical_run_pending,
    logical_run.active AS logical_run_active,
    logical_run.completed AS logical_run_completed,
    logical_run.cancelled AS logical_run_cancelled,
    logical_run.failed AS logical_run_failed,
    logical_job.pending AS logical_job_pending,
    logical_job.activating AS logical_job_activating,
    logical_job.activated AS logical_job_activated,
    logical_job.completed AS logical_job_completed,
    logical_job.skipped AS logical_job_skipped,
    logical_job.cancelled AS logical_job_cancelled,
    logical_job.failed AS logical_job_failed,
    logical_job.pending_oldest_at_ms AS logical_activation_pending_oldest_at_ms,
    logical_job.activating_oldest_at_ms AS logical_activation_activating_oldest_at_ms,
    logical_job.expired AS logical_activation_expired,
    logical_job.expired_oldest_at_ms AS logical_activation_expired_oldest_at_ms,
    logical_publication.publications AS logical_activation_publications,
    logical_instance.instances AS logical_materialized_instances,
    attempt.queued AS attempt_queued,
    attempt.leased AS attempt_leased,
    attempt.preparing AS attempt_preparing,
    attempt.running AS attempt_running,
    attempt.cancelling AS attempt_cancelling,
    attempt.finalizing AS attempt_finalizing,
    attempt.succeeded AS attempt_succeeded,
    attempt.failed AS attempt_failed,
    attempt.cancelled AS attempt_cancelled,
    attempt.timed_out AS attempt_timed_out,
    attempt.skipped AS attempt_skipped,
    attempt.lost AS attempt_lost,
    runner.offline_active AS runner_offline_active,
    runner.offline_draining AS runner_offline_draining,
    runner.offline_disabled AS runner_offline_disabled,
    runner.online_active AS runner_online_active,
    runner.online_draining AS runner_online_draining,
    runner.online_disabled AS runner_online_disabled,
    session_state.live AS session_live,
    session_state.disconnected AS session_disconnected,
    queue.depth AS queue_depth,
    queue.oldest_at_ms AS queue_oldest_at_ms,
    eligible_queue.depth AS eligible_queue_depth,
    eligible_queue.oldest_at_ms AS eligible_queue_oldest_at_ms,
    lease.active AS lease_active,
    lease.near_expiry AS lease_near_expiry,
    lease.expired AS lease_expired,
    pending_command.depth AS pending_commands,
    pending_command.oldest_at_ms AS pending_commands_oldest_at_ms,
    pending_cancellation.depth AS pending_cancellation_intents,
    pending_cancellation.oldest_at_ms AS pending_cancellation_intents_oldest_at_ms,
    builtin_secret_cleanup.pending AS builtin_secret_cleanup_pending,
    builtin_secret_cleanup.pending_oldest_created_at_ms
        AS builtin_secret_cleanup_pending_oldest_created_at_ms,
    builtin_secret_cleanup.in_progress AS builtin_secret_cleanup_in_progress,
    builtin_secret_cleanup.in_progress_oldest_created_at_ms
        AS builtin_secret_cleanup_in_progress_oldest_created_at_ms,
    builtin_secret_cleanup.dead_letter AS builtin_secret_cleanup_dead_letter,
    builtin_secret_cleanup.dead_letter_oldest_created_at_ms
        AS builtin_secret_cleanup_dead_letter_oldest_created_at_ms,
    artifact.pending_upload AS artifact_pending_upload,
    artifact.publication_reserved AS artifact_publication_reserved,
    artifact.finalized AS artifact_finalized,
    block_reservation.depth AS artifact_block_reservations,
    block_reservation.oldest_at_seconds AS artifact_block_reservations_oldest_at_seconds,
    manifest_reservation.depth AS artifact_manifest_reservations,
    manifest_reservation.oldest_at_seconds AS artifact_manifest_reservations_oldest_at_seconds
FROM workflow
CROSS JOIN logical_run
CROSS JOIN logical_job
CROSS JOIN logical_publication
CROSS JOIN logical_instance
CROSS JOIN attempt
CROSS JOIN runner
CROSS JOIN session_state
CROSS JOIN queue
CROSS JOIN eligible_queue
CROSS JOIN lease
CROSS JOIN pending_command
CROSS JOIN pending_cancellation
CROSS JOIN builtin_secret_cleanup
CROSS JOIN artifact
CROSS JOIN block_reservation
CROSS JOIN manifest_reservation
";

const CAPACITY_CANDIDATE_QUERY: &str = r"
SELECT repository.tenant_id, attempt.id AS attempt_id, job.id AS job_id,
       attempt.queued_at_ms, job.requirements
FROM job_attempts AS attempt
JOIN jobs AS job ON job.id = attempt.job_id
JOIN workflow_runs AS run ON run.id = job.run_id
JOIN repositories AS repository ON repository.id = run.repository_id
WHERE job.admission_epoch = $2
  AND job.job_ir_schema = $3
  AND attempt.lifecycle = 'queued'
  AND attempt.queued_at_ms <= $1
  AND run.status IN ('queued', 'in_progress')
  AND NOT EXISTS (
      SELECT 1 FROM attempt_cancellation_intents AS cancellation
      WHERE cancellation.attempt_id = attempt.id
  )
  AND (
      run.concurrency_group_key IS NULL
      OR EXISTS (
          SELECT 1 FROM concurrency_groups AS concurrency
          WHERE concurrency.repository_id = run.repository_id
            AND concurrency.normalized_key = run.concurrency_group_key
            AND concurrency.running_run_id = run.id
      )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM job_dependencies AS dependency
      WHERE dependency.run_id = job.run_id
        AND dependency.job_id = job.id
        AND coalesce((
            SELECT prerequisite_attempt.lifecycle
            FROM job_attempts AS prerequisite_attempt
            WHERE prerequisite_attempt.job_id = dependency.prerequisite_job_id
            ORDER BY prerequisite_attempt.attempt_number DESC
            LIMIT 1
        ), '') <> 'succeeded'
  )
ORDER BY attempt.queued_at_ms, attempt.id
LIMIT $4
";

const CAPACITY_RUNNER_QUERY: &str = r"
SELECT runner.tenant_id, runner.id AS runner_id, session.id AS session_id,
       runner.generation, runner.session_epoch,
       runner_group.normalized_name AS group_name, runner.labels,
       runner.capabilities, session.capability_snapshot,
       runner.slots,
       ARRAY(
           SELECT attempt.runner_slot
           FROM job_attempts AS attempt
           WHERE attempt.runner_id = runner.id
             AND attempt.lease_id IS NOT NULL
           ORDER BY attempt.runner_slot
           LIMIT $3
       ) AS occupied_slots
FROM runners AS runner
JOIN runner_sessions AS session
  ON session.runner_id = runner.id
 AND session.runner_generation = runner.generation
 AND session.session_epoch = runner.session_epoch
LEFT JOIN runner_groups AS runner_group ON runner_group.id = runner.group_id
WHERE runner.status = 'online'
  AND runner.desired_state = 'active'
  AND session.disconnected_at_ms IS NULL
  AND session.job_ir_schema = $1
ORDER BY runner.id
LIMIT $2
";

#[async_trait]
impl ControlPlaneStateRepository for PostgresStore {
    async fn control_plane_state_snapshot(
        &self,
        request: ControlPlaneStateSnapshotRequest,
    ) -> Result<ControlPlaneStateSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(StoreError::operation)?;
        configure_read_only_transaction(&mut transaction).await?;
        let row = sqlx::query(CONTROL_PLANE_STATE_QUERY)
            .bind(request.observed_at().get())
            .bind(request.near_expiry_at().get())
            .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
            .bind(i32::from(JOB_IR_SCHEMA_VERSION))
            .fetch_one(&mut *transaction)
            .await
            .map_err(StoreError::operation)?;
        let candidate_rows = sqlx::query(CAPACITY_CANDIDATE_QUERY)
            .bind(request.observed_at().get())
            .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
            .bind(i32::from(JOB_IR_SCHEMA_VERSION))
            .bind(
                i64::try_from(MAX_CONTROL_PLANE_CAPACITY_CANDIDATES + 1)
                    .map_err(|_| StoreError::corrupt_data("capacity candidate bound overflow"))?,
            )
            .fetch_all(&mut *transaction)
            .await
            .map_err(StoreError::operation)?;
        let capacity_candidates = candidate_rows
            .iter()
            .map(decode_capacity_candidate)
            .collect::<Result<Vec<_>, _>>()?;
        let runner_rows = sqlx::query(CAPACITY_RUNNER_QUERY)
            .bind(i32::from(JOB_IR_SCHEMA_VERSION))
            .bind(
                i64::try_from(MAX_CONTROL_PLANE_CAPACITY_RUNNERS + 1)
                    .map_err(|_| StoreError::corrupt_data("capacity runner bound overflow"))?,
            )
            .bind(i64::from(MAX_CONTROL_PLANE_CAPACITY_SLOTS_PER_RUNNER) + 1)
            .fetch_all(&mut *transaction)
            .await
            .map_err(StoreError::operation)?;
        let capacity_runners = runner_rows
            .iter()
            .map(decode_capacity_runner)
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot = decode_snapshot(&row, capacity_candidates, capacity_runners)?;
        transaction.commit().await.map_err(StoreError::operation)?;
        Ok(snapshot)
    }

    fn database_pool_snapshot(&self) -> Result<DatabasePoolSnapshot, StoreError> {
        let maximum = self.pool.options().get_max_connections();
        for _ in 0..POOL_SNAPSHOT_ATTEMPTS {
            let open = self.pool.size();
            let idle = u32::try_from(self.pool.num_idle()).map_err(|_| {
                StoreError::corrupt_data("database pool idle count is out of range")
            })?;
            if let Ok(snapshot) = DatabasePoolSnapshot::new(maximum, open, idle) {
                return Ok(snapshot);
            }
        }
        Err(StoreError::corrupt_data(
            "database pool occupancy remained inconsistent",
        ))
    }
}

async fn configure_read_only_transaction(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    sqlx::query(STATE_TRANSACTION_MODE)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::operation)?;
    sqlx::query(STATE_STATEMENT_TIMEOUT)
        .execute(&mut **transaction)
        .await
        .map_err(StoreError::operation)?;
    Ok(())
}

fn decode_snapshot(
    row: &PgRow,
    capacity_candidates: Vec<ControlPlaneCapacityCandidate>,
    capacity_runners: Vec<ControlPlaneCapacityRunner>,
) -> Result<ControlPlaneStateSnapshot, StoreError> {
    let snapshot = ControlPlaneStateSnapshot::new(
        decode_workflow_runs(row)?,
        decode_job_attempts(row)?,
        decode_runners(row)?,
        decode_runner_sessions(row)?,
        decode_count(row, "queue_depth")?,
        decode_timestamp(row, "queue_oldest_at_ms")?,
        decode_leases(row)?,
        decode_count(row, "pending_commands")?,
        decode_timestamp(row, "pending_commands_oldest_at_ms")?,
        decode_count(row, "pending_cancellation_intents")?,
        decode_timestamp(row, "pending_cancellation_intents_oldest_at_ms")?,
        decode_artifacts(row)?,
        decode_artifact_reservations(row)?,
    )
    .map_err(|_| StoreError::corrupt_data("control-plane metrics snapshot is inconsistent"))?
    .with_builtin_secret_cleanup(decode_builtin_secret_cleanup(row)?);
    snapshot
        .with_logical_orchestration(
            decode_logical_workflow_runs(row)?,
            decode_logical_jobs(row)?,
            decode_logical_activations(row)?,
            decode_count(row, "logical_activation_publications")?,
            decode_count(row, "logical_materialized_instances")?,
            decode_count(row, "eligible_queue_depth")?,
            decode_timestamp(row, "eligible_queue_oldest_at_ms")?,
            capacity_candidates,
            capacity_runners,
        )
        .map_err(|_| StoreError::corrupt_data("control-plane metrics snapshot is inconsistent"))
}

fn decode_workflow_runs(row: &PgRow) -> Result<WorkflowRunCounts, StoreError> {
    let mut workflow_runs = WorkflowRunCounts::default();
    for (status, column) in [
        (WorkflowRunStatus::Queued, "workflow_queued"),
        (WorkflowRunStatus::InProgress, "workflow_in_progress"),
        (WorkflowRunStatus::Completed, "workflow_completed"),
        (WorkflowRunStatus::Cancelled, "workflow_cancelled"),
    ] {
        workflow_runs.set(status, decode_count(row, column)?);
    }
    Ok(workflow_runs)
}

fn decode_logical_workflow_runs(row: &PgRow) -> Result<LogicalWorkflowRunCounts, StoreError> {
    let mut counts = LogicalWorkflowRunCounts::default();
    for (state, column) in [
        (LogicalWorkflowRunState::Pending, "logical_run_pending"),
        (LogicalWorkflowRunState::Active, "logical_run_active"),
        (LogicalWorkflowRunState::Completed, "logical_run_completed"),
        (LogicalWorkflowRunState::Cancelled, "logical_run_cancelled"),
        (LogicalWorkflowRunState::Failed, "logical_run_failed"),
    ] {
        counts.set(state, decode_count(row, column)?);
    }
    Ok(counts)
}

fn decode_logical_jobs(row: &PgRow) -> Result<LogicalJobCounts, StoreError> {
    let mut counts = LogicalJobCounts::default();
    for (state, column) in [
        (LogicalJobState::Pending, "logical_job_pending"),
        (LogicalJobState::Activating, "logical_job_activating"),
        (LogicalJobState::Activated, "logical_job_activated"),
        (LogicalJobState::Completed, "logical_job_completed"),
        (LogicalJobState::Skipped, "logical_job_skipped"),
        (LogicalJobState::Cancelled, "logical_job_cancelled"),
        (LogicalJobState::Failed, "logical_job_failed"),
    ] {
        counts.set(state, decode_count(row, column)?);
    }
    Ok(counts)
}

fn decode_logical_activations(row: &PgRow) -> Result<LogicalActivationCounts, StoreError> {
    let mut counts = LogicalActivationCounts::default();
    for (state, count_column, timestamp_column) in [
        (
            LogicalActivationState::Pending,
            "logical_job_pending",
            "logical_activation_pending_oldest_at_ms",
        ),
        (
            LogicalActivationState::Activating,
            "logical_job_activating",
            "logical_activation_activating_oldest_at_ms",
        ),
        (
            LogicalActivationState::Expired,
            "logical_activation_expired",
            "logical_activation_expired_oldest_at_ms",
        ),
    ] {
        counts
            .set(
                state,
                decode_count(row, count_column)?,
                decode_timestamp(row, timestamp_column)?,
            )
            .map_err(|_| StoreError::corrupt_data("logical activation snapshot is inconsistent"))?;
    }
    Ok(counts)
}

fn decode_job_attempts(row: &PgRow) -> Result<JobAttemptCounts, StoreError> {
    let mut job_attempts = JobAttemptCounts::default();
    for (lifecycle, column) in [
        (JobLifecycle::Queued, "attempt_queued"),
        (JobLifecycle::Leased, "attempt_leased"),
        (JobLifecycle::Preparing, "attempt_preparing"),
        (JobLifecycle::Running, "attempt_running"),
        (JobLifecycle::Cancelling, "attempt_cancelling"),
        (JobLifecycle::Finalizing, "attempt_finalizing"),
        (JobLifecycle::Succeeded, "attempt_succeeded"),
        (JobLifecycle::Failed, "attempt_failed"),
        (JobLifecycle::Cancelled, "attempt_cancelled"),
        (JobLifecycle::TimedOut, "attempt_timed_out"),
        (JobLifecycle::Skipped, "attempt_skipped"),
        (JobLifecycle::Lost, "attempt_lost"),
    ] {
        job_attempts.set(lifecycle, decode_count(row, column)?);
    }
    Ok(job_attempts)
}

fn decode_runners(row: &PgRow) -> Result<RunnerCounts, StoreError> {
    let mut runners = RunnerCounts::default();
    for (observed, desired, column) in [
        (
            RunnerObservedState::Offline,
            RunnerDesiredState::Active,
            "runner_offline_active",
        ),
        (
            RunnerObservedState::Offline,
            RunnerDesiredState::Draining,
            "runner_offline_draining",
        ),
        (
            RunnerObservedState::Offline,
            RunnerDesiredState::Disabled,
            "runner_offline_disabled",
        ),
        (
            RunnerObservedState::Online,
            RunnerDesiredState::Active,
            "runner_online_active",
        ),
        (
            RunnerObservedState::Online,
            RunnerDesiredState::Draining,
            "runner_online_draining",
        ),
        (
            RunnerObservedState::Online,
            RunnerDesiredState::Disabled,
            "runner_online_disabled",
        ),
    ] {
        runners.set(observed, desired, decode_count(row, column)?);
    }
    Ok(runners)
}

fn decode_runner_sessions(row: &PgRow) -> Result<RunnerSessionCounts, StoreError> {
    let mut runner_sessions = RunnerSessionCounts::default();
    runner_sessions.set(RunnerSessionState::Live, decode_count(row, "session_live")?);
    runner_sessions.set(
        RunnerSessionState::Disconnected,
        decode_count(row, "session_disconnected")?,
    );
    Ok(runner_sessions)
}

fn decode_leases(row: &PgRow) -> Result<LeaseCounts, StoreError> {
    let mut leases = LeaseCounts::default();
    leases.set(LeaseState::Active, decode_count(row, "lease_active")?);
    leases.set(
        LeaseState::NearExpiry,
        decode_count(row, "lease_near_expiry")?,
    );
    leases.set(LeaseState::Expired, decode_count(row, "lease_expired")?);
    Ok(leases)
}

fn decode_builtin_secret_cleanup(row: &PgRow) -> Result<BuiltinSecretCleanupCounts, StoreError> {
    let mut cleanup = BuiltinSecretCleanupCounts::default();
    for (status, count_column, timestamp_column) in [
        (
            BuiltinSecretCleanupStatus::Pending,
            "builtin_secret_cleanup_pending",
            "builtin_secret_cleanup_pending_oldest_created_at_ms",
        ),
        (
            BuiltinSecretCleanupStatus::InProgress,
            "builtin_secret_cleanup_in_progress",
            "builtin_secret_cleanup_in_progress_oldest_created_at_ms",
        ),
        (
            BuiltinSecretCleanupStatus::DeadLetter,
            "builtin_secret_cleanup_dead_letter",
            "builtin_secret_cleanup_dead_letter_oldest_created_at_ms",
        ),
    ] {
        cleanup
            .set(
                status,
                decode_count(row, count_column)?,
                decode_timestamp(row, timestamp_column)?,
            )
            .map_err(|_| {
                StoreError::corrupt_data("built-in secret cleanup snapshot is inconsistent")
            })?;
    }
    Ok(cleanup)
}

fn decode_artifacts(row: &PgRow) -> Result<ArtifactCounts, StoreError> {
    let mut artifacts = ArtifactCounts::default();
    artifacts.set(
        ArtifactState::PendingUpload,
        decode_count(row, "artifact_pending_upload")?,
    );
    artifacts.set(
        ArtifactState::PublicationReserved,
        decode_count(row, "artifact_publication_reserved")?,
    );
    artifacts.set(
        ArtifactState::Finalized,
        decode_count(row, "artifact_finalized")?,
    );
    Ok(artifacts)
}

fn decode_artifact_reservations(row: &PgRow) -> Result<ArtifactReservations, StoreError> {
    let mut artifact_reservations = ArtifactReservations::default();
    artifact_reservations
        .set(
            ArtifactReservationKind::Block,
            decode_count(row, "artifact_block_reservations")?,
            decode_seconds_timestamp(row, "artifact_block_reservations_oldest_at_seconds")?,
        )
        .map_err(|_| StoreError::corrupt_data("artifact reservation snapshot is inconsistent"))?;
    artifact_reservations
        .set(
            ArtifactReservationKind::Manifest,
            decode_count(row, "artifact_manifest_reservations")?,
            decode_seconds_timestamp(row, "artifact_manifest_reservations_oldest_at_seconds")?,
        )
        .map_err(|_| StoreError::corrupt_data("artifact reservation snapshot is inconsistent"))?;
    Ok(artifact_reservations)
}

fn decode_capacity_candidate(row: &PgRow) -> Result<ControlPlaneCapacityCandidate, StoreError> {
    let requirements = serde_json::from_value::<RunnerRequirements>(
        row.try_get::<serde_json::Value, _>("requirements")
            .map_err(StoreError::operation)?,
    )
    .map_err(|_| StoreError::corrupt_data("invalid runnable requirements"))?;
    Ok(ControlPlaneCapacityCandidate::new(
        row.try_get("tenant_id").map_err(StoreError::operation)?,
        AttemptId::from_uuid(
            row.try_get::<Uuid, _>("attempt_id")
                .map_err(StoreError::operation)?,
        ),
        JobId::from_uuid(
            row.try_get::<Uuid, _>("job_id")
                .map_err(StoreError::operation)?,
        ),
        UnixMillis::new(row.try_get("queued_at_ms").map_err(StoreError::operation)?),
        requirements,
    ))
}

fn decode_capacity_runner(row: &PgRow) -> Result<ControlPlaneCapacityRunner, StoreError> {
    let runner_id = RunnerId::from_uuid(
        row.try_get::<Uuid, _>("runner_id")
            .map_err(StoreError::operation)?,
    );
    let generation = decode_positive_u64(row, "generation")
        .and_then(|value| RunnerGeneration::new(value).map_err(|_| invalid_capacity_runner()))?;
    let epoch = decode_positive_u64(row, "session_epoch")
        .and_then(|value| SessionEpoch::new(value).map_err(|_| invalid_capacity_runner()))?;
    let session = RunnerSessionFence::new(
        RunnerSessionId::from_uuid(
            row.try_get::<Uuid, _>("session_id")
                .map_err(StoreError::operation)?,
        ),
        runner_id,
        generation,
        epoch,
    );
    let registered_capabilities = serde_json::from_value::<RunnerCapabilities>(
        row.try_get::<serde_json::Value, _>("capabilities")
            .map_err(StoreError::operation)?,
    )
    .map_err(|_| invalid_capacity_runner())?;
    let observed_capabilities = serde_json::from_value::<RunnerCapabilities>(
        row.try_get::<serde_json::Value, _>("capability_snapshot")
            .map_err(StoreError::operation)?,
    )
    .map_err(|_| invalid_capacity_runner())?;
    let slots = u16::try_from(
        row.try_get::<i32, _>("slots")
            .map_err(StoreError::operation)?,
    )
    .ok()
    .and_then(|value| RunnerSlotCount::new(value).ok())
    .ok_or_else(invalid_capacity_runner)?;
    let labels = row
        .try_get::<Vec<String>, _>("labels")
        .map_err(StoreError::operation)?
        .into_iter()
        .map(RoutingLabel::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_capacity_runner())?;
    let occupied_slots = row
        .try_get::<Vec<i32>, _>("occupied_slots")
        .map_err(StoreError::operation)?
        .into_iter()
        .map(|value| {
            u16::try_from(value)
                .ok()
                .and_then(|ordinal| StableRunnerSlot::new(ordinal).ok())
                .ok_or_else(invalid_capacity_runner)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ControlPlaneCapacityRunner::try_new(
        row.try_get("tenant_id").map_err(StoreError::operation)?,
        session,
        row.try_get("group_name").map_err(StoreError::operation)?,
        labels,
        registered_capabilities,
        observed_capabilities,
        slots,
        occupied_slots,
    )
    .map_err(|_| invalid_capacity_runner())
}

fn decode_positive_u64(row: &PgRow, column: &'static str) -> Result<u64, StoreError> {
    u64::try_from(
        row.try_get::<i64, _>(column)
            .map_err(StoreError::operation)?,
    )
    .ok()
    .filter(|value| *value > 0)
    .ok_or_else(invalid_capacity_runner)
}

fn invalid_capacity_runner() -> StoreError {
    StoreError::corrupt_data("invalid bounded capacity runner snapshot")
}

fn decode_count(row: &PgRow, column: &'static str) -> Result<u64, StoreError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(StoreError::operation)?;
    u64::try_from(value)
        .map_err(|_| StoreError::corrupt_data("control-plane metrics count is negative"))
}

fn decode_timestamp(row: &PgRow, column: &'static str) -> Result<Option<UnixMillis>, StoreError> {
    row.try_get::<Option<i64>, _>(column)
        .map(|value| value.map(UnixMillis::new))
        .map_err(StoreError::operation)
}

fn decode_seconds_timestamp(
    row: &PgRow,
    column: &'static str,
) -> Result<Option<UnixMillis>, StoreError> {
    let seconds = row
        .try_get::<Option<i64>, _>(column)
        .map_err(StoreError::operation)?;
    seconds
        .map(|value| {
            value
                .checked_mul(1_000)
                .map(UnixMillis::new)
                .ok_or_else(|| {
                    StoreError::corrupt_data(
                        "control-plane metrics timestamp is outside millisecond range",
                    )
                })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_queries_are_bounded_and_preserve_the_production_runnable_predicate() {
        for table in [
            "workflow_runs",
            "logical_workflow_runs",
            "logical_workflow_jobs",
            "logical_workflow_activation_publications",
            "logical_workflow_instances",
            "job_attempts",
            "runners",
            "runner_sessions",
            "runner_command_outbox",
            "attempt_cancellation_intents",
            "secret_cleanup_outbox",
            "workflow_artifacts",
            "workflow_artifact_blocks",
        ] {
            assert!(CONTROL_PLANE_STATE_QUERY.contains(table));
        }
        assert!(STATE_TRANSACTION_MODE.contains("REPEATABLE READ, READ ONLY"));
        assert!(STATE_STATEMENT_TIMEOUT.contains("2000ms"));
        for clause in [
            "provider_id = 'builtin'",
            "cleanup_kind = 'destroy_secret_version'",
            "status IN ('pending', 'in_progress', 'dead_letter')",
        ] {
            assert!(CONTROL_PLANE_STATE_QUERY.contains(clause), "{clause}");
        }
        for clause in [
            "job.admission_epoch =",
            "job.job_ir_schema =",
            "attempt.lifecycle = 'queued'",
            "attempt.queued_at_ms <=",
            "run.status IN ('queued', 'in_progress')",
            "cancellation.attempt_id = attempt.id",
            "concurrency.running_run_id = run.id",
            "prerequisite_attempt.attempt_number DESC",
            "), '') <> 'succeeded'",
        ] {
            assert!(CONTROL_PLANE_STATE_QUERY.contains(clause), "{clause}");
            assert!(CAPACITY_CANDIDATE_QUERY.contains(clause), "{clause}");
        }
        assert!(CAPACITY_CANDIDATE_QUERY.contains("LIMIT $4"));
        assert!(CAPACITY_RUNNER_QUERY.contains("LIMIT $2"));
        assert!(CAPACITY_RUNNER_QUERY.contains("LIMIT $3"));
        assert!(CAPACITY_RUNNER_QUERY.contains("runner.status = 'online'"));
        assert!(CAPACITY_RUNNER_QUERY.contains("runner.desired_state = 'active'"));
        assert!(CAPACITY_RUNNER_QUERY.contains("session.disconnected_at_ms IS NULL"));
        assert!(!CONTROL_PLANE_STATE_QUERY.contains("tenant_id AS"));
        assert!(!CONTROL_PLANE_STATE_QUERY.contains("runner_id AS"));
        assert!(!CONTROL_PLANE_STATE_QUERY.contains("attempt_id AS"));
        assert!(!CONTROL_PLANE_STATE_QUERY.contains("SELECT *"));
    }
}
