mod common;

use automata_core::{
    AttemptId, AttemptNumber, JobId, JobIrVersion, JobLifecycle, LeaseGuard, LeaseId, OperationId,
    RunId, RunnerRequirements, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_store::{
    AcquireLease, BeginLeaseRequest, CommandCursor, CompleteLeaseRequest,
    ControlPlaneMaintenanceRepository as _, ControlPlaneMaintenanceRequest, DocumentSchema,
    ExpiredAttemptDisposition, HeartbeatRunnerSession, InternalAttemptRepository as _,
    JobDependency, LeaseFailureLimit, LeaseRequestKey, MaintenanceBatchSize, NoWorkLeaseRequest,
    OpenRunnerSession, QueuedAttempt, RunReconciliationRepository as _,
    RunnableAttemptRepository as _, RunnableScanLimit, RunnableScanRequest,
    RunnerClaimRepository as _, RunnerGeneration, RunnerLeaseRequestRepository as _,
    RunnerOperationResponse, RunnerProtocolVersion, RunnerSessionRepository as _, StableRunnerSlot,
    StaleSessionTimeoutMillis, TransitionAttempt, TryClaimOutcome, WORKFLOW_ADMISSION_EPOCH,
    WorkflowPlanRepository as _, WorkflowRunStatus,
};
use std::time::Duration;
use uuid::Uuid;

use common::{
    TestDatabase, TestResult, run_with_database, runner_capability_document, seed_control_plane,
};

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_maintenance_requeues_unstarted_and_loses_started_work_once() -> TestResult {
    run_with_database(|database| async move {
        let fixture = seed_expiry_fixture(&database).await?;
        let seed = fixture.seed;
        let retry_attempt = fixture.retry_attempt;
        let lost_attempt = fixture.lost_attempt;

        let request = maintenance_request(50, 2, 10, 100)?;
        let (left, right) = tokio::join!(
            database.store().maintain_control_plane(request),
            database.store().maintain_control_plane(request)
        );
        let left = left?;
        let right = right?;
        let outcomes = left
            .expired_attempts()
            .iter()
            .chain(right.expired_attempts())
            .map(|attempt| (attempt.attempt_id(), attempt.disposition()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            outcomes.get(&retry_attempt),
            Some(&ExpiredAttemptDisposition::Requeued)
        );
        assert_eq!(
            outcomes.get(&lost_attempt),
            Some(&ExpiredAttemptDisposition::Lost)
        );
        assert_eq!(
            left.expired_attempts().len() + right.expired_attempts().len(),
            2,
            "racing replicas must not apply an expiration twice"
        );

        let retry = database.store().get_attempt(retry_attempt).await?;
        assert_eq!(retry.lifecycle(), JobLifecycle::Queued);
        assert_eq!(retry.lease_failures(), 1);
        assert_eq!(retry.changed_at(), UnixMillis::new(50));
        let lost = database.store().get_attempt(lost_attempt).await?;
        assert_eq!(lost.lifecycle(), JobLifecycle::Lost);
        assert_eq!(lost.lease_failures(), 1);
        assert_eq!(lost.changed_at(), UnixMillis::new(50));
        assert_eq!(run_status(&database, seed.run_id).await?, "in_progress");

        let replay = database.store().maintain_control_plane(request).await?;
        assert!(replay.is_empty(), "a completed pass must be idempotent");

        let retry_guard =
            acquire(&database, retry_attempt, seed.session_fences[0], 1, 51, 60).await?;
        transition(
            &database,
            retry_attempt,
            seed.session_fences[0],
            retry_guard,
            JobLifecycle::Preparing,
            52,
        )
        .await?;
        let exhausted = database
            .store()
            .maintain_control_plane(maintenance_request(60, 2, 10, 100)?)
            .await?;
        assert_eq!(exhausted.expired_attempts().len(), 1);
        assert_eq!(
            exhausted.expired_attempts()[0].disposition(),
            ExpiredAttemptDisposition::Lost
        );
        assert_eq!(
            database
                .store()
                .get_attempt(retry_attempt)
                .await?
                .lease_failures(),
            2
        );
        assert_eq!(run_status(&database, seed.run_id).await?, "completed");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn blocked_failure_propagation_completes_run_and_promotes_pending_concurrency() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let verify_job = seed.job_id;
        let frontend_job = insert_job(&database, seed.run_id, "frontend").await?;
        let dist_job = insert_job(&database, seed.run_id, "dist").await?;
        let publish_job = insert_job(&database, seed.run_id, "publish").await?;
        let verify = insert_attempt(&database, verify_job, 1, 10).await?;
        let frontend = insert_attempt(&database, frontend_job, 1, 11).await?;
        let dist = insert_attempt(&database, dist_job, 1, 12).await?;
        let publish = insert_attempt(&database, publish_job, 1, 13).await?;
        database
            .store()
            .insert_dependency(JobDependency::new(seed.run_id, dist_job, verify_job)?)
            .await?;
        database
            .store()
            .insert_dependency(JobDependency::new(seed.run_id, dist_job, frontend_job)?)
            .await?;
        database
            .store()
            .insert_dependency(JobDependency::new(seed.run_id, publish_job, dist_job)?)
            .await?;

        finish(
            &database,
            verify,
            seed.session_fences[0],
            1,
            JobLifecycle::Failed,
        )
        .await?;
        finish(
            &database,
            frontend,
            seed.session_fences[0],
            2,
            JobLifecycle::Succeeded,
        )
        .await?;

        let pending_run = insert_pending_concurrency_run(&database, &seed).await?;
        let report = database
            .store()
            .maintain_control_plane(maintenance_request(100, 3, 10, 1_000)?)
            .await?;
        assert_eq!(report.skipped_blocked_attempts(), 2);
        assert_eq!(
            database.store().get_attempt(dist).await?.lifecycle(),
            JobLifecycle::Skipped
        );
        assert_eq!(
            database.store().get_attempt(publish).await?.lifecycle(),
            JobLifecycle::Skipped,
            "skip propagation must advance a dependency chain within the same bounded pass"
        );
        assert_eq!(run_status(&database, seed.run_id).await?, "completed");
        let reconciliation = database
            .store()
            .reconcile_run(seed.run_id, UnixMillis::new(100))
            .await?;
        assert_eq!(reconciliation.status(), WorkflowRunStatus::Completed);

        let slots: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            r"
            SELECT running_run_id, pending_run_id
            FROM concurrency_groups
            WHERE repository_id = $1 AND normalized_key = 'dogfood'
            ",
        )
        .bind(seed.repository_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(slots, (Some(pending_run.as_uuid()), None));
        assert!(
            database
                .store()
                .maintain_control_plane(maintenance_request(101, 3, 10, 1_000)?)
                .await?
                .is_empty()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn stale_session_timeout_preserves_short_resume_window_then_fences_offline_runner()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let short = database
            .store()
            .maintain_control_plane(maintenance_request(100, 3, 10, 99)?)
            .await?;
        assert_eq!(short.closed_stale_sessions(), 0);
        assert!(database.store().get_session(fence).await?.is_live());

        let stale = database
            .store()
            .maintain_control_plane(maintenance_request(1_000, 3, 10, 500)?)
            .await?;
        assert_eq!(stale.closed_stale_sessions(), 1);
        assert!(!database.store().get_session(fence).await?.is_live());
        let status: String = sqlx::query_scalar("SELECT status FROM runners WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
        assert_eq!(status, "offline");

        let capabilities = runner_capability_document(database.pool(), fence.runner_id()).await?;
        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                fence.runner_id(),
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(4)?,
                JobIrVersion::current(),
                capabilities,
                UnixMillis::new(1_001),
            ))
            .await?;
        assert!(replacement.is_live());
        assert_ne!(replacement.fence(), fence);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn authenticated_no_work_refresh_keeps_the_session_live_until_the_later_cutoff() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let observed_at = UnixMillis::new(900);
        let slot = StableRunnerSlot::new(1)?;
        let request_key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        let begin = BeginLeaseRequest::new(request_key, Sha256Digest::from_bytes([71; 32]));
        database.store().begin_lease_request(begin).await?;

        // The authenticated runner-control handler performs this exact fenced
        // refresh after validating any existing receipt and immediately before
        // entering the no-work lease-poll service.
        let refreshed = database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                fence,
                CommandCursor::initial(),
                observed_at,
            ))
            .await?;
        assert_eq!(refreshed.heartbeat_at(), observed_at);

        let page = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                slot,
                RunnableScanLimit::new(10)?,
                observed_at,
            ))
            .await?;
        let no_work = database
            .store()
            .record_no_work(NoWorkLeaseRequest::new(
                request_key,
                observed_at,
                page.no_work_advance(),
            )?)
            .await?;
        assert!(matches!(no_work.outcome(), TryClaimOutcome::NoWork));
        database
            .store()
            .complete_lease_request(CompleteLeaseRequest::new(
                begin,
                RunnerOperationResponse::new(DocumentSchema::new(1)?, vec![1])?,
                observed_at,
            ))
            .await?;

        let protected = database
            .store()
            .maintain_control_plane(maintenance_request(1_000, 3, 10, 500)?)
            .await?;
        assert_eq!(protected.closed_stale_sessions(), 0);
        assert!(database.store().get_session(fence).await?.is_live());

        let stale = database
            .store()
            .maintain_control_plane(maintenance_request(1_401, 3, 10, 500)?)
            .await?;
        assert_eq!(stale.closed_stale_sessions(), 1);
        assert!(!database.store().get_session(fence).await?.is_live());
        let retry_state: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runner_lease_request_heads WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_operation_receipts WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_kind = 'automata.runner.lease-request.v1'),
                (SELECT count(*) FROM runner_queue_cursors WHERE runner_id = $2)
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fence.runner_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(retry_state, (0, 0, 0, 1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_reverse_time_refresh_wins_a_selected_maintenance_candidate_race() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let mut blocker = database.pool().begin().await?;
        sqlx::query("SELECT id FROM runners WHERE id = $1 FOR UPDATE")
            .bind(fence.runner_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;

        let newer_store = database.store().clone();
        let newer = tokio::spawn(async move {
            newer_store
                .heartbeat_session(HeartbeatRunnerSession::new(
                    fence,
                    CommandCursor::initial(),
                    UnixMillis::new(900),
                ))
                .await
        });
        wait_for_lock_waiters(
            database.pool(),
            r"SELECT generation, session_epoch, status, desired_state[[:space:]]+FROM runners[[:space:]]+WHERE id = \$1[[:space:]]+FOR UPDATE",
            1,
        )
        .await?;

        let older_store = database.store().clone();
        let older = tokio::spawn(async move {
            older_store
                .heartbeat_session(HeartbeatRunnerSession::new(
                    fence,
                    CommandCursor::initial(),
                    UnixMillis::new(800),
                ))
                .await
        });
        wait_for_lock_waiters(
            database.pool(),
            r"SELECT generation, session_epoch, status, desired_state[[:space:]]+FROM runners[[:space:]]+WHERE id = \$1[[:space:]]+FOR UPDATE",
            2,
        )
        .await?;

        let maintenance_store = database.store().clone();
        let request = maintenance_request(1_000, 3, 10, 500)?;
        let maintenance =
            tokio::spawn(async move { maintenance_store.maintain_control_plane(request).await });
        wait_for_lock_waiters(
            database.pool(),
            r"SELECT generation, session_epoch[[:space:]]+FROM runners[[:space:]]+WHERE id = \$1[[:space:]]+FOR UPDATE",
            1,
        )
        .await?;

        blocker.commit().await?;
        let newer = newer.await??;
        let older = older.await??;
        let report = maintenance.await??;
        assert_eq!(newer.heartbeat_at(), UnixMillis::new(900));
        assert_eq!(older.heartbeat_at(), UnixMillis::new(900));
        assert_eq!(report.closed_stale_sessions(), 0);
        let durable = database.store().get_session(fence).await?;
        assert!(durable.is_live());
        assert_eq!(durable.heartbeat_at(), UnixMillis::new(900));
        Ok(())
    })
    .await
}

async fn wait_for_lock_waiters(
    pool: &sqlx::PgPool,
    query_pattern: &str,
    minimum: i64,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiters: i64 = sqlx::query_scalar(
                r"
                SELECT count(*)
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND wait_event_type = 'Lock'
                  AND query ~ $1
                ",
            )
            .bind(query_pattern)
            .fetch_one(pool)
            .await?;
            if waiters >= minimum {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "timed out waiting for PostgreSQL row-lock contention")??;
    Ok(())
}

struct ExpiryFixture {
    seed: common::SeedData,
    retry_attempt: AttemptId,
    lost_attempt: AttemptId,
}

async fn seed_expiry_fixture(database: &TestDatabase) -> TestResult<ExpiryFixture> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let lost_job = insert_job(database, seed.run_id, "started").await?;
    let retry_attempt = insert_attempt(database, seed.job_id, 1, 10).await?;
    let lost_attempt = insert_attempt(database, lost_job, 1, 11).await?;
    let retry_guard = acquire(database, retry_attempt, seed.session_fences[0], 1, 20, 50).await?;
    let lost_guard = acquire(database, lost_attempt, seed.session_fences[0], 2, 21, 50).await?;
    transition(
        database,
        retry_attempt,
        seed.session_fences[0],
        retry_guard,
        JobLifecycle::Preparing,
        30,
    )
    .await?;
    for (lifecycle, observed_at) in [(JobLifecycle::Preparing, 30), (JobLifecycle::Running, 31)] {
        transition(
            database,
            lost_attempt,
            seed.session_fences[0],
            lost_guard,
            lifecycle,
            observed_at,
        )
        .await?;
    }
    Ok(ExpiryFixture {
        seed,
        retry_attempt,
        lost_attempt,
    })
}

fn maintenance_request(
    observed_at: i64,
    failures: u32,
    batch: u16,
    stale_millis: u64,
) -> TestResult<ControlPlaneMaintenanceRequest> {
    Ok(ControlPlaneMaintenanceRequest::new(
        UnixMillis::new(observed_at),
        LeaseFailureLimit::new(failures)?,
        MaintenanceBatchSize::new(batch)?,
        StaleSessionTimeoutMillis::new(stale_millis)?,
    )?)
}

async fn insert_job(database: &TestDatabase, run_id: RunId, key: &str) -> TestResult<JobId> {
    let job_id = JobId::new();
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        ) VALUES ($1,$2,$3,$3,$4,$5,$6::jsonb,$7,$8,128,1)
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id.as_uuid())
    .bind(key)
    .bind(vec![13_u8; 32])
    .bind(format!("test/job-ir/{key}"))
    .bind(serde_json::to_value(RunnerRequirements::default())?)
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(i32::from(JobIrVersion::current().get()))
    .execute(database.pool())
    .await?;
    Ok(job_id)
}

async fn insert_attempt(
    database: &TestDatabase,
    job_id: JobId,
    number: u32,
    queued_at: i64,
) -> TestResult<AttemptId> {
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            job_id,
            AttemptNumber::new(number)?,
            UnixMillis::new(queued_at),
        ))
        .await?;
    Ok(attempt_id)
}

async fn acquire(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: automata_store::RunnerSessionFence,
    slot: u16,
    observed_at: i64,
    expires_at: i64,
) -> TestResult<LeaseGuard> {
    Ok(database
        .store()
        .acquire_lease(AcquireLease::new(
            attempt_id,
            LeaseId::new(),
            session,
            StableRunnerSlot::new(slot)?,
            UnixMillis::new(observed_at),
            UnixMillis::new(expires_at),
        )?)
        .await?
        .guard())
}

async fn transition(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: automata_store::RunnerSessionFence,
    guard: LeaseGuard,
    lifecycle: JobLifecycle,
    observed_at: i64,
) -> TestResult {
    database
        .store()
        .transition(TransitionAttempt::new(
            attempt_id,
            session,
            guard,
            lifecycle,
            UnixMillis::new(observed_at),
        ))
        .await?;
    Ok(())
}

async fn finish(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: automata_store::RunnerSessionFence,
    slot: u16,
    conclusion: JobLifecycle,
) -> TestResult {
    let guard = acquire(database, attempt_id, session, slot, 20, 90).await?;
    for (lifecycle, observed_at) in [
        (JobLifecycle::Preparing, 30),
        (JobLifecycle::Running, 40),
        (JobLifecycle::Finalizing, 50),
        (conclusion, 60),
    ] {
        transition(database, attempt_id, session, guard, lifecycle, observed_at).await?;
    }
    Ok(())
}

async fn insert_pending_concurrency_run(
    database: &TestDatabase,
    seed: &common::SeedData,
) -> TestResult<RunId> {
    let pending = RunId::new();
    sqlx::query(
        r"
        INSERT INTO concurrency_groups (
            repository_id, normalized_key, display_key, updated_at_ms
        ) VALUES ($1, 'dogfood', 'dogfood', 70)
        ",
    )
    .bind(seed.repository_id)
    .execute(database.pool())
    .await?;
    sqlx::query("UPDATE workflow_runs SET concurrency_group_key = 'dogfood' WHERE id = $1")
        .bind(seed.run_id.as_uuid())
        .execute(database.pool())
        .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key
        )
        SELECT $1, repository_id, workflow_id, snapshot_id, 2, event_name,
               event_object_key, head_sha, 'queued', 70, 70, 'dogfood'
        FROM workflow_runs WHERE id = $2
        ",
    )
    .bind(pending.as_uuid())
    .bind(seed.run_id.as_uuid())
    .execute(database.pool())
    .await?;
    let pending_job = insert_job(database, pending, "pending").await?;
    insert_attempt(database, pending_job, 1, 70).await?;
    sqlx::query(
        r"
        UPDATE concurrency_groups
        SET running_run_id = $2, pending_run_id = $3
        WHERE repository_id = $1 AND normalized_key = 'dogfood'
        ",
    )
    .bind(seed.repository_id)
    .bind(seed.run_id.as_uuid())
    .bind(pending.as_uuid())
    .execute(database.pool())
    .await?;
    Ok(pending)
}

async fn run_status(database: &TestDatabase, run_id: RunId) -> TestResult<String> {
    Ok(
        sqlx::query_scalar("SELECT status FROM workflow_runs WHERE id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}
