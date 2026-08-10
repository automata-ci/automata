mod common;

use automata_ci_core::{
    AttemptId, AttemptNumber, JobId, JobIrVersion, JobLifecycle, LeaseGuard, LeaseId, OperationId,
    RunId, RunnerRequirements, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
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

const LIVE_LEASE_MILLIS: i64 = 120_000;
const NON_SESSION_TEST_STALE_MILLIS: u64 = 60_000;
const SESSION_TEST_STALE_MILLIS: u64 = 10_000;

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)] // One scenario proves the complete expiration/retry lifecycle.
async fn concurrent_maintenance_requeues_unstarted_and_loses_started_work_once() -> TestResult {
    run_with_database(|database| async move {
        let ExpiryFixture {
            seed,
            retry_attempt,
            lost_attempt,
            retry_started_at,
            lost_started_at,
        } = seed_expiry_fixture(&database).await?;

        let lower_bound = database_now(&database).await?;
        let request = maintenance_request(&database, 2, 10, NON_SESSION_TEST_STALE_MILLIS).await?;
        let (left, right) = tokio::join!(
            database.store().maintain_control_plane(request),
            database.store().maintain_control_plane(request)
        );
        let left = left?;
        let right = right?;
        let upper_bound = database_now(&database).await?;
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
        assert_database_time_bound(retry.changed_at(), lower_bound, upper_bound);
        let lost = database.store().get_attempt(lost_attempt).await?;
        assert_eq!(lost.lifecycle(), JobLifecycle::Lost);
        assert_eq!(lost.lease_failures(), 1);
        assert_database_time_bound(lost.changed_at(), lower_bound, upper_bound);
        assert_eq!(
            started_at(&database, retry_attempt).await?,
            retry_started_at
        );
        assert_eq!(started_at(&database, lost_attempt).await?, lost_started_at);
        assert_eq!(run_status(&database, seed.run_id).await?, "in_progress");

        let replay = database
            .store()
            .maintain_control_plane(
                maintenance_request(&database, 2, 10, NON_SESSION_TEST_STALE_MILLIS).await?,
            )
            .await?;
        assert!(replay.is_empty(), "a completed pass must be idempotent");

        let retry_guard = acquire(
            &database,
            retry_attempt,
            seed.session_fences[0],
            1,
            LIVE_LEASE_MILLIS,
        )
        .await?;
        transition(
            &database,
            retry_attempt,
            seed.session_fences[0],
            retry_guard,
            JobLifecycle::Preparing,
        )
        .await?;
        expire_active_attempt(&database, retry_attempt).await?;
        let exhausted = database
            .store()
            .maintain_control_plane(
                maintenance_request(&database, 2, 10, NON_SESSION_TEST_STALE_MILLIS).await?,
            )
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
        assert_eq!(
            started_at(&database, retry_attempt).await?,
            retry_started_at,
            "retries must retain the attempt's first concrete execution start"
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
            .maintain_control_plane(
                maintenance_request(&database, 3, 10, NON_SESSION_TEST_STALE_MILLIS).await?,
            )
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
        let reconcile_at = database_now(&database).await?;
        let reconciliation = database
            .store()
            .reconcile_run(seed.run_id, reconcile_at)
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
                .maintain_control_plane(
                    maintenance_request(&database, 3, 10, NON_SESSION_TEST_STALE_MILLIS).await?,
                )
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
        age_session_heartbeat(&database, fence, 100).await?;
        let short = database
            .store()
            .maintain_control_plane(
                maintenance_request(&database, 3, 10, SESSION_TEST_STALE_MILLIS).await?,
            )
            .await?;
        assert_eq!(short.closed_stale_sessions(), 0);
        assert!(database.store().get_session(fence).await?.is_live());

        age_session_heartbeat(&database, fence, 20_000).await?;
        let stale = database
            .store()
            .maintain_control_plane(
                maintenance_request(&database, 3, 10, SESSION_TEST_STALE_MILLIS).await?,
            )
            .await?;
        assert_eq!(stale.closed_stale_sessions(), 1);
        assert!(!database.store().get_session(fence).await?.is_live());
        let status: String = sqlx::query_scalar("SELECT status FROM runners WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
        assert_eq!(status, "offline");

        let capabilities = runner_capability_document(database.pool(), fence.runner_id()).await?;
        let open_observed_at = database_now(&database).await?;
        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                fence.runner_id(),
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(4)?,
                JobIrVersion::current(),
                capabilities,
                open_observed_at,
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
        let observed_at = database_now(&database).await?;
        let slot = StableRunnerSlot::new(1)?;
        let request_key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        let begin = BeginLeaseRequest::new(request_key, Sha256Digest::from_bytes([71; 32]));
        database.store().begin_lease_request(begin).await?;

        // The authenticated runner-control handler performs this exact fenced
        // refresh after validating any existing receipt and immediately before
        // entering the no-work lease-poll service.
        let heartbeat_lower = database_now(&database).await?;
        let refreshed = database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                fence,
                CommandCursor::initial(),
                observed_at,
            ))
            .await?;
        let heartbeat_upper = database_now(&database).await?;
        assert_database_time_bound(
            refreshed.heartbeat_at(),
            heartbeat_lower,
            heartbeat_upper,
        );

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
            .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                begin,
                RunnerOperationResponse::new(DocumentSchema::new(1)?, vec![1])?,
                observed_at,
            ))
            .await?;

        let protected = database
            .store()
            .maintain_control_plane(
                maintenance_request(&database, 3, 10, SESSION_TEST_STALE_MILLIS).await?,
            )
            .await?;
        assert_eq!(protected.closed_stale_sessions(), 0);
        assert!(database.store().get_session(fence).await?.is_live());

        age_session_heartbeat(&database, fence, 20_000).await?;
        let stale = database
            .store()
            .maintain_control_plane(
                maintenance_request(&database, 3, 10, SESSION_TEST_STALE_MILLIS).await?,
            )
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
        age_session_heartbeat(&database, fence, 20_000).await?;
        let caller_base = database_now(&database).await?;
        let newer_caller = checked_add_millis(caller_base, 100)?;
        let older_caller = checked_sub_millis(caller_base, 100)?;
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
                    newer_caller,
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
                    older_caller,
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
        let request =
            maintenance_request(&database, 3, 10, SESSION_TEST_STALE_MILLIS).await?;
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
        let refresh_upper = database_now(&database).await?;
        assert_database_time_bound(newer.heartbeat_at(), caller_base, refresh_upper);
        assert_database_time_bound(older.heartbeat_at(), newer.heartbeat_at(), refresh_upper);
        assert_eq!(report.closed_stale_sessions(), 0);
        let durable = database.store().get_session(fence).await?;
        assert!(durable.is_live());
        assert_eq!(durable.heartbeat_at(), older.heartbeat_at());
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
    retry_started_at: Option<i64>,
    lost_started_at: Option<i64>,
}

async fn seed_expiry_fixture(database: &TestDatabase) -> TestResult<ExpiryFixture> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let lost_job = insert_job(database, seed.run_id, "started").await?;
    let retry_attempt = insert_attempt(database, seed.job_id, 1, 10).await?;
    let lost_attempt = insert_attempt(database, lost_job, 1, 11).await?;
    let retry_guard = acquire(
        database,
        retry_attempt,
        seed.session_fences[0],
        1,
        LIVE_LEASE_MILLIS,
    )
    .await?;
    let lost_guard = acquire(
        database,
        lost_attempt,
        seed.session_fences[0],
        2,
        LIVE_LEASE_MILLIS,
    )
    .await?;
    transition(
        database,
        retry_attempt,
        seed.session_fences[0],
        retry_guard,
        JobLifecycle::Preparing,
    )
    .await?;
    for lifecycle in [JobLifecycle::Preparing, JobLifecycle::Running] {
        transition(
            database,
            lost_attempt,
            seed.session_fences[0],
            lost_guard,
            lifecycle,
        )
        .await?;
    }
    let retry_started_at = started_at(database, retry_attempt).await?;
    let lost_started_at = started_at(database, lost_attempt).await?;
    expire_active_attempt(database, retry_attempt).await?;
    expire_active_attempt(database, lost_attempt).await?;
    Ok(ExpiryFixture {
        seed,
        retry_attempt,
        lost_attempt,
        retry_started_at,
        lost_started_at,
    })
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    ))
}

fn checked_add_millis(base: UnixMillis, duration_millis: i64) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        base.get()
            .checked_add(duration_millis)
            .ok_or("test timestamp overflow")?,
    ))
}

fn checked_sub_millis(base: UnixMillis, duration_millis: i64) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        base.get()
            .checked_sub(duration_millis)
            .ok_or("test timestamp underflow")?,
    ))
}

fn assert_database_time_bound(value: UnixMillis, lower: UnixMillis, upper: UnixMillis) {
    assert!(
        value >= lower && value <= upper,
        "database-issued timestamp {value:?} fell outside {lower:?}..={upper:?}"
    );
}

async fn expire_active_attempt(
    database: &TestDatabase,
    attempt_id: AttemptId,
) -> TestResult<UnixMillis> {
    let expires_at: i64 = sqlx::query_scalar(
        r"
        UPDATE job_attempts
        SET lease_expires_at_ms = GREATEST(lease_issued_at_ms, changed_at_ms) + 1
        WHERE id = $1 AND lease_id IS NOT NULL
        RETURNING lease_expires_at_ms
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    let expires_at = UnixMillis::new(expires_at);
    wait_until_database_time(database, expires_at).await?;
    Ok(expires_at)
}

async fn wait_until_database_time(database: &TestDatabase, deadline: UnixMillis) -> TestResult {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let observed_at: i64 = sqlx::query_scalar(
                "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            )
            .fetch_one(database.pool())
            .await?;
            if observed_at >= deadline.get() {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "timed out waiting for an explicitly expired test lease")??;
    Ok(())
}

async fn age_session_heartbeat(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
    age_millis: i64,
) -> TestResult<UnixMillis> {
    let heartbeat_at = checked_sub_millis(database_now(database).await?, age_millis)?;
    sqlx::query(
        r"
        UPDATE runner_sessions
        SET connected_at_ms = LEAST(connected_at_ms, $2), heartbeat_at_ms = $2
        WHERE id = $1
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(heartbeat_at.get())
    .execute(database.pool())
    .await?;
    Ok(heartbeat_at)
}

async fn maintenance_request(
    database: &TestDatabase,
    failures: u32,
    batch: u16,
    stale_millis: u64,
) -> TestResult<ControlPlaneMaintenanceRequest> {
    let observed_at = database_now(database).await?;
    Ok(ControlPlaneMaintenanceRequest::new(
        observed_at,
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
    session: automata_ci_store::RunnerSessionFence,
    slot: u16,
    duration_millis: i64,
) -> TestResult<LeaseGuard> {
    let observed_at = database_now(database).await?;
    let expires_at = checked_add_millis(observed_at, duration_millis)?;
    Ok(database
        .store()
        .acquire_lease(AcquireLease::new(
            attempt_id,
            LeaseId::new(),
            session,
            StableRunnerSlot::new(slot)?,
            observed_at,
            expires_at,
        )?)
        .await?
        .guard())
}

async fn transition(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: automata_ci_store::RunnerSessionFence,
    guard: LeaseGuard,
    lifecycle: JobLifecycle,
) -> TestResult {
    let observed_at = database_now(database).await?;
    database
        .store()
        .transition(TransitionAttempt::new(
            attempt_id,
            session,
            guard,
            lifecycle,
            observed_at,
        ))
        .await?;
    Ok(())
}

async fn started_at(database: &TestDatabase, attempt_id: AttemptId) -> TestResult<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT started_at_ms FROM job_attempts WHERE id = $1")
            .bind(attempt_id.as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn finish(
    database: &TestDatabase,
    attempt_id: AttemptId,
    session: automata_ci_store::RunnerSessionFence,
    slot: u16,
    conclusion: JobLifecycle,
) -> TestResult {
    let guard = acquire(database, attempt_id, session, slot, LIVE_LEASE_MILLIS).await?;
    for lifecycle in [
        JobLifecycle::Preparing,
        JobLifecycle::Running,
        JobLifecycle::Finalizing,
        conclusion,
    ] {
        transition(database, attempt_id, session, guard, lifecycle).await?;
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
