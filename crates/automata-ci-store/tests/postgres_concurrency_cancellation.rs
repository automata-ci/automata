mod common;

use automata_ci_core::{
    AttemptId, FencingToken, JobId, JobIrVersion, LeaseGuard, LeaseId, OperationId, QueuePolicy,
    RunId, RunnerRequirements, Sha256Digest, UnixMillis, WorkflowId,
};
use automata_ci_store::{
    AcknowledgeRunnerCommands, AdmissionObject, AdmissionRepository, AdmitWorkflowRun,
    AdmittedWorkflowJob, BeginLeaseRequest, CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA,
    CancelJobCommandPayload, CancellationRepository as _, CommandCursor, CommandReplayLimit,
    CommitCommandAcknowledgement, DocumentSchema, HumanRunScope, HumanWorkflowReadRepository as _,
    LeaseRequestKey, ObjectKey, OpenRunnerSession, RepositoryId, RoutingDocument,
    RunnableAttemptRepository as _, RunnableScanLimit, RunnableScanRequest,
    RunnerClaimRepository as _, RunnerCommandOutbox as _, RunnerControlTransactionRepository as _,
    RunnerGeneration, RunnerLeaseRequestRepository as _, RunnerOperationKind,
    RunnerOperationRequest, RunnerOperationResponse, RunnerProtocolVersion,
    RunnerSessionRepository as _, StableRunnerSlot, StoreError, TenantScope, TryClaimAttempt,
    TryClaimOutcome, WorkflowAdmissionIdempotency, WorkflowAdmissionRepository as _,
    WorkflowConcurrency, WorkflowSnapshotId,
};
use common::{
    SeedData, TestDatabase, TestResult, run_with_database, runner_capability_document,
    seed_control_plane,
};

const GROUP: &str = "deploy-main";
const CANCELLATION_REASON: &str = "superseded by a newer workflow run";
const TEST_LEASE_DURATION_MILLIS: i64 = 300_000;

#[derive(Clone, Debug)]
struct AdmissionCase {
    command: AdmitWorkflowRun,
    run_id: RunId,
    attempt_id: AttemptId,
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
async fn cancel_in_progress_is_atomic_race_safe_idempotent_and_fenced() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        seed_run_number_counter(&database, &seed).await?;
        let snapshot_id = WorkflowSnapshotId::from_uuid(uuid::Uuid::new_v4());
        let active = admission_case(&seed, snapshot_id, 21, 10)?;
        let first = database
            .store()
            .admit_workflow(active.command.clone())
            .await?;
        assert!(!first.is_replay());

        let fence = seed.session_fences[0];
        let guard = activate_attempt(&database, &active, fence).await?;
        verify_late_failure_rolls_back(&database, &seed, snapshot_id, &active).await?;

        let left = admission_case(&seed, snapshot_id, 31, 40)?;
        let right = admission_case(&seed, snapshot_id, 32, 40)?;
        let (left_receipt, right_receipt) = tokio::join!(
            database.store().admit_workflow(left.command.clone()),
            database.store().admit_workflow(right.command.clone()),
        );
        assert!(!left_receipt?.is_replay());
        assert!(!right_receipt?.is_replay());

        let (winner, loser) = verify_race_outcome(&database, &active, &left, &right).await?;
        verify_server_cancelled_human_read(&database, &seed, loser).await?;
        verify_admission_replays(&database, &left, &right).await?;
        let sequence =
            verify_typed_cancel_replay(&database, active.attempt_id, fence, guard).await?;
        acknowledge_cancel(&database, active.attempt_id, fence, sequence).await?;
        verify_stale_fence_rejected(&database, &seed, fence).await?;

        assert_eq!(run_status(&database, winner.run_id).await?, "queued");
        assert_eq!(run_status(&database, loser.run_id).await?, "cancelled");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
async fn cancel_in_progress_serializes_with_claim_without_an_orphan_lease() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        seed_run_number_counter(&database, &seed).await?;
        let snapshot_id = WorkflowSnapshotId::from_uuid(uuid::Uuid::new_v4());
        let old = admission_case(&seed, snapshot_id, 41, 10)?;
        database.store().admit_workflow(old.command.clone()).await?;

        let fence = seed.session_fences[0];
        let slot = StableRunnerSlot::new(1)?;
        let claim_observed_at = database_now(&database).await?;
        let page = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                slot,
                RunnableScanLimit::new(10)?,
                claim_observed_at,
            ))
            .await?;
        let request_key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        database
            .store()
            .begin_lease_request(BeginLeaseRequest::new(
                request_key,
                Sha256Digest::from_bytes([91; 32]),
            ))
            .await?;
        let claim = TryClaimAttempt::new(
            request_key,
            old.attempt_id,
            LeaseId::new(),
            claim_observed_at,
            UnixMillis::new(
                claim_observed_at
                    .get()
                    .checked_add(TEST_LEASE_DURATION_MILLIS)
                    .ok_or("test claim expiry overflowed")?,
            ),
            page.claim_advance(old.attempt_id)?,
        )?;
        let replacement = admission_case(&seed, snapshot_id, 42, 20)?;
        let (claim_receipt, admission_receipt) = tokio::join!(
            database.store().try_claim(claim.clone()),
            database.store().admit_workflow(replacement.command.clone()),
        );
        let claim_receipt = claim_receipt?;
        assert!(!admission_receipt?.is_replay());

        assert_eq!(run_status(&database, old.run_id).await?, "cancelled");
        assert_eq!(run_status(&database, replacement.run_id).await?, "queued");
        let intent = database
            .store()
            .cancellation_for_attempt(old.attempt_id)
            .await?
            .expect("preempted attempt cancellation");
        match claim_receipt.outcome() {
            TryClaimOutcome::Claimed(claimed) => {
                assert_eq!(
                    attempt_lifecycle(&database, old.attempt_id).await?,
                    "cancelling"
                );
                let delivery = intent.delivery().expect("active cancellation delivery");
                let payload =
                    CancelJobCommandPayload::decode_json(delivery.request().payload().bytes())?;
                assert_eq!(payload.guard(), claimed.lease().guard());
                assert_server_cancellation_terminal(&database, old.attempt_id, false).await?;
            }
            TryClaimOutcome::Rejected(_) => {
                assert_eq!(
                    attempt_lifecycle(&database, old.attempt_id).await?,
                    "cancelled"
                );
                assert!(intent.delivery().is_none());
                assert_server_cancellation_terminal(&database, old.attempt_id, true).await?;
            }
            TryClaimOutcome::NoWork => panic!("a selected attempt cannot become no-work"),
        }
        let claim_replay = database.store().try_claim(claim).await?;
        assert!(claim_replay.was_replayed());
        assert_eq!(claim_replay.outcome(), claim_receipt.outcome());
        assert!(
            database
                .store()
                .admit_workflow(replacement.command)
                .await?
                .is_replay()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates an isolated PostgreSQL schema"]
async fn max_queue_retains_fifo_order_and_recovers_a_stale_running_slot() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        seed_run_number_counter(&database, &seed).await?;
        let snapshot_id = WorkflowSnapshotId::from_uuid(uuid::Uuid::new_v4());
        let active =
            admission_case_with_concurrency(&seed, snapshot_id, 51, 10, false, QueuePolicy::Max)?;
        let first =
            admission_case_with_concurrency(&seed, snapshot_id, 52, 20, false, QueuePolicy::Max)?;
        let second =
            admission_case_with_concurrency(&seed, snapshot_id, 53, 30, false, QueuePolicy::Max)?;
        for case in [&active, &first, &second] {
            database
                .store()
                .admit_workflow(case.command.clone())
                .await?;
        }
        assert_eq!(running_run(&database, &seed).await?, active.run_id);
        assert_eq!(
            pending_runs(&database, &seed).await?,
            [first.run_id, second.run_id]
        );

        sqlx::query("UPDATE workflow_runs SET status = 'completed' WHERE id = $1")
            .bind(active.run_id.as_uuid())
            .execute(database.pool())
            .await?;
        let third =
            admission_case_with_concurrency(&seed, snapshot_id, 54, 40, false, QueuePolicy::Max)?;
        database
            .store()
            .admit_workflow(third.command.clone())
            .await?;

        assert_eq!(running_run(&database, &seed).await?, first.run_id);
        assert_eq!(
            pending_runs(&database, &seed).await?,
            [second.run_id, third.run_id]
        );
        assert_eq!(run_status(&database, second.run_id).await?, "queued");
        assert_eq!(run_status(&database, third.run_id).await?, "queued");
        Ok(())
    })
    .await
}

async fn seed_run_number_counter(database: &TestDatabase, seed: &SeedData) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO workflow_run_number_counters (workflow_id, next_run_number)
        VALUES ($1, 2)
        ON CONFLICT (workflow_id) DO NOTHING
        ",
    )
    .bind(seed.workflow_id)
    .execute(database.pool())
    .await?;
    Ok(())
}

fn admission_case(
    seed: &SeedData,
    snapshot_id: WorkflowSnapshotId,
    tag: u8,
    admitted_at: i64,
) -> TestResult<AdmissionCase> {
    admission_case_with_concurrency(
        seed,
        snapshot_id,
        tag,
        admitted_at,
        true,
        QueuePolicy::Single,
    )
}

fn admission_case_with_concurrency(
    seed: &SeedData,
    snapshot_id: WorkflowSnapshotId,
    tag: u8,
    admitted_at: i64,
    cancel_in_progress: bool,
    queue_policy: QueuePolicy,
) -> TestResult<AdmissionCase> {
    let run_id = RunId::new();
    let job_id = JobId::new();
    let attempt_id = AttemptId::new();
    let job = AdmittedWorkflowJob::new(
        job_id,
        attempt_id,
        format!("job-{tag}"),
        format!("Job {tag}"),
        object(tag, format!("cancel/job-{tag}.json"), "application/json")?,
        RoutingDocument::new(serde_json::to_string(&RunnerRequirements::default())?)?,
        Vec::new(),
    )?;
    let command = AdmitWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id(seed.tenant_id.clone())?,
        WorkflowAdmissionIdempotency::operation(OperationId::new()),
        Sha256Digest::from_bytes([tag; 32]),
        AdmissionRepository::new(
            RepositoryId::from_uuid(seed.repository_id),
            "test",
            seed.repository_id.to_string(),
            "automata",
            "store-test",
        )?,
        WorkflowId::from_uuid(seed.workflow_id),
        ".github/workflows/test.yml",
        "Store test",
        "refs/heads/main",
        snapshot_id,
        object(91, "cancel/source.yml", "application/yaml")?,
        object(
            tag.wrapping_add(64),
            format!("cancel/plan-{tag}.json"),
            "application/json",
        )?,
        run_id,
        1,
        "push",
        object(
            tag.wrapping_add(96),
            format!("cancel/event-{tag}.json"),
            "application/json",
        )?,
        vec![tag; 20],
        vec![job],
        UnixMillis::new(admitted_at),
    )
    .concurrency(Some(
        WorkflowConcurrency::new(GROUP, cancel_in_progress)?.with_queue_policy(queue_policy),
    ))
    .build()?;
    Ok(AdmissionCase {
        command,
        run_id,
        attempt_id,
    })
}

async fn running_run(database: &TestDatabase, seed: &SeedData) -> TestResult<RunId> {
    let run_id: uuid::Uuid = sqlx::query_scalar(
        r"
        SELECT running_run_id
        FROM concurrency_groups
        WHERE repository_id = $1 AND normalized_key = $2
        ",
    )
    .bind(seed.repository_id)
    .bind(GROUP)
    .fetch_one(database.pool())
    .await?;
    Ok(RunId::from_uuid(run_id))
}

async fn pending_runs(database: &TestDatabase, seed: &SeedData) -> TestResult<Vec<RunId>> {
    let run_ids: Vec<uuid::Uuid> = sqlx::query_scalar(
        r"
        SELECT run_id
        FROM concurrency_group_pending_runs
        WHERE repository_id = $1 AND normalized_key = $2
        ORDER BY queue_sequence
        ",
    )
    .bind(seed.repository_id)
    .bind(GROUP)
    .fetch_all(database.pool())
    .await?;
    Ok(run_ids.into_iter().map(RunId::from_uuid).collect())
}

fn object(digest_tag: u8, key: impl Into<String>, media_type: &str) -> TestResult<AdmissionObject> {
    Ok(AdmissionObject::new(
        Sha256Digest::from_bytes([digest_tag; 32]),
        ObjectKey::new(key)?,
        8,
        media_type,
    )?)
}

async fn activate_attempt(
    database: &TestDatabase,
    active: &AdmissionCase,
    fence: automata_ci_store::RunnerSessionFence,
) -> TestResult<LeaseGuard> {
    let guard = LeaseGuard::new(LeaseId::new(), FencingToken::new(1)?);
    let changed_at = database_now(database).await?;
    let lease_expires_at = changed_at
        .get()
        .checked_add(TEST_LEASE_DURATION_MILLIS)
        .ok_or("test lease expiry overflowed")?;
    sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'running', fencing_token = $2, lease_id = $3,
            runner_id = $4, lease_issued_at_ms = $5, lease_expires_at_ms = $9,
            runner_session_id = $6, runner_session_epoch = $7,
            runner_generation = $8, runner_slot = 1, changed_at_ms = $5
        WHERE id = $1
        ",
    )
    .bind(active.attempt_id.as_uuid())
    .bind(i64::try_from(guard.fencing_token().get())?)
    .bind(guard.lease_id().as_uuid())
    .bind(fence.runner_id().as_uuid())
    .bind(changed_at.get())
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(fence.session_epoch().get())?)
    .bind(i64::try_from(fence.runner_generation().get())?)
    .bind(lease_expires_at)
    .execute(database.pool())
    .await?;
    sqlx::query(
        "UPDATE workflow_runs SET status = 'in_progress', updated_at_ms = $2 WHERE id = $1",
    )
    .bind(active.run_id.as_uuid())
    .bind(changed_at.get())
    .execute(database.pool())
    .await?;
    Ok(guard)
}

async fn verify_late_failure_rolls_back(
    database: &TestDatabase,
    seed: &SeedData,
    snapshot_id: WorkflowSnapshotId,
    active: &AdmissionCase,
) -> TestResult {
    sqlx::query(
        "UPDATE concurrency_groups SET generation = 9223372036854775807 WHERE repository_id = $1 AND normalized_key = $2",
    )
    .bind(seed.repository_id)
    .bind(GROUP)
    .execute(database.pool())
    .await?;
    let failed = admission_case(seed, snapshot_id, 22, 30)?;
    assert!(
        database
            .store()
            .admit_workflow(failed.command)
            .await
            .is_err()
    );

    assert_eq!(run_count(database, failed.run_id).await?, 0);
    assert_eq!(run_status(database, active.run_id).await?, "in_progress");
    assert_eq!(
        attempt_lifecycle(database, active.attempt_id).await?,
        "running"
    );
    assert_eq!(cancellation_count(database).await?, 0);
    assert_eq!(cancel_command_count(database).await?, 0);
    sqlx::query(
        "UPDATE concurrency_groups SET generation = 1 WHERE repository_id = $1 AND normalized_key = $2",
    )
    .bind(seed.repository_id)
    .bind(GROUP)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn verify_race_outcome<'a>(
    database: &TestDatabase,
    active: &AdmissionCase,
    left: &'a AdmissionCase,
    right: &'a AdmissionCase,
) -> TestResult<(&'a AdmissionCase, &'a AdmissionCase)> {
    let running: uuid::Uuid = sqlx::query_scalar(
        "SELECT running_run_id FROM concurrency_groups WHERE repository_id = (SELECT repository_id FROM workflow_runs WHERE id = $1) AND normalized_key = $2",
    )
    .bind(active.run_id.as_uuid())
    .bind(GROUP)
    .fetch_one(database.pool())
    .await?;
    let (winner, loser) = if running == left.run_id.as_uuid() {
        (left, right)
    } else {
        assert_eq!(running, right.run_id.as_uuid());
        (right, left)
    };
    assert_eq!(run_status(database, active.run_id).await?, "cancelled");
    assert_eq!(
        attempt_lifecycle(database, active.attempt_id).await?,
        "cancelling"
    );
    assert_eq!(
        attempt_lifecycle(database, winner.attempt_id).await?,
        "queued"
    );
    assert_eq!(
        attempt_lifecycle(database, loser.attempt_id).await?,
        "cancelled"
    );
    assert_eq!(cancellation_count(database).await?, 2);
    assert_eq!(cancel_command_count(database).await?, 1);
    assert_server_cancellation_terminal(database, active.attempt_id, false).await?;
    assert_server_cancellation_terminal(database, winner.attempt_id, false).await?;
    assert_server_cancellation_terminal(database, loser.attempt_id, true).await?;
    Ok((winner, loser))
}

async fn verify_admission_replays(
    database: &TestDatabase,
    left: &AdmissionCase,
    right: &AdmissionCase,
) -> TestResult {
    let (left_replay, right_replay) = tokio::join!(
        database.store().admit_workflow(left.command.clone()),
        database.store().admit_workflow(right.command.clone()),
    );
    assert!(left_replay?.is_replay());
    assert!(right_replay?.is_replay());
    assert_eq!(cancellation_count(database).await?, 2);
    assert_eq!(cancel_command_count(database).await?, 1);
    for case in [left, right] {
        let cancelled = attempt_lifecycle(database, case.attempt_id).await? == "cancelled";
        assert_server_cancellation_terminal(database, case.attempt_id, cancelled).await?;
    }
    Ok(())
}

async fn verify_server_cancelled_human_read(
    database: &TestDatabase,
    seed: &SeedData,
    cancelled: &AdmissionCase,
) -> TestResult {
    let detail = database
        .store()
        .get_run(&HumanRunScope::new(
            TenantScope::from_authenticated_tenant_id(&seed.tenant_id)?,
            RepositoryId::from_uuid(seed.repository_id),
            cancelled.run_id,
        ))
        .await?
        .expect("cancelled run detail");
    let attempt = detail.jobs[0]
        .latest_attempt
        .as_ref()
        .expect("cancelled latest attempt");
    assert_eq!(attempt.id, cancelled.attempt_id);
    assert!(attempt.finished_at.is_some());
    assert!(
        attempt.terminal_result.is_none(),
        "server cancellation must not appear as a runner-authored result blob"
    );
    Ok(())
}

async fn verify_typed_cancel_replay(
    database: &TestDatabase,
    attempt_id: AttemptId,
    fence: automata_ci_store::RunnerSessionFence,
    guard: LeaseGuard,
) -> TestResult<automata_ci_store::CommandSequence> {
    let first = database
        .store()
        .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
        .await?;
    let second = database
        .store()
        .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
        .await?;
    assert_eq!(first, second);
    let command = first.first().expect("active cancellation command");
    assert_eq!(command.request().kind().as_str(), CANCEL_JOB_COMMAND_KIND);
    assert_eq!(
        command.request().payload().schema().get(),
        CANCEL_JOB_COMMAND_SCHEMA
    );
    let payload = CancelJobCommandPayload::decode_json(command.request().payload().bytes())?;
    assert_eq!(payload.attempt_id(), attempt_id);
    assert_eq!(payload.guard(), guard);
    assert_eq!(payload.protocol_version(), 5);
    assert_eq!(payload.reason(), CANCELLATION_REASON);
    let intent = database
        .store()
        .cancellation_for_attempt(attempt_id)
        .await?
        .expect("active attempt cancellation intent");
    let intent_delivery = intent.delivery().expect("durable delivery");
    assert_eq!(intent_delivery.request(), command.request());
    assert_eq!(intent_delivery.sequence(), command.sequence());
    assert_eq!(intent.acknowledged_at(), None);
    Ok(command.sequence())
}

async fn acknowledge_cancel(
    database: &TestDatabase,
    attempt_id: AttemptId,
    fence: automata_ci_store::RunnerSessionFence,
    sequence: automata_ci_store::CommandSequence,
) -> TestResult {
    let acknowledgement_started_at = database_now(database).await?;
    let operation = RunnerOperationRequest::new(
        fence,
        OperationId::new(),
        RunnerOperationKind::new("automata.runner.command-ack.v1")?,
        Sha256Digest::from_bytes([77; 32]),
    );
    let acknowledgement = CommitCommandAcknowledgement::new(
        operation,
        AcknowledgeRunnerCommands::new(
            fence,
            CommandCursor::through(sequence),
            acknowledgement_started_at,
        ),
        RunnerOperationResponse::new(DocumentSchema::new(1)?, b"cancel acknowledged".to_vec())?,
    )?;
    database
        .store()
        .commit_command_acknowledgement(acknowledgement)
        .await?;
    let acknowledgement_finished_at = database_now(database).await?;
    let tombstoned_at: i64 = sqlx::query_scalar(
        r"
        SELECT payload_tombstoned_at_ms
        FROM runner_command_outbox
        WHERE runner_session_id = $1 AND command_sequence = $2
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(i64::try_from(sequence.get())?)
    .fetch_one(database.pool())
    .await?;
    assert!(tombstoned_at >= acknowledgement_started_at.get());
    assert!(tombstoned_at <= acknowledgement_finished_at.get());
    assert!(matches!(
        database.store().cancellation_for_attempt(attempt_id).await,
        Err(StoreError::RunnerPayloadUnavailable { session_id, tombstone })
            if session_id == fence.session_id()
                && tombstone.reason()
                    == automata_ci_store::RunnerPayloadTombstoneReason::Acknowledged
                && tombstone.tombstoned_at() == UnixMillis::new(tombstoned_at)
    ));
    assert!(
        database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?
            .is_empty()
    );
    Ok(())
}

async fn verify_stale_fence_rejected(
    database: &TestDatabase,
    seed: &SeedData,
    old_fence: automata_ci_store::RunnerSessionFence,
) -> TestResult {
    let capabilities = runner_capability_document(database.pool(), old_fence.runner_id()).await?;
    let opened_at = database_now(database).await?;
    let replacement = database
        .store()
        .open_session(OpenRunnerSession::new(
            automata_ci_core::RunnerSessionId::new(),
            old_fence.runner_id(),
            RunnerGeneration::new(1)?,
            RunnerProtocolVersion::new(5)?,
            JobIrVersion::current(),
            capabilities,
            opened_at,
        ))
        .await?;
    assert_ne!(replacement.fence(), old_fence);
    assert!(matches!(
        database
            .store()
            .replay_commands(
                old_fence,
                CommandCursor::initial(),
                CommandReplayLimit::new(1)?,
            )
            .await,
        Err(StoreError::RunnerPayloadUnavailable { session_id, tombstone })
            if session_id == old_fence.session_id()
                && tombstone.reason()
                    == automata_ci_store::RunnerPayloadTombstoneReason::SessionSuperseded
    ));
    assert_eq!(replacement.fence().runner_id(), seed.runner_ids[0]);
    Ok(())
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?,
    ))
}

async fn run_status(database: &TestDatabase, run_id: RunId) -> TestResult<String> {
    Ok(
        sqlx::query_scalar("SELECT status FROM workflow_runs WHERE id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn attempt_lifecycle(database: &TestDatabase, attempt_id: AttemptId) -> TestResult<String> {
    Ok(
        sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
            .bind(attempt_id.as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn run_count(database: &TestDatabase, run_id: RunId) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM workflow_runs WHERE id = $1")
            .bind(run_id.as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn cancellation_count(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM attempt_cancellation_intents")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn cancel_command_count(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM runner_command_outbox WHERE command_kind = $1")
            .bind(CANCEL_JOB_COMMAND_KIND)
            .fetch_one(database.pool())
            .await?,
    )
}

async fn assert_server_cancellation_terminal(
    database: &TestDatabase,
    attempt_id: AttemptId,
    expected: bool,
) -> TestResult {
    let row: Option<(String, bool, bool, bool, bool)> = sqlx::query_as(
        r"
        SELECT terminal.terminal_authority,
               terminal.server_cancellation_operation_id = cancellation.operation_id,
               terminal.server_cancellation_digest =
                   automata_server_cancellation_terminal_digest(
                       cancellation.attempt_id, cancellation.operation_id,
                       cancellation.requested_by, cancellation.reason,
                       cancellation.requested_at_ms
                   ),
               terminal.completed_at_ms = cancellation.requested_at_ms
                   AND terminal.committed_at_ms = cancellation.requested_at_ms,
               num_nonnulls(
                   terminal.runner_session_id, terminal.operation_id,
                   terminal.runner_id, terminal.runner_session_epoch,
                   terminal.runner_generation, terminal.runner_slot,
                   terminal.lease_id, terminal.fencing_token,
                   terminal.result_schema, terminal.result_size_bytes,
                   terminal.result_digest, terminal.result_object_key,
                   terminal.workflow_plan_v2_logical_job_id,
                   terminal.workflow_plan_v2_terminal_ordinal
               ) = 0
        FROM attempt_terminal_results AS terminal
        JOIN attempt_cancellation_intents AS cancellation
          ON cancellation.attempt_id = terminal.attempt_id
        WHERE terminal.attempt_id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_optional(database.pool())
    .await?;
    if expected {
        let (authority, exact_operation, exact_digest, exact_time, runner_fields_null) =
            row.expect("queued cancellation must atomically persist terminal authority");
        assert_eq!(authority, "server_cancellation");
        assert!(exact_operation);
        assert!(exact_digest);
        assert!(exact_time);
        assert!(runner_fields_null);
    } else {
        assert!(
            row.is_none(),
            "leasing wins must retain the runner-authored terminal path"
        );
    }
    Ok(())
}
