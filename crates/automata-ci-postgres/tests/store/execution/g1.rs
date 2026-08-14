use automata_ci_core::{
    Architecture, AttemptId, AttemptNumber, JobId, JobIrVersion, JobLifecycle, LeaseId,
    OperatingSystem, OperationId, RunnerCapabilities, RunnerFeature, RunnerGroup, RunnerLabel,
    RunnerPlatform, RunnerRequirements, RunnerSessionId, Sha256Digest, UnixMillis,
};
use automata_ci_postgres::store::PostgresStore;
use automata_ci_store::{
    AcknowledgeRunnerCommands, BeginLeaseRequest, BlockedAttemptRepository as _, BlockedConclusion,
    CANCEL_JOB_COMMAND_KIND, CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload, CancellationActor,
    CancellationReason, CancellationRepository as _, ClaimRejection, CloseRunnerSession,
    CommandCursor, CommandReplayLimit, CommandSequence, ConcludeBlockedAttempt, DocumentSchema,
    EnqueueRunnerCommand, HeartbeatRunnerSession, InternalAttemptRepository as _, JobDependency,
    LeaseRequestKey, MAX_COMMAND_REPLAY_BYTES, NoWorkLeaseRequest, OpenRunnerSession,
    QueuedAttempt, RequestCancellation, ResumeRunnerSession, RunnableAttemptRepository as _,
    RunnableScanLimit, RunnableScanRequest, RunnerClaimRepository as _, RunnerCommandOutbox as _,
    RunnerGeneration, RunnerLeaseRequestRepository as _, RunnerOperationKind,
    RunnerOperationReceiptRepository as _, RunnerOperationRequest, RunnerOperationResponse,
    RunnerProtocolVersion, RunnerRoutingRepository as _, RunnerSessionRepository as _,
    RunnerSlotAvailability, RunnerSlotAvailabilityRepository as _, StableRunnerSlot, StoreError,
    TransitionAttempt, TryClaimAttempt, TryClaimOutcome, WORKFLOW_ADMISSION_EPOCH,
    WorkflowPlanRepository as _,
};

use crate::support::{
    TestClock, TestDatabase, TestResult, run_with_database, runner_capability_document,
    seed_control_plane, test_runner_payload_key_provider,
};

const TEST_LEASE_DURATION_MILLIS: i64 = 120_000;

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn sessions_resume_and_replay_exact_server_commands_and_rpc_receipts() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let first_fence = seed.session_fences[0];
        assert_eq!(first_fence.session_epoch().get(), 1);

        let first_command_created_at = database_now(&database).await?;
        let first_command = command(
            first_fence,
            OperationId::new(),
            "automata.lease.v1",
            first_command_created_at,
            b"lease",
        )?;
        let first = database.store().enqueue_command(first_command.clone()).await?;
        assert_eq!(first.sequence().get(), 1);
        assert!(!first.was_replayed());
        let duplicate = database.store().enqueue_command(first_command.clone()).await?;
        assert_eq!(duplicate.sequence(), first.sequence());
        assert!(duplicate.was_replayed());

        let changed_retry = command(
            first_fence,
            first_command.operation_id(),
            "automata.lease.v1",
            checked_add_millis(first_command_created_at, 1)?,
            b"lease",
        )?;
        assert!(matches!(
            database.store().enqueue_command(changed_retry).await,
            Err(StoreError::OperationConflict { operation_id, .. })
                if operation_id == first_command.operation_id()
        ));

        let second = database
            .store()
            .enqueue_command(command(
                first_fence,
                OperationId::new(),
                "automata.drain.v1",
                database_now(&database).await?,
                b"drain",
            )?)
            .await?;
        assert_eq!(second.sequence().get(), 2);
        let replay = database
            .store()
            .replay_commands(
                first_fence,
                CommandCursor::initial(),
                CommandReplayLimit::new(10)?,
            )
            .await?;
        assert_eq!(
            replay
                .iter()
                .map(|entry| entry.sequence().get())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(
            replay
                .iter()
                .all(automata_ci_store::DurableRunnerCommand::was_replayed)
        );

        let through_one = CommandCursor::through(CommandSequence::new(1)?);
        let heartbeat_observed_at = database_now(&database).await?;
        let heartbeat = database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                first_fence,
                through_one,
                heartbeat_observed_at,
            ))
            .await?;
        assert_eq!(heartbeat.fence(), first_fence);
        assert_eq!(heartbeat.command_cursor(), through_one);

        let through_two = CommandCursor::through(CommandSequence::new(2)?);
        let resumed = database
            .store()
            .resume_session(ResumeRunnerSession::new(
                first_fence.runner_id(),
                first_fence.runner_generation(),
                first_fence.session_id(),
                through_two,
                database_now(&database).await?,
            ))
            .await?;
        assert_eq!(resumed.fence(), first_fence);
        assert_eq!(resumed.command_cursor(), through_two);
        assert_eq!(resumed.fence().session_epoch().get(), 1);
        assert!(matches!(
            database
                .store()
                .resume_session(ResumeRunnerSession::new(
                    first_fence.runner_id(),
                    first_fence.runner_generation(),
                    first_fence.session_id(),
                    through_one,
                    database_now(&database).await?,
                ))
                .await,
            Err(StoreError::CommandCursorBehind { requested, durable, .. })
                if requested == through_one && durable == through_two
        ));
        assert_eq!(
            database
                .store()
                .acknowledge_commands(AcknowledgeRunnerCommands::new(
                    first_fence,
                    through_one,
                    database_now(&database).await?,
                ))
                .await?,
            through_two,
            "a stale cumulative acknowledgement must never move the cursor backwards"
        );

        let ahead = CommandCursor::through(CommandSequence::new(3)?);
        assert!(matches!(
            database
                .store()
                .resume_session(ResumeRunnerSession::new(
                    first_fence.runner_id(),
                    first_fence.runner_generation(),
                    first_fence.session_id(),
                    ahead,
                    database_now(&database).await?,
                ))
                .await,
            Err(StoreError::CommandCursorAhead { .. })
        ));
        assert!(matches!(
            database
                .store()
                .heartbeat_session(HeartbeatRunnerSession::new(
                    first_fence,
                    ahead,
                    database_now(&database).await?,
                ))
                .await,
            Err(StoreError::CommandCursorAhead { .. })
        ));

        let request = RunnerOperationRequest::new(
            first_fence,
            OperationId::new(),
            RunnerOperationKind::new("automata.renew.v1")?,
            Sha256Digest::from_bytes([7; 32]),
        );
        let original_response = RunnerOperationResponse::new(DocumentSchema::new(1)?, b"accepted".to_vec())?;
        let receipt_committed_at = database_now(&database).await?;
        let recorded = database
            .store()
            .record_operation(
                request.clone(),
                original_response.clone(),
                receipt_committed_at,
            )
            .await?;
        assert!(!recorded.was_replayed());
        let repeated = database
            .store()
            .record_operation(
                request.clone(),
                RunnerOperationResponse::new(DocumentSchema::new(1)?, b"different".to_vec())?,
                checked_add_millis(receipt_committed_at, 1)?,
            )
            .await?;
        assert!(repeated.was_replayed());
        assert_eq!(repeated.response(), &original_response);
        assert_eq!(
            database.store().lookup_operation(&request).await?.expect("receipt").response(),
            &original_response
        );
        let conflicting_request = RunnerOperationRequest::new(
            first_fence,
            request.operation_id(),
            request.kind().clone(),
            Sha256Digest::from_bytes([8; 32]),
        );
        assert!(matches!(
            database.store().lookup_operation(&conflicting_request).await,
            Err(StoreError::OperationConflict { .. })
        ));

        assert!(
            database
                .store()
                .open_session(OpenRunnerSession::new(
                    RunnerSessionId::new(),
                    first_fence.runner_id(),
                    RunnerGeneration::new(1)?,
                    RunnerProtocolVersion::new(1)?,
                    JobIrVersion::new(2)?,
                    runner_capability_document(database.pool(), first_fence.runner_id()).await?,
                    database_now(&database).await?,
                ))
                .await
                .is_err(),
            "the durable admission boundary must reject a negotiated JobIR downgrade"
        );
        assert!(
            database.store().get_session(first_fence).await?.is_live(),
            "a rejected downgrade must roll back session replacement"
        );

        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                first_fence.runner_id(),
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                runner_capability_document(database.pool(), first_fence.runner_id()).await?,
                database_now(&database).await?,
            ))
            .await?;
        assert_eq!(replacement.fence().session_epoch().get(), 2);
        assert!(!database.store().get_session(first_fence).await?.is_live());
        assert!(matches!(
            database
                .store()
                .replay_commands(
                    first_fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(10)?,
                )
                .await,
            Err(StoreError::RunnerPayloadUnavailable { session_id, tombstone })
                if session_id == first_fence.session_id()
                    && tombstone.reason()
                        == automata_ci_store::RunnerPayloadTombstoneReason::SessionSuperseded
        ));
        let live_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_sessions WHERE runner_id = $1 AND disconnected_at_ms IS NULL",
        )
        .bind(first_fence.runner_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(live_count, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn command_replay_is_bounded_by_rows_and_aggregate_payload_bytes() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let payload_size = MAX_COMMAND_REPLAY_BYTES / 2 + 1;
        for (index, byte) in [1_u8, 2].into_iter().enumerate() {
            let created_at = database_now(&database).await?;
            database
                .store()
                .enqueue_command(command(
                    fence,
                    OperationId::new(),
                    "automata.test.large-command.v1",
                    checked_add_millis(created_at, i64::try_from(index)?)?,
                    &vec![byte; payload_size],
                )?)
                .await?;
        }
        let first_page = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(2)?)
            .await?;
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].sequence().get(), 1);

        let first_cursor = CommandCursor::through(first_page[0].sequence());
        database
            .store()
            .acknowledge_commands(AcknowledgeRunnerCommands::new(
                fence,
                first_cursor,
                database_now(&database).await?,
            ))
            .await?;
        let second_page = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(2)?)
            .await?;
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].sequence().get(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn claim_receipts_bind_one_based_slots_and_cancellation_delivery() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let attempt_id = insert_attempt(database.store(), seed.job_id, 1, 10).await?;
        let operation_id = OperationId::new();
        let initial_claim = claim(&database, operation_id, attempt_id, fence, 1).await?;
        let receipt = database.store().try_claim(initial_claim.clone()).await?;
        let claimed = match receipt.outcome() {
            TryClaimOutcome::Claimed(claimed) => claimed,
            outcome @ TryClaimOutcome::Rejected(_) => {
                panic!("claim must succeed: {outcome:?}")
            }
            TryClaimOutcome::NoWork => panic!("claim unexpectedly returned no work"),
        };
        assert_eq!(claimed.assignment().slot().ordinal(), 1);
        assert!(!receipt.was_replayed());
        let replay = database.store().try_claim(initial_claim.clone()).await?;
        assert!(replay.was_replayed());
        assert_eq!(replay.outcome(), receipt.outcome());

        let changed_job = insert_job(&database, seed.run_id, "changed-selection").await?;
        let changed_attempt = insert_attempt(database.store(), changed_job, 1, 11).await?;
        let changed_page = scan(&database, fence, 1).await?;
        let changed_observed_at = database_now(&database).await?;
        let changed = TryClaimAttempt::new(
            initial_claim.request_key(),
            changed_attempt,
            LeaseId::new(),
            changed_observed_at,
            checked_add_millis(changed_observed_at, TEST_LEASE_DURATION_MILLIS)?,
            changed_page.claim_advance(changed_attempt)?,
        )?;
        let changed_selection = database.store().try_claim(changed).await?;
        assert!(changed_selection.was_replayed());
        assert_eq!(changed_selection.outcome(), receipt.outcome());
        assert_eq!(
            database
                .store()
                .get_attempt(changed_attempt)
                .await?
                .lifecycle(),
            JobLifecycle::Queued
        );
        let changed_slot = LeaseRequestKey::first(fence, operation_id, StableRunnerSlot::new(2)?);
        assert!(matches!(
            database.store().lookup_lease_request(changed_slot).await,
            Err(StoreError::OperationConflict { .. })
        ));

        let occupied_job = insert_job(&database, seed.run_id, "occupied-selection").await?;
        let occupied_attempt = insert_attempt(database.store(), occupied_job, 1, 12).await?;
        let occupied = database
            .store()
            .try_claim(claim(&database, OperationId::new(), occupied_attempt, fence, 1).await?)
            .await?;
        assert!(matches!(
            occupied.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied { attempt_id: id })
                if *id == attempt_id
        ));

        let cancellation_at = database_now(&database).await?;
        let invalid_operation = OperationId::new();
        let invalid_cancellation = RequestCancellation::new(
            invalid_operation,
            attempt_id,
            CancellationActor::new("scheduler")?,
            Some(CancellationReason::new("run cancelled")?),
            cancellation_at,
        )
        .with_delivery(command(
            fence,
            invalid_operation,
            "automata.cancel.v1",
            cancellation_at,
            b"untyped cancel",
        )?);
        assert!(matches!(
            database
                .store()
                .request_cancellation(invalid_cancellation)
                .await,
            Err(StoreError::CancellationDeliveryMismatch(id)) if id == attempt_id
        ));

        let cancellation_operation = OperationId::new();
        let delivery = cancellation_command(
            fence,
            cancellation_operation,
            attempt_id,
            claimed.lease().guard(),
            RunnerProtocolVersion::new(1)?,
            "run cancelled",
            cancellation_at,
        )?;
        let cancellation = RequestCancellation::new(
            cancellation_operation,
            attempt_id,
            CancellationActor::new("scheduler")?,
            Some(CancellationReason::new("run cancelled")?),
            cancellation_at,
        )
        .with_delivery(delivery);
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let intent = database
            .store()
            .request_cancellation(cancellation.clone())
            .await?;
        assert_eq!(intent.delivery().expect("delivery").sequence().get(), 1);
        assert!(!intent.was_replayed());
        let repeated = database.store().request_cancellation(cancellation).await?;
        assert!(repeated.was_replayed());
        assert_eq!(repeated.delivery().expect("delivery").sequence().get(), 1);
        assert_eq!(
            database.store().get_attempt(attempt_id).await?.lifecycle(),
            JobLifecycle::Cancelling
        );
        let acknowledgement_before = database_now(&database).await?;
        database
            .store()
            .acknowledge_commands(AcknowledgeRunnerCommands::new(
                fence,
                CommandCursor::through(CommandSequence::new(1)?),
                acknowledgement_before,
            ))
            .await?;
        let acknowledgement_after = database_now(&database).await?;
        let acknowledged_at = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT acknowledged_at_ms FROM attempt_cancellation_intents WHERE attempt_id = $1",
        )
        .bind(attempt_id.as_uuid())
        .fetch_one(database.pool())
        .await?
        .map(UnixMillis::new)
        .expect("the delivered cancellation must record its acknowledgement time");
        assert!(
            acknowledged_at >= acknowledgement_before && acknowledged_at <= acknowledgement_after,
            "database acknowledgement time {acknowledged_at:?} fell outside \
             {acknowledgement_before:?}..={acknowledgement_after:?}"
        );
        assert!(matches!(
            database.store().cancellation_for_attempt(attempt_id).await,
            Err(StoreError::RunnerPayloadUnavailable { session_id, tombstone })
                if session_id == fence.session_id()
                    && tombstone.reason()
                        == automata_ci_store::RunnerPayloadTombstoneReason::Acknowledged
                    && tombstone.tombstoned_at() >= acknowledgement_before
                    && tombstone.tombstoned_at() <= acknowledgement_after
        ));
        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let disabled_state: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM attempt_cancellation_intents WHERE attempt_id = $1),
                (SELECT count(*) FROM runner_command_outbox WHERE runner_session_id = $2)
            ",
        )
        .bind(attempt_id.as_uuid())
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let disabled_retry_at = checked_add_millis(cancellation_at, 1)?;
        let disabled_retry = RequestCancellation::new(
            cancellation_operation,
            attempt_id,
            CancellationActor::new("scheduler")?,
            Some(CancellationReason::new("run cancelled")?),
            disabled_retry_at,
        )
        .with_delivery(cancellation_command(
            fence,
            cancellation_operation,
            attempt_id,
            claimed.lease().guard(),
            RunnerProtocolVersion::new(1)?,
            "run cancelled",
            disabled_retry_at,
        )?);
        assert!(matches!(
            database.store().request_cancellation(disabled_retry).await,
            Err(StoreError::RunnerDisabled(id)) if id == fence.runner_id()
        ));
        let disabled_state_after: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM attempt_cancellation_intents WHERE attempt_id = $1),
                (SELECT count(*) FROM runner_command_outbox WHERE runner_session_id = $2)
            ",
        )
        .bind(attempt_id.as_uuid())
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(disabled_state_after, disabled_state);

        expire_attempt_leases(&database, &clock, &[attempt_id]).await?;
        let expired = database
            .store()
            .requeue_expired(database_now(&database).await?, 10, 10)
            .await?;
        assert_eq!(expired, vec![attempt_id]);
        assert_eq!(
            database.store().get_attempt(attempt_id).await?.lifecycle(),
            JobLifecycle::Lost,
            "cancelling work must never silently requeue"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn lease_poll_receipts_replay_selection_and_no_work_before_rescheduling() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let attempt_a = insert_attempt(database.store(), seed.job_id, 1, 10).await?;
        let job_b = insert_job(&database, seed.run_id, "lease-poll-b").await?;
        let attempt_b = insert_attempt(database.store(), job_b, 1, 11).await?;
        let lease_key =
            LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(1)?);
        begin_isolated_lease_request(&database, lease_key).await?;
        assert!(
            database
                .store()
                .lookup_lease_request(lease_key)
                .await?
                .is_none()
        );
        let first = database
            .store()
            .try_claim(claim(&database, lease_key.operation_id(), attempt_a, fence, 1).await?)
            .await?;
        let first_lease_id = match first.outcome() {
            TryClaimOutcome::Claimed(claimed) => claimed.lease().lease_id(),
            outcome => panic!("first lease poll must claim A: {outcome:?}"),
        };
        let runnable = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                StableRunnerSlot::new(1)?,
                RunnableScanLimit::new(10)?,
                database_now(&database).await?,
            ))
            .await?;
        assert_eq!(
            runnable
                .candidates()
                .iter()
                .map(automata_ci_store::RunnableAttempt::attempt_id)
                .collect::<Vec<_>>(),
            vec![attempt_b],
            "the original selection is no longer a runnable candidate"
        );
        let looked_up = database
            .store()
            .lookup_lease_request(lease_key)
            .await?
            .expect("durable lease receipt");
        assert!(looked_up.was_replayed());
        assert_eq!(looked_up.outcome(), first.outcome());

        let reselected_page = scan(&database, fence, 1).await?;
        let reselected_at = database_now(&database).await?;
        let reselected = database
            .store()
            .try_claim(TryClaimAttempt::new(
                lease_key,
                attempt_b,
                LeaseId::new(),
                reselected_at,
                checked_add_millis(reselected_at, TEST_LEASE_DURATION_MILLIS)?,
                reselected_page.claim_advance(attempt_b)?,
            )?)
            .await?;
        let replayed_lease_id = match reselected.outcome() {
            TryClaimOutcome::Claimed(claimed) => claimed.lease().lease_id(),
            outcome => panic!("retry must replay A: {outcome:?}"),
        };
        assert!(reselected.was_replayed());
        assert_eq!(replayed_lease_id, first_lease_id);
        assert_eq!(
            database.store().get_attempt(attempt_b).await?.lifecycle(),
            JobLifecycle::Queued,
            "retrying one poll must never double-assign a newly selected candidate"
        );
        let different_slot =
            LeaseRequestKey::first(fence, lease_key.operation_id(), StableRunnerSlot::new(2)?);
        assert!(matches!(
            database.store().lookup_lease_request(different_slot).await,
            Err(StoreError::OperationConflict { .. })
        ));

        claim_success(
            &database,
            claim(&database, OperationId::new(), attempt_b, fence, 2).await?,
        )
        .await?;
        let no_work_key =
            LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(3)?);
        begin_isolated_lease_request(&database, no_work_key).await?;
        let no_work_page = scan(&database, fence, 3).await?;
        let no_work = database
            .store()
            .record_no_work(NoWorkLeaseRequest::new(
                no_work_key,
                database_now(&database).await?,
                no_work_page.no_work_advance(),
            )?)
            .await?;
        assert!(matches!(no_work.outcome(), TryClaimOutcome::NoWork));
        assert!(!no_work.was_replayed());

        let job_c = insert_job(&database, seed.run_id, "lease-poll-c").await?;
        let attempt_c = insert_attempt(database.store(), job_c, 1, 24).await?;
        let no_work_retry_page = scan(&database, fence, 3).await?;
        let no_work_retry_at = database_now(&database).await?;
        let no_work_retry = database
            .store()
            .try_claim(TryClaimAttempt::new(
                no_work_key,
                attempt_c,
                LeaseId::new(),
                no_work_retry_at,
                checked_add_millis(no_work_retry_at, TEST_LEASE_DURATION_MILLIS)?,
                no_work_retry_page.claim_advance(attempt_c)?,
            )?)
            .await?;
        assert!(matches!(no_work_retry.outcome(), TryClaimOutcome::NoWork));
        assert!(no_work_retry.was_replayed());
        assert_eq!(
            database.store().get_attempt(attempt_c).await?.lifecycle(),
            JobLifecycle::Queued,
            "a no-work retry must not claim work that arrived later"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn runnable_scan_is_authoritatively_tenant_scoped() -> TestResult {
    run_with_database(|database| async move {
        let first = seed_control_plane(database.pool(), 1).await?;
        let second = seed_control_plane(database.pool(), 1).await?;
        let first_attempt = insert_attempt(database.store(), first.job_id, 1, 10).await?;
        let second_attempt = insert_attempt(database.store(), second.job_id, 1, 11).await?;

        let first_page = scan(&database, first.session_fences[0], 1).await?;
        assert_eq!(
            first_page
                .candidates()
                .iter()
                .map(automata_ci_store::RunnableAttempt::attempt_id)
                .collect::<Vec<_>>(),
            vec![first_attempt]
        );
        assert!(
            first_page.claim_advance(second_attempt).is_err(),
            "a cross-tenant attempt cannot be smuggled into an opaque cursor proof"
        );

        let second_page = scan(&database, second.session_fences[0], 1).await?;
        assert_eq!(
            second_page
                .candidates()
                .iter()
                .map(automata_ci_store::RunnableAttempt::attempt_id)
                .collect::<Vec<_>>(),
            vec![second_attempt]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn bounded_cursor_progresses_past_more_than_one_page_of_incompatible_work() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let incompatible =
            RunnerRequirements::default().with_labels([RunnerLabel::new("unavailable-label")?]);
        let mut incompatible_attempts = Vec::new();
        for ordinal in 0_i64..4 {
            let job = insert_job_with_requirements(
                &database,
                seed.run_id,
                &format!("incompatible-{ordinal}"),
                incompatible.clone(),
            )
            .await?;
            incompatible_attempts
                .push(insert_attempt(database.store(), job, 1, 10 + ordinal).await?);
        }
        let compatible_job = insert_job(&database, seed.run_id, "compatible").await?;
        let compatible_attempt = insert_attempt(database.store(), compatible_job, 1, 20).await?;

        let first = scan_with_limit(&database, fence, 1, 2).await?;
        assert_eq!(
            first
                .candidates()
                .iter()
                .map(automata_ci_store::RunnableAttempt::attempt_id)
                .collect::<Vec<_>>(),
            incompatible_attempts[..2]
        );
        assert!(matches!(
            record_page_no_work(&database, fence, 1, &first)
                .await?
                .outcome(),
            TryClaimOutcome::NoWork
        ));

        let second = scan_with_limit(&database, fence, 1, 2).await?;
        assert_eq!(
            second
                .candidates()
                .iter()
                .map(automata_ci_store::RunnableAttempt::attempt_id)
                .collect::<Vec<_>>(),
            incompatible_attempts[2..]
        );
        record_page_no_work(&database, fence, 1, &second).await?;

        let third = scan_with_limit(&database, fence, 1, 2).await?;
        assert_eq!(third.candidates()[0].attempt_id(), compatible_attempt);
        let key = LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(1)?);
        begin_isolated_lease_request(&database, key).await?;
        let receipt = database
            .store()
            .try_claim(fresh_claim_from_page(&database, key, compatible_attempt, &third).await?)
            .await?;
        let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
            panic!(
                "the compatible tail must eventually be claimed: {:?}",
                receipt.outcome()
            );
        };
        assert_eq!(claimed.job_ir().job_id(), compatible_job);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn finite_high_water_cycle_wraps_and_eventually_reaches_new_arrivals() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let incompatible =
            RunnerRequirements::default().with_labels([RunnerLabel::new("unavailable-label")?]);
        let old_first_job =
            insert_job_with_requirements(&database, seed.run_id, "old-first", incompatible.clone())
                .await?;
        let old_second_job =
            insert_job_with_requirements(&database, seed.run_id, "old-second", incompatible)
                .await?;
        let old_first = insert_attempt(database.store(), old_first_job, 1, 10).await?;
        let old_second = insert_attempt(database.store(), old_second_job, 1, 20).await?;

        let first_page = scan_with_limit(&database, fence, 1, 1).await?;
        assert_eq!(first_page.candidates()[0].attempt_id(), old_first);
        record_page_no_work(&database, fence, 1, &first_page).await?;

        let new_job = insert_job(&database, seed.run_id, "new-compatible").await?;
        let new_attempt = insert_attempt(database.store(), new_job, 1, 30).await?;
        let second_page = scan_with_limit(&database, fence, 1, 1).await?;
        assert_eq!(
            second_page.candidates()[0].attempt_id(),
            old_second,
            "an arrival beyond the captured high-water mark cannot extend the active cycle"
        );
        record_page_no_work(&database, fence, 1, &second_page).await?;

        let mut claimed_new = false;
        for _ in 0..3 {
            let page = scan_with_limit(&database, fence, 1, 1).await?;
            let selected = page.candidates()[0].attempt_id();
            if selected == new_attempt {
                let request_key =
                    LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(1)?);
                begin_isolated_lease_request(&database, request_key).await?;
                let request =
                    fresh_claim_from_page(&database, request_key, new_attempt, &page).await?;
                assert!(matches!(
                    database.store().try_claim(request).await?.outcome(),
                    TryClaimOutcome::Claimed(_)
                ));
                claimed_new = true;
                break;
            }
            record_page_no_work(&database, fence, 1, &page).await?;
        }
        assert!(
            claimed_new,
            "finite wrap must eventually reach the new tail"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn routing_fingerprint_change_supersedes_stale_cursor_proofs() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let stale_page = scan(&database, fence, 1).await?;
        let expanded = RunnerCapabilities::new(
            fence.runner_id(),
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_max_parallel_jobs(2)?;
        sqlx::query("UPDATE runners SET capabilities = $2::jsonb WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .bind(serde_json::to_value(expanded)?)
            .execute(database.pool())
            .await?;

        let stale = record_page_no_work(&database, fence, 1, &stale_page).await?;
        assert!(matches!(
            stale.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::ScanSuperseded)
        ));
        let durable_cursor: Option<i64> = sqlx::query_scalar(
            "SELECT cursor_version FROM runner_queue_cursors WHERE runner_id = $1 AND runner_slot = 1",
        )
        .bind(fence.runner_id().as_uuid())
        .fetch_optional(database.pool())
        .await?;
        assert_eq!(durable_cursor, None);

        let refreshed = scan(&database, fence, 1).await?;
        assert_eq!(refreshed.expected_cursor_version(), 0);
        assert!(matches!(
            record_page_no_work(&database, fence, 1, &refreshed)
                .await?
                .outcome(),
            TryClaimOutcome::NoWork
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_exact_retry_replays_without_double_cursor_advancement() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let first_page = scan(&database, fence, 1).await?;
        let first_key =
            LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(1)?);
        begin_isolated_lease_request(&database, first_key).await?;
        let first_request = NoWorkLeaseRequest::new(
            first_key,
            database_now(&database).await?,
            first_page.no_work_advance(),
        )?;

        let (first, second) = tokio::join!(
            database.store().record_no_work(first_request.clone()),
            database.store().record_no_work(first_request.clone())
        );
        let first = first?;
        let second = second?;
        assert!(matches!(first.outcome(), TryClaimOutcome::NoWork));
        assert!(matches!(second.outcome(), TryClaimOutcome::NoWork));
        assert_ne!(first.was_replayed(), second.was_replayed());
        let before: i64 = sqlx::query_scalar(
            "SELECT cursor_version FROM runner_queue_cursors WHERE runner_id = $1 AND runner_slot = 1",
        )
        .bind(fence.runner_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let replay = database.store().record_no_work(first_request).await?;
        assert!(replay.was_replayed());
        assert!(matches!(replay.outcome(), TryClaimOutcome::NoWork));
        assert_eq!(replay.request_key(), first_key);
        let after: i64 = sqlx::query_scalar(
            "SELECT cursor_version FROM runner_queue_cursors WHERE runner_id = $1 AND runner_slot = 1",
        )
        .bind(fence.runner_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(before, 1);
        assert_eq!(after, before, "an exact replay cannot advance again");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn receipt_completion_fault_rolls_back_cursor_and_pending_receipt() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let page = scan(&database, fence, 2).await?;
        let request_key =
            LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(2)?);
        begin_isolated_lease_request(&database, request_key).await?;
        let request = NoWorkLeaseRequest::new(
            request_key,
            database_now(&database).await?,
            page.no_work_advance(),
        )?;
        sqlx::query(
            r"
            CREATE FUNCTION automata_test_fail_receipt_completion()
            RETURNS trigger LANGUAGE plpgsql AS $automata_test$
            BEGIN
                IF OLD.outcome = 'pending' AND NEW.outcome <> 'pending' THEN
                    RAISE EXCEPTION 'injected receipt completion failure';
                END IF;
                RETURN NEW;
            END;
            $automata_test$
            ",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            CREATE TRIGGER automata_test_fail_receipt_completion
            BEFORE UPDATE ON runner_operation_receipts
            FOR EACH ROW EXECUTE FUNCTION automata_test_fail_receipt_completion()
            ",
        )
        .execute(database.pool())
        .await?;

        assert!(
            database
                .store()
                .record_no_work(request.clone())
                .await
                .is_err()
        );
        let cursor_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_queue_cursors WHERE runner_id = $1 AND runner_slot = 2",
        )
        .bind(fence.runner_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let receipt_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_operation_receipts WHERE runner_session_id = $1 AND operation_id = $2",
        )
        .bind(fence.session_id().as_uuid())
        .bind(request_key.operation_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!((cursor_count, receipt_count), (0, 0));

        sqlx::query(
            "DROP TRIGGER automata_test_fail_receipt_completion ON runner_operation_receipts",
        )
        .execute(database.pool())
        .await?;
        sqlx::query("DROP FUNCTION automata_test_fail_receipt_completion()")
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database.store().record_no_work(request).await?.outcome(),
            TryClaimOutcome::NoWork
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn reconnect_does_not_release_a_stable_runner_slot() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let original = seed.session_fences[0];
        let occupied_attempt = insert_attempt(database.store(), seed.job_id, 1, 10).await?;
        let occupied = database
            .store()
            .try_claim(claim(&database, OperationId::new(), occupied_attempt, original, 1).await?)
            .await?;
        assert!(matches!(occupied.outcome(), TryClaimOutcome::Claimed(_)));

        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                original.runner_id(),
                original.runner_generation(),
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                runner_capability_document(database.pool(), original.runner_id()).await?,
                database_now(&database).await?,
            ))
            .await?;
        let blocked_job = insert_job(&database, seed.run_id, "reconnect-blocked").await?;
        let blocked_attempt = insert_attempt(database.store(), blocked_job, 1, 11).await?;
        let blocked = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    blocked_attempt,
                    replacement.fence(),
                    1,
                )
                .await?,
            )
            .await?;
        assert!(matches!(
            blocked.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::SlotOccupied { attempt_id })
                if *attempt_id == occupied_attempt
        ));

        let free_job = insert_job(&database, seed.run_id, "reconnect-free").await?;
        let free_attempt = insert_attempt(database.store(), free_job, 1, 12).await?;
        let free = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    free_attempt,
                    replacement.fence(),
                    2,
                )
                .await?,
            )
            .await?;
        assert!(matches!(free.outcome(), TryClaimOutcome::Claimed(_)));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn exact_slot_availability_is_fenced_bounded_and_assignment_aware() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let original = seed.session_fences[0];
        sqlx::query("UPDATE runners SET slots = 1 WHERE id = $1")
            .bind(original.runner_id().as_uuid())
            .execute(database.pool())
            .await?;

        assert_eq!(
            database
                .store()
                .slot_availability(
                    original,
                    StableRunnerSlot::new(1)?,
                    database_now(&database).await?,
                )
                .await?,
            RunnerSlotAvailability::Available
        );
        assert_eq!(
            database
                .store()
                .slot_availability(
                    original,
                    StableRunnerSlot::new(2)?,
                    database_now(&database).await?,
                )
                .await?,
            RunnerSlotAvailability::OutOfRange
        );

        let occupied_attempt = insert_attempt(database.store(), seed.job_id, 1, 11).await?;
        claim_success(
            &database,
            claim(&database, OperationId::new(), occupied_attempt, original, 1).await?,
        )
        .await?;
        assert_eq!(
            database
                .store()
                .slot_availability(
                    original,
                    StableRunnerSlot::new(1)?,
                    database_now(&database).await?,
                )
                .await?,
            RunnerSlotAvailability::Occupied {
                attempt_id: occupied_attempt,
            }
        );

        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                original.runner_id(),
                original.runner_generation(),
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                runner_capability_document(database.pool(), original.runner_id()).await?,
                database_now(&database).await?,
            ))
            .await?;
        assert!(
            database
                .store()
                .slot_availability(
                    original,
                    StableRunnerSlot::new(1)?,
                    database_now(&database).await?,
                )
                .await
                .is_err(),
            "a superseded session fence must not inspect capacity"
        );
        assert_eq!(
            database
                .store()
                .slot_availability(
                    replacement.fence(),
                    StableRunnerSlot::new(1)?,
                    database_now(&database).await?,
                )
                .await?,
            RunnerSlotAvailability::Occupied {
                attempt_id: occupied_attempt,
            },
            "stable slot occupancy survives reconnect"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn draining_between_availability_and_claim_rejects_without_dequeuing() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        sqlx::query("UPDATE runners SET slots = 1, status = 'online' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert_eq!(
            database
                .store()
                .slot_availability(
                    fence,
                    StableRunnerSlot::new(1)?,
                    database_now(&database).await?,
                )
                .await?,
            RunnerSlotAvailability::Available
        );

        let attempt_id = insert_attempt(database.store(), seed.job_id, 1, 11).await?;
        let page = scan(&database, fence, 1).await?;
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let claim_key =
            LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(1)?);
        begin_isolated_lease_request(&database, claim_key).await?;
        let claim_request = fresh_claim_from_page(&database, claim_key, attempt_id, &page).await?;
        let receipt = database.store().try_claim(claim_request.clone()).await?;
        assert!(matches!(
            receipt.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::NotRoutable)
        ));
        assert!(
            database
                .store()
                .try_claim(claim_request)
                .await?
                .was_replayed(),
            "a draining authority rejection must replay exactly"
        );
        assert_eq!(
            database.store().get_attempt(attempt_id).await?.lifecycle(),
            JobLifecycle::Queued
        );
        let no_work_key =
            LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(1)?);
        begin_isolated_lease_request(&database, no_work_key).await?;
        let no_work_request = NoWorkLeaseRequest::new(
            no_work_key,
            database_now(&database).await?,
            page.no_work_advance(),
        )?;
        let no_work = database
            .store()
            .record_no_work(no_work_request.clone())
            .await?;
        assert!(matches!(
            no_work.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::NotRoutable)
        ));
        assert!(
            database
                .store()
                .record_no_work(no_work_request)
                .await?
                .was_replayed(),
            "a draining no-work rejection must replay exactly"
        );
        let outcomes: Vec<String> = sqlx::query_scalar(
            r"
            SELECT outcome
            FROM runner_operation_receipts
            WHERE runner_session_id = $1 AND operation_id IN ($2, $3)
            ORDER BY operation_id
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(claim_key.operation_id().as_uuid())
        .bind(no_work_key.operation_id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(outcomes, vec!["authority_rejected"]);
        let cursor_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM runner_queue_cursors WHERE runner_id = $1")
                .bind(fence.runner_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(cursor_count, 0, "draining must not consume a scan cursor");
        assert_eq!(
            database
                .store()
                .slot_availability(
                    fence,
                    StableRunnerSlot::new(1)?,
                    database_now(&database).await?,
                )
                .await?,
            RunnerSlotAvailability::RunnerUnavailable
        );
        let resumed = database
            .store()
            .resume_session(ResumeRunnerSession::new(
                fence.runner_id(),
                fence.runner_generation(),
                fence.session_id(),
                CommandCursor::initial(),
                database_now(&database).await?,
            ))
            .await?;
        assert_eq!(resumed.fence(), fence);
        assert!(matches!(
            database
                .store()
                .open_session(OpenRunnerSession::new(
                    RunnerSessionId::new(),
                    fence.runner_id(),
                    fence.runner_generation(),
                    RunnerProtocolVersion::new(1)?,
                    JobIrVersion::current(),
                    runner_capability_document(database.pool(), fence.runner_id()).await?,
                    database_now(&database).await?,
                ))
                .await,
            Err(StoreError::RunnerNotAcceptingWork(id)) if id == fence.runner_id()
        ));
        database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                fence,
                CommandCursor::initial(),
                database_now(&database).await?,
            ))
            .await?;
        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let disabled_observed_at = database_now(&database).await?;
        assert!(matches!(
            database
                .store()
                .try_claim(TryClaimAttempt::new(
                    LeaseRequestKey::first(
                        fence,
                        OperationId::new(),
                        StableRunnerSlot::new(1)?,
                    ),
                    attempt_id,
                    LeaseId::new(),
                    disabled_observed_at,
                    checked_add_millis(disabled_observed_at, TEST_LEASE_DURATION_MILLIS)?,
                    page.claim_advance(attempt_id)?,
                )?)
                .await,
            Err(StoreError::RunnerDisabled(id)) if id == fence.runner_id()
        ));
        assert!(matches!(
            database
                .store()
                .heartbeat_session(HeartbeatRunnerSession::new(
                    fence,
                    CommandCursor::initial(),
                    database_now(&database).await?,
                ))
                .await,
            Err(StoreError::RunnerDisabled(id)) if id == fence.runner_id()
        ));
        database
            .store()
            .close_session(CloseRunnerSession::new(
                fence,
                database_now(&database).await?,
            ))
            .await?;
        let observed_status: String =
            sqlx::query_scalar("SELECT status FROM runners WHERE id = $1")
                .bind(fence.runner_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(observed_status, "offline");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn routing_labels_are_case_insensitive_and_case_folded_duplicates_are_corrupt() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        sqlx::query("UPDATE runners SET labels = ARRAY['LINUX'], slots = 1 WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let labeled_job = insert_job_with_requirements(
            &database,
            seed.run_id,
            "labeled-job",
            RunnerRequirements::default().with_labels([RunnerLabel::new("linux")?]),
        )
        .await?;
        let attempt_id = insert_attempt(database.store(), labeled_job, 1, 10).await?;
        let receipt = database
            .store()
            .try_claim(claim(&database, OperationId::new(), attempt_id, fence, 1).await?)
            .await?;
        assert!(matches!(receipt.outcome(), TryClaimOutcome::Claimed(_)));

        sqlx::query("UPDATE runners SET labels = ARRAY['Linux', 'linux'] WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database.store().routing_for_session(fence).await,
            Err(StoreError::CorruptData(_))
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn claims_intersect_registered_and_observed_machine_capabilities() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let runner_id = seed.runner_ids[0];
        assert!(matches!(
            database
                .store()
                .open_session(OpenRunnerSession::new(
                    RunnerSessionId::new(),
                    runner_id,
                    RunnerGeneration::new(1)?,
                    RunnerProtocolVersion::new(1)?,
                    JobIrVersion::current(),
                    automata_ci_store::RoutingDocument::new("{}")?,
                    database_now(&database).await?,
                ))
                .await,
            Err(StoreError::InvalidCapabilitySnapshot(id)) if id == runner_id
        ));
        let feature = RunnerFeature::new("example.test/cache@v1")?;
        let registered = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_features([feature.clone()])
        .with_max_parallel_jobs(3)?;
        sqlx::query("UPDATE runners SET capabilities = $2::jsonb WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(&registered)?)
            .execute(database.pool())
            .await?;

        let observed_without_feature = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_max_parallel_jobs(3)?;
        let first_session = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                runner_id,
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                capability_document(&observed_without_feature)?,
                database_now(&database).await?,
            ))
            .await?;
        let feature_job = insert_job_with_requirements(
            &database,
            seed.run_id,
            "feature-job",
            RunnerRequirements::default().with_features([feature.clone()]),
        )
        .await?;
        let feature_attempt = insert_attempt(database.store(), feature_job, 1, 11).await?;
        let absent = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    feature_attempt,
                    first_session.fence(),
                    1,
                )
                .await?,
            )
            .await?;
        assert!(matches!(
            absent.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::NotRoutable)
        ));

        let observed_with_feature = registered.clone();
        let feature_session = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                runner_id,
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                capability_document(&observed_with_feature)?,
                database_now(&database).await?,
            ))
            .await?;
        let present = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    feature_attempt,
                    feature_session.fence(),
                    1,
                )
                .await?,
            )
            .await?;
        assert!(matches!(present.outcome(), TryClaimOutcome::Claimed(_)));

        let self_label = RunnerLabel::new("self-only")?;
        let self_group = RunnerGroup::new("self-group")?;
        let self_advertised = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        )
        .with_labels([self_label.clone()])
        .with_groups([self_group.clone()])
        .with_features([feature.clone()])
        .with_max_parallel_jobs(3)?;
        sqlx::query("UPDATE runners SET capabilities = $2::jsonb WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(serde_json::to_value(&self_advertised)?)
            .execute(database.pool())
            .await?;
        let selector_session = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                runner_id,
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                JobIrVersion::current(),
                capability_document(&self_advertised)?,
                database_now(&database).await?,
            ))
            .await?;
        let selector_requirements = RunnerRequirements::default()
            .with_labels([self_label])
            .with_eligible_groups([self_group, RunnerGroup::new("alternate-eligible-group")?])
            .with_features([feature]);
        let selector_job = insert_job_with_requirements(
            &database,
            seed.run_id,
            "selector-job",
            selector_requirements,
        )
        .await?;
        let selector_attempt = insert_attempt(database.store(), selector_job, 1, 31).await?;
        let self_routed = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    selector_attempt,
                    selector_session.fence(),
                    2,
                )
                .await?,
            )
            .await?;
        assert!(matches!(
            self_routed.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::NotRoutable)
        ));

        let runner_group_id = uuid::Uuid::new_v4();
        sqlx::query(
            r"
            INSERT INTO runner_groups (
                id, tenant_id, name, normalized_name, created_at_ms, updated_at_ms
            )
            VALUES ($1, $2, 'Self Group', 'self-group', 33, 33)
            ",
        )
        .bind(runner_group_id)
        .bind(&seed.tenant_id)
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE runners SET group_id = $2, labels = ARRAY['self-only'] WHERE id = $1")
            .bind(runner_id.as_uuid())
            .bind(runner_group_id)
            .execute(database.pool())
            .await?;
        let server_routed = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    selector_attempt,
                    selector_session.fence(),
                    2,
                )
                .await?,
            )
            .await?;
        assert!(matches!(
            server_routed.outcome(),
            TryClaimOutcome::Claimed(_)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn expiry_only_requeues_work_that_never_started_running() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let mut attempts = Vec::new();
        let mut claims = Vec::new();
        for ordinal in 1_u16..=5 {
            let job = insert_job(&database, seed.run_id, &format!("expiry-{ordinal}")).await?;
            let attempt = insert_attempt(database.store(), job, 1, i64::from(ordinal)).await?;
            let receipt = database
                .store()
                .try_claim(claim(&database, OperationId::new(), attempt, fence, ordinal).await?)
                .await?;
            let claimed = match receipt.outcome() {
                TryClaimOutcome::Claimed(claimed) => claimed.clone(),
                outcome @ TryClaimOutcome::Rejected(_) => {
                    panic!("expiry fixture claim must succeed: {outcome:?}")
                }
                TryClaimOutcome::NoWork => panic!("fixture unexpectedly returned no work"),
            };
            attempts.push(attempt);
            claims.push(claimed);
        }

        transition_path(
            &database,
            attempts[1],
            &claims[1],
            &[JobLifecycle::Preparing],
        )
        .await?;
        transition_path(
            &database,
            attempts[2],
            &claims[2],
            &[JobLifecycle::Preparing, JobLifecycle::Running],
        )
        .await?;
        transition_path(
            &database,
            attempts[3],
            &claims[3],
            &[
                JobLifecycle::Preparing,
                JobLifecycle::Running,
                JobLifecycle::Cancelling,
            ],
        )
        .await?;
        transition_path(
            &database,
            attempts[4],
            &claims[4],
            &[
                JobLifecycle::Preparing,
                JobLifecycle::Running,
                JobLifecycle::Finalizing,
            ],
        )
        .await?;

        let processed =
            requeue_at_exact_database_expiry(&database, &clock, &attempts, 10, 10).await?;
        assert_eq!(processed.len(), 5);
        for attempt in &attempts[..2] {
            assert_eq!(
                database.store().get_attempt(*attempt).await?.lifecycle(),
                JobLifecycle::Queued
            );
        }
        for attempt in &attempts[2..] {
            assert_eq!(
                database.store().get_attempt(*attempt).await?.lifecycle(),
                JobLifecycle::Lost,
                "running, cancelling, and finalizing attempts must fail closed"
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn runnable_scan_and_claim_recheck_run_dag_cancellation_and_concurrency() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let missing_job = JobId::new();
        assert!(matches!(
            database.store().get_job_ir_metadata(missing_job).await,
            Err(StoreError::JobNotFound(job_id)) if job_id == missing_job
        ));
        let prerequisite_attempt = insert_attempt(database.store(), seed.job_id, 1, 10).await?;
        let dependent_job = insert_job(&database, seed.run_id, "dependent").await?;
        let dependent_attempt = insert_attempt(database.store(), dependent_job, 1, 11).await?;
        let stale_dependent_page = scan(&database, fence, 2).await?;
        database
            .store()
            .insert_dependency(JobDependency::new(seed.run_id, dependent_job, seed.job_id)?)
            .await?;

        let runnable = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                StableRunnerSlot::new(1)?,
                RunnableScanLimit::new(10)?,
                database_now(&database).await?,
            ))
            .await?;
        assert_eq!(
            runnable
                .candidates()
                .iter()
                .map(automata_ci_store::RunnableAttempt::attempt_id)
                .collect::<Vec<_>>(),
            vec![prerequisite_attempt]
        );
        let blocked_operation = OperationId::new();
        let blocked_key =
            LeaseRequestKey::first(fence, blocked_operation, StableRunnerSlot::new(2)?);
        begin_isolated_lease_request(&database, blocked_key).await?;
        let blocked_claim = fresh_claim_from_page(
            &database,
            blocked_key,
            dependent_attempt,
            &stale_dependent_page,
        )
        .await?;
        let blocked = database.store().try_claim(blocked_claim.clone()).await?;
        assert!(matches!(
            blocked.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable)
        ));

        let prerequisite = database
            .store()
            .try_claim(
                claim(
                    &database,
                    OperationId::new(),
                    prerequisite_attempt,
                    fence,
                    1,
                )
                .await?,
            )
            .await?;
        let prerequisite = match prerequisite.outcome() {
            TryClaimOutcome::Claimed(claimed) => claimed,
            outcome @ TryClaimOutcome::Rejected(_) => {
                panic!("prerequisite claim must succeed: {outcome:?}")
            }
            TryClaimOutcome::NoWork => panic!("fixture unexpectedly returned no work"),
        };
        transition_path(
            &database,
            prerequisite_attempt,
            prerequisite,
            &[
                JobLifecycle::Preparing,
                JobLifecycle::Running,
                JobLifecycle::Finalizing,
                JobLifecycle::Succeeded,
            ],
        )
        .await?;

        let replayed_negative = database.store().try_claim(blocked_claim).await?;
        assert!(replayed_negative.was_replayed());
        assert!(matches!(
            replayed_negative.outcome(),
            TryClaimOutcome::Rejected(ClaimRejection::NoLongerRunnable)
        ));
        let runnable = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                StableRunnerSlot::new(1)?,
                RunnableScanLimit::new(10)?,
                database_now(&database).await?,
            ))
            .await?;
        assert_eq!(runnable.candidates().len(), 1);
        assert_eq!(runnable.candidates()[0].attempt_id(), dependent_attempt);

        sqlx::query(
            r"
            INSERT INTO concurrency_groups (
                repository_id, normalized_key, display_key, updated_at_ms
            )
            VALUES ($1, 'g1', 'g1', 30)
            ",
        )
        .bind(seed.repository_id)
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE workflow_runs SET concurrency_group_key = 'g1' WHERE id = $1")
            .bind(seed.run_id.as_uuid())
            .execute(database.pool())
            .await?;
        assert!(
            database
                .store()
                .scan_runnable(RunnableScanRequest::new(
                    fence,
                    StableRunnerSlot::new(1)?,
                    RunnableScanLimit::new(10)?,
                    database_now(&database).await?,
                ))
                .await?
                .candidates()
                .is_empty()
        );
        sqlx::query(
            r"
            UPDATE concurrency_groups
            SET running_run_id = $2
            WHERE repository_id = $1 AND normalized_key = 'g1'
            ",
        )
        .bind(seed.repository_id)
        .bind(seed.run_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(
            database
                .store()
                .scan_runnable(RunnableScanRequest::new(
                    fence,
                    StableRunnerSlot::new(1)?,
                    RunnableScanLimit::new(10)?,
                    database_now(&database).await?,
                ))
                .await?
                .candidates()[0]
                .attempt_id(),
            dependent_attempt
        );

        let cancellation_at = database_now(&database).await?;
        let cancellation = RequestCancellation::new(
            OperationId::new(),
            dependent_attempt,
            CancellationActor::new("scheduler")?,
            None,
            cancellation_at,
        );
        database.store().request_cancellation(cancellation).await?;
        assert!(
            database
                .store()
                .scan_runnable(RunnableScanRequest::new(
                    fence,
                    StableRunnerSlot::new(1)?,
                    RunnableScanLimit::new(10)?,
                    database_now(&database).await?,
                ))
                .await?
                .candidates()
                .is_empty()
        );
        assert_eq!(
            database
                .store()
                .get_attempt(dependent_attempt)
                .await?
                .lifecycle(),
            JobLifecycle::Cancelled
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn blocked_dependency_reconciliation_uses_latest_prerequisite_attempt() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];

        let failed_job = insert_job(&database, seed.run_id, "failed-prerequisite").await?;
        let skipped_job = insert_job(&database, seed.run_id, "must-skip").await?;
        let failed_attempt = insert_attempt(database.store(), failed_job, 1, 10).await?;
        let skipped_attempt = insert_attempt(database.store(), skipped_job, 1, 11).await?;
        database
            .store()
            .insert_dependency(JobDependency::new(seed.run_id, skipped_job, failed_job)?)
            .await?;
        let failed_claim = claim_success(
            &database,
            claim(&database, OperationId::new(), failed_attempt, fence, 1).await?,
        )
        .await?;
        transition_path(
            &database,
            failed_attempt,
            &failed_claim,
            &[
                JobLifecycle::Preparing,
                JobLifecycle::Running,
                JobLifecycle::Finalizing,
                JobLifecycle::Failed,
            ],
        )
        .await?;

        let retry_job = insert_job(&database, seed.run_id, "retry-prerequisite").await?;
        let retry_dependent_job = insert_job(&database, seed.run_id, "retry-dependent").await?;
        let first_retry_attempt = insert_attempt(database.store(), retry_job, 1, 30).await?;
        let retry_dependent_attempt =
            insert_attempt(database.store(), retry_dependent_job, 1, 31).await?;
        database
            .store()
            .insert_dependency(JobDependency::new(
                seed.run_id,
                retry_dependent_job,
                retry_job,
            )?)
            .await?;
        let first_retry_claim = claim_success(
            &database,
            claim(&database, OperationId::new(), first_retry_attempt, fence, 1).await?,
        )
        .await?;
        transition_path(
            &database,
            first_retry_attempt,
            &first_retry_claim,
            &[
                JobLifecycle::Preparing,
                JobLifecycle::Running,
                JobLifecycle::Finalizing,
                JobLifecycle::Failed,
            ],
        )
        .await?;

        sqlx::query(
            r"
            INSERT INTO concurrency_groups (
                repository_id, normalized_key, display_key, updated_at_ms
            )
            VALUES ($1, 'blocked', 'blocked', 40)
            ",
        )
        .bind(seed.repository_id)
        .execute(database.pool())
        .await?;
        sqlx::query("UPDATE workflow_runs SET concurrency_group_key = 'blocked' WHERE id = $1")
            .bind(seed.run_id.as_uuid())
            .execute(database.pool())
            .await?;

        let blocked_at = database_now(&database).await?;
        let blocked = database
            .store()
            .scan_blocked(RunnableScanLimit::new(10)?, blocked_at)
            .await?;
        assert_eq!(
            blocked
                .iter()
                .map(|candidate| candidate.attempt_id())
                .collect::<std::collections::BTreeSet<_>>(),
            [skipped_attempt, retry_dependent_attempt]
                .into_iter()
                .collect(),
            "terminal dependency failure outranks concurrency admission"
        );
        assert_eq!(
            database
                .store()
                .conclude_blocked(ConcludeBlockedAttempt::new(skipped_attempt, blocked_at,))
                .await?,
            BlockedConclusion::Skipped
        );
        let replay_at = database_now(&database).await?;
        assert_eq!(
            database
                .store()
                .conclude_blocked(ConcludeBlockedAttempt::new(skipped_attempt, replay_at,))
                .await?,
            BlockedConclusion::AlreadySkipped
        );

        let latest_retry = insert_attempt(database.store(), retry_job, 2, 51).await?;
        let retry_observed_at = database_now(&database).await?;
        assert_eq!(
            database
                .store()
                .conclude_blocked(ConcludeBlockedAttempt::new(
                    retry_dependent_attempt,
                    retry_observed_at,
                ))
                .await?,
            BlockedConclusion::NoLongerBlocked,
            "a new queued retry becomes the latest prerequisite attempt"
        );
        assert!(
            database
                .store()
                .scan_blocked(RunnableScanLimit::new(10)?, retry_observed_at)
                .await?
                .is_empty()
        );

        sqlx::query(
            r"
            UPDATE concurrency_groups
            SET running_run_id = $2
            WHERE repository_id = $1 AND normalized_key = 'blocked'
            ",
        )
        .bind(seed.repository_id)
        .bind(seed.run_id.as_uuid())
        .execute(database.pool())
        .await?;
        let latest_claim = claim_success(
            &database,
            claim(&database, OperationId::new(), latest_retry, fence, 1).await?,
        )
        .await?;
        transition_path(
            &database,
            latest_retry,
            &latest_claim,
            &[
                JobLifecycle::Preparing,
                JobLifecycle::Running,
                JobLifecycle::Finalizing,
                JobLifecycle::Succeeded,
            ],
        )
        .await?;
        let runnable_at = database_now(&database).await?;
        let runnable = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                StableRunnerSlot::new(1)?,
                RunnableScanLimit::new(10)?,
                runnable_at,
            ))
            .await?;
        assert!(
            runnable
                .candidates()
                .iter()
                .any(|candidate| candidate.attempt_id() == retry_dependent_attempt),
            "a successful latest retry supersedes an older failure"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn encrypted_runner_payloads_survive_replica_restart_without_plaintext_at_rest() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let sentinel = b"runner-payload-plaintext-sentinel";
        let operation_id = OperationId::new();
        let request = RunnerOperationRequest::new(
            fence,
            OperationId::new(),
            RunnerOperationKind::new("automata.encrypted-receipt.v1")?,
            Sha256Digest::from_bytes([0x51; 32]),
        );

        let writer = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(test_runner_payload_key_provider());
        let durable = writer
            .enqueue_command(command(
                fence,
                operation_id,
                "automata.encrypted-command.v1",
                database_now(&database).await?,
                sentinel,
            )?)
            .await?;
        writer
            .record_operation(
                request.clone(),
                RunnerOperationResponse::new(DocumentSchema::new(1)?, sentinel.to_vec())?,
                database_now(&database).await?,
            )
            .await?;

        let command_parts: (String, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r"
            SELECT wrapping_key_id, wrapped_data_key, nonce, ciphertext
            FROM runner_command_outbox
            WHERE runner_session_id = $1 AND command_sequence = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(i64::try_from(durable.sequence().get())?)
        .fetch_one(database.pool())
        .await?;
        let receipt_parts: (String, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r"
            SELECT wrapping_key_id, wrapped_data_key, nonce, ciphertext
            FROM runner_rpc_receipts
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(request.operation_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let sentinel_text = std::str::from_utf8(sentinel)?;
        assert!(!command_parts.0.contains(sentinel_text));
        assert!(!receipt_parts.0.contains(sentinel_text));
        for durable_part in [
            &command_parts.1,
            &command_parts.2,
            &command_parts.3,
            &receipt_parts.1,
            &receipt_parts.2,
            &receipt_parts.3,
        ] {
            assert!(
                !durable_part
                    .windows(sentinel.len())
                    .any(|window| window == sentinel),
                "no envelope column may retain the plaintext sentinel"
            );
        }

        drop(writer);
        let restarted_replica = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(test_runner_payload_key_provider());
        let replay = restarted_replica
            .replay_commands(
                fence,
                CommandCursor::initial(),
                CommandReplayLimit::new(10)?,
            )
            .await?;
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].request().payload().bytes(), sentinel);
        assert_eq!(
            restarted_replica
                .lookup_operation(&request)
                .await?
                .expect("encrypted receipt")
                .response()
                .payload(),
            sentinel
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn encrypted_runner_payloads_authenticate_metadata_tenant_purpose_and_row_identity()
-> TestResult {
    run_with_database(|database| async move {
        let tenant_a = seed_control_plane(database.pool(), 1).await?;
        let tenant_b = seed_control_plane(database.pool(), 1).await?;
        let fence_a = tenant_a.session_fences[0];
        let fence_b = tenant_b.session_fences[0];
        let store = database.store();

        let first = store
            .enqueue_command(command(
                fence_a,
                OperationId::new(),
                "automata.context-a.v1",
                database_now(&database).await?,
                b"same-length-a",
            )?)
            .await?;
        let second = store
            .enqueue_command(command(
                fence_a,
                OperationId::new(),
                "automata.context-a.v1",
                database_now(&database).await?,
                b"same-length-b",
            )?)
            .await?;
        let other_tenant = store
            .enqueue_command(command(
                fence_b,
                OperationId::new(),
                "automata.context-b.v1",
                database_now(&database).await?,
                b"same-length-c",
            )?)
            .await?;

        let response_request = RunnerOperationRequest::new(
            fence_a,
            OperationId::new(),
            RunnerOperationKind::new("automata.context-response.v1")?,
            Sha256Digest::from_bytes([0x44; 32]),
        );
        store
            .record_operation(
                response_request.clone(),
                RunnerOperationResponse::new(DocumentSchema::new(1)?, b"same-length-r".to_vec())?,
                database_now(&database).await?,
            )
            .await?;

        let command_kind_tamper = sqlx::query(
            r"
            UPDATE runner_command_outbox
            SET command_kind = 'automata.tampered-command.v1'
            WHERE runner_session_id = $1 AND command_sequence = $2
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(i64::try_from(first.sequence().get())?)
        .execute(database.pool())
        .await
        .expect_err("authenticated command kind must be immutable");
        assert_database_constraint(
            &command_kind_tamper,
            "runner_command_outbox_metadata_immutable",
        );

        let command_timestamp_tamper = sqlx::query(
            r"
            UPDATE runner_command_outbox
            SET created_at_ms = created_at_ms + 1
            WHERE runner_session_id = $1 AND command_sequence = $2
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(i64::try_from(first.sequence().get())?)
        .execute(database.pool())
        .await
        .expect_err("authenticated command timestamp must be immutable");
        assert_database_constraint(
            &command_timestamp_tamper,
            "runner_command_outbox_metadata_immutable",
        );

        let response_schema_tamper = sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET response_schema = 2
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(response_request.operation_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("authenticated response schema must be immutable");
        assert_database_constraint(
            &response_schema_tamper,
            "runner_rpc_receipts_metadata_immutable",
        );

        let response_timestamp_tamper = sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET committed_at_ms = committed_at_ms + 1
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(response_request.operation_id().as_uuid())
        .execute(database.pool())
        .await
        .expect_err("authenticated response timestamp must be immutable");
        assert_database_constraint(
            &response_timestamp_tamper,
            "runner_rpc_receipts_metadata_immutable",
        );

        let purpose_swap = sqlx::query(
            r"
            UPDATE runner_rpc_receipts AS target
            SET response_plaintext_size_bytes = source.command_plaintext_size_bytes,
                envelope_schema = source.envelope_schema,
                wrapping_key_id = source.wrapping_key_id,
                wrapped_data_key = source.wrapped_data_key,
                nonce = source.nonce,
                ciphertext = source.ciphertext
            FROM runner_command_outbox AS source
            WHERE target.runner_session_id = $1 AND target.operation_id = $2
              AND source.runner_session_id = $1 AND source.command_sequence = $3
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(response_request.operation_id().as_uuid())
        .bind(i64::try_from(first.sequence().get())?)
        .execute(database.pool())
        .await
        .expect_err("live RPC response envelope must be immutable");
        assert_database_constraint(&purpose_swap, "runner_rpc_receipts_envelope_immutable");

        let row_swap = sqlx::query(
            r"
            UPDATE runner_command_outbox AS target
            SET command_plaintext_size_bytes = source.command_plaintext_size_bytes,
                envelope_schema = source.envelope_schema,
                wrapping_key_id = source.wrapping_key_id,
                wrapped_data_key = source.wrapped_data_key,
                nonce = source.nonce,
                ciphertext = source.ciphertext
            FROM runner_command_outbox AS source
            WHERE target.runner_session_id = $1 AND target.command_sequence = $2
              AND source.runner_session_id = $1 AND source.command_sequence = $3
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(i64::try_from(second.sequence().get())?)
        .bind(i64::try_from(first.sequence().get())?)
        .execute(database.pool())
        .await
        .expect_err("live command envelope must be immutable across row identity");
        assert_database_constraint(&row_swap, "runner_command_outbox_envelope_immutable");

        let tenant_swap = sqlx::query(
            r"
            UPDATE runner_command_outbox AS target
            SET command_plaintext_size_bytes = source.command_plaintext_size_bytes,
                envelope_schema = source.envelope_schema,
                wrapping_key_id = source.wrapping_key_id,
                wrapped_data_key = source.wrapped_data_key,
                nonce = source.nonce,
                ciphertext = source.ciphertext
            FROM runner_command_outbox AS source
            WHERE target.runner_session_id = $1 AND target.command_sequence = $2
              AND source.runner_session_id = $3 AND source.command_sequence = $4
            ",
        )
        .bind(fence_a.session_id().as_uuid())
        .bind(i64::try_from(first.sequence().get())?)
        .bind(fence_b.session_id().as_uuid())
        .bind(i64::try_from(other_tenant.sequence().get())?)
        .execute(database.pool())
        .await
        .expect_err("live command envelope must be immutable across tenants");
        assert_database_constraint(&tenant_swap, "runner_command_outbox_envelope_immutable");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn runner_payload_access_fails_closed_without_encryption_configuration() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let raw_store = PostgresStore::from_postgres_pool(database.pool().clone());
        let request = RunnerOperationRequest::new(
            fence,
            OperationId::new(),
            RunnerOperationKind::new("automata.unconfigured.v1")?,
            Sha256Digest::from_bytes([0x73; 32]),
        );

        assert!(matches!(
            raw_store
                .enqueue_command(command(
                    fence,
                    OperationId::new(),
                    "automata.unconfigured.v1",
                    database_now(&database).await?,
                    b"must-not-persist",
                )?)
                .await,
            Err(StoreError::RunnerPayloadEncryptionUnavailable)
        ));
        assert!(matches!(
            raw_store
                .record_operation(
                    request.clone(),
                    RunnerOperationResponse::new(
                        DocumentSchema::new(1)?,
                        b"must-not-persist".to_vec(),
                    )?,
                    database_now(&database).await?,
                )
                .await,
            Err(StoreError::RunnerPayloadEncryptionUnavailable)
        ));
        assert!(matches!(
            raw_store.lookup_operation(&request).await,
            Err(StoreError::RunnerPayloadEncryptionUnavailable)
        ));
        assert!(matches!(
            raw_store
                .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?,)
                .await,
            Err(StoreError::RunnerPayloadEncryptionUnavailable)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn maximum_runner_command_payload_round_trips_through_envelope_storage() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let payload = vec![0xa7; MAX_COMMAND_REPLAY_BYTES];
        database
            .store()
            .enqueue_command(command(
                fence,
                OperationId::new(),
                "automata.maximum-command.v1",
                database_now(&database).await?,
                &payload,
            )?)
            .await?;
        let replay = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].request().payload().bytes(), payload);
        Ok(())
    })
    .await
}

fn command(
    fence: automata_ci_store::RunnerSessionFence,
    operation_id: OperationId,
    kind: &str,
    created_at: UnixMillis,
    payload: &[u8],
) -> TestResult<EnqueueRunnerCommand> {
    Ok(EnqueueRunnerCommand::new(
        fence,
        operation_id,
        RunnerOperationKind::new(kind)?,
        automata_ci_store::RunnerCommandPayload::new(DocumentSchema::new(1)?, payload.to_vec())?,
        created_at,
    ))
}

fn cancellation_command(
    fence: automata_ci_store::RunnerSessionFence,
    operation_id: OperationId,
    attempt_id: AttemptId,
    guard: automata_ci_core::LeaseGuard,
    protocol_version: RunnerProtocolVersion,
    reason: &str,
    requested_at: UnixMillis,
) -> TestResult<EnqueueRunnerCommand> {
    let payload =
        CancelJobCommandPayload::new(attempt_id, guard, protocol_version, reason, requested_at)?
            .encode_json()?;
    Ok(EnqueueRunnerCommand::new(
        fence,
        operation_id,
        RunnerOperationKind::new(CANCEL_JOB_COMMAND_KIND)?,
        automata_ci_store::RunnerCommandPayload::new(
            DocumentSchema::new(CANCEL_JOB_COMMAND_SCHEMA)?,
            payload,
        )?,
        requested_at,
    ))
}

fn capability_document(
    capabilities: &RunnerCapabilities,
) -> TestResult<automata_ci_store::RoutingDocument> {
    Ok(automata_ci_store::RoutingDocument::new(
        serde_json::to_string(capabilities)?,
    )?)
}

fn assert_database_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.constraint()),
        Some(expected)
    );
}

async fn scan(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
    slot: u16,
) -> TestResult<automata_ci_store::RunnableScanPage> {
    scan_with_limit(database, fence, slot, 10).await
}

async fn scan_with_limit(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
    slot: u16,
    limit: u16,
) -> TestResult<automata_ci_store::RunnableScanPage> {
    let observed_at = database_now(database).await?;
    Ok(database
        .store()
        .scan_runnable(RunnableScanRequest::new(
            fence,
            StableRunnerSlot::new(slot)?,
            RunnableScanLimit::new(limit)?,
            observed_at,
        ))
        .await?)
}

async fn record_page_no_work(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
    slot: u16,
    page: &automata_ci_store::RunnableScanPage,
) -> TestResult<automata_ci_store::TryClaimReceipt> {
    let request_key =
        LeaseRequestKey::first(fence, OperationId::new(), StableRunnerSlot::new(slot)?);
    begin_isolated_lease_request(database, request_key).await?;
    Ok(database
        .store()
        .record_no_work(NoWorkLeaseRequest::new(
            request_key,
            database_now(database).await?,
            page.no_work_advance(),
        )?)
        .await?)
}

async fn claim(
    database: &TestDatabase,
    operation_id: OperationId,
    attempt_id: AttemptId,
    fence: automata_ci_store::RunnerSessionFence,
    slot: u16,
) -> TestResult<TryClaimAttempt> {
    let request_key = LeaseRequestKey::first(fence, operation_id, StableRunnerSlot::new(slot)?);
    begin_isolated_lease_request(database, request_key).await?;
    let page = scan(database, fence, slot).await?;
    fresh_claim_from_page(database, request_key, attempt_id, &page).await
}

async fn fresh_claim_from_page(
    database: &TestDatabase,
    request_key: LeaseRequestKey,
    attempt_id: AttemptId,
    page: &automata_ci_store::RunnableScanPage,
) -> TestResult<TryClaimAttempt> {
    let observed_at = database_now(database).await?;
    Ok(TryClaimAttempt::new(
        request_key,
        attempt_id,
        LeaseId::new(),
        observed_at,
        checked_add_millis(observed_at, TEST_LEASE_DURATION_MILLIS)?,
        page.claim_advance(attempt_id)?,
    )?)
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
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

async fn requeue_at_exact_database_expiry(
    database: &TestDatabase,
    clock: &TestClock,
    attempt_ids: &[AttemptId],
    maximum_failures: u32,
    limit: u32,
) -> TestResult<Vec<AttemptId>> {
    let durable_attempt_ids = attempt_ids
        .iter()
        .map(|attempt_id| attempt_id.as_uuid())
        .collect::<Vec<_>>();
    let exact_expiry = UnixMillis::new(
        sqlx::query_scalar(
            r"
            SELECT max(greatest(lease_issued_at_ms, changed_at_ms)) + 1
            FROM job_attempts
            WHERE id = ANY($1) AND lease_id IS NOT NULL
            ",
        )
        .bind(&durable_attempt_ids)
        .fetch_one(database.pool())
        .await?,
    );
    let updated = sqlx::query(
        r"
        UPDATE job_attempts
        SET lease_expires_at_ms = $2
        WHERE id = ANY($1) AND lease_id IS NOT NULL
        ",
    )
    .bind(&durable_attempt_ids)
    .bind(exact_expiry.get())
    .execute(database.pool())
    .await?;
    assert_eq!(
        updated.rows_affected(),
        u64::try_from(attempt_ids.len())?,
        "every exact-boundary fixture must retain an active lease"
    );

    let exact_clock_pool = exact_database_clock_pool(database, clock, exact_expiry).await?;
    let exact_clock_store = PostgresStore::from_postgres_pool(exact_clock_pool.clone())
        .with_runner_payload_encryption(test_runner_payload_key_provider());
    let processed = exact_clock_store
        .requeue_expired(exact_expiry, maximum_failures, limit)
        .await;
    drop(exact_clock_store);
    exact_clock_pool.close().await;
    let processed = processed?;

    let changed_at: Vec<i64> =
        sqlx::query_scalar("SELECT changed_at_ms FROM job_attempts WHERE id = ANY($1) ORDER BY id")
            .bind(&durable_attempt_ids)
            .fetch_all(database.pool())
            .await?;
    assert_eq!(changed_at.len(), attempt_ids.len());
    assert!(
        changed_at
            .iter()
            .all(|changed_at| *changed_at == exact_expiry.get()),
        "requeue must include equality at the exact database-time expiry boundary"
    );
    Ok(processed)
}

async fn exact_database_clock_pool(
    database: &TestDatabase,
    clock: &TestClock,
    exact_now: UnixMillis,
) -> TestResult<sqlx::PgPool> {
    clock.set(exact_now.get()).await?;

    let pool = database.connect_pool(1).await?;
    let fixed_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        fixed_now,
        exact_now.get(),
        "the exact-boundary Store connection must resolve the schema-local test clock"
    );
    Ok(pool)
}

async fn expire_attempt_leases(
    database: &TestDatabase,
    clock: &TestClock,
    attempt_ids: &[AttemptId],
) -> TestResult {
    let mut latest_expiry = None;
    for attempt_id in attempt_ids {
        let expiry: i64 = sqlx::query_scalar(
            r"
            UPDATE job_attempts
            SET lease_expires_at_ms = greatest(lease_issued_at_ms, changed_at_ms) + 1
            WHERE id = $1 AND lease_issued_at_ms IS NOT NULL
            RETURNING lease_expires_at_ms
            ",
        )
        .bind(attempt_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        latest_expiry = Some(latest_expiry.map_or(expiry, |current: i64| current.max(expiry)));
    }
    let latest_expiry = latest_expiry.ok_or("at least one active attempt must be expired")?;
    clock
        .set(
            latest_expiry
                .checked_add(1)
                .ok_or("test expiry clock deadline overflow")?,
        )
        .await?;
    Ok(())
}

async fn begin_isolated_lease_request(
    database: &TestDatabase,
    request_key: LeaseRequestKey,
) -> TestResult {
    let current: Option<uuid::Uuid> = sqlx::query_scalar(
        r"
        SELECT operation_id
        FROM runner_lease_request_heads
        WHERE runner_session_id = $1 AND runner_slot = $2
        ",
    )
    .bind(request_key.session().session_id().as_uuid())
    .bind(i32::from(request_key.slot().ordinal()))
    .fetch_optional(database.pool())
    .await?;
    if let Some(operation_id) = current {
        sqlx::query(
            "DELETE FROM runner_operation_receipts WHERE runner_session_id = $1 AND operation_id = $2",
        )
        .bind(request_key.session().session_id().as_uuid())
        .bind(operation_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "DELETE FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_id = $2 AND operation_kind = 'automata.runner.lease-request.v1'",
        )
        .bind(request_key.session().session_id().as_uuid())
        .bind(operation_id)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "DELETE FROM runner_lease_request_heads WHERE runner_session_id = $1 AND runner_slot = $2",
        )
        .bind(request_key.session().session_id().as_uuid())
        .bind(i32::from(request_key.slot().ordinal()))
        .execute(database.pool())
        .await?;
    }
    database
        .store()
        .begin_lease_request(BeginLeaseRequest::new(
            request_key,
            request_key.request_digest(),
        ))
        .await?;
    Ok(())
}

async fn insert_attempt(
    store: &PostgresStore,
    job_id: JobId,
    attempt_number: u32,
    queued_at: i64,
) -> TestResult<AttemptId> {
    let attempt_id = AttemptId::new();
    store
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            job_id,
            AttemptNumber::new(attempt_number)?,
            UnixMillis::new(queued_at),
        ))
        .await?;
    Ok(attempt_id)
}

async fn insert_job(
    database: &TestDatabase,
    run_id: automata_ci_core::RunId,
    job_key: &str,
) -> TestResult<JobId> {
    insert_job_with_requirements(database, run_id, job_key, RunnerRequirements::default()).await
}

async fn insert_job_with_requirements(
    database: &TestDatabase,
    run_id: automata_ci_core::RunId,
    job_key: &str,
    requirements: RunnerRequirements,
) -> TestResult<JobId> {
    let job_id = JobId::new();
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        VALUES ($1, $2, $3, $3, $4, $5, $6::jsonb, $7, $8, 128, 1)
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id.as_uuid())
    .bind(job_key)
    .bind(vec![13_u8; 32])
    .bind(format!("test/job-ir/{job_key}"))
    .bind(serde_json::to_value(requirements)?)
    .bind(i32::from(WORKFLOW_ADMISSION_EPOCH))
    .bind(i32::from(JobIrVersion::current().get()))
    .execute(database.pool())
    .await?;
    Ok(job_id)
}

async fn transition_path(
    database: &TestDatabase,
    attempt_id: AttemptId,
    claimed: &automata_ci_store::ClaimedAttempt,
    path: &[JobLifecycle],
) -> TestResult {
    let first_observed_at = database_now(database).await?;
    for (offset, lifecycle) in path.iter().copied().enumerate() {
        database
            .store()
            .transition(TransitionAttempt::new(
                attempt_id,
                claimed.assignment().session(),
                claimed.lease().guard(),
                lifecycle,
                checked_add_millis(first_observed_at, i64::try_from(offset)?)?,
            ))
            .await?;
    }
    Ok(())
}

async fn claim_success(
    database: &TestDatabase,
    request: TryClaimAttempt,
) -> TestResult<automata_ci_store::ClaimedAttempt> {
    let receipt = database.store().try_claim(request).await?;
    match receipt.outcome() {
        TryClaimOutcome::Claimed(claimed) => Ok(claimed.as_ref().clone()),
        outcome @ TryClaimOutcome::Rejected(_) => {
            panic!("fixture claim must succeed: {outcome:?}")
        }
        TryClaimOutcome::NoWork => panic!("fixture unexpectedly returned no work"),
    }
}
