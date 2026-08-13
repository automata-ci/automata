use crate::common;

use automata_ci_auth::{authorization::SecretExposureClass, human::TenantId};
use automata_ci_core::{
    AttemptId, AttemptNumber, FencingToken, JobConclusion, JobLifecycle, Lease, LeaseGuard,
    LeaseId, LogSequence, LogStreamId, OperationId, Sha256Digest, UnixMillis,
};
use automata_ci_store::{
    AcknowledgeRunnerCommands, BeginLeaseRequest, CANCEL_JOB_COMMAND_KIND,
    CANCEL_JOB_COMMAND_SCHEMA, CancelJobCommandPayload, CancellationActor, CancellationReason,
    CancellationRepository as _, CloseRunnerSession, CommandCursor, CommandSequence,
    CommitCommandAcknowledgement, CommitLeaseHeartbeat, CommitLeaseResponse,
    CommitRunnerLogSegment, CommitRunnerTerminalResult, CompleteLeaseRequest,
    ControlPlaneMaintenanceRepository as _, ControlPlaneMaintenanceRequest, CurrentRunnerSession,
    CurrentRunnerSessionRepository as _, DocumentSchema, EnqueueRunnerCommand,
    InternalAttemptRepository as _, JobIrMetadata, LeaseFailureLimit, LeaseOfferClaimStatus,
    LeaseOfferCommandIdentity, LeaseRequestKey, LeaseResponseAction, MaintenanceBatchSize,
    NoWorkLeaseRequest, ObjectKey, OpenRunnerSession, PublishLeaseOffer, QueuedAttempt,
    RawLogDisposition, RenewLease, RequestCancellation, RunnableAttemptRepository as _,
    RunnableScanLimit, RunnableScanRequest, RunnerClaimRepository as _, RunnerCommandOutbox as _,
    RunnerCommandPayload, RunnerControlTransactionRepository as _, RunnerGeneration,
    RunnerLeaseOfferRepository as _, RunnerLeaseRequestRepository as _, RunnerLogAdmission,
    RunnerLogAdmissionRequest, RunnerOperationKind, RunnerOperationReceiptRepository as _,
    RunnerOperationRequest, RunnerOperationResponse, RunnerProtocolVersion,
    RunnerSessionRepository as _, StableRunnerSlot, StaleSessionTimeoutMillis, StoreError,
    TryClaimAttempt, TryClaimOutcome,
};

use common::{
    SeedData, TestClock, TestDatabase, TestResult, run_with_database, runner_capability_document,
    seed_control_plane,
};

const LEASE_REQUEST_KIND: &str = "automata.runner.lease-request.v1";
const LEASE_OFFER_KIND: &str = "automata.runner.lease-offer.v1";
const ACTIVE_LEASE_DURATION_MILLIS: i64 = 300_000;
const EXPIRING_LEASE_DURATION_MILLIS: i64 = 2_000;
const OFFER_HORIZON_MIGRATION: &str = include_str!("../migrations/0001_initial_schema.sql");

#[test]
fn offer_receipt_migration_requires_a_complete_supported_fallback_projection() {
    for required in [
        "lease_offer_response_disposition IS NOT NULL",
        "lease_offer_primary_response_schema IS NOT NULL",
        "lease_offer_primary_response_digest IS NOT NULL",
        "lease_offer_fallback_version IS NOT NULL",
        "lease_offer_fallback_operation_id IS NOT NULL",
        "lease_offer_fallback_retry_after_millis IS NOT NULL",
        "lease_offer_fallback_response_schema IS NOT NULL",
        "lease_offer_fallback_response_digest IS NOT NULL",
        "lease_offer_fallback_version = 1",
        "lease_offer_response_disposition = 'primary'",
        "lease_offer_response_disposition = 'revoked_fallback'",
    ] {
        assert!(
            OFFER_HORIZON_MIGRATION.contains(required),
            "0045 is missing fallback shape contract: {required}"
        );
    }
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_request_chains_bound_retry_state_per_live_slot() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        sqlx::query("UPDATE runners SET slots = 2 WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;

        for slot_number in 1_u16..=2 {
            let slot = StableRunnerSlot::new(slot_number)?;
            let mut predecessor = None;
            for sequence in 0_u16..100 {
                let operation_id = OperationId::new();
                let key = match predecessor {
                    Some(predecessor) => {
                        LeaseRequestKey::successor(fence, operation_id, slot, predecessor)?
                    }
                    None => LeaseRequestKey::first(fence, operation_id, slot),
                };
                let mut digest = [0_u8; 32];
                digest[..2].copy_from_slice(&slot_number.to_be_bytes());
                digest[2..4].copy_from_slice(&sequence.to_be_bytes());
                let begin = BeginLeaseRequest::new(key, Sha256Digest::from_bytes(digest));
                let admission = database.store().begin_lease_request(begin).await?;
                assert!(admission.completed_response().is_none());

                let observed_at = UnixMillis::new(10 + i64::from(sequence));
                let page = database
                    .store()
                    .scan_runnable(RunnableScanRequest::new(
                        fence,
                        slot,
                        RunnableScanLimit::new(10)?,
                        observed_at,
                    ))
                    .await?;
                let receipt = database
                    .store()
                    .record_no_work(NoWorkLeaseRequest::new(
                        key,
                        observed_at,
                        page.no_work_advance(),
                    )?)
                    .await?;
                assert!(matches!(receipt.outcome(), TryClaimOutcome::NoWork));
                database
                    .store()
                    .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                        begin,
                        test_lease_response(sequence)?,
                        observed_at,
                    ))
                    .await?;
                predecessor = Some(operation_id);
            }
        }

        let heads: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_lease_request_heads WHERE runner_session_id = $1",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let semantic: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_operation_receipts WHERE runner_session_id = $1",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let rpc: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_kind = $2",
        )
        .bind(fence.session_id().as_uuid())
        .bind(LEASE_REQUEST_KIND)
        .fetch_one(database.pool())
        .await?;
        assert_eq!((heads, semantic, rpc), (2, 2, 2));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_request_begin_rejects_slots_outside_registered_capacity_without_mutation()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let initial_heartbeat: i64 =
            sqlx::query_scalar("SELECT heartbeat_at_ms FROM runner_sessions WHERE id = $1")
                .bind(fence.session_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        sqlx::query("UPDATE runners SET slots = 2 WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;

        let slot = StableRunnerSlot::new(3)?;
        let first_operation = OperationId::new();
        let first = BeginLeaseRequest::new(
            LeaseRequestKey::first(fence, first_operation, slot),
            Sha256Digest::from_bytes([31; 32]),
        );
        let successor = BeginLeaseRequest::new(
            LeaseRequestKey::successor(fence, OperationId::new(), slot, first_operation)?,
            Sha256Digest::from_bytes([32; 32]),
        );

        for request in [first, successor] {
            assert!(matches!(
                database.store().begin_lease_request(request).await,
                Err(StoreError::SlotOutOfRange {
                    session_id,
                    slot: rejected_slot,
                }) if session_id == fence.session_id() && rejected_slot == slot
            ));
            let state: (i64, i64, i64, i64) = sqlx::query_as(
                r"
                SELECT
                    (SELECT count(*) FROM runner_lease_request_heads
                     WHERE runner_session_id = $1),
                    (SELECT count(*) FROM runner_operation_receipts
                     WHERE runner_session_id = $1),
                    (SELECT count(*) FROM runner_rpc_receipts
                     WHERE runner_session_id = $1),
                    (SELECT heartbeat_at_ms FROM runner_sessions WHERE id = $1)
                ",
            )
            .bind(fence.session_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
            assert_eq!(state, (0, 0, 0, initial_heartbeat));
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_request_drop_retry_predecessor_and_late_handler_are_fenced() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let slot = StableRunnerSlot::new(1)?;
        let first_key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        let first_begin = BeginLeaseRequest::new(first_key, Sha256Digest::from_bytes([41; 32]));
        assert!(
            database
                .store()
                .begin_lease_request(first_begin)
                .await?
                .completed_response()
                .is_none()
        );
        let page = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                slot,
                RunnableScanLimit::new(10)?,
                UnixMillis::new(10),
            ))
            .await?;
        let no_work =
            NoWorkLeaseRequest::new(first_key, UnixMillis::new(10), page.no_work_advance())?;
        database.store().record_no_work(no_work.clone()).await?;

        let dropped_retry = database.store().begin_lease_request(first_begin).await?;
        assert!(dropped_retry.completed_response().is_none());
        assert!(
            database
                .store()
                .lookup_lease_request(first_key)
                .await?
                .expect("semantic receipt")
                .was_replayed()
        );
        let first_response = database
            .store()
            .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                first_begin,
                test_lease_response(1)?,
                UnixMillis::new(11),
            ))
            .await?;
        assert_eq!(
            database
                .store()
                .begin_lease_request(first_begin)
                .await?
                .completed_response(),
            first_response.response()
        );

        for invalid in [
            LeaseRequestKey::first(fence, OperationId::new(), slot),
            LeaseRequestKey::successor(fence, OperationId::new(), slot, OperationId::new())?,
        ] {
            let begin = BeginLeaseRequest::new(invalid, Sha256Digest::from_bytes([42; 32]));
            assert!(matches!(
                database.store().begin_lease_request(begin).await,
                Err(StoreError::OperationConflict { .. })
            ));
        }

        let successor_key =
            LeaseRequestKey::successor(fence, OperationId::new(), slot, first_key.operation_id())?;
        let successor = BeginLeaseRequest::new(successor_key, Sha256Digest::from_bytes([43; 32]));
        database.store().begin_lease_request(successor).await?;
        assert!(matches!(
            database.store().record_no_work(no_work).await,
            Err(StoreError::OperationConflict { .. })
        ));
        assert!(matches!(
            database
                .store()
                .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                    first_begin,
                    test_lease_response(2)?,
                    UnixMillis::new(12),
                ))
                .await,
            Err(StoreError::OperationConflict { .. })
        ));
        assert!(matches!(
            database
                .store()
                .record_operation(
                    RunnerOperationRequest::new(
                        fence,
                        first_key.operation_id(),
                        RunnerOperationKind::new(LEASE_REQUEST_KIND)?,
                        first_begin.request_digest(),
                    ),
                    test_lease_response(2)?,
                    UnixMillis::new(12),
                )
                .await,
            Err(StoreError::OperationConflict { .. })
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_distinct_first_requests_admit_one_head_and_cross_slot_ids_conflict()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let slot = StableRunnerSlot::new(1)?;
        let left_key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        let right_key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        let left = database.store().clone();
        let right = database.store().clone();
        let (left, right) = tokio::join!(
            left.begin_lease_request(BeginLeaseRequest::new(
                left_key,
                Sha256Digest::from_bytes([44; 32]),
            )),
            right.begin_lease_request(BeginLeaseRequest::new(
                right_key,
                Sha256Digest::from_bytes([45; 32]),
            )),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let conflict = if left.is_err() { left } else { right };
        assert!(matches!(conflict, Err(StoreError::OperationConflict { .. })));

        let current_operation: uuid::Uuid = sqlx::query_scalar(
            "SELECT operation_id FROM runner_lease_request_heads WHERE runner_session_id = $1 AND runner_slot = 1",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let duplicate = LeaseRequestKey::first(
            fence,
            OperationId::from_uuid(current_operation),
            StableRunnerSlot::new(2)?,
        );
        assert!(matches!(
            database
                .store()
                .begin_lease_request(BeginLeaseRequest::new(
                    duplicate,
                    Sha256Digest::from_bytes([46; 32]),
                ))
                .await,
            Err(StoreError::OperationConflict { .. })
        ));
        let heads: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_lease_request_heads WHERE runner_session_id = $1",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(heads, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_request_rpc_failpoint_recovers_without_losing_head_or_semantic_receipt() -> TestResult
{
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let slot = StableRunnerSlot::new(1)?;
        let key = LeaseRequestKey::first(fence, OperationId::new(), slot);
        let begin = BeginLeaseRequest::new(key, Sha256Digest::from_bytes([51; 32]));
        database.store().begin_lease_request(begin).await?;
        let page = database
            .store()
            .scan_runnable(RunnableScanRequest::new(
                fence,
                slot,
                RunnableScanLimit::new(10)?,
                UnixMillis::new(10),
            ))
            .await?;
        database
            .store()
            .record_no_work(NoWorkLeaseRequest::new(
                key,
                UnixMillis::new(10),
                page.no_work_advance(),
            )?)
            .await?;

        install_receipt_failpoint(&database, "runner_rpc_receipts").await?;
        assert!(
            database
                .store()
                .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                    begin,
                    test_lease_response(3)?,
                    UnixMillis::new(11),
                ))
                .await
                .is_err()
        );
        let counts: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runner_lease_request_heads WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_operation_receipts WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_kind = $2)
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(LEASE_REQUEST_KIND)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 0));
        remove_receipt_failpoint(&database, "runner_rpc_receipts").await?;
        database
            .store()
            .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                begin,
                test_lease_response(3)?,
                UnixMillis::new(12),
            ))
            .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn session_close_and_open_supersession_clean_retry_state_but_retain_queue_cursor()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let first = seed.session_fences[0];
        install_completed_no_work_head(&database, first, 1, UnixMillis::new(10)).await?;
        database
            .store()
            .close_session(CloseRunnerSession::new(first, UnixMillis::new(11)))
            .await?;
        assert_eq!(lease_retry_counts(&database, first).await?, (0, 0, 0));
        assert_eq!(queue_cursor_count(&database, first).await?, 1);

        let second = database
            .store()
            .open_session(OpenRunnerSession::new(
                automata_ci_core::RunnerSessionId::new(),
                first.runner_id(),
                first.runner_generation(),
                RunnerProtocolVersion::new(1)?,
                automata_ci_core::JobIrVersion::current(),
                runner_capability_document(database.pool(), first.runner_id()).await?,
                UnixMillis::new(12),
            ))
            .await?
            .fence();
        install_completed_no_work_head(&database, second, 1, UnixMillis::new(13)).await?;
        let third = database
            .store()
            .open_session(OpenRunnerSession::new(
                automata_ci_core::RunnerSessionId::new(),
                second.runner_id(),
                second.runner_generation(),
                RunnerProtocolVersion::new(1)?,
                automata_ci_core::JobIrVersion::current(),
                runner_capability_document(database.pool(), second.runner_id()).await?,
                UnixMillis::new(14),
            ))
            .await?
            .fence();
        assert_ne!(third.session_id(), second.session_id());
        assert_eq!(lease_retry_counts(&database, second).await?, (0, 0, 0));
        assert_eq!(queue_cursor_count(&database, second).await?, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn current_session_resolution_separates_desired_and_observed_state() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let exact = CurrentRunnerSession::new(
            fence.runner_id(),
            fence.runner_generation(),
            fence.session_id(),
        );
        assert_eq!(
            database.store().resolve_current_session(exact).await?,
            Some(fence)
        );
        assert!(
            database
                .store()
                .resolve_current_session(CurrentRunnerSession::new(
                    automata_ci_core::RunnerId::new(),
                    fence.runner_generation(),
                    fence.session_id(),
                ))
                .await?
                .is_none()
        );
        assert!(
            database
                .store()
                .resolve_current_session(CurrentRunnerSession::new(
                    fence.runner_id(),
                    RunnerGeneration::new(2)?,
                    fence.session_id(),
                ))
                .await?
                .is_none()
        );
        assert!(
            database
                .store()
                .resolve_current_session(CurrentRunnerSession::new(
                    fence.runner_id(),
                    fence.runner_generation(),
                    automata_ci_core::RunnerSessionId::new(),
                ))
                .await?
                .is_none()
        );

        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert_eq!(
            database.store().resolve_current_session(exact).await?,
            Some(fence),
            "an observed-online draining runner may finish its current session"
        );

        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(
            database
                .store()
                .resolve_current_session(exact)
                .await?
                .is_none(),
            "a disabled runner must not resolve as live authority"
        );

        sqlx::query(
            "UPDATE runners SET status = 'offline', desired_state = 'active' WHERE id = $1",
        )
        .bind(fence.runner_id().as_uuid())
        .execute(database.pool())
        .await?;
        assert!(
            database
                .store()
                .resolve_current_session(exact)
                .await?
                .is_none(),
            "an observed-offline runner must not resolve as a live session"
        );

        sqlx::query("UPDATE runners SET status = 'online', session_epoch = 2 WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(
            database
                .store()
                .resolve_current_session(exact)
                .await?
                .is_none(),
            "a runner/session current-epoch mismatch must fail closed"
        );
        sqlx::query("UPDATE runners SET session_epoch = 1 WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;

        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                automata_ci_core::RunnerSessionId::new(),
                fence.runner_id(),
                fence.runner_generation(),
                RunnerProtocolVersion::new(1)?,
                automata_ci_core::JobIrVersion::current(),
                runner_capability_document(database.pool(), fence.runner_id()).await?,
                UnixMillis::new(10),
            ))
            .await?;
        assert!(
            database
                .store()
                .resolve_current_session(exact)
                .await?
                .is_none()
        );
        assert_eq!(
            database
                .store()
                .resolve_current_session(CurrentRunnerSession::new(
                    replacement.fence().runner_id(),
                    replacement.fence().runner_generation(),
                    replacement.fence().session_id(),
                ))
                .await?,
            Some(replacement.fence())
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn lease_offer_publication_is_atomic_concurrent_and_exactly_replayed() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        let first = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let second = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.publish_lease_offer(first),
            right_store.publish_lease_offer(second)
        );
        let left = left?;
        let right = right?;
        assert_eq!(left.command().sequence(), right.command().sequence());
        assert_eq!(left.command().request(), right.command().request());
        assert_ne!(left.was_replayed(), right.was_replayed());
        assert_eq!(left.command().sequence().get(), 1);

        let publication_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_lease_offer_publications WHERE runner_session_id = $1",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        let command_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_command_outbox WHERE runner_session_id = $1",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!((publication_count, command_count), (1, 1));

        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let replay_while_draining = database
            .store()
            .publish_lease_offer(offer(
                fence,
                &lease,
                &metadata,
                slot,
                request_operation_id,
                request_digest,
                OperationId::new(),
            )?)
            .await?;
        assert!(replay_while_draining.was_replayed());
        let (
            draining_seed,
            draining_lease,
            draining_metadata,
            draining_slot,
            draining_operation_id,
            draining_digest,
        ) = active_lease(&database).await?;
        let draining_fence = draining_seed.session_fences[0];
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(draining_fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let before_new_offer = offer_state(&database, draining_fence.session_id()).await?;
        let new_while_draining = offer(
            draining_fence,
            &draining_lease,
            &draining_metadata,
            draining_slot,
            draining_operation_id,
            draining_digest,
            OperationId::new(),
        )?;
        assert!(matches!(
            database
                .store()
                .inspect_lease_offer_claim(new_while_draining.claim().clone())
                .await,
            Err(StoreError::RunnerNotAcceptingWork(id)) if id == draining_fence.runner_id()
        ));
        assert_eq!(
            offer_state(&database, draining_fence.session_id()).await?,
            before_new_offer,
            "draining inspection must not commit an offer or outbox command"
        );
        assert!(matches!(
            database
                .store()
                .publish_lease_offer(new_while_draining)
                .await,
            Err(StoreError::RunnerNotAcceptingWork(id)) if id == draining_fence.runner_id()
        ));
        assert_eq!(
            offer_state(&database, draining_fence.session_id()).await?,
            before_new_offer,
            "draining must not commit a new offer or outbox command"
        );
        sqlx::query("UPDATE runners SET desired_state = 'active' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;

        let conflict = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            Sha256Digest::from_bytes([32; 32]),
            OperationId::new(),
        )?;
        assert!(matches!(
            database.store().publish_lease_offer(conflict).await,
            Err(StoreError::OperationConflict { operation_id, .. })
                if operation_id == request_operation_id
        ));

        let (
            failed_seed,
            failed_lease,
            failed_metadata,
            failed_slot,
            failed_operation_id,
            failed_digest,
        ) = active_lease(&database).await?;
        let failed_fence = failed_seed.session_fences[0];
        install_receipt_failpoint(&database, "runner_lease_offer_publications").await?;
        let before = offer_state(&database, failed_fence.session_id()).await?;
        let failed = offer(
            failed_fence,
            &failed_lease,
            &failed_metadata,
            failed_slot,
            failed_operation_id,
            failed_digest,
            OperationId::new(),
        )?;
        assert!(database.store().publish_lease_offer(failed).await.is_err());
        assert_eq!(
            offer_state(&database, failed_fence.session_id()).await?,
            before
        );
        remove_receipt_failpoint(&database, "runner_lease_offer_publications").await?;

        let replacement = database
            .store()
            .open_session(OpenRunnerSession::new(
                automata_ci_core::RunnerSessionId::new(),
                fence.runner_id(),
                fence.runner_generation(),
                RunnerProtocolVersion::new(1)?,
                automata_ci_core::JobIrVersion::current(),
                runner_capability_document(database.pool(), fence.runner_id()).await?,
                UnixMillis::new(20),
            ))
            .await?;
        assert_ne!(replacement.fence(), fence);
        let stale = offer(
            fence,
            &lease,
            &metadata,
            slot,
            OperationId::new(),
            Sha256Digest::from_bytes([34; 32]),
            OperationId::new(),
        )?;
        assert!(matches!(
            database.store().publish_lease_offer(stale).await,
            Err(StoreError::SessionFenceRejected(id)) if id == fence.session_id()
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn live_lease_offer_fence_rejects_corrupt_job_ir_metadata_without_writes() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        let publication = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let claim = publication.claim().clone();
        let mut corruption = database.pool().begin().await?;
        sqlx::query("ALTER TABLE jobs DISABLE TRIGGER jobs_plan_immutable")
            .execute(&mut *corruption)
            .await?;
        let updated = sqlx::query("UPDATE jobs SET job_ir_object_key = $2 WHERE id = $1")
            .bind(metadata.job_id().as_uuid())
            .bind("job-ir/corrupt-live-fence.pb")
            .execute(&mut *corruption)
            .await?;
        sqlx::query("ALTER TABLE jobs ENABLE TRIGGER jobs_plan_immutable")
            .execute(&mut *corruption)
            .await?;
        corruption.commit().await?;
        assert_eq!(updated.rows_affected(), 1);
        let before = offer_state(&database, fence.session_id()).await?;

        assert!(matches!(
            database.store().inspect_lease_offer_claim(claim).await,
            Err(StoreError::CorruptData(message))
                if message.contains("live lease-offer fence")
        ));
        assert!(matches!(
            database.store().publish_lease_offer(publication).await,
            Err(StoreError::CorruptData(message))
                if message.contains("live lease-offer fence")
        ));
        assert_eq!(
            offer_state(&database, fence.session_id()).await?,
            before,
            "corrupt live metadata must not publish an offer or outbox command"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_offer_recovery_rejects_publication_command_time_mismatch() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        let publication = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let claim = publication.claim().clone();
        database.store().publish_lease_offer(publication).await?;
        let updated = sqlx::query(
            r"
            UPDATE runner_lease_offer_publications
            SET created_at_ms = created_at_ms + 1
            WHERE runner_session_id = $1 AND request_operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(updated.rows_affected(), 1);

        assert!(matches!(
            database.store().inspect_lease_offer_claim(claim).await,
            Err(StoreError::CorruptData(message))
                if message.contains("creation times disagree")
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(
    clippy::too_many_lines,
    reason = "keep exact resolution, orphan handling, and the deliberate duplicate-publication corruption probe together"
)]
async fn lease_offer_command_resolution_is_exact_optional_and_bounded() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        let published = database
            .store()
            .publish_lease_offer(offer(
                fence,
                &lease,
                &metadata,
                slot,
                request_operation_id,
                request_digest,
                OperationId::new(),
            )?)
            .await?;
        let identity = LeaseOfferCommandIdentity::new(
            fence,
            published.command().request().operation_id(),
            published.command().sequence(),
        );
        let resolved = database
            .store()
            .resolve_lease_offer_command(identity)
            .await?
            .expect("published command");
        assert_eq!(resolved.command().request(), published.command().request());
        assert_eq!(
            resolved.command().sequence(),
            published.command().sequence()
        );
        assert!(resolved.was_replayed());

        let orphan = database
            .store()
            .enqueue_command(EnqueueRunnerCommand::new(
                fence,
                OperationId::new(),
                RunnerOperationKind::new(LEASE_OFFER_KIND)?,
                RunnerCommandPayload::new(
                    DocumentSchema::new(1)?,
                    b"orphan offer command".to_vec(),
                )?,
                UnixMillis::new(12),
            ))
            .await?;
        assert!(
            database
                .store()
                .resolve_lease_offer_command(LeaseOfferCommandIdentity::new(
                    fence,
                    orphan.request().operation_id(),
                    orphan.sequence(),
                ))
                .await?
                .is_none()
        );

        sqlx::query("DROP INDEX runner_lease_offer_publications_lease")
            .execute(database.pool())
            .await?;
        sqlx::query(
            "ALTER TABLE runner_lease_offer_publications \
             DROP CONSTRAINT runner_lease_offer_publications_command_unique",
        )
        .execute(database.pool())
        .await?;
        let duplicated = sqlx::query(
            r"
            INSERT INTO runner_lease_offer_publications (
                runner_session_id, request_operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                request_digest, protocol_version, runner_slot,
                attempt_id, lease_id, fencing_token, lease_issued_at_ms,
                lease_expires_at_ms, offer_valid_until_ms, job_id, run_id, job_ir_schema,
                job_ir_size_bytes, job_ir_digest, job_ir_object_key,
                command_sequence, created_at_ms
            )
            SELECT runner_session_id, $2, runner_id,
                   runner_session_epoch, runner_generation, operation_kind,
                   request_digest, protocol_version, runner_slot,
                   attempt_id, lease_id, fencing_token, lease_issued_at_ms,
                   lease_expires_at_ms, offer_valid_until_ms, job_id, run_id, job_ir_schema,
                   job_ir_size_bytes, job_ir_digest, job_ir_object_key,
                   command_sequence, created_at_ms
            FROM runner_lease_offer_publications
            WHERE runner_session_id = $1 AND request_operation_id = $3
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(OperationId::new().as_uuid())
        .bind(request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(duplicated.rows_affected(), 1);
        assert!(matches!(
            database.store().resolve_lease_offer_command(identity).await,
            Err(StoreError::CorruptData(message))
                if message.contains("multiple lease-offer publications")
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn reaped_claim_completes_no_work_and_evicts_without_offer_publication() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease_with_duration(&database, EXPIRING_LEASE_DURATION_MILLIS).await?;
        let fence = seed.session_fences[0];
        let publication = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let claim = publication.claim().clone();
        let late_publication = publication.clone();

        wait_until_database_time(&clock, lease.expires_at()).await?;
        let maintenance = database
            .store()
            .maintain_control_plane(maintenance_request(&database).await?)
            .await?;
        assert_eq!(maintenance.expired_attempts().len(), 1);
        assert_eq!(
            maintenance.expired_attempts()[0].attempt_id(),
            lease.attempt_id()
        );
        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert_eq!(
            database.store().inspect_lease_offer_claim(claim).await?,
            LeaseOfferClaimStatus::ClaimSuperseded
        );
        assert!(matches!(
            database.store().publish_lease_offer(publication).await,
            Err(StoreError::AttemptFenceRejected(attempt_id))
                if attempt_id == lease.attempt_id()
        ));
        assert_eq!(offer_state(&database, fence.session_id()).await?, (0, 0, 0));

        let request_key = LeaseRequestKey::first(fence, request_operation_id, slot);
        let begin = BeginLeaseRequest::new(request_key, request_digest);
        let response = database
            .store()
            .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
                begin,
                test_lease_response(201)?,
                UnixMillis::new(101),
            ))
            .await?;
        assert_eq!(
            database
                .store()
                .begin_lease_request(begin)
                .await?
                .completed_response(),
            response.response()
        );

        let successor = BeginLeaseRequest::new(
            LeaseRequestKey::successor(fence, OperationId::new(), slot, request_operation_id)?,
            Sha256Digest::from_bytes([202; 32]),
        );
        database.store().begin_lease_request(successor).await?;
        assert!(matches!(
            database.store().publish_lease_offer(late_publication).await,
            Err(StoreError::OperationConflict { operation_id, .. })
                if operation_id == request_operation_id
        ));
        let retry_state: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runner_lease_request_heads
                 WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_operation_receipts
                 WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_rpc_receipts
                 WHERE runner_session_id = $1 AND operation_kind = $2)
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(LEASE_REQUEST_KIND)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(retry_state, (1, 0, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn durable_publication_is_retained_but_not_live_after_claim_reaping() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease_with_duration(&database, EXPIRING_LEASE_DURATION_MILLIS).await?;
        let fence = seed.session_fences[0];
        let publication = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let claim = publication.claim().clone();
        let attempt_id = publication.lease().attempt_id();
        let committed = database.store().publish_lease_offer(publication).await?;
        let identity = LeaseOfferCommandIdentity::new(
            fence,
            committed.command().request().operation_id(),
            committed.command().sequence(),
        );
        wait_until_database_time(&clock, lease.expires_at()).await?;
        database
            .store()
            .maintain_control_plane(maintenance_request(&database).await?)
            .await?;

        assert_eq!(
            database.store().inspect_lease_offer_claim(claim).await?,
            LeaseOfferClaimStatus::ClaimSuperseded
        );
        assert!(matches!(
            database.store().resolve_lease_offer_command(identity).await,
            Err(StoreError::AttemptFenceRejected(rejected))
                if rejected == attempt_id
        ));
        assert_eq!(offer_state(&database, fence.session_id()).await?, (1, 1, 1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_expired_publish_and_reap_leave_no_partial_offer() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease_with_duration(&database, EXPIRING_LEASE_DURATION_MILLIS).await?;
        let fence = seed.session_fences[0];
        let publication = offer(
            fence,
            &lease,
            &metadata,
            slot,
            request_operation_id,
            request_digest,
            OperationId::new(),
        )?;
        let claim = publication.claim().clone();
        wait_until_database_time(&clock, lease.expires_at()).await?;
        let maintenance_request = maintenance_request(&database).await?;
        let publishing_store = database.store().clone();
        let reaper = database.store().clone();
        let (publication_result, maintained) = tokio::join!(
            publishing_store.publish_lease_offer(publication),
            reaper.maintain_control_plane(maintenance_request)
        );
        let maintained = maintained?;
        assert_eq!(maintained.expired_attempts().len(), 1);

        let state = offer_state(&database, fence.session_id()).await?;
        assert!(matches!(
            publication_result,
            Err(StoreError::AttemptFenceRejected(attempt_id))
                if attempt_id == lease.attempt_id()
        ));
        assert_eq!(state, (0, 0, 0));
        assert_eq!(
            database.store().inspect_lease_offer_claim(claim).await?,
            LeaseOfferClaimStatus::ClaimSuperseded
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn heartbeat_and_ack_transactions_roll_back_and_replay_exact_responses() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        database
            .store()
            .publish_lease_offer(offer(
                fence,
                &lease,
                &metadata,
                slot,
                request_operation_id,
                request_digest,
                OperationId::new(),
            )?)
            .await?;

        let heartbeat_request = operation_request(
            fence,
            OperationId::new(),
            "automata.runner.lease-heartbeat.v1",
            [42; 32],
        )?;
        let first_renewal = authorized_renewal_from_database_now(
            &database,
            &lease,
            fence,
            JobLifecycle::Leased,
            ACTIVE_LEASE_DURATION_MILLIS * 2,
        )
        .await?;
        let first_renewal_expiry = first_renewal.expires_at();
        let heartbeat = CommitLeaseHeartbeat::new(
            heartbeat_request.clone(),
            CommandCursor::initial(),
            first_renewal,
            response(b"first heartbeat response")?,
        )?;
        let first = database
            .store()
            .commit_lease_heartbeat(heartbeat.clone())
            .await?;
        assert!(!first.was_replayed());
        let replay = database
            .store()
            .commit_lease_heartbeat(CommitLeaseHeartbeat::new(
                heartbeat_request.clone(),
                CommandCursor::initial(),
                renewal_from_database_now(
                    &database,
                    &lease,
                    fence,
                    ACTIVE_LEASE_DURATION_MILLIS * 3,
                )
                .await?,
                response(b"ignored replay response")?,
            )?)
            .await?;
        assert!(replay.was_replayed());
        assert_eq!(replay.response(), first.response());
        assert_eq!(
            lease_expiry(&database, lease.attempt_id()).await?,
            first_renewal_expiry.get()
        );

        let conflicting_request = operation_request(
            fence,
            heartbeat_request.operation_id(),
            "automata.runner.lease-heartbeat.v1",
            [43; 32],
        )?;
        assert!(matches!(
            database
                .store()
                .commit_lease_heartbeat(CommitLeaseHeartbeat::new(
                    conflicting_request,
                    CommandCursor::initial(),
                    renewal_from_database_now(
                        &database,
                        &lease,
                        fence,
                        ACTIVE_LEASE_DURATION_MILLIS * 3,
                    )
                    .await?,
                    response(b"conflict")?,
                )?)
                .await,
            Err(StoreError::OperationConflict { .. })
        ));

        install_receipt_failpoint(&database, "runner_rpc_receipts").await?;
        let heartbeat_before =
            session_and_lease_state(&database, fence.session_id(), lease.attempt_id()).await?;
        let failed_heartbeat = CommitLeaseHeartbeat::new(
            operation_request(
                fence,
                OperationId::new(),
                "automata.runner.lease-heartbeat.v1",
                [44; 32],
            )?,
            CommandCursor::initial(),
            authorized_renewal_from_database_now(
                &database,
                &lease,
                fence,
                JobLifecycle::Leased,
                ACTIVE_LEASE_DURATION_MILLIS * 3,
            )
            .await?,
            response(b"must roll back")?,
        )?;
        assert!(
            database
                .store()
                .commit_lease_heartbeat(failed_heartbeat)
                .await
                .is_err()
        );
        assert_eq!(
            session_and_lease_state(&database, fence.session_id(), lease.attempt_id()).await?,
            heartbeat_before
        );
        remove_receipt_failpoint(&database, "runner_rpc_receipts").await?;

        let acknowledged = CommandCursor::through(CommandSequence::new(1)?);
        let ack_request = operation_request(
            fence,
            OperationId::new(),
            "automata.runner.command-ack.v1",
            [45; 32],
        )?;
        let ack = CommitCommandAcknowledgement::new(
            ack_request.clone(),
            AcknowledgeRunnerCommands::new(fence, acknowledged, UnixMillis::new(31)),
            response(b"first ack response")?,
        )?;
        let first_ack = database.store().commit_command_acknowledgement(ack).await?;
        let replay_ack = database
            .store()
            .commit_command_acknowledgement(CommitCommandAcknowledgement::new(
                ack_request,
                AcknowledgeRunnerCommands::new(fence, acknowledged, UnixMillis::new(32)),
                response(b"ignored ack replay response")?,
            )?)
            .await?;
        assert!(replay_ack.was_replayed());
        assert_eq!(replay_ack.response(), first_ack.response());

        let second_command = EnqueueRunnerCommand::new(
            fence,
            OperationId::new(),
            RunnerOperationKind::new("automata.runner.test-command.v1")?,
            RunnerCommandPayload::new(DocumentSchema::new(1)?, b"second command".to_vec())?,
            UnixMillis::new(33),
        );
        let second = database.store().enqueue_command(second_command).await?;
        assert_eq!(second.sequence().get(), 2);

        install_receipt_failpoint(&database, "runner_rpc_receipts").await?;
        let ack_before = session_state(&database, fence.session_id()).await?;
        let failed_ack = CommitCommandAcknowledgement::new(
            operation_request(
                fence,
                OperationId::new(),
                "automata.runner.command-ack.v1",
                [46; 32],
            )?,
            AcknowledgeRunnerCommands::new(
                fence,
                CommandCursor::through(second.sequence()),
                UnixMillis::new(40),
            ),
            response(b"ack must roll back")?,
        )?;
        assert!(
            database
                .store()
                .commit_command_acknowledgement(failed_ack)
                .await
                .is_err()
        );
        assert_eq!(
            session_state(&database, fence.session_id()).await?,
            ack_before
        );
        remove_receipt_failpoint(&database, "runner_rpc_receipts").await?;

        let concurrent_request = operation_request(
            fence,
            OperationId::new(),
            "automata.runner.command-ack.v1",
            [47; 32],
        )?;
        let concurrent = CommitCommandAcknowledgement::new(
            concurrent_request,
            AcknowledgeRunnerCommands::new(
                fence,
                CommandCursor::through(second.sequence()),
                UnixMillis::new(41),
            ),
            response(b"concurrent exact response")?,
        )?;
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.commit_command_acknowledgement(concurrent.clone()),
            right_store.commit_command_acknowledgement(concurrent)
        );
        let left = left?;
        let right = right?;
        assert_eq!(left.response(), right.response());
        assert_ne!(left.was_replayed(), right.was_replayed());

        sqlx::query("UPDATE runners SET desired_state = 'draining' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        database
            .store()
            .commit_lease_heartbeat(CommitLeaseHeartbeat::new(
                operation_request(
                    fence,
                    OperationId::new(),
                    "automata.runner.lease-heartbeat.v1",
                    [48; 32],
                )?,
                CommandCursor::through(second.sequence()),
                authorized_renewal_from_database_now(
                    &database,
                    &lease,
                    fence,
                    JobLifecycle::Leased,
                    ACTIVE_LEASE_DURATION_MILLIS * 3,
                )
                .await?,
                response(b"draining heartbeat")?,
            )?)
            .await?;
        database
            .store()
            .commit_command_acknowledgement(CommitCommandAcknowledgement::new(
                operation_request(
                    fence,
                    OperationId::new(),
                    "automata.runner.command-ack.v1",
                    [49; 32],
                )?,
                AcknowledgeRunnerCommands::new(
                    fence,
                    CommandCursor::through(second.sequence()),
                    UnixMillis::new(51),
                ),
                response(b"draining acknowledgement")?,
            )?)
            .await?;

        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let disabled_before =
            session_and_lease_state(&database, fence.session_id(), lease.attempt_id()).await?;
        let disabled_heartbeat = CommitLeaseHeartbeat::new(
            operation_request(
                fence,
                OperationId::new(),
                "automata.runner.lease-heartbeat.v1",
                [50; 32],
            )?,
            CommandCursor::through(second.sequence()),
            renewal_from_database_now(&database, &lease, fence, ACTIVE_LEASE_DURATION_MILLIS * 4)
                .await?,
            response(b"disabled heartbeat")?,
        )?;
        assert!(matches!(
            database
                .store()
                .commit_lease_heartbeat(disabled_heartbeat)
                .await,
            Err(StoreError::RunnerDisabled(id)) if id == fence.runner_id()
        ));
        let disabled_ack = CommitCommandAcknowledgement::new(
            operation_request(
                fence,
                OperationId::new(),
                "automata.runner.command-ack.v1",
                [51; 32],
            )?,
            AcknowledgeRunnerCommands::new(
                fence,
                CommandCursor::through(second.sequence()),
                UnixMillis::new(52),
            ),
            response(b"disabled acknowledgement")?,
        )?;
        assert!(matches!(
            database
                .store()
                .commit_command_acknowledgement(disabled_ack)
                .await,
            Err(StoreError::RunnerDisabled(id)) if id == fence.runner_id()
        ));
        assert_eq!(
            session_and_lease_state(&database, fence.session_id(), lease.attempt_id()).await?,
            disabled_before,
            "disabled runner mutations must roll back completely"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_response_and_reported_lifecycle_are_atomic_fenced_and_replayed() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        database
            .store()
            .publish_lease_offer(offer(
                fence,
                &lease,
                &metadata,
                slot,
                request_operation_id,
                request_digest,
                OperationId::new(),
            )?)
            .await?;

        let accept_request = operation_request(
            fence,
            OperationId::new(),
            "automata.runner.lease-response.v1",
            [61; 32],
        )?;
        let acceptance_observed_at = database_now(&database).await?;
        let acceptance = CommitLeaseResponse::new(
            accept_request.clone(),
            CommandCursor::initial(),
            lease.attempt_id(),
            slot,
            lease.guard(),
            LeaseResponseAction::Accept,
            acceptance_observed_at,
            response(b"accepted")?,
        );
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.commit_lease_response(acceptance.clone()),
            right_store.commit_lease_response(acceptance)
        );
        let left = left?;
        let right = right?;
        assert_ne!(left.was_replayed(), right.was_replayed());
        assert_eq!(left.response(), right.response());
        let lifecycle: String =
            sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
                .bind(lease.attempt_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(lifecycle, "preparing");

        let renewal = authorized_renewal_from_database_now(
            &database,
            &lease,
            fence,
            JobLifecycle::Running,
            ACTIVE_LEASE_DURATION_MILLIS * 2,
        )
        .await?;
        let renewed_expires_at = renewal.expires_at();
        let heartbeat = CommitLeaseHeartbeat::new(
            operation_request(
                fence,
                OperationId::new(),
                "automata.runner.lease-heartbeat.v1",
                [62; 32],
            )?,
            CommandCursor::initial(),
            renewal,
            response(b"running")?,
        )?
        .with_reported_lifecycle(JobLifecycle::Running)?;
        database.store().commit_lease_heartbeat(heartbeat).await?;
        let state: (String, i64) =
            sqlx::query_as("SELECT lifecycle, lease_expires_at_ms FROM job_attempts WHERE id = $1")
                .bind(lease.attempt_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(state, ("running".to_owned(), renewed_expires_at.get()));

        let late_response = CommitLeaseResponse::new(
            operation_request(
                fence,
                OperationId::new(),
                "automata.runner.lease-response.v1",
                [63; 32],
            )?,
            CommandCursor::initial(),
            lease.attempt_id(),
            slot,
            lease.guard(),
            LeaseResponseAction::Requeue,
            database_now(&database).await?,
            response(b"late rejection")?,
        );
        assert!(matches!(
            database.store().commit_lease_response(late_response).await,
            Err(StoreError::AttemptFenceRejected(id)) if id == lease.attempt_id()
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
#[allow(clippy::too_many_lines)]
async fn log_and_terminal_ingress_commit_contiguously_and_roll_back_with_receipts() -> TestResult {
    run_with_database(|database| async move {
        let (seed, lease, metadata, slot, request_operation_id, request_digest) =
            active_lease(&database).await?;
        let fence = seed.session_fences[0];
        database
            .store()
            .publish_lease_offer(offer(
                fence,
                &lease,
                &metadata,
                slot,
                request_operation_id,
                request_digest,
                OperationId::new(),
            )?)
            .await?;
        database
            .store()
            .commit_lease_response(CommitLeaseResponse::new(
                operation_request(
                    fence,
                    OperationId::new(),
                    "automata.runner.lease-response.v1",
                    [71; 32],
                )?,
                CommandCursor::initial(),
                lease.attempt_id(),
                slot,
                lease.guard(),
                LeaseResponseAction::Accept,
                database_now(&database).await?,
                response(b"accepted")?,
            ))
            .await?;

        let stream_id = LogStreamId::new();
        let first_request = operation_request(
            fence,
            OperationId::new(),
            "automata.runner.log-batch.v1",
            [72; 32],
        )?;
        let first_admission = database
            .store()
            .admit_runner_log_segment(RunnerLogAdmissionRequest::new(
                first_request,
                lease.attempt_id(),
                lease.guard(),
                stream_id,
                DocumentSchema::new(1)?,
                LogSequence::new(0),
                LogSequence::new(0),
                database_now(&database).await?,
                false,
            )?)
            .await?;
        assert_eq!(
            first_admission.secret_exposure(),
            SecretExposureClass::ReadableSecret
        );
        assert_eq!(
            first_admission.raw_log_disposition(),
            RawLogDisposition::Persist
        );
        let first_segment = CommitRunnerLogSegment::new(
            first_admission,
            ObjectKey::new("logs/first.json.gz")?,
            Sha256Digest::from_bytes([73; 32]),
            30,
            60,
            response(b"ack zero")?,
        )?;
        let first = database
            .store()
            .commit_runner_log_segment(first_segment.clone())
            .await?;
        let replay = database
            .store()
            .commit_runner_log_segment(first_segment.clone())
            .await?;
        assert!(!first.was_replayed());
        assert!(replay.was_replayed());

        let admitted_request = first_segment.admission().request();
        let wrong_attempt_admission = RunnerLogAdmission::new(
            RunnerLogAdmissionRequest::new(
                admitted_request.request().clone(),
                AttemptId::new(),
                admitted_request.guard(),
                admitted_request.stream_id(),
                admitted_request.schema(),
                admitted_request.first_sequence(),
                admitted_request.last_sequence(),
                admitted_request.observed_at(),
                admitted_request.is_end_of_stream(),
            )?,
            first_segment.admission().tenant_id().clone(),
            first_segment.admission().slot(),
            first_segment.admission().secret_exposure(),
            first_segment.admission().raw_log_disposition(),
        )?;
        let wrong_guard_admission = RunnerLogAdmission::new(
            RunnerLogAdmissionRequest::new(
                admitted_request.request().clone(),
                admitted_request.attempt_id(),
                LeaseGuard::new(
                    admitted_request.guard().lease_id(),
                    FencingToken::new(admitted_request.guard().fencing_token().get() + 1)?,
                ),
                admitted_request.stream_id(),
                admitted_request.schema(),
                admitted_request.first_sequence(),
                admitted_request.last_sequence(),
                admitted_request.observed_at(),
                admitted_request.is_end_of_stream(),
            )?,
            first_segment.admission().tenant_id().clone(),
            first_segment.admission().slot(),
            first_segment.admission().secret_exposure(),
            first_segment.admission().raw_log_disposition(),
        )?;
        let wrong_tenant_admission = RunnerLogAdmission::new(
            admitted_request.clone(),
            TenantId::new("unrelated-tenant")?,
            first_segment.admission().slot(),
            first_segment.admission().secret_exposure(),
            first_segment.admission().raw_log_disposition(),
        )?;
        let swapped_policy_admission = RunnerLogAdmission::new(
            admitted_request.clone(),
            first_segment.admission().tenant_id().clone(),
            first_segment.admission().slot(),
            SecretExposureClass::Secretless,
            RawLogDisposition::Persist,
        )?;
        for forged in [
            wrong_attempt_admission,
            wrong_guard_admission,
            wrong_tenant_admission,
            swapped_policy_admission,
        ] {
            let forged_replay = CommitRunnerLogSegment::new(
                forged,
                ObjectKey::new("logs/first.json.gz")?,
                Sha256Digest::from_bytes([73; 32]),
                30,
                60,
                response(b"ack zero")?,
            )?;
            assert!(
                database
                    .store()
                    .commit_runner_log_segment(forged_replay)
                    .await
                    .is_err(),
                "a receipt must not replay under swapped attempt, fence, tenant, or policy authority"
            );
        }
        let first_segment_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM attempt_log_segments WHERE stream_id = $1",
        )
        .bind(stream_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(first_segment_count, 1);

        let offline_request = operation_request(
                fence,
                OperationId::new(),
                "automata.runner.log-batch.v1",
                [83; 32],
            )?;
        let offline_admission = database
            .store()
            .admit_runner_log_segment(RunnerLogAdmissionRequest::new(
                offline_request,
                lease.attempt_id(),
                lease.guard(),
                stream_id,
                DocumentSchema::new(1)?,
                LogSequence::new(1),
                LogSequence::new(1),
                database_now(&database).await?,
                false,
            )?)
            .await?;
        sqlx::query("UPDATE runners SET status = 'offline' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let offline_segment = CommitRunnerLogSegment::new(
            offline_admission,
            ObjectKey::new("logs/offline.json.gz")?,
            Sha256Digest::from_bytes([84; 32]),
            31,
            61,
            response(b"must reject offline")?,
        )?;
        assert!(matches!(
            database
                .store()
                .commit_runner_log_segment(offline_segment)
                .await,
            Err(StoreError::SessionClosed(id)) if id == fence.session_id()
        ));
        sqlx::query("UPDATE runners SET status = 'online' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;

        let second_request = operation_request(
                fence,
                OperationId::new(),
                "automata.runner.log-batch.v1",
                [74; 32],
            )?;
        let second_admission = database
            .store()
            .admit_runner_log_segment(RunnerLogAdmissionRequest::new(
                second_request,
                lease.attempt_id(),
                lease.guard(),
                stream_id,
                DocumentSchema::new(1)?,
                LogSequence::new(1),
                LogSequence::new(1),
                database_now(&database).await?,
                true,
            )?)
            .await?;
        install_receipt_failpoint(&database, "runner_rpc_receipts").await?;
        let second = CommitRunnerLogSegment::new(
            second_admission,
            ObjectKey::new("logs/second.json.gz")?,
            Sha256Digest::from_bytes([75; 32]),
            31,
            61,
            response(b"ack one")?,
        )?;
        assert!(
            database
                .store()
                .commit_runner_log_segment(second.clone())
                .await
                .is_err()
        );
        let segment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM attempt_log_segments WHERE stream_id = $1")
                .bind(stream_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(
            segment_count, 1,
            "segment metadata must roll back with its receipt"
        );
        remove_receipt_failpoint(&database, "runner_rpc_receipts").await?;
        database.store().commit_runner_log_segment(second).await?;

        let cancellation_operation = OperationId::new();
        let cancellation_reason = CancellationReason::new("stop after uploaded logs")?;
        let cancellation_requested_at = database_now(&database).await?;
        let cancellation_payload = CancelJobCommandPayload::new(
            lease.attempt_id(),
            lease.guard(),
            RunnerProtocolVersion::new(1)?,
            cancellation_reason.as_str(),
            cancellation_requested_at,
        )?
        .encode_json()?;
        database
            .store()
            .request_cancellation(
                RequestCancellation::new(
                    cancellation_operation,
                    lease.attempt_id(),
                    CancellationActor::new("test scheduler")?,
                    Some(cancellation_reason),
                    cancellation_requested_at,
                )
                .with_delivery(EnqueueRunnerCommand::new(
                    fence,
                    cancellation_operation,
                    RunnerOperationKind::new(CANCEL_JOB_COMMAND_KIND)?,
                    RunnerCommandPayload::new(
                        DocumentSchema::new(CANCEL_JOB_COMMAND_SCHEMA)?,
                        cancellation_payload,
                    )?,
                    cancellation_requested_at,
                )),
            )
            .await?;

        let terminal_request = operation_request(
            fence,
            OperationId::new(),
            "automata.runner.job-result.v1",
            [76; 32],
        )?;
        let terminal_observed_at = database_now(&database).await?;
        let terminal = CommitRunnerTerminalResult::new(
            terminal_request,
            lease.attempt_id(),
            lease.guard(),
            DocumentSchema::new(1)?,
            80,
            Sha256Digest::from_bytes([77; 32]),
            ObjectKey::new("results/result.json")?,
            JobConclusion::Success,
            terminal_observed_at,
            terminal_observed_at,
            response(b"result ack")?,
        )?;
        sqlx::query("UPDATE runners SET desired_state = 'disabled' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        assert!(matches!(
            database
                .store()
                .commit_runner_terminal_result(terminal.clone())
                .await,
            Err(StoreError::RunnerDisabled(id)) if id == fence.runner_id()
        ));
        sqlx::query("UPDATE runners SET desired_state = 'active' WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .execute(database.pool())
            .await?;
        let terminal_commit_before = database_now(&database).await?;
        let committed = database
            .store()
            .commit_runner_terminal_result(terminal.clone())
            .await?;
        let terminal_commit_after = database_now(&database).await?;
        let replayed = database
            .store()
            .commit_runner_terminal_result(terminal)
            .await?;
        assert!(!committed.was_replayed());
        assert!(replayed.was_replayed());
        let terminal_state: (String, Option<uuid::Uuid>, i64) = sqlx::query_as(
            r"
            SELECT lifecycle, lease_id,
                   (SELECT count(*) FROM attempt_terminal_results WHERE attempt_id = $1)
            FROM job_attempts WHERE id = $1
            ",
        )
        .bind(lease.attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(terminal_state, ("succeeded".to_owned(), None, 1));
        assert!(matches!(
            database
                .store()
                .cancellation_for_attempt(lease.attempt_id())
                .await,
            Err(StoreError::RunnerPayloadUnavailable { session_id, tombstone })
                if session_id == fence.session_id()
                    && tombstone.reason()
                        == automata_ci_store::RunnerPayloadTombstoneReason::Acknowledged
                    && tombstone.tombstoned_at() >= terminal_commit_before
                    && tombstone.tombstoned_at() <= terminal_commit_after
        ));
        let run_status: String =
            sqlx::query_scalar("SELECT status FROM workflow_runs WHERE id = $1")
                .bind(seed.run_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(run_status, "completed");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn lease_rejection_actions_requeue_transient_and_fail_invalid_work() -> TestResult {
    run_with_database(|database| async move {
        for (action, expected_lifecycle, expected_failures, digest_byte) in [
            (LeaseResponseAction::Requeue, "queued", 1_i32, 90_u8),
            (LeaseResponseAction::Fail, "failed", 0_i32, 91_u8),
        ] {
            let (seed, lease, metadata, slot, request_operation_id, request_digest) =
                active_lease(&database).await?;
            let fence = seed.session_fences[0];
            database
                .store()
                .publish_lease_offer(offer(
                    fence,
                    &lease,
                    &metadata,
                    slot,
                    request_operation_id,
                    request_digest,
                    OperationId::new(),
                )?)
                .await?;
            database
                .store()
                .commit_lease_response(CommitLeaseResponse::new(
                    operation_request(
                        fence,
                        OperationId::new(),
                        "automata.runner.lease-response.v1",
                        [digest_byte.wrapping_add(10); 32],
                    )?,
                    CommandCursor::initial(),
                    lease.attempt_id(),
                    slot,
                    lease.guard(),
                    action,
                    database_now(&database).await?,
                    response(b"rejected")?,
                ))
                .await?;
            let state: (String, Option<uuid::Uuid>, i32) = sqlx::query_as(
                "SELECT lifecycle, lease_id, lease_failures FROM job_attempts WHERE id = $1",
            )
            .bind(lease.attempt_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
            assert_eq!(
                state,
                (expected_lifecycle.to_owned(), None, expected_failures)
            );
        }
        Ok(())
    })
    .await
}

async fn active_lease(
    database: &TestDatabase,
) -> TestResult<(
    SeedData,
    Lease,
    JobIrMetadata,
    StableRunnerSlot,
    OperationId,
    Sha256Digest,
)> {
    active_lease_with_duration(database, ACTIVE_LEASE_DURATION_MILLIS).await
}

async fn active_lease_with_duration(
    database: &TestDatabase,
    duration_millis: i64,
) -> TestResult<(
    SeedData,
    Lease,
    JobIrMetadata,
    StableRunnerSlot,
    OperationId,
    Sha256Digest,
)> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            seed.job_id,
            AttemptNumber::new(1)?,
            UnixMillis::new(3),
        ))
        .await?;
    let slot = StableRunnerSlot::new(1)?;
    let operation_id = OperationId::new();
    let request_digest = Sha256Digest::from_bytes([29; 32]);
    let request_key = LeaseRequestKey::first(seed.session_fences[0], operation_id, slot);
    database
        .store()
        .begin_lease_request(BeginLeaseRequest::new(request_key, request_digest))
        .await?;
    let observed_at = database_now(database).await?;
    let page = database
        .store()
        .scan_runnable(RunnableScanRequest::new(
            seed.session_fences[0],
            slot,
            RunnableScanLimit::new(10)?,
            observed_at,
        ))
        .await?;
    let expires_at = UnixMillis::new(
        observed_at
            .get()
            .checked_add(duration_millis)
            .ok_or("test lease expiry overflowed")?,
    );
    let receipt = database
        .store()
        .try_claim(TryClaimAttempt::new(
            request_key,
            attempt_id,
            LeaseId::new(),
            observed_at,
            expires_at,
            page.claim_advance(attempt_id)?,
        )?)
        .await?;
    let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
        panic!("fixture attempt was not claimed");
    };
    Ok((
        seed,
        claimed.lease().clone(),
        claimed.job_ir().clone(),
        slot,
        operation_id,
        request_digest,
    ))
}

#[allow(clippy::too_many_arguments)]
fn offer(
    fence: automata_ci_store::RunnerSessionFence,
    lease: &Lease,
    metadata: &JobIrMetadata,
    slot: StableRunnerSlot,
    request_operation_id: OperationId,
    request_digest: Sha256Digest,
    command_operation_id: OperationId,
) -> TestResult<PublishLeaseOffer> {
    let request = RunnerOperationRequest::new(
        fence,
        request_operation_id,
        RunnerOperationKind::new(LEASE_REQUEST_KIND)?,
        request_digest,
    );
    let command = EnqueueRunnerCommand::new(
        fence,
        command_operation_id,
        RunnerOperationKind::new(LEASE_OFFER_KIND)?,
        RunnerCommandPayload::new(
            DocumentSchema::new(1)?,
            b"canonical typed lease offer body".to_vec(),
        )?,
        lease.issued_at(),
    );
    Ok(PublishLeaseOffer::new(
        request,
        RunnerProtocolVersion::new(1)?,
        slot,
        lease.clone(),
        metadata.clone(),
        lease.expires_at(),
        command,
    )?)
}

fn operation_request(
    fence: automata_ci_store::RunnerSessionFence,
    operation_id: OperationId,
    kind: &str,
    digest: [u8; 32],
) -> TestResult<RunnerOperationRequest> {
    Ok(RunnerOperationRequest::new(
        fence,
        operation_id,
        RunnerOperationKind::new(kind)?,
        Sha256Digest::from_bytes(digest),
    ))
}

fn response(bytes: &[u8]) -> TestResult<RunnerOperationResponse> {
    Ok(RunnerOperationResponse::new(
        DocumentSchema::new(1)?,
        bytes.to_vec(),
    )?)
}

async fn offer_state(
    database: &TestDatabase,
    session_id: automata_ci_core::RunnerSessionId,
) -> TestResult<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        r"
        SELECT session.last_command_sequence,
               (SELECT count(*) FROM runner_command_outbox WHERE runner_session_id = $1),
               (SELECT count(*) FROM runner_lease_offer_publications WHERE runner_session_id = $1)
        FROM runner_sessions AS session
        WHERE session.id = $1
        ",
    )
    .bind(session_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn maintenance_request(
    database: &TestDatabase,
) -> TestResult<ControlPlaneMaintenanceRequest> {
    Ok(ControlPlaneMaintenanceRequest::new(
        database_now(database).await?,
        LeaseFailureLimit::new(3)?,
        MaintenanceBatchSize::new(10)?,
        StaleSessionTimeoutMillis::new(600_000)?,
    )?)
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await
            .map(UnixMillis::new)?,
    )
}

async fn wait_until_database_time(clock: &TestClock, target: UnixMillis) -> TestResult {
    clock
        .set(
            target
                .get()
                .checked_add(1)
                .ok_or("runner-control expiry clock overflow")?,
        )
        .await?;
    Ok(())
}

async fn renewal_from_database_now(
    database: &TestDatabase,
    lease: &Lease,
    fence: automata_ci_store::RunnerSessionFence,
    duration_millis: i64,
) -> TestResult<RenewLease> {
    let observed_at = database_now(database).await?;
    let expires_at = UnixMillis::new(
        observed_at
            .get()
            .checked_add(duration_millis)
            .ok_or("test renewal expiry overflowed")?,
    );
    Ok(RenewLease::new(
        lease.attempt_id(),
        fence,
        lease.guard(),
        observed_at,
        expires_at,
    )?)
}

async fn authorized_renewal_from_database_now(
    database: &TestDatabase,
    lease: &Lease,
    fence: automata_ci_store::RunnerSessionFence,
    reported_lifecycle: JobLifecycle,
    duration_millis: i64,
) -> TestResult<RenewLease> {
    Ok(database
        .store()
        .authorize_lease_renewal(
            renewal_from_database_now(database, lease, fence, duration_millis).await?,
            reported_lifecycle,
        )
        .await?)
}

async fn lease_expiry(database: &TestDatabase, attempt_id: AttemptId) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT lease_expires_at_ms FROM job_attempts WHERE id = $1")
            .bind(attempt_id.as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}

async fn session_state(
    database: &TestDatabase,
    session_id: automata_ci_core::RunnerSessionId,
) -> TestResult<(i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT heartbeat_at_ms, acknowledged_command_sequence FROM runner_sessions WHERE id = $1",
    )
    .bind(session_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn session_and_lease_state(
    database: &TestDatabase,
    session_id: automata_ci_core::RunnerSessionId,
    attempt_id: AttemptId,
) -> TestResult<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        r"
        SELECT session.heartbeat_at_ms, session.acknowledged_command_sequence,
               attempt.lease_expires_at_ms
        FROM runner_sessions AS session
        CROSS JOIN job_attempts AS attempt
        WHERE session.id = $1 AND attempt.id = $2
        ",
    )
    .bind(session_id.as_uuid())
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn install_receipt_failpoint(database: &TestDatabase, table: &str) -> TestResult {
    let (function, trigger) = failpoint_names(table)?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''intentional runner-control rollback''; END'"
    )))
    .execute(database.pool())
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER {trigger} BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()"
    )))
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn remove_receipt_failpoint(database: &TestDatabase, table: &str) -> TestResult {
    let (function, trigger) = failpoint_names(table)?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {trigger} ON {table}"
    )))
    .execute(database.pool())
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP FUNCTION {function}()")))
        .execute(database.pool())
        .await?;
    Ok(())
}

fn failpoint_names(table: &str) -> TestResult<(&'static str, &'static str)> {
    match table {
        "runner_lease_offer_publications" => Ok((
            "fail_runner_lease_offer_publication",
            "runner_lease_offer_publication_failpoint",
        )),
        "runner_rpc_receipts" => Ok(("fail_runner_rpc_receipt", "runner_rpc_receipt_failpoint")),
        _ => Err("unsupported test failpoint table".into()),
    }
}

fn test_lease_response(sequence: u16) -> TestResult<RunnerOperationResponse> {
    Ok(RunnerOperationResponse::new(
        DocumentSchema::new(1)?,
        sequence.to_be_bytes().to_vec(),
    )?)
}

async fn install_completed_no_work_head(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
    slot_number: u16,
    observed_at: UnixMillis,
) -> TestResult {
    let slot = StableRunnerSlot::new(slot_number)?;
    let key = LeaseRequestKey::first(fence, OperationId::new(), slot);
    let begin = BeginLeaseRequest::new(key, Sha256Digest::from_bytes([61; 32]));
    database.store().begin_lease_request(begin).await?;
    let page = database
        .store()
        .scan_runnable(RunnableScanRequest::new(
            fence,
            slot,
            RunnableScanLimit::new(10)?,
            observed_at,
        ))
        .await?;
    database
        .store()
        .record_no_work(NoWorkLeaseRequest::new(
            key,
            observed_at,
            page.no_work_advance(),
        )?)
        .await?;
    database
        .store()
        .complete_lease_request(CompleteLeaseRequest::without_lease_offer(
            begin,
            test_lease_response(slot_number)?,
            observed_at,
        ))
        .await?;
    Ok(())
}

async fn lease_retry_counts(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
) -> TestResult<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM runner_lease_request_heads WHERE runner_session_id = $1),
            (SELECT count(*) FROM runner_operation_receipts WHERE runner_session_id = $1),
            (SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_kind = $2)
        ",
    )
    .bind(fence.session_id().as_uuid())
    .bind(LEASE_REQUEST_KIND)
    .fetch_one(database.pool())
    .await?)
}

async fn queue_cursor_count(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM runner_queue_cursors WHERE runner_id = $1")
            .bind(fence.runner_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
    )
}
