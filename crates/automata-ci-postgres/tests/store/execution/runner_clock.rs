use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_control::{
    lease::repository::{
        RunnableAttemptRepository as _, RunnerClaimRepository as _,
        RunnerLeaseRequestRepository as _,
    },
    runner_control::{
        durable::{
            CommitLeaseHeartbeat, CommitLeaseResponse, LeaseOfferClaimStatus, LeaseResponseAction,
            PublishLeaseOffer, RunnerControlTransactionRepository as _,
            RunnerLeaseOfferRepository as _,
        },
        repository::{RunnerCommandOutbox as _, RunnerSessionRepository as _},
    },
};
use automata_ci_core::{
    AttemptId, AttemptNumber, Lease, LeaseId, OperationId, RunnerSessionId, Sha256Digest,
    UnixMillis,
};
use automata_ci_key_management::{
    KeyEncryptionContext, KeyEncryptionError, KeyEncryptionProvider, SecretBytes, WrappedDataKey,
};
use automata_ci_postgres::store::PostgresStore;
use automata_ci_store::{
    AcquireLease, AttemptStoreError, BeginLeaseRequest, CommandCursor, CommandReplayDisposition,
    CommandReplayLimit, CommandSequence, CompleteLeaseRequest,
    ControlPlaneMaintenanceRepository as _, ControlPlaneMaintenanceRequest, DocumentSchema,
    EnqueueRunnerCommand, GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS, HeartbeatRunnerSession,
    InternalAttemptRepository as _, JobIrMetadata, LeaseFailureLimit, LeaseOfferCommandIdentity,
    LeaseRequestCompletion, LeaseRequestKey, MaintenanceBatchSize, OpenRunnerSession,
    QueuedAttempt, RenewLease, ResumeRunnerSession, RevokedLeaseOfferFallback, RunnableScanLimit,
    RunnableScanRequest, RunnerCommandPayload, RunnerOperationKind, RunnerOperationRequest,
    RunnerOperationResponse, RunnerProtocolVersion, StableRunnerSlot, StaleSessionTimeoutMillis,
    StoreError, TryClaimAttempt, TryClaimOutcome,
};
use sqlx::PgPool;
use tokio::sync::Semaphore;

use crate::support::{
    SeedData, TestClock, TestDatabase, TestResult, run_with_database, seed_control_plane,
    test_runner_payload_key_provider,
};

const LEASE_REQUEST_KIND: &str = "automata.runner.lease-request.v1";
const LEASE_OFFER_KIND: &str = "automata.runner.lease-offer.v1";
const HEARTBEAT_KIND: &str = "automata.runner.lease-heartbeat.v1";
const LEASE_RESPONSE_KIND: &str = "automata.runner.lease-response.v1";
const RUNNER_RESPONSE_KEY_PURPOSE: &str = "control-plane/runner-rpc-response:v1";

#[allow(
    clippy::type_complexity,
    reason = "the tuple mirrors one exact nullable SQL projection used by a single assertion"
)]
type LeaseOfferReceiptCompletionRow = (
    Option<uuid::Uuid>,
    Option<i64>,
    Option<String>,
    Option<i32>,
    Option<Vec<u8>>,
    Option<i32>,
    Option<uuid::Uuid>,
    Option<i64>,
    Option<i32>,
    Option<Vec<u8>>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockingKeyOperation {
    Wrap,
    Unwrap,
}

#[derive(Debug)]
struct BlockingKeyProvider {
    inner: Arc<dyn KeyEncryptionProvider>,
    operation: BlockingKeyOperation,
    blocked: AtomicBool,
    started: Semaphore,
    release: Semaphore,
}

impl BlockingKeyProvider {
    fn new(operation: BlockingKeyOperation) -> Arc<Self> {
        Arc::new(Self {
            inner: test_runner_payload_key_provider(),
            operation,
            blocked: AtomicBool::new(false),
            started: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }

    async fn block_once(&self, operation: BlockingKeyOperation, context: &KeyEncryptionContext) {
        if operation == self.operation
            && context.purpose().as_str() == RUNNER_RESPONSE_KEY_PURPOSE
            && !self.blocked.swap(true, Ordering::SeqCst)
        {
            self.started.add_permits(1);
            self.release
                .acquire()
                .await
                .expect("test release semaphore remains open")
                .forget();
        }
    }

    async fn wait_until_blocked(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.started.acquire())
            .await
            .expect("runner payload operation reached the blocking provider")
            .expect("test start semaphore remains open")
            .forget();
    }

    fn release(&self) {
        self.release.add_permits(1);
    }
}

#[async_trait]
impl KeyEncryptionProvider for BlockingKeyProvider {
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        self.block_once(BlockingKeyOperation::Wrap, context).await;
        self.inner.wrap_data_key(plaintext_key, context).await
    }

    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        self.block_once(BlockingKeyOperation::Unwrap, context).await;
        self.inner.unwrap_data_key(wrapped_key, context).await
    }
}

#[derive(Debug)]
struct UnavailableKeyProvider;

#[async_trait]
impl KeyEncryptionProvider for UnavailableKeyProvider {
    async fn wrap_data_key(
        &self,
        _plaintext_key: &SecretBytes,
        _context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        Err(KeyEncryptionError::Unavailable)
    }

    async fn unwrap_data_key(
        &self,
        _wrapped_key: &WrappedDataKey,
        _context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        Err(KeyEncryptionError::Unavailable)
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn fast_and_slow_callers_are_closed_while_direct_leases_keep_exact_duration() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        for (attempt_number, offset) in [(1_u32, 61_000_i64), (2, -61_000)] {
            let database_now = database_now(database.pool()).await?;
            let attempt_id = insert_queued(
                &database,
                seed.job_id,
                attempt_number,
                database_now.get() - 1_000,
            )
            .await?;
            let caller_now = UnixMillis::new(database_now.get() + offset);
            let result = database
                .store()
                .acquire_lease(AcquireLease::new(
                    attempt_id,
                    LeaseId::new(),
                    fence,
                    StableRunnerSlot::new(u16::try_from(attempt_number)?)?,
                    caller_now,
                    UnixMillis::new(caller_now.get() + 5_000),
                )?)
                .await;
            assert!(matches!(result, Err(AttemptStoreError::Operation(_))));
            terminalize_attempt_as_lost(&database, attempt_id).await?;
        }

        let before = database_now(database.pool()).await?;
        let attempt_id = insert_queued(&database, seed.job_id, 3, before.get() - 1_000).await?;
        let lease = database
            .store()
            .acquire_lease(AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                fence,
                StableRunnerSlot::new(3)?,
                before,
                UnixMillis::new(before.get() + 5_000),
            )?)
            .await?;
        let after = database_now(database.pool()).await?;
        assert_eq!(lease.expires_at().get() - lease.issued_at().get(), 5_000);
        assert!(lease.issued_at() >= before && lease.issued_at() <= after);

        let renewal_observed = database_now(database.pool()).await?;
        let renewed = database
            .store()
            .renew_lease(RenewLease::new(
                attempt_id,
                fence,
                lease.guard(),
                renewal_observed,
                UnixMillis::new(renewal_observed.get() + 6_000),
            )?)
            .await?;
        let renewal_after = database_now(database.pool()).await?;
        assert!(renewed.expires_at().get() >= renewal_observed.get() + 6_000);
        assert!(renewed.expires_at().get() <= renewal_after.get() + 6_000);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn session_mutations_ignore_caller_clock_and_publish_nonregressing_database_time()
-> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let original = seed.session_fences[0];

        for offset in [10_000_000_i64, -10_000_000] {
            let before = database_now(database.pool()).await?;
            let caller_now = UnixMillis::new(before.get() + offset);
            let snapshot = database
                .store()
                .heartbeat_session(HeartbeatRunnerSession::new(
                    original,
                    CommandCursor::initial(),
                    caller_now,
                ))
                .await?;
            let after = database_now(database.pool()).await?;
            assert!(snapshot.heartbeat_at() >= before && snapshot.heartbeat_at() <= after);
            assert_ne!(snapshot.heartbeat_at(), caller_now);
        }

        let existing = database.store().get_session(original).await?;
        let before_open = database_now(database.pool()).await?;
        let fast_caller = UnixMillis::new(before_open.get() + 30_000);
        let opened = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                original.runner_id(),
                original.runner_generation(),
                existing.protocol_version(),
                existing.job_ir_version(),
                existing.capability_snapshot().clone(),
                fast_caller,
            ))
            .await?;
        let after_open = database_now(database.pool()).await?;
        assert!(opened.connected_at() >= before_open && opened.connected_at() <= after_open);
        assert_eq!(opened.heartbeat_at(), opened.connected_at());
        assert!(opened.heartbeat_at() < fast_caller);

        let before_resume = database_now(database.pool()).await?;
        let resumed = database
            .store()
            .resume_session(ResumeRunnerSession::new(
                opened.fence().runner_id(),
                opened.fence().runner_generation(),
                opened.fence().session_id(),
                CommandCursor::initial(),
                UnixMillis::new(before_resume.get() - 30_000),
            ))
            .await?;
        let after_resume = database_now(database.pool()).await?;
        assert!(resumed.heartbeat_at() >= before_resume);
        assert!(resumed.heartbeat_at() <= after_resume);

        let before_heartbeat = database_now(database.pool()).await?;
        let heartbeat = database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                opened.fence(),
                CommandCursor::initial(),
                UnixMillis::new(before_heartbeat.get() + 30_000),
            ))
            .await?;
        let after_heartbeat = database_now(database.pool()).await?;
        assert!(heartbeat.heartbeat_at() >= before_heartbeat);
        assert!(heartbeat.heartbeat_at() <= after_heartbeat);

        let before_close = database_now(database.pool()).await?;
        database
            .store()
            .close_session(automata_ci_store::CloseRunnerSession::new(
                opened.fence(),
                UnixMillis::new(before_close.get() - 30_000),
            ))
            .await?;
        let after_close = database_now(database.pool()).await?;
        let closed = database.store().get_session(opened.fence()).await?;
        let disconnected_at = closed.disconnected_at().expect("session must be closed");
        assert!(disconnected_at >= before_close && disconnected_at <= after_close);

        database
            .store()
            .close_session(automata_ci_store::CloseRunnerSession::new(
                opened.fence(),
                UnixMillis::new(1),
            ))
            .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn open_resume_and_close_sample_database_time_after_the_runner_fence_lock() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let original = database.store().get_session(seed.session_fences[0]).await?;

        let mut open_blocker = database.pool().begin().await?;
        let open_blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *open_blocker)
            .await?;
        sqlx::query("SELECT id FROM runners WHERE id = $1 FOR UPDATE")
            .bind(original.fence().runner_id().as_uuid())
            .fetch_one(&mut *open_blocker)
            .await?;
        let store = database.store().clone();
        let open_request = OpenRunnerSession::new(
            RunnerSessionId::new(),
            original.fence().runner_id(),
            original.fence().runner_generation(),
            original.protocol_version(),
            original.job_ir_version(),
            original.capability_snapshot().clone(),
            database_now(database.pool()).await?,
        );
        let opening = tokio::spawn(async move { store.open_session(open_request).await });
        wait_for_direct_database_blocker(database.pool(), open_blocker_pid).await?;
        let open_unlocked_at = database_now(database.pool()).await?;
        open_blocker.commit().await?;
        let opened = opening.await??;
        assert!(opened.connected_at() >= open_unlocked_at);
        assert_eq!(opened.heartbeat_at(), opened.connected_at());

        let mut resume_blocker = database.pool().begin().await?;
        let resume_blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *resume_blocker)
            .await?;
        sqlx::query("SELECT id FROM runners WHERE id = $1 FOR UPDATE")
            .bind(opened.fence().runner_id().as_uuid())
            .fetch_one(&mut *resume_blocker)
            .await?;
        let store = database.store().clone();
        let resume_request = ResumeRunnerSession::new(
            opened.fence().runner_id(),
            opened.fence().runner_generation(),
            opened.fence().session_id(),
            CommandCursor::initial(),
            database_now(database.pool()).await?,
        );
        let resuming = tokio::spawn(async move { store.resume_session(resume_request).await });
        wait_for_direct_database_blocker(database.pool(), resume_blocker_pid).await?;
        let resume_unlocked_at = database_now(database.pool()).await?;
        resume_blocker.commit().await?;
        let resumed = resuming.await??;
        assert!(resumed.heartbeat_at() >= resume_unlocked_at);

        let mut close_blocker = database.pool().begin().await?;
        let close_blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *close_blocker)
            .await?;
        sqlx::query("SELECT id FROM runners WHERE id = $1 FOR UPDATE")
            .bind(opened.fence().runner_id().as_uuid())
            .fetch_one(&mut *close_blocker)
            .await?;
        let store = database.store().clone();
        let close_request = automata_ci_store::CloseRunnerSession::new(
            opened.fence(),
            database_now(database.pool()).await?,
        );
        let closing = tokio::spawn(async move { store.close_session(close_request).await });
        wait_for_direct_database_blocker(database.pool(), close_blocker_pid).await?;
        let close_unlocked_at = database_now(database.pool()).await?;
        close_blocker.commit().await?;
        closing.await??;
        let closed = database.store().get_session(opened.fence()).await?;
        assert!(
            closed
                .disconnected_at()
                .is_some_and(|disconnected| disconnected >= close_unlocked_at)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn future_durable_session_timestamps_fail_closed() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let snapshot = database.store().get_session(fence).await?;
        let database_time = database_now(database.pool()).await?;
        let future = UnixMillis::new(database_time.get() + 120_000);

        sqlx::query("UPDATE runner_sessions SET heartbeat_at_ms = $2 WHERE id = $1")
            .bind(fence.session_id().as_uuid())
            .bind(future.get())
            .execute(database.pool())
            .await?;
        let heartbeat = database
            .store()
            .heartbeat_session(HeartbeatRunnerSession::new(
                fence,
                CommandCursor::initial(),
                database_time,
            ))
            .await;
        assert!(matches!(heartbeat, Err(StoreError::CorruptData(_))));

        let open = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                fence.runner_id(),
                fence.runner_generation(),
                snapshot.protocol_version(),
                snapshot.job_ir_version(),
                snapshot.capability_snapshot().clone(),
                database_time,
            ))
            .await;
        assert!(matches!(open, Err(StoreError::CorruptData(_))));
        let retained_heartbeat: i64 =
            sqlx::query_scalar("SELECT heartbeat_at_ms FROM runner_sessions WHERE id = $1")
                .bind(fence.session_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(retained_heartbeat, future.get());

        let reset_at = database_now(database.pool()).await?;
        set_session_heartbeat(&database, fence.session_id(), reset_at).await?;
        sqlx::query("UPDATE runners SET updated_at_ms = $2 WHERE id = $1")
            .bind(fence.runner_id().as_uuid())
            .bind(reset_at.get() + 120_000)
            .execute(database.pool())
            .await?;
        let open = database
            .store()
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                fence.runner_id(),
                fence.runner_generation(),
                snapshot.protocol_version(),
                snapshot.job_ir_version(),
                snapshot.capability_snapshot().clone(),
                reset_at,
            ))
            .await;
        assert!(matches!(open, Err(StoreError::CorruptData(_))));
        let retained_runner_time: i64 =
            sqlx::query_scalar("SELECT updated_at_ms FROM runners WHERE id = $1")
                .bind(fence.runner_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(retained_runner_time, reset_at.get() + 120_000);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn session_heartbeat_samples_database_time_after_waiting_for_its_fence() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let mut blocker = database.pool().begin().await?;
        sqlx::query("SELECT id FROM runners WHERE id = $1 FOR UPDATE")
            .bind(fence.runner_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;

        let caller_now = database_now(database.pool()).await?;
        let store = database.store().clone();
        let task = tokio::spawn(async move {
            store
                .heartbeat_session(HeartbeatRunnerSession::new(
                    fence,
                    CommandCursor::initial(),
                    caller_now,
                ))
                .await
        });
        wait_for_database_lock(
            database.pool(),
            "SELECT generation, session_epoch, status, desired_state",
        )
        .await?;
        let unlock_at = database_now(database.pool()).await?;
        blocker.commit().await?;

        let snapshot = task.await??;
        assert!(snapshot.heartbeat_at() >= unlock_at);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn production_claim_rejects_fast_and_slow_callers_before_issuing_authority() -> TestResult {
    run_with_database(|database| async move {
        let prepared = prepare_claim(&database, 5_000).await?;
        for offset in [61_000_i64, -61_000] {
            let database_now = database_now(database.pool()).await?;
            let caller_now = UnixMillis::new(database_now.get() + offset);
            let result = database
                .store()
                .try_claim(TryClaimAttempt::new(
                    prepared.request_key,
                    prepared.attempt_id,
                    LeaseId::new(),
                    caller_now,
                    UnixMillis::new(caller_now.get() + prepared.duration_millis),
                    prepared.cursor,
                )?)
                .await;
            assert!(matches!(
                result,
                Err(StoreError::Attempt(AttemptStoreError::Operation(_)))
            ));
        }

        let caller_now = database_now(database.pool()).await?;
        let receipt = database
            .store()
            .try_claim(TryClaimAttempt::new(
                prepared.request_key,
                prepared.attempt_id,
                LeaseId::new(),
                caller_now,
                UnixMillis::new(caller_now.get() + prepared.duration_millis),
                prepared.cursor,
            )?)
            .await?;
        assert!(matches!(receipt.outcome(), TryClaimOutcome::Claimed(_)));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn delayed_claim_lock_issues_a_full_database_time_lease() -> TestResult {
    run_with_database(|database| async move {
        let prepared = prepare_claim(&database, 2_000).await?;
        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(prepared.attempt_id.as_uuid())
            .fetch_one(&mut *blocker)
            .await?;

        let caller_now = database_now(database.pool()).await?;
        let request = TryClaimAttempt::new(
            prepared.request_key,
            prepared.attempt_id,
            LeaseId::new(),
            caller_now,
            UnixMillis::new(caller_now.get() + prepared.duration_millis),
            prepared.cursor,
        )?;
        let store = database.store().clone();
        let task = tokio::spawn(async move { store.try_claim(request).await });
        wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
        let unlock_at = database_now(database.pool()).await?;
        blocker.commit().await?;

        let receipt = task.await??;
        let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
            panic!("delayed exact claim must still win");
        };
        assert!(claimed.lease().issued_at() >= unlock_at);
        assert_eq!(
            claimed.lease().expires_at().get() - claimed.lease().issued_at().get(),
            prepared.duration_millis
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn lease_offer_horizon_closes_publication_acceptance_and_every_replay_path() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 30_000).await?;
        let fence = fixture.seed.session_fences[0];
        let attempt_id = fixture.lease.attempt_id();

        let mut blocker = database.pool().begin().await?;
        sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(attempt_id.as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let blocked_horizon = UnixMillis::new(database_now(database.pool()).await?.get() + 500);
        let blocked_offer = offer_with_horizon(
            &fixture,
            OperationId::new(),
            fixture.lease.issued_at(),
            blocked_horizon,
        )?;
        let store = database.store().clone();
        let blocked_publish =
            tokio::spawn(async move { store.publish_lease_offer(blocked_offer).await });
        wait_for_database_lock(database.pool(), "FROM job_attempts AS attempt").await?;
        wait_until_database_time(&clock, blocked_horizon).await?;
        blocker.commit().await?;
        assert!(matches!(
            blocked_publish.await?,
            Err(StoreError::AttemptFenceRejected(rejected)) if rejected == attempt_id
        ));
        let empty: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runner_command_outbox WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_lease_offer_publications
                 WHERE runner_session_id = $1)
            ",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(empty, (0, 0), "late publication must roll back its outbox row");

        let future_created_at =
            UnixMillis::new(database_now(database.pool()).await?.get() + 2_000);
        let future_offer = offer_with_horizon(
            &fixture,
            OperationId::new(),
            future_created_at,
            UnixMillis::new(future_created_at.get() + 2_000),
        )?;
        assert!(matches!(
            database.store().publish_lease_offer(future_offer).await,
            Err(StoreError::AttemptFenceRejected(rejected)) if rejected == attempt_id
        ));
        let empty_after_future: (i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM runner_command_outbox WHERE runner_session_id = $1),
                (SELECT count(*) FROM runner_lease_offer_publications
                 WHERE runner_session_id = $1)
            ",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(empty_after_future, (0, 0));

        let live_horizon = UnixMillis::new(database_now(database.pool()).await?.get() + 5_000);
        let live_offer = offer_with_horizon(
            &fixture,
            OperationId::new(),
            fixture.lease.issued_at(),
            live_horizon,
        )?;
        let published = database
            .store()
            .publish_lease_offer(live_offer.clone())
            .await?;
        assert_eq!(published.offer_valid_until(), live_horizon);
        let durable_horizon: i64 = sqlx::query_scalar(
            "SELECT offer_valid_until_ms FROM runner_lease_offer_publications WHERE runner_session_id = $1 AND request_operation_id = $2",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable_horizon, live_horizon.get());

        let immutable = sqlx::query(
            "UPDATE runner_lease_offer_publications \
             SET offer_valid_until_ms = offer_valid_until_ms - 1 \
             WHERE runner_session_id = $1 AND request_operation_id = $2",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("the authenticated offer horizon must be immutable");
        assert_eq!(
            immutable
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runner_lease_offer_authority_horizon_immutable")
        );
        let pre_lease_creation = sqlx::query(
            "UPDATE runner_lease_offer_publications \
             SET created_at_ms = lease_issued_at_ms - 1 \
             WHERE runner_session_id = $1 AND request_operation_id = $2",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("offer creation cannot predate lease issuance");
        assert_eq!(
            pre_lease_creation
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runner_lease_offer_publications_authority_horizon")
        );
        for forged_reason in ["attempt_superseded", "authority_expired"] {
            let forged = sqlx::query(
                r"
                UPDATE runner_lease_offer_publications
                SET delivery_revoked_at_ms = CASE $3
                        WHEN 'authority_expired' THEN offer_valid_until_ms
                        ELSE created_at_ms
                    END,
                    delivery_revocation_reason = $3
                WHERE runner_session_id = $1 AND request_operation_id = $2
                ",
            )
            .bind(fence.session_id().as_uuid())
            .bind(fixture.request_operation_id.as_uuid())
            .bind(forged_reason)
            .execute(database.pool())
            .await
            .expect_err("direct DML cannot forge an initial delivery revocation");
            assert_eq!(
                forged
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::constraint),
                Some("runner_lease_offer_delivery_revocation_authority")
            );
        }
        let unrevoked: (Option<i64>, Option<String>) = sqlx::query_as(
            r"
            SELECT delivery_revoked_at_ms, delivery_revocation_reason
            FROM runner_lease_offer_publications
            WHERE runner_session_id = $1 AND request_operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(unrevoked, (None, None));

        let replay = database
            .store()
            .publish_lease_offer(live_offer.clone())
            .await?;
        assert!(replay.was_replayed());
        let changed_creation = offer_with_horizon(
            &fixture,
            OperationId::new(),
            UnixMillis::new(fixture.lease.issued_at().get() + 1),
            live_horizon,
        )?;
        assert!(matches!(
            database.store().publish_lease_offer(changed_creation).await,
            Err(StoreError::OperationConflict { .. })
        ));

        let identity = LeaseOfferCommandIdentity::new(
            fence,
            published.command().request().operation_id(),
            published.command().sequence(),
        );
        assert!(
            database
                .store()
                .resolve_lease_offer_command(identity)
                .await?
                .is_some()
        );
        assert_eq!(
            database
                .store()
                .replay_commands(
                    fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(1)?,
                )
                .await?
                .len(),
            1
        );

        wait_until_database_time(&clock, live_horizon).await?;
        let acceptance = CommitLeaseResponse::new(
            operation_request(fence, OperationId::new(), LEASE_RESPONSE_KIND, [41; 32])?,
            CommandCursor::initial(),
            attempt_id,
            fixture.slot,
            fixture.lease.guard(),
            LeaseResponseAction::Accept,
            database_now(database.pool()).await?,
            response(b"expired authority horizon")?,
        );
        assert!(matches!(
            database.store().commit_lease_response(acceptance).await,
            Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(expired)))
                if expired == attempt_id
        ));
        let unavailable_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(Arc::new(UnavailableKeyProvider));
        assert!(matches!(
            unavailable_store.resolve_lease_offer_command(identity).await,
            Err(StoreError::AttemptFenceRejected(rejected)) if rejected == attempt_id
        ));
        assert!(matches!(
            database.store().resolve_lease_offer_command(identity).await,
            Err(StoreError::AttemptFenceRejected(rejected)) if rejected == attempt_id
        ));
        let revocation: (Option<i64>, Option<String>) = sqlx::query_as(
            r"
            SELECT delivery_revoked_at_ms, delivery_revocation_reason
            FROM runner_lease_offer_publications
            WHERE runner_session_id = $1 AND request_operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(revocation.0.is_some_and(|observed| observed >= live_horizon.get()));
        assert_eq!(revocation.1.as_deref(), Some("authority_expired"));
        assert!(matches!(
            unavailable_store.resolve_lease_offer_command(identity).await,
            Err(StoreError::AttemptFenceRejected(rejected)) if rejected == attempt_id
        ));
        let immutable_revocation = sqlx::query(
            "UPDATE runner_lease_offer_publications \
             SET delivery_revoked_at_ms = delivery_revoked_at_ms + 1 \
             WHERE runner_session_id = $1 AND request_operation_id = $2",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await
        .expect_err("persisted delivery revocation must be immutable");
        assert_eq!(
            immutable_revocation
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("runner_lease_offer_delivery_revocation_immutable")
        );
        let revoked_replay = database
            .store()
            .replay_commands(
                fence,
                CommandCursor::initial(),
                CommandReplayLimit::new(1)?,
            )
            .await?;
        assert!(revoked_replay.is_empty());
        assert_eq!(
            revoked_replay.disposition(),
            CommandReplayDisposition::Exhausted
        );
        let later_command = database
            .store()
            .enqueue_command(EnqueueRunnerCommand::new(
                fence,
                OperationId::new(),
                RunnerOperationKind::new("automata.runner.clock-probe.v1")?,
                RunnerCommandPayload::new(
                    DocumentSchema::new(1)?,
                    b"later command remains deliverable".to_vec(),
                )?,
                database_now(database.pool()).await?,
            ))
            .await?;
        let replayed_commands = database
            .store()
            .replay_commands(
                fence,
                CommandCursor::initial(),
                CommandReplayLimit::new(1)?,
            )
            .await?;
        assert_eq!(replayed_commands.len(), 1);
        assert_eq!(replayed_commands[0].request(), later_command.request());
        assert_eq!(replayed_commands[0].sequence(), later_command.sequence());
        assert!(replayed_commands[0].was_replayed());
        assert_eq!(
            database
                .store()
                .inspect_lease_offer_claim(live_offer.claim().clone())
                .await?,
            LeaseOfferClaimStatus::ClaimSuperseded
        );
        assert!(matches!(
            database.store().publish_lease_offer(live_offer).await,
            Err(StoreError::AttemptFenceRejected(rejected)) if rejected == attempt_id
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn direct_delivery_revocation_uses_locked_attempt_and_database_time() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 60_000).await?;
        let fence = fixture.seed.session_fences[0];
        database
            .store()
            .publish_lease_offer(offer(&fixture, OperationId::new())?)
            .await?;
        wait_until_database_time(&clock, UnixMillis::new(fixture.lease.issued_at().get() + 1))
            .await?;
        let before_takeover = database_now(database.pool()).await?;
        let mut takeover = database.pool().begin().await?;
        replace_locked_lease(&mut takeover, &fixture).await?;
        takeover.commit().await?;

        let marker: (i64, String) = sqlx::query_as(
            r"
            UPDATE runner_lease_offer_publications
            SET delivery_revoked_at_ms = $3,
                delivery_revocation_reason = 'attempt_superseded'
            WHERE runner_session_id = $1 AND request_operation_id = $2
            RETURNING delivery_revoked_at_ms, delivery_revocation_reason
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(fixture.lease.issued_at().get())
        .fetch_one(database.pool())
        .await?;
        assert!(marker.0 >= before_takeover.get());
        assert_ne!(marker.0, fixture.lease.issued_at().get());
        assert_eq!(marker.1, "attempt_superseded");

        let unavailable_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(Arc::new(UnavailableKeyProvider));
        let replay = unavailable_store
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert!(replay.is_empty());
        assert_eq!(replay.disposition(), CommandReplayDisposition::Exhausted);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "keep the post-KMS revocation marker, bound receipt, exact replay, and successor deletion assertions in one linear transaction narrative"
)]
async fn lease_offer_receipt_completion_persists_successor_continuity_after_encryption()
-> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 10_000).await?;
        let horizon = UnixMillis::new(database_now(database.pool()).await?.get() + 2_000);
        let published = database
            .store()
            .publish_lease_offer(offer_with_horizon(
                &fixture,
                OperationId::new(),
                fixture.lease.issued_at(),
                horizon,
            )?)
            .await?;
        let begin = BeginLeaseRequest::new(
            LeaseRequestKey::first(
                fixture.seed.session_fences[0],
                fixture.request_operation_id,
                fixture.slot,
            ),
            fixture.request_digest,
        );
        let primary_response = response(b"full lease offer response")?;
        let primary_schema = primary_response.schema();
        let primary_digest = primary_response.digest();
        let revoked_response = response(b"durable revoked lease offer response")?;
        let persisted_fallback = fallback(&revoked_response, OperationId::new(), 1_000)?;
        let command_identity = LeaseOfferCommandIdentity::new(
            fixture.seed.session_fences[0],
            published.command().request().operation_id(),
            published.command().sequence(),
        );
        let completion = CompleteLeaseRequest::for_lease_offer_with_fallback(
            begin,
            primary_response.clone(),
            revoked_response.clone(),
            persisted_fallback,
            database_now(database.pool()).await?,
            command_identity,
        )?;
        let different_primary = CompleteLeaseRequest::for_lease_offer_with_fallback(
            begin,
            response(b"different bearer lease offer response")?,
            revoked_response.clone(),
            persisted_fallback,
            database_now(database.pool()).await?,
            command_identity,
        )?;
        let provider = BlockingKeyProvider::new(BlockingKeyOperation::Wrap);
        let store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(provider.clone());
        let replay_completion = completion.clone();
        let completion_task = tokio::spawn(async move {
            store.complete_lease_request(completion).await
        });
        provider.wait_until_blocked().await;
        let second_store = database.store().clone();
        let second_completion_task = tokio::spawn(async move {
            second_store
                .complete_lease_request(different_primary)
                .await
        });
        wait_until_database_time(&clock, horizon).await?;
        provider.release();

        let winner = completion_task.await??;
        assert_eq!(
            winner.revoked_offer_fallback(),
            Some(persisted_fallback),
            "the first caller persists the structured fallback winner"
        );
        assert!(matches!(
            second_completion_task.await?,
            Err(StoreError::CorruptData(message))
                if message.contains("different primary response")
        ));
        let changed_fallback_response = response(b"different revoked lease offer response")?;
        let changed_fallback = CompleteLeaseRequest::for_lease_offer_with_fallback(
            begin,
            primary_response,
            changed_fallback_response.clone(),
            fallback(&changed_fallback_response, OperationId::new(), 9_000)?,
            database_now(database.pool()).await?,
            command_identity,
        )?;
        let unavailable_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(Arc::new(UnavailableKeyProvider));
        assert_eq!(
            unavailable_store
                .complete_lease_request(changed_fallback)
                .await?
                .revoked_offer_fallback(),
            Some(persisted_fallback),
            "the durable fallback wins over retry-policy drift without consulting KMS"
        );
        assert_eq!(
            unavailable_store
                .complete_lease_request(replay_completion)
                .await?
                .revoked_offer_fallback(),
            Some(persisted_fallback),
            "the locked marker and bound receipt classify exact replay before KMS"
        );
        let wrong_sequence = CommandSequence::new(
            published
                .command()
                .sequence()
                .get()
                .checked_add(1)
                .ok_or("command sequence overflowed")?,
        )?;
        let wrong_command_identity = LeaseOfferCommandIdentity::new(
            fixture.seed.session_fences[0],
            published.command().request().operation_id(),
            wrong_sequence,
        );
        let wrong_sequence_completion = CompleteLeaseRequest::for_lease_offer_with_fallback(
            begin,
            response(b"full lease offer response")?,
            revoked_response,
            persisted_fallback,
            database_now(database.pool()).await?,
            wrong_command_identity,
        )?;
        assert!(matches!(
            unavailable_store
                .complete_lease_request(wrong_sequence_completion)
                .await,
            Err(StoreError::CorruptData(message))
                if message.contains("different lease-offer command identity")
        ));
        let receipt_completion: LeaseOfferReceiptCompletionRow = sqlx::query_as(
            r"
            SELECT lease_offer_request_operation_id, lease_offer_command_sequence,
                   lease_offer_response_disposition,
                   lease_offer_primary_response_schema,
                   lease_offer_primary_response_digest,
                   lease_offer_fallback_version,
                   lease_offer_fallback_operation_id,
                   lease_offer_fallback_retry_after_millis,
                   lease_offer_fallback_response_schema,
                   lease_offer_fallback_response_digest
            FROM runner_rpc_receipts
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            receipt_completion,
            (
                Some(fixture.request_operation_id.as_uuid()),
                Some(i64::try_from(published.command().sequence().get())?),
                Some("revoked_fallback".to_owned()),
                Some(i32::from(primary_schema.get())),
                Some(primary_digest.as_bytes().to_vec()),
                Some(i32::from(persisted_fallback.representation_version())),
                Some(persisted_fallback.response_operation_id().as_uuid()),
                Some(i64::from(persisted_fallback.retry_after_millis())),
                Some(i32::from(persisted_fallback.response_schema().get())),
                Some(persisted_fallback.response_digest().as_bytes().to_vec()),
            ),
            "the revoked payload keeps separate primary and structured fallback identity"
        );
        let predecessor_replay = unavailable_store.begin_lease_request(begin).await?;
        assert!(predecessor_replay.completed_response().is_none());
        assert_eq!(
            predecessor_replay.revoked_offer_operation_id(),
            Some(command_identity.operation_id()),
            "the bound receipt and monotonic marker resolve the deterministic revocation response"
        );

        let successor_operation_id = OperationId::new();
        let successor_key = LeaseRequestKey::successor(
            fixture.seed.session_fences[0],
            successor_operation_id,
            fixture.slot,
            fixture.request_operation_id,
        )?;
        let successor = BeginLeaseRequest::new(successor_key, successor_key.request_digest());
        let admitted = database.store().begin_lease_request(successor).await?;
        assert_eq!(admitted.request(), successor);
        assert!(admitted.completed_response().is_none());
        assert!(admitted.revoked_offer_operation_id().is_none());
        let predecessor_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runner_rpc_receipts WHERE runner_session_id = $1 AND operation_id = $2",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(predecessor_receipts, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "keep the exact primary projection, post-decrypt expiry, and KMS-free fallback replay in one linear regression"
)]
async fn lease_offer_receipt_replay_resamples_horizon_after_decryption() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 10_000).await?;
        let horizon = UnixMillis::new(database_now(database.pool()).await?.get() + 3_000);
        let published = database
            .store()
            .publish_lease_offer(offer_with_horizon(
                &fixture,
                OperationId::new(),
                fixture.lease.issued_at(),
                horizon,
            )?)
            .await?;
        let begin = BeginLeaseRequest::new(
            LeaseRequestKey::first(
                fixture.seed.session_fences[0],
                fixture.request_operation_id,
                fixture.slot,
            ),
            fixture.request_digest,
        );
        let offer_response = response(b"full lease offer replay response")?;
        let primary_schema = offer_response.schema();
        let primary_digest = offer_response.digest();
        let revoked_response = response(b"revoked full lease offer replay response")?;
        let persisted_fallback = fallback(&revoked_response, OperationId::new(), 1_500)?;
        let command_identity = LeaseOfferCommandIdentity::new(
            fixture.seed.session_fences[0],
            published.command().request().operation_id(),
            published.command().sequence(),
        );
        let completion = CompleteLeaseRequest::for_lease_offer_with_fallback(
            begin,
            offer_response.clone(),
            revoked_response,
            persisted_fallback,
            database_now(database.pool()).await?,
            command_identity,
        )?;
        let replay_completion = completion.clone();
        let completed = database.store().complete_lease_request(completion).await?;
        assert_eq!(completed, offer_response);
        let binding: LeaseOfferReceiptCompletionRow = sqlx::query_as(
            r"
            SELECT lease_offer_request_operation_id, lease_offer_command_sequence,
                   lease_offer_response_disposition,
                   lease_offer_primary_response_schema,
                   lease_offer_primary_response_digest,
                   lease_offer_fallback_version,
                   lease_offer_fallback_operation_id,
                   lease_offer_fallback_retry_after_millis,
                   lease_offer_fallback_response_schema,
                   lease_offer_fallback_response_digest
            FROM runner_rpc_receipts
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            binding,
            (
                Some(fixture.request_operation_id.as_uuid()),
                Some(i64::try_from(published.command().sequence().get())?),
                Some("primary".to_owned()),
                Some(i32::from(primary_schema.get())),
                Some(primary_digest.as_bytes().to_vec()),
                Some(i32::from(persisted_fallback.representation_version())),
                Some(persisted_fallback.response_operation_id().as_uuid()),
                Some(i64::from(persisted_fallback.retry_after_millis())),
                Some(i32::from(persisted_fallback.response_schema().get())),
                Some(persisted_fallback.response_digest().as_bytes().to_vec()),
            )
        );
        assert_eq!(
            database
                .store()
                .begin_lease_request(begin)
                .await?
                .completed_response(),
            Some(&offer_response)
        );

        let provider = BlockingKeyProvider::new(BlockingKeyOperation::Unwrap);
        let store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(provider.clone());
        let replay_task = tokio::spawn(async move { store.begin_lease_request(begin).await });
        provider.wait_until_blocked().await;
        wait_until_database_time(&clock, horizon).await?;
        provider.release();

        let replay = replay_task.await??;
        assert!(replay.completed_response().is_none());
        assert_eq!(
            replay.revoked_offer_operation_id(),
            Some(command_identity.operation_id())
        );
        assert_authority_expired_offer_revocation(&database, &fixture, horizon).await?;
        let unavailable_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(Arc::new(UnavailableKeyProvider));
        let replay_without_kms = unavailable_store.begin_lease_request(begin).await?;
        assert!(replay_without_kms.completed_response().is_none());
        assert_eq!(
            replay_without_kms.revoked_offer_operation_id(),
            Some(command_identity.operation_id())
        );
        assert_eq!(
            unavailable_store
                .complete_lease_request(replay_completion)
                .await?
                .revoked_offer_fallback(),
            Some(persisted_fallback),
            "a live primary which later revokes replays its separately persisted fallback"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(
    clippy::too_many_lines,
    reason = "keep each direct corruption mutation and its immediate fail-closed replay assertion linear"
)]
async fn lease_offer_fallback_projection_corruption_fails_closed_before_replay() -> TestResult {
    run_with_database(|database| async move {
        let fixture = claim_attempt(&database, 30_000).await?;
        let horizon = UnixMillis::new(database_now(database.pool()).await?.get() + 20_000);
        let published = database
            .store()
            .publish_lease_offer(offer_with_horizon(
                &fixture,
                OperationId::new(),
                fixture.lease.issued_at(),
                horizon,
            )?)
            .await?;
        let begin = BeginLeaseRequest::new(
            LeaseRequestKey::first(
                fixture.seed.session_fences[0],
                fixture.request_operation_id,
                fixture.slot,
            ),
            fixture.request_digest,
        );
        let primary_response = response(b"corruption-test primary lease offer")?;
        let primary_schema = primary_response.schema();
        let primary_digest = primary_response.digest();
        let revoked_response = response(b"corruption-test revoked fallback")?;
        let persisted_fallback = fallback(&revoked_response, OperationId::new(), 2_500)?;
        let command_identity = LeaseOfferCommandIdentity::new(
            fixture.seed.session_fences[0],
            published.command().request().operation_id(),
            published.command().sequence(),
        );
        let completed = database
            .store()
            .complete_lease_request(CompleteLeaseRequest::for_lease_offer_with_fallback(
                begin,
                primary_response,
                revoked_response,
                persisted_fallback,
                database_now(database.pool()).await?,
                command_identity,
            )?)
            .await?;
        assert!(matches!(
            completed,
            LeaseRequestCompletion::LiveLeaseOffer { .. }
        ));

        sqlx::query(
            "DROP TRIGGER runner_rpc_receipt_lease_offer_binding_guard ON runner_rpc_receipts",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE runner_rpc_receipts DROP CONSTRAINT runner_rpc_receipts_lease_offer_completion_shape",
        )
        .execute(database.pool())
        .await?;

        sqlx::query(
            "UPDATE runner_rpc_receipts SET lease_offer_fallback_version = 2 WHERE runner_session_id = $1 AND operation_id = $2",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message)) if message.contains("version is unsupported")
        ));

        sqlx::query(
            "UPDATE runner_rpc_receipts SET lease_offer_fallback_version = 1, lease_offer_fallback_response_digest = NULL WHERE runner_session_id = $1 AND operation_id = $2",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message)) if message.contains("partial lease-offer completion")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_fallback_response_digest = $3,
                lease_offer_response_disposition = 'revoked_fallback'
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(persisted_fallback.response_digest().as_bytes().as_slice())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message)) if message.contains("disposition mismatches")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_response_disposition = 'primary',
                lease_offer_fallback_operation_id =
                    '00000000-0000-0000-0000-000000000000'::UUID
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message)) if message.contains("operation identity is nil")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_fallback_operation_id = $3,
                lease_offer_response_disposition = 'unsupported'
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(persisted_fallback.response_operation_id().as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message))
                if message.contains("invalid lease-offer response disposition")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_response_disposition = 'primary',
                lease_offer_primary_response_schema = 0
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(_))
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_primary_response_schema = $3,
                lease_offer_primary_response_digest = $4
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(i32::from(primary_schema.get()))
        .bind(vec![0x91_u8; 31])
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(_))
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_primary_response_digest = $3,
                lease_offer_fallback_version = 65536
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(primary_digest.as_bytes().as_slice())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message))
                if message.contains("version is outside the durable range")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_fallback_version = 1,
                lease_offer_fallback_retry_after_millis = 0
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message)) if message.contains("retry delay is zero")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_fallback_retry_after_millis = 4294967296
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(message))
                if message.contains("retry is outside the durable range")
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_fallback_retry_after_millis = $3,
                lease_offer_fallback_response_schema = 0
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(i64::from(persisted_fallback.retry_after_millis()))
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(_))
        ));

        sqlx::query(
            r"
            UPDATE runner_rpc_receipts
            SET lease_offer_fallback_response_schema = $3,
                lease_offer_fallback_response_digest = $4
            WHERE runner_session_id = $1 AND operation_id = $2
            ",
        )
        .bind(fixture.seed.session_fences[0].session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(i32::from(persisted_fallback.response_schema().get()))
        .bind(vec![0x92_u8; 31])
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database.store().begin_lease_request(begin).await,
            Err(StoreError::CorruptData(_))
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn command_replay_resamples_horizon_after_waiting_for_attempt_lock() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 30_000).await?;
        let fence = fixture.seed.session_fences[0];
        let horizon = UnixMillis::new(database_now(database.pool()).await?.get() + 500);
        let published = database
            .store()
            .publish_lease_offer(offer_with_horizon(
                &fixture,
                OperationId::new(),
                fixture.lease.issued_at(),
                horizon,
            )?)
            .await?;
        let later = enqueue_clock_probe(&database, fence, b"after expired replay horizon").await?;

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(fixture.lease.attempt_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let store = database.store().clone();
        let replay = tokio::spawn(async move {
            store
                .replay_commands(
                    fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(1).expect("bounded replay limit"),
                )
                .await
        });
        wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
        wait_until_database_time(&clock, horizon).await?;
        blocker.commit().await?;

        let saturated = replay.await??;
        assert!(saturated.is_empty());
        assert_eq!(saturated.disposition(), CommandReplayDisposition::Saturated);
        let replayed = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert_eq!(replayed.disposition(), CommandReplayDisposition::Exhausted);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].sequence(), later.sequence());
        assert_eq!(replayed[0].request(), later.request());
        assert_ne!(replayed[0].sequence(), published.command().sequence());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn command_replay_rereads_takeover_after_waiting_for_attempt_lock() -> TestResult {
    run_with_database(|database| async move {
        let fixture = claim_attempt(&database, 30_000).await?;
        let fence = fixture.seed.session_fences[0];
        let published = database
            .store()
            .publish_lease_offer(offer(&fixture, OperationId::new())?)
            .await?;
        let later = enqueue_clock_probe(&database, fence, b"after lease takeover").await?;

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(fixture.lease.attempt_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let store = database.store().clone();
        let replay = tokio::spawn(async move {
            store
                .replay_commands(
                    fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(1).expect("bounded replay limit"),
                )
                .await
        });
        wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
        replace_locked_lease(&mut blocker, &fixture).await?;
        blocker.commit().await?;

        let saturated = replay.await??;
        assert!(saturated.is_empty());
        assert_eq!(saturated.disposition(), CommandReplayDisposition::Saturated);
        let replayed = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert_eq!(replayed.disposition(), CommandReplayDisposition::Exhausted);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].sequence(), later.sequence());
        assert_eq!(replayed[0].request(), later.request());
        assert_ne!(replayed[0].sequence(), published.command().sequence());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn command_resolver_persists_takeover_seen_after_attempt_lock_wait() -> TestResult {
    run_with_database(|database| async move {
        let fixture = claim_attempt(&database, 30_000).await?;
        let fence = fixture.seed.session_fences[0];
        let published = database
            .store()
            .publish_lease_offer(offer(&fixture, OperationId::new())?)
            .await?;
        let identity = LeaseOfferCommandIdentity::new(
            fence,
            published.command().request().operation_id(),
            published.command().sequence(),
        );

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(fixture.lease.attempt_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let store = database.store().clone();
        let resolver =
            tokio::spawn(async move { store.resolve_lease_offer_command(identity).await });
        wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
        replace_locked_lease(&mut blocker, &fixture).await?;
        blocker.commit().await?;

        assert!(matches!(
            resolver.await?,
            Err(StoreError::AttemptFenceRejected(rejected))
                if rejected == fixture.lease.attempt_id()
        ));
        let revocation: (Option<i64>, Option<String>) = sqlx::query_as(
            r"
            SELECT delivery_revoked_at_ms, delivery_revocation_reason
            FROM runner_lease_offer_publications
            WHERE runner_session_id = $1 AND request_operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(revocation.0.is_some());
        assert_eq!(revocation.1.as_deref(), Some("attempt_superseded"));
        let replay = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert!(replay.is_empty());
        assert_eq!(replay.disposition(), CommandReplayDisposition::Exhausted);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn future_created_publication_evidence_is_corrupt_not_revoked() -> TestResult {
    run_with_database(|database| async move {
        let fixture = claim_attempt(&database, 60_000).await?;
        let fence = fixture.seed.session_fences[0];
        let published = database
            .store()
            .publish_lease_offer(offer(&fixture, OperationId::new())?)
            .await?;
        let future_created_at = database_now(database.pool()).await?.get() + 30_000;
        let mut corruption = database.pool().begin().await?;
        sqlx::query(
            "ALTER TABLE runner_command_outbox DISABLE TRIGGER runner_command_outbox_payload_guard",
        )
        .execute(&mut *corruption)
        .await?;
        let updated = sqlx::query(
            r"
            UPDATE runner_lease_offer_publications
            SET created_at_ms = $3
            WHERE runner_session_id = $1 AND request_operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(future_created_at)
        .execute(&mut *corruption)
        .await?;
        assert_eq!(updated.rows_affected(), 1);
        let updated_command = sqlx::query(
            r"
            UPDATE runner_command_outbox
            SET created_at_ms = $3
            WHERE runner_session_id = $1 AND command_sequence = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(i64::try_from(published.command().sequence().get())?)
        .bind(future_created_at)
        .execute(&mut *corruption)
        .await?;
        assert_eq!(updated_command.rows_affected(), 1);
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *corruption)
            .await?;
        sqlx::query(
            "ALTER TABLE runner_command_outbox ENABLE TRIGGER runner_command_outbox_payload_guard",
        )
        .execute(&mut *corruption)
        .await?;
        corruption.commit().await?;

        assert!(matches!(
            database
                .store()
                .replay_commands(
                    fence,
                    CommandCursor::initial(),
                    CommandReplayLimit::new(1)?,
                )
                .await,
            Err(StoreError::CorruptData(message))
                if message.contains("observed before its creation time")
        ));
        let marker_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM runner_lease_offer_publications
            WHERE runner_session_id = $1
              AND delivery_revoked_at_ms IS NOT NULL
            ",
        )
        .bind(fence.session_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(marker_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn command_replay_bounds_stale_offer_inspection_and_preserves_progress() -> TestResult {
    run_with_database(|database| async move {
        for stale_count in [255_u16, 256, 257] {
            let (fence, later) = install_stale_offer_prefix(&database, stale_count, true).await?;
            let first = database
                .store()
                .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
                .await?;
            assert_eq!(first.disposition(), CommandReplayDisposition::Saturated);
            assert!(first.is_empty());
            let second = database
                .store()
                .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
                .await?;
            let delivered = if stale_count == 257 {
                assert!(second.is_empty());
                assert_eq!(second.disposition(), CommandReplayDisposition::Saturated);
                database
                    .store()
                    .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
                    .await?
            } else {
                second
            };
            assert_eq!(delivered.disposition(), CommandReplayDisposition::Exhausted);
            assert_eq!(delivered.len(), 1);
            assert_eq!(
                delivered[0].sequence(),
                later.expect("live command").sequence()
            );
            assert_eq!(
                delivery_revocation_counts(&database, fence).await?,
                (i64::from(stale_count), i64::from(stale_count))
            );
        }

        let (fence, later) = install_stale_offer_prefix(&database, 256, false).await?;
        assert!(later.is_none());
        let unavailable_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(Arc::new(UnavailableKeyProvider));
        let saturated = unavailable_store
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert!(saturated.is_empty());
        assert_eq!(saturated.disposition(), CommandReplayDisposition::Saturated);
        let exhausted = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert!(exhausted.is_empty());
        assert_eq!(exhausted.disposition(), CommandReplayDisposition::Exhausted);

        let (fence, later) = install_stale_offer_prefix(&database, 255, true).await?;
        let unavailable_store = PostgresStore::from_postgres_pool(database.pool().clone())
            .with_runner_payload_encryption(Arc::new(UnavailableKeyProvider));
        let saturated = unavailable_store
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert!(saturated.is_empty());
        assert_eq!(saturated.disposition(), CommandReplayDisposition::Saturated);
        assert_eq!(
            delivery_revocation_counts(&database, fence).await?,
            (255, 255)
        );
        let delivered = database
            .store()
            .replay_commands(fence, CommandCursor::initial(), CommandReplayLimit::new(1)?)
            .await?;
        assert_eq!(delivered.disposition(), CommandReplayDisposition::Exhausted);
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].sequence(),
            later.expect("live command").sequence()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn renewal_samples_database_time_after_waiting_for_runtime_authority_row() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        for commit in [false, true] {
            let (fixture, authority_ceiling) =
                install_short_lived_runtime_authority(&database).await?;
            let observed_at = database_now(database.pool()).await?;
            let proposed = RenewLease::new(
                fixture.lease.attempt_id(),
                fixture.seed.session_fences[0],
                fixture.lease.guard(),
                observed_at,
                UnixMillis::new(observed_at.get() + 30_000),
            )?;
            let request = if commit {
                database
                    .store()
                    .authorize_lease_renewal(proposed, automata_ci_core::JobLifecycle::Running)
                    .await?
            } else {
                proposed
            };
            if commit {
                assert_eq!(
                    request.expires_at(),
                    authority_ceiling,
                    "authorized renewal must be clamped to the locked authority horizon"
                );
            }
            let heartbeat = commit
                .then(|| {
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(CommitLeaseHeartbeat::new(
                        operation_request(
                            fixture.seed.session_fences[0],
                            OperationId::new(),
                            HEARTBEAT_KIND,
                            [0x42; 32],
                        )?,
                        CommandCursor::initial(),
                        request,
                        response(b"authority-lock renewal")?,
                    )?)
                })
                .transpose()?;
            let mut blocker = database.pool().begin().await?;
            let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker)
                .await?;
            sqlx::query(
                "SELECT 1 FROM github_runtime_authority_issuances WHERE attempt_id = $1 AND fencing_token = $2 FOR UPDATE",
            )
            .bind(fixture.lease.attempt_id().as_uuid())
            .bind(i64::try_from(fixture.lease.fencing_token().get())?)
            .fetch_one(&mut *blocker)
            .await?;
            let store = database.store().clone();
            let renewal = tokio::spawn(async move {
                if let Some(heartbeat) = heartbeat {
                    store
                        .commit_lease_heartbeat(heartbeat)
                        .await
                        .map(|_| ())
                } else {
                    store
                        .authorize_lease_renewal(
                            request,
                            automata_ci_core::JobLifecycle::Running,
                        )
                        .await
                        .map(|_| ())
                }
            });
            wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
            wait_until_database_time(&clock, authority_ceiling).await?;
            blocker.commit().await?;

            let result = renewal.await?;
            if commit {
                assert!(matches!(
                    result,
                    Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(rejected)))
                        if rejected == fixture.lease.attempt_id()
                ), "commit renewal sampled the wrong authority-clock outcome: {result:?}");
            } else {
                assert!(matches!(
                    result,
                    Err(StoreError::Attempt(
                        AttemptStoreError::RuntimeAuthorityUnavailable(rejected)
                    )) if rejected == fixture.lease.attempt_id()
                ), "authorization sampled the wrong authority-clock outcome: {result:?}");
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn expired_lease_cannot_requeue_or_fail_from_a_stale_response() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 500).await?;
        let fence = fixture.seed.session_fences[0];
        let attempt_id = fixture.lease.attempt_id();
        database
            .store()
            .publish_lease_offer(offer(&fixture, OperationId::new())?)
            .await?;
        wait_until_database_time(&clock, fixture.lease.expires_at()).await?;

        for (action, body, digest) in [
            (
                LeaseResponseAction::Requeue,
                b"stale requeue".as_slice(),
                [51; 32],
            ),
            (
                LeaseResponseAction::Fail,
                b"stale failure".as_slice(),
                [52; 32],
            ),
        ] {
            let request = CommitLeaseResponse::new(
                operation_request(fence, OperationId::new(), LEASE_RESPONSE_KIND, digest)?,
                CommandCursor::initial(),
                attempt_id,
                fixture.slot,
                fixture.lease.guard(),
                action,
                database_now(database.pool()).await?,
                response(body)?,
            );
            assert!(matches!(
                database.store().commit_lease_response(request).await,
                Err(StoreError::Attempt(AttemptStoreError::LeaseExpired(expired)))
                    if expired == attempt_id
            ));
        }
        let lifecycle: String =
            sqlx::query_scalar("SELECT lifecycle FROM job_attempts WHERE id = $1")
                .bind(attempt_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(lifecycle, "leased");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn expired_attempt_requeue_samples_database_time_after_the_exact_attempt_lock() -> TestResult
{
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 500).await?;
        wait_until_database_time(&clock, fixture.lease.expires_at()).await?;

        let mut blocker = database.pool().begin().await?;
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM job_attempts WHERE id = $1 FOR UPDATE")
            .bind(fixture.lease.attempt_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let store = database.store().clone();
        let request = maintenance_request(database_now(database.pool()).await?, 60_000)?;
        let maintenance = tokio::spawn(async move { store.maintain_control_plane(request).await });
        wait_for_direct_database_blocker(database.pool(), blocker_pid).await?;
        clock.advance(1).await?;
        let unlocked_at = database_now(database.pool()).await?;
        blocker.commit().await?;

        let report = maintenance.await??;
        assert_eq!(report.expired_attempts().len(), 1);
        assert_eq!(
            report.expired_attempts()[0].attempt_id(),
            fixture.lease.attempt_id()
        );
        let durable: (String, i64, i64, i32) = sqlx::query_as(
            r"
            SELECT lifecycle, queued_at_ms, changed_at_ms, lease_failures
            FROM job_attempts
            WHERE id = $1
            ",
        )
        .bind(fixture.lease.attempt_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable.0, "queued");
        assert_eq!(durable.1, durable.2);
        assert!(durable.2 >= unlocked_at.get());
        assert_eq!(durable.3, 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn live_acceptance_and_renewal_replay_stop_after_expiry_and_takeover() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        let fixture = claim_attempt(&database, 2_000).await?;
        let fence = fixture.seed.session_fences[0];
        database
            .store()
            .publish_lease_offer(offer(&fixture, OperationId::new())?)
            .await?;
        let acceptance_request =
            operation_request(fence, OperationId::new(), LEASE_RESPONSE_KIND, [31; 32])?;
        let acceptance = CommitLeaseResponse::new(
            acceptance_request.clone(),
            CommandCursor::initial(),
            fixture.lease.attempt_id(),
            fixture.slot,
            fixture.lease.guard(),
            LeaseResponseAction::Accept,
            database_now(database.pool()).await?,
            response(b"accepted")?,
        );
        let accepted = database
            .store()
            .commit_lease_response(acceptance.clone())
            .await?;
        assert!(!accepted.was_replayed());

        let renewal_observed = database_now(database.pool()).await?;
        let authorization_before = database_now(database.pool()).await?;
        let authorized = database
            .store()
            .authorize_lease_renewal(
                RenewLease::new(
                    fixture.lease.attempt_id(),
                    fence,
                    fixture.lease.guard(),
                    renewal_observed,
                    UnixMillis::new(renewal_observed.get() + 10_000),
                )?,
                automata_ci_core::JobLifecycle::Preparing,
            )
            .await?;
        let authorization_after = database_now(database.pool()).await?;
        assert!(authorized.observed_at() >= authorization_before);
        assert!(authorized.observed_at() <= authorization_after);
        let heartbeat_request =
            operation_request(fence, OperationId::new(), HEARTBEAT_KIND, [32; 32])?;
        let heartbeat = CommitLeaseHeartbeat::new(
            heartbeat_request.clone(),
            CommandCursor::initial(),
            authorized,
            response(b"renewed")?,
        )?;
        let renewed = database
            .store()
            .commit_lease_heartbeat(heartbeat.clone())
            .await?;
        assert!(!renewed.was_replayed());

        wait_until_database_time(&clock, fixture.lease.expires_at()).await?;
        let replayed_acceptance = database
            .store()
            .commit_lease_response(CommitLeaseResponse::new(
                acceptance_request.clone(),
                CommandCursor::initial(),
                fixture.lease.attempt_id(),
                fixture.slot,
                fixture.lease.guard(),
                LeaseResponseAction::Accept,
                UnixMillis::new(database_now(database.pool()).await?.get() + 61_000),
                response(b"ignored")?,
            ))
            .await?;
        assert!(replayed_acceptance.was_replayed());
        let replayed_renewal = database
            .store()
            .commit_lease_heartbeat(CommitLeaseHeartbeat::new(
                heartbeat_request.clone(),
                CommandCursor::initial(),
                authorized,
                response(b"ignored")?,
            )?)
            .await?;
        assert!(replayed_renewal.was_replayed());

        expire_active_attempt(&database, &clock, fixture.lease.attempt_id()).await?;
        assert!(
            database
                .store()
                .commit_lease_response(acceptance)
                .await
                .is_err()
        );
        assert!(
            database
                .store()
                .commit_lease_heartbeat(heartbeat)
                .await
                .is_err()
        );

        let maintenance_now = database_now(database.pool()).await?;
        let report = database
            .store()
            .maintain_control_plane(maintenance_request(maintenance_now, 60_000)?)
            .await?;
        assert_eq!(report.expired_attempts().len(), 1);
        let takeover_now = database_now(database.pool()).await?;
        let successor = database
            .store()
            .acquire_lease(AcquireLease::new(
                fixture.lease.attempt_id(),
                LeaseId::new(),
                fence,
                fixture.slot,
                takeover_now,
                UnixMillis::new(takeover_now.get() + 5_000),
            )?)
            .await?;
        assert_eq!(successor.fencing_token().get(), 2);
        assert!(
            database
                .store()
                .commit_lease_heartbeat(CommitLeaseHeartbeat::new(
                    heartbeat_request,
                    CommandCursor::initial(),
                    authorized,
                    response(b"stale")?,
                )?)
                .await
                .is_err()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn fast_maintenance_cannot_expire_a_live_lease_or_close_a_live_session() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let now = database_now(database.pool()).await?;
        set_session_heartbeat(&database, fence.session_id(), now).await?;
        let attempt_id = insert_queued(&database, seed.job_id, 1, now.get() - 1_000).await?;
        let lease = database
            .store()
            .acquire_lease(AcquireLease::new(
                attempt_id,
                LeaseId::new(),
                fence,
                StableRunnerSlot::new(1)?,
                now,
                UnixMillis::new(now.get() + 5_000),
            )?)
            .await?;

        let fast = UnixMillis::new(database_now(database.pool()).await?.get() + 59_000);
        assert!(
            database
                .store()
                .requeue_expired(fast, 3, 10)
                .await?
                .is_empty()
        );
        let report = database
            .store()
            .maintain_control_plane(maintenance_request(fast, 30_000)?)
            .await?;
        assert!(report.expired_attempts().is_empty());
        assert_eq!(report.closed_stale_sessions(), 0);
        let durable: (String, Option<uuid::Uuid>) =
            sqlx::query_as("SELECT lifecycle, lease_id FROM job_attempts WHERE id = $1")
                .bind(attempt_id.as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(
            durable,
            ("leased".to_owned(), Some(lease.lease_id().as_uuid()))
        );

        let fresh = database_now(database.pool()).await?;
        set_session_heartbeat(
            &database,
            fence.session_id(),
            UnixMillis::new(fresh.get() - 31_000),
        )
        .await?;
        let closed = database
            .store()
            .maintain_control_plane(maintenance_request(fresh, 30_000)?)
            .await?;
        assert_eq!(closed.closed_stale_sessions(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn stale_session_close_rereads_a_heartbeat_after_waiting_for_its_lock() -> TestResult {
    run_with_database(|database| async move {
        let seed = seed_control_plane(database.pool(), 1).await?;
        let fence = seed.session_fences[0];
        let observed = database_now(database.pool()).await?;
        set_session_heartbeat(
            &database,
            fence.session_id(),
            UnixMillis::new(observed.get() - 10_000),
        )
        .await?;

        let mut blocker = database.pool().begin().await?;
        sqlx::query("SELECT id FROM runners WHERE id = $1 FOR UPDATE")
            .bind(fence.runner_id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let store = database.store().clone();
        let request = maintenance_request(observed, 5_000)?;
        let task = tokio::spawn(async move { store.maintain_control_plane(request).await });
        wait_for_database_lock(
            database.pool(),
            "SELECT generation, session_epoch FROM runners",
        )
        .await?;
        let heartbeat = database_now(database.pool()).await?;
        set_session_heartbeat(&database, fence.session_id(), heartbeat).await?;
        blocker.commit().await?;

        let report = task.await??;
        assert_eq!(report.closed_stale_sessions(), 0);
        let disconnected: Option<i64> =
            sqlx::query_scalar("SELECT disconnected_at_ms FROM runner_sessions WHERE id = $1")
                .bind(fence.session_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert!(disconnected.is_none());
        Ok(())
    })
    .await
}

#[derive(Clone, Copy)]
struct PreparedClaim {
    attempt_id: AttemptId,
    request_key: LeaseRequestKey,
    cursor: automata_ci_store::RunnableCursorAdvance,
    duration_millis: i64,
}

struct ClaimedFixture {
    seed: SeedData,
    lease: Lease,
    metadata: JobIrMetadata,
    slot: StableRunnerSlot,
    request_operation_id: OperationId,
    request_digest: Sha256Digest,
}

async fn prepare_claim(database: &TestDatabase, duration_millis: i64) -> TestResult<PreparedClaim> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let observed = database_now(database.pool()).await?;
    set_session_heartbeat(database, seed.session_fences[0].session_id(), observed).await?;
    let attempt_id = insert_queued(database, seed.job_id, 1, observed.get() - 1_000).await?;
    let slot = StableRunnerSlot::new(1)?;
    let request_key = LeaseRequestKey::first(seed.session_fences[0], OperationId::new(), slot);
    let request_digest = request_key.request_digest();
    database
        .store()
        .begin_lease_request(BeginLeaseRequest::new(request_key, request_digest))
        .await?;
    let page = database
        .store()
        .scan_runnable(RunnableScanRequest::new(
            seed.session_fences[0],
            slot,
            RunnableScanLimit::new(10)?,
            observed,
        ))
        .await?;
    Ok(PreparedClaim {
        attempt_id,
        request_key,
        cursor: page.claim_advance(attempt_id)?,
        duration_millis,
    })
}

async fn claim_attempt(
    database: &TestDatabase,
    duration_millis: i64,
) -> TestResult<ClaimedFixture> {
    let seed = seed_control_plane(database.pool(), 1).await?;
    let observed = database_now(database.pool()).await?;
    set_session_heartbeat(database, seed.session_fences[0].session_id(), observed).await?;
    let attempt_id = insert_queued(database, seed.job_id, 1, observed.get() - 1_000).await?;
    let slot = StableRunnerSlot::new(1)?;
    let request_operation_id = OperationId::new();
    let request_key = LeaseRequestKey::first(seed.session_fences[0], request_operation_id, slot);
    let request_digest = request_key.request_digest();
    database
        .store()
        .begin_lease_request(BeginLeaseRequest::new(request_key, request_digest))
        .await?;
    let page = database
        .store()
        .scan_runnable(RunnableScanRequest::new(
            seed.session_fences[0],
            slot,
            RunnableScanLimit::new(10)?,
            observed,
        ))
        .await?;
    let receipt = database
        .store()
        .try_claim(TryClaimAttempt::new(
            request_key,
            attempt_id,
            LeaseId::new(),
            observed,
            UnixMillis::new(observed.get() + duration_millis),
            page.claim_advance(attempt_id)?,
        )?)
        .await?;
    let TryClaimOutcome::Claimed(claimed) = receipt.outcome() else {
        panic!("fixture claim must succeed");
    };
    Ok(ClaimedFixture {
        seed,
        lease: claimed.lease().clone(),
        metadata: claimed.job_ir().clone(),
        slot,
        request_operation_id,
        request_digest,
    })
}

#[allow(clippy::too_many_lines)] // One exact isolated ready-row fixture with explicit custody fields.
async fn install_short_lived_runtime_authority(
    database: &TestDatabase,
) -> TestResult<(ClaimedFixture, UnixMillis)> {
    let fixture = claim_attempt(database, 180_000).await?;
    sqlx::query(
        r"
        UPDATE repositories
        SET scm_provider = 'github',
            provider_repository_id = '4242',
            owner = 'automata-ci',
            name = 'automata',
            updated_at_ms = greatest(
                updated_at_ms,
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
            )
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(fixture.seed.repository_id)
    .bind(&fixture.seed.tenant_id)
    .execute(database.pool())
    .await?;
    let requested_at = fixture.lease.issued_at();
    let request_deadline = UnixMillis::new(
        requested_at
            .get()
            .checked_add(120_000)
            .ok_or("runtime-authority request deadline overflowed")?
            .min(fixture.lease.expires_at().get()),
    );
    let authority_ceiling = UnixMillis::new(requested_at.get() + 4_000);
    let provider_expires_at =
        UnixMillis::new(authority_ceiling.get() + GITHUB_AUTHORITY_PROVIDER_CLOCK_SKEW_MILLIS);
    let fence = fixture.seed.session_fences[0];
    set_runtime_authority_fixture_guards(database.pool(), false).await?;
    let installation: TestResult = async {
        let ready_at = database_now(database.pool()).await?;
        let selection_expires_at = UnixMillis::new(
            ready_at
                .get()
                .checked_add(120_000)
                .ok_or("runtime-authority selection expiry overflowed")?,
        );
        let preparation_selection_id = uuid::Uuid::new_v4();
        let preparation_selection_owner_id = uuid::Uuid::new_v4();
        let activation_selection_id = uuid::Uuid::new_v4();
        let activation_selection_owner_id = uuid::Uuid::new_v4();
        let materialization_selection_id = uuid::Uuid::new_v4();
        let materialization_selection_owner_id = uuid::Uuid::new_v4();
        let mut selection_transaction = database.pool().begin().await?;
        sqlx::query(
            r"
            INSERT INTO logical_workflow_activation_work_selections (
                selection_id, owner_id, requested_at_ms, duration_ms, outcome
            ) VALUES
                ($1, $2, $3, 120000, 'selecting'),
                ($4, $5, $3, 120000, 'selecting')
            ",
        )
        .bind(preparation_selection_id)
        .bind(preparation_selection_owner_id)
        .bind(ready_at.get())
        .bind(activation_selection_id)
        .bind(activation_selection_owner_id)
        .execute(&mut *selection_transaction)
        .await?;
        sqlx::query(
            r"
            UPDATE logical_workflow_activation_work_selections
            SET outcome = 'contended', claimed_at_ms = $3, expires_at_ms = $4
            WHERE selection_id IN ($1, $2)
            ",
        )
        .bind(preparation_selection_id)
        .bind(activation_selection_id)
        .bind(ready_at.get())
        .bind(selection_expires_at.get())
        .execute(&mut *selection_transaction)
        .await?;
        sqlx::query(
            r"
            INSERT INTO logical_workflow_materialization_work_selections (
                selection_id, owner_id, requested_at_ms, duration_ms, outcome
            ) VALUES ($1, $2, $3, 120000, 'selecting')
            ",
        )
        .bind(materialization_selection_id)
        .bind(materialization_selection_owner_id)
        .bind(ready_at.get())
        .execute(&mut *selection_transaction)
        .await?;
        sqlx::query(
            r"
            UPDATE logical_workflow_materialization_work_selections
            SET outcome = 'contended', claimed_at_ms = $2, expires_at_ms = $3
            WHERE selection_id = $1
            ",
        )
        .bind(materialization_selection_id)
        .bind(ready_at.get())
        .bind(selection_expires_at.get())
        .execute(&mut *selection_transaction)
        .await?;
        selection_transaction.commit().await?;
        let ready = sqlx::query(
            r"
            INSERT INTO github_runtime_authority_issuances (
                tenant_id, attempt_id, fencing_token, lease_id,
                lease_issued_at_ms, lease_expires_at_ms, run_id, job_id,
                runner_id, runner_session_id, runner_session_epoch,
                runner_generation, runner_slot, job_ir_schema,
                job_ir_size_bytes, job_ir_digest, repository_id,
                provider_connection_id, provider_installation_id,
                github_app_id, github_app_client_id,
                github_app_jwt_issuer_kind, github_app_jwt_issuer_value,
                github_repository_id, github_repository_name,
                authority_namespace, policy_digest, issuer_fingerprint,
                configuration_fingerprint,
                preparation_selection_id, preparation_selection_owner_id,
                preparation_selection_generation,
                preparation_selection_descriptor_digest,
                preparation_selection_claimed_at_ms,
                preparation_selection_expires_at_ms,
                activation_selection_id, activation_selection_owner_id,
                activation_selection_generation, activation_selection_input_digest,
                activation_selection_claimed_at_ms, activation_selection_expires_at_ms,
                materialization_selection_id, materialization_selection_owner_id,
                materialization_selection_generation,
                materialization_selection_descriptor_digest,
                materialization_selection_claimed_at_ms,
                materialization_selection_expires_at_ms,
                requested_at_ms,
                request_deadline_at_ms, conservative_expiry_at_ms,
                state, mint_claim_owner_id, mint_claimed_at_ms,
                mint_claim_expires_at_ms, mint_started_at_ms,
                provider_expires_at_ms, safe_erase_after_ms,
                commit_disposition, plaintext_schema, plaintext_size_bytes,
                plaintext_digest, aad_digest, envelope_schema,
                wrapping_key_id, wrapped_data_key, nonce, ciphertext,
                ready_at_ms, state_updated_at_ms
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, 9001, 9002,
                'Iv1.automata-runtime', 'app_client_id', 'Iv1.automata-runtime',
                4242, 'automata-ci/automata', 'github.repository', $16, $19, $20,
                $21, $22, 1, $16, $23, $24,
                $25, $26, 1, $16, $23, $24,
                $27, $28, 1, $16, $23, $24,
                $5, $29, $29 + 3780000,
                'ready', $30, $31, NULL, $31,
                $32, $32 + 120000, 'deliverable', 1, 32,
                $33, $34, 1, 'github-runtime-clock-test-v1',
                $35, $36, $37, $31, $31
            )
            ",
        )
        .bind(&fixture.seed.tenant_id)
        .bind(fixture.lease.attempt_id().as_uuid())
        .bind(i64::try_from(fixture.lease.fencing_token().get())?)
        .bind(fixture.lease.lease_id().as_uuid())
        .bind(requested_at.get())
        .bind(fixture.lease.expires_at().get())
        .bind(fixture.seed.run_id.as_uuid())
        .bind(fixture.seed.job_id.as_uuid())
        .bind(fence.runner_id().as_uuid())
        .bind(fence.session_id().as_uuid())
        .bind(i64::try_from(fence.session_epoch().get())?)
        .bind(i64::try_from(fence.runner_generation().get())?)
        .bind(i32::from(fixture.slot.ordinal()))
        .bind(i32::from(fixture.metadata.version().get()))
        .bind(i64::try_from(fixture.metadata.encoded_size())?)
        .bind(fixture.metadata.digest().as_bytes().as_slice())
        .bind(fixture.seed.repository_id)
        .bind(uuid::Uuid::new_v4())
        .bind(vec![0x52_u8; 32])
        .bind(vec![0x53_u8; 32])
        .bind(preparation_selection_id)
        .bind(preparation_selection_owner_id)
        .bind(ready_at.get())
        .bind(selection_expires_at.get())
        .bind(activation_selection_id)
        .bind(activation_selection_owner_id)
        .bind(materialization_selection_id)
        .bind(materialization_selection_owner_id)
        .bind(request_deadline.get())
        .bind(uuid::Uuid::new_v4())
        .bind(ready_at.get())
        .bind(provider_expires_at.get())
        .bind(vec![0x61_u8; 32])
        .bind(vec![0x65_u8; 32])
        .bind(vec![0x62_u8; 48])
        .bind(vec![0x63_u8; 12])
        .bind(vec![0x64_u8; 48])
        .execute(database.pool())
        .await?;
        if ready.rows_affected() != 1 {
            return Err("runtime-authority fixture was not made ready".into());
        }
        Ok(())
    }
    .await;
    let restoration = set_runtime_authority_fixture_guards(database.pool(), true).await;
    installation?;
    restoration?;
    Ok((fixture, authority_ceiling))
}

async fn set_runtime_authority_fixture_guards(pool: &PgPool, enabled: bool) -> TestResult {
    // This runner-clock fixture needs a lockable ready row, while the separately owned
    // authority-currentness suite supplies the full logical/provenance graph.
    let statements = if enabled {
        [
            "ALTER TABLE github_runtime_authority_issuances ENABLE TRIGGER github_runtime_authority_insert_guard",
            "ALTER TABLE github_runtime_authority_issuances ENABLE TRIGGER github_runtime_authority_00_identity_guard",
            "ALTER TABLE github_runtime_authority_issuances ENABLE TRIGGER github_runtime_authority_01_database_time_guard",
        ]
    } else {
        [
            "ALTER TABLE github_runtime_authority_issuances DISABLE TRIGGER github_runtime_authority_insert_guard",
            "ALTER TABLE github_runtime_authority_issuances DISABLE TRIGGER github_runtime_authority_00_identity_guard",
            "ALTER TABLE github_runtime_authority_issuances DISABLE TRIGGER github_runtime_authority_01_database_time_guard",
        ]
    };
    for statement in statements {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

fn offer(
    fixture: &ClaimedFixture,
    command_operation_id: OperationId,
) -> TestResult<PublishLeaseOffer> {
    offer_with_horizon(
        fixture,
        command_operation_id,
        fixture.lease.issued_at(),
        fixture.lease.expires_at(),
    )
}

fn offer_with_horizon(
    fixture: &ClaimedFixture,
    command_operation_id: OperationId,
    created_at: UnixMillis,
    offer_valid_until: UnixMillis,
) -> TestResult<PublishLeaseOffer> {
    let fence = fixture.seed.session_fences[0];
    Ok(PublishLeaseOffer::new(
        RunnerOperationRequest::new(
            fence,
            fixture.request_operation_id,
            RunnerOperationKind::new(LEASE_REQUEST_KIND)?,
            fixture.request_digest,
        ),
        RunnerProtocolVersion::new(1)?,
        fixture.slot,
        fixture.lease.clone(),
        fixture.metadata.clone(),
        offer_valid_until,
        EnqueueRunnerCommand::new(
            fence,
            command_operation_id,
            RunnerOperationKind::new(LEASE_OFFER_KIND)?,
            RunnerCommandPayload::new(DocumentSchema::new(1)?, b"clock offer".to_vec())?,
            created_at,
        ),
    )?)
}

async fn enqueue_clock_probe(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
    body: &[u8],
) -> TestResult<automata_ci_store::DurableRunnerCommand> {
    Ok(database
        .store()
        .enqueue_command(EnqueueRunnerCommand::new(
            fence,
            OperationId::new(),
            RunnerOperationKind::new("automata.runner.clock-probe.v1")?,
            RunnerCommandPayload::new(DocumentSchema::new(1)?, body.to_vec())?,
            database_now(database.pool()).await?,
        ))
        .await?)
}

async fn delivery_revocation_counts(
    database: &TestDatabase,
    fence: automata_ci_store::RunnerSessionFence,
) -> TestResult<(i64, i64)> {
    Ok(sqlx::query_as(
        r"
        SELECT count(*),
               count(*) FILTER (
                   WHERE delivery_revocation_reason = 'attempt_superseded'
               )
        FROM runner_lease_offer_publications
        WHERE runner_session_id = $1
          AND delivery_revoked_at_ms IS NOT NULL
        ",
    )
    .bind(fence.session_id().as_uuid())
    .fetch_one(database.pool())
    .await?)
}

async fn assert_authority_expired_offer_revocation(
    database: &TestDatabase,
    fixture: &ClaimedFixture,
    horizon: UnixMillis,
) -> TestResult {
    let persisted: (Option<i64>, Option<String>) = sqlx::query_as(
        r"
        SELECT delivery_revoked_at_ms, delivery_revocation_reason
        FROM runner_lease_offer_publications
        WHERE runner_session_id = $1 AND request_operation_id = $2
        ",
    )
    .bind(fixture.seed.session_fences[0].session_id().as_uuid())
    .bind(fixture.request_operation_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert!(persisted.0.is_some_and(|value| value >= horizon.get()));
    assert_eq!(persisted.1.as_deref(), Some("authority_expired"));
    Ok(())
}

#[allow(clippy::too_many_lines)] // Explicitly duplicates only ciphertext that replay must revoke before decrypting.
async fn install_stale_offer_prefix(
    database: &TestDatabase,
    stale_count: u16,
    append_live_command: bool,
) -> TestResult<(
    automata_ci_store::RunnerSessionFence,
    Option<automata_ci_store::DurableRunnerCommand>,
)> {
    assert!(stale_count > 0);
    let fixture = claim_attempt(database, 60_000).await?;
    let fence = fixture.seed.session_fences[0];
    let published = database
        .store()
        .publish_lease_offer(offer(&fixture, OperationId::new())?)
        .await?;
    terminalize_attempt_as_lost(database, fixture.lease.attempt_id()).await?;
    for ordinal in 2_u32..=u32::from(stale_count) {
        let attempt_id = insert_queued(
            database,
            fixture.seed.job_id,
            ordinal,
            database_now(database.pool()).await?.get(),
        )
        .await?;
        let sequence = i64::from(ordinal);
        let command = sqlx::query(
            r"
            INSERT INTO runner_command_outbox (
                runner_session_id, command_sequence, operation_id, runner_id,
                runner_session_epoch, runner_generation, command_kind,
                command_schema, command_digest, tenant_id,
                command_plaintext_size_bytes, envelope_schema, wrapping_key_id,
                wrapped_data_key, nonce, ciphertext, created_at_ms
            )
            SELECT runner_session_id, $3, $4, runner_id,
                   runner_session_epoch, runner_generation, command_kind,
                   command_schema, command_digest, tenant_id,
                   command_plaintext_size_bytes, envelope_schema, wrapping_key_id,
                   wrapped_data_key, nonce, ciphertext, created_at_ms
            FROM runner_command_outbox
            WHERE runner_session_id = $1 AND command_sequence = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(i64::try_from(published.command().sequence().get())?)
        .bind(sequence)
        .bind(OperationId::new().as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(command.rows_affected(), 1);
        let publication = sqlx::query(
            r"
            INSERT INTO runner_lease_offer_publications (
                runner_session_id, request_operation_id, runner_id,
                runner_session_epoch, runner_generation, operation_kind,
                request_digest, protocol_version, runner_slot,
                attempt_id, lease_id, fencing_token, lease_issued_at_ms,
                lease_expires_at_ms, offer_valid_until_ms, job_id, run_id,
                job_ir_schema, job_ir_size_bytes, job_ir_digest,
                job_ir_object_key, command_sequence, created_at_ms
            )
            SELECT runner_session_id, $3, runner_id,
                   runner_session_epoch, runner_generation, operation_kind,
                   request_digest, protocol_version, runner_slot,
                   $4, $5, 1, lease_issued_at_ms,
                   lease_expires_at_ms, offer_valid_until_ms, job_id, run_id,
                   job_ir_schema, job_ir_size_bytes, job_ir_digest,
                   job_ir_object_key, $6, created_at_ms
            FROM runner_lease_offer_publications
            WHERE runner_session_id = $1 AND request_operation_id = $2
            ",
        )
        .bind(fence.session_id().as_uuid())
        .bind(fixture.request_operation_id.as_uuid())
        .bind(OperationId::new().as_uuid())
        .bind(attempt_id.as_uuid())
        .bind(LeaseId::new().as_uuid())
        .bind(sequence)
        .execute(database.pool())
        .await?;
        assert_eq!(publication.rows_affected(), 1);
        terminalize_attempt_as_lost(database, attempt_id).await?;
    }
    insert_queued(
        database,
        fixture.seed.job_id,
        u32::from(stale_count) + 1,
        database_now(database.pool()).await?.get(),
    )
    .await?;
    sqlx::query("UPDATE runner_sessions SET last_command_sequence = $2 WHERE id = $1")
        .bind(fence.session_id().as_uuid())
        .bind(i64::from(stale_count))
        .execute(database.pool())
        .await?;
    let later = if append_live_command {
        Some(enqueue_clock_probe(database, fence, b"after stale offer prefix").await?)
    } else {
        None
    };
    Ok((fence, later))
}

async fn replace_locked_lease(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fixture: &ClaimedFixture,
) -> TestResult {
    let takeover_at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await?;
    let replaced = sqlx::query(
        r"
        UPDATE job_attempts
        SET lease_id = $2,
            fencing_token = fencing_token + 1,
            lease_issued_at_ms = $3,
            lease_expires_at_ms = $4,
            changed_at_ms = $3
        WHERE id = $1
        ",
    )
    .bind(fixture.lease.attempt_id().as_uuid())
    .bind(LeaseId::new().as_uuid())
    .bind(takeover_at)
    .bind(takeover_at + 30_000)
    .execute(&mut **transaction)
    .await?;
    assert_eq!(replaced.rows_affected(), 1);
    Ok(())
}

async fn insert_queued(
    database: &TestDatabase,
    job_id: automata_ci_core::JobId,
    attempt_number: u32,
    queued_at: i64,
) -> TestResult<AttemptId> {
    let attempt_id = AttemptId::new();
    database
        .store()
        .insert_queued(QueuedAttempt::new(
            attempt_id,
            job_id,
            AttemptNumber::new(attempt_number)?,
            UnixMillis::new(queued_at),
        ))
        .await?;
    Ok(attempt_id)
}

async fn terminalize_attempt_as_lost(database: &TestDatabase, attempt_id: AttemptId) -> TestResult {
    let terminalized = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'lost',
            lease_id = NULL,
            runner_id = NULL,
            lease_issued_at_ms = NULL,
            lease_expires_at_ms = NULL,
            runner_session_id = NULL,
            runner_session_epoch = NULL,
            runner_generation = NULL,
            runner_slot = NULL,
            changed_at_ms = greatest(
                changed_at_ms,
                floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT
            )
        WHERE id = $1
        ",
    )
    .bind(attempt_id.as_uuid())
    .execute(database.pool())
    .await?;
    assert_eq!(terminalized.rows_affected(), 1);
    Ok(())
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

fn fallback(
    response: &RunnerOperationResponse,
    operation_id: OperationId,
    retry_after_millis: u32,
) -> TestResult<RevokedLeaseOfferFallback> {
    Ok(RevokedLeaseOfferFallback::new(
        operation_id,
        retry_after_millis,
        response.schema(),
        response.digest(),
    )?)
}

fn maintenance_request(
    observed_at: UnixMillis,
    stale_timeout_millis: u64,
) -> TestResult<ControlPlaneMaintenanceRequest> {
    Ok(ControlPlaneMaintenanceRequest::new(
        observed_at,
        LeaseFailureLimit::new(3)?,
        MaintenanceBatchSize::new(10)?,
        StaleSessionTimeoutMillis::new(stale_timeout_millis)?,
    )?)
}

async fn database_now(pool: &PgPool) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await?,
    ))
}

async fn wait_until_database_time(clock: &TestClock, deadline: UnixMillis) -> TestResult {
    let deadline = deadline
        .get()
        .checked_add(1)
        .ok_or("runner clock deadline overflow")?;
    clock.set(clock.now().await?.max(deadline)).await?;
    Ok(())
}

async fn wait_for_database_lock(pool: &PgPool, query_fragment: &str) -> TestResult {
    for _ in 0..200 {
        let waiting: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND query LIKE '%' || $1 || '%'
            )
            ",
        )
        .bind(query_fragment)
        .fetch_one(pool)
        .await?;
        if waiting {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("timed out waiting for PostgreSQL lock: {query_fragment}").into())
}

async fn wait_for_direct_database_blocker(pool: &PgPool, blocker_pid: i32) -> TestResult {
    for _ in 0..200 {
        let waiting: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM pg_stat_activity AS activity
                WHERE activity.datname = current_database()
                  AND activity.pid <> pg_backend_pid()
                  AND $1 = ANY(pg_blocking_pids(activity.pid))
            )
            ",
        )
        .bind(blocker_pid)
        .fetch_one(pool)
        .await?;
        if waiting {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("timed out waiting for a direct PostgreSQL blocker edge".into())
}

async fn expire_active_attempt(
    database: &TestDatabase,
    clock: &TestClock,
    attempt_id: AttemptId,
) -> TestResult {
    let expiry: i64 = sqlx::query_scalar(
        r"
        UPDATE job_attempts
        SET lease_expires_at_ms = changed_at_ms + 1
        WHERE id = $1
        RETURNING lease_expires_at_ms
        ",
    )
    .bind(attempt_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    wait_until_database_time(clock, UnixMillis::new(expiry)).await
}

async fn set_session_heartbeat(
    database: &TestDatabase,
    session_id: automata_ci_core::RunnerSessionId,
    heartbeat_at: UnixMillis,
) -> TestResult {
    sqlx::query(
        "UPDATE runner_sessions \
         SET connected_at_ms = least(connected_at_ms, $2), heartbeat_at_ms = $2 \
         WHERE id = $1",
    )
    .bind(session_id.as_uuid())
    .bind(heartbeat_at.get())
    .execute(database.pool())
    .await?;
    Ok(())
}
