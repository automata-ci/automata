use std::{
    collections::VecDeque,
    future::pending,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_core::{JobConclusion, RunId, Sha256Digest, UnixMillis, WorkflowJobKey};
use automata_ci_store::{
    ClaimLogicalRunFinalization, ClaimedLogicalRunFinalization, CommitLogicalRunFinalization,
    LogicalRunFinalizationClaimFence, LogicalRunFinalizationDescriptor,
    LogicalRunFinalizationGeneration, LogicalRunFinalizationOpenState,
    LogicalRunFinalizationReceipt, LogicalRunFinalizationRepository,
    LogicalRunFinalizationStoreError, LogicalRunFinalizationTarget, LogicalRunFinalizationWorkerId,
    LogicalRunFinalizationWorkflowStatus, LogicalRunJobResultEvidence, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, StoreError, TenantScope,
};
use automata_ci_workflow_service::{
    AdmissionClock, LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS, LogicalRunFinalizationError,
    LogicalRunFinalizationOutcome, LogicalRunFinalizationService,
};
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[tokio::test]
async fn idle_poll_uses_one_bounded_global_claim() {
    let repository = Arc::new(SyntheticRepository::idle());
    let service = service(repository.clone(), TestClock::new([250]));

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("idle poll"),
        LogicalRunFinalizationOutcome::Idle
    );
    let claims = repository.claims();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].owner(), worker(3));
    assert_eq!(claims[0].observed_at(), UnixMillis::new(250));
    assert_eq!(
        claims[0].expires_at(),
        UnixMillis::new(250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS)
    );
    assert!(repository.commits().is_empty());
}

#[tokio::test]
async fn exact_claim_is_aggregated_and_committed_once() {
    let claimed = claimed(worker(3), 275, 275 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS);
    let repository = Arc::new(SyntheticRepository::ready(claimed));
    let service = service(repository.clone(), TestClock::new([250]));

    let LogicalRunFinalizationOutcome::Finalized(receipt) = service
        .run_once(CancellationToken::new())
        .await
        .expect("finalization")
    else {
        panic!("expected a finalized run");
    };

    assert_eq!(receipt.conclusion(), JobConclusion::Failure);
    assert!(!receipt.is_replay());
    let commits = repository.commits();
    assert_eq!(commits.len(), 1);
    assert_eq!(commits[0].claim().owner(), worker(3));
    assert_eq!(commits[0].finalized_at(), UnixMillis::new(275));
    assert_eq!(commits[0].commit_digest(), receipt.commit_digest());
}

#[tokio::test]
async fn repository_fence_rejection_is_a_retryable_outcome() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::Reject);
    let service = service(repository.clone(), TestClock::new([250]));

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("lost fence is retryable"),
        LogicalRunFinalizationOutcome::FenceLost
    );
    assert_eq!(repository.commits().len(), 1);
}

#[tokio::test]
async fn repository_claim_must_match_this_exact_worker_interval() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(4),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    let finalizer = service(repository.clone(), TestClock::new([250]));

    assert!(matches!(
        finalizer
            .run_once(CancellationToken::new())
            .await
            .expect_err("foreign claim must fail closed"),
        LogicalRunFinalizationError::ClaimMismatch
    ));
    assert!(repository.commits().is_empty());

    let wrong_duration = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        275,
        275 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS + 1,
    )));
    assert!(matches!(
        service(wrong_duration.clone(), TestClock::new([250]))
            .run_once(CancellationToken::new())
            .await
            .expect_err("repository-issued duration must match"),
        LogicalRunFinalizationError::ClaimMismatch
    ));
    assert!(wrong_duration.commits().is_empty());
}

#[tokio::test]
async fn cancellation_prevents_new_work_and_interrupts_an_inflight_claim() {
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let idle = Arc::new(SyntheticRepository::idle());
    service(idle.clone(), TestClock::new([250]))
        .run(cancelled)
        .await
        .expect("pre-cancelled supervision stops normally");
    assert!(idle.claims().is_empty());

    let pending_repository = Arc::new(SyntheticRepository::pending());
    let pending_service = Arc::new(service(pending_repository.clone(), TestClock::new([250])));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let service = pending_service;
        let shutdown = shutdown.clone();
        async move { service.run(shutdown).await }
    });
    timeout(Duration::from_secs(1), async {
        while pending_repository.claim_count.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("claim start deadline");
    shutdown.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .expect("cancellation deadline")
        .expect("worker task")
        .expect("normal cancellation");
    assert_eq!(pending_repository.claim_count.load(Ordering::Relaxed), 1);
    assert!(pending_repository.commits().is_empty());
}

#[tokio::test]
async fn continuously_ready_work_yields_to_supervisor_cancellation() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    let service = Arc::new(service(repository.clone(), TestClock::repeating(250)));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let service = service.clone();
        let shutdown = shutdown.clone();
        async move { service.run(shutdown).await }
    });
    while repository.commits().is_empty() {
        tokio::task::yield_now().await;
    }
    shutdown.cancel();

    timeout(Duration::from_secs(1), task)
        .await
        .expect("cooperative cancellation deadline")
        .expect("worker task")
        .expect("normal cancellation");
}

#[tokio::test]
async fn ambiguous_commit_replays_the_byte_identical_request() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::OperationThenSucceed);
    let service = service(repository.clone(), TestClock::new([250]));

    let LogicalRunFinalizationOutcome::Finalized(receipt) = service
        .run_once(CancellationToken::new())
        .await
        .expect("exact replay resolves the lost response")
    else {
        panic!("expected a finalized replay receipt");
    };
    assert!(receipt.is_replay());
    let commits = repository.commits();
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0], commits[1]);
    assert_eq!(commits[1].commit_digest(), receipt.commit_digest());
}

#[tokio::test]
async fn cancellation_during_commit_returns_replayable_custody() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::Pending);
    let service = Arc::new(service(repository.clone(), TestClock::new([250])));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let service = service.clone();
        let shutdown = shutdown.clone();
        async move { service.run_once(shutdown).await }
    });
    timeout(Duration::from_secs(1), async {
        while repository.commits().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("commit dispatch deadline");
    shutdown.cancel();
    let pending = match timeout(Duration::from_secs(2), task)
        .await
        .expect("commit cancellation deadline")
        .expect("worker task")
    {
        Err(LogicalRunFinalizationError::CommitIndeterminate(pending)) => pending,
        other => panic!("expected indeterminate commit, got {other:?}"),
    };
    assert_eq!(pending.request(), &repository.commits()[0]);

    let foreign = LogicalRunFinalizationService::new(
        repository.clone(),
        Arc::new(TestClock::new([])),
        worker(4),
    );
    assert!(matches!(
        foreign
            .resume_pending_commit(&pending, CancellationToken::new())
            .await
            .expect_err("a foreign worker cannot replay the commit"),
        LogicalRunFinalizationError::ClaimMismatch
    ));
    assert_eq!(pending.request(), &repository.commits()[0]);

    repository.set_commit_behavior(CommitBehavior::Succeed);
    let LogicalRunFinalizationOutcome::Finalized(receipt) = service
        .resume_pending_commit(&pending, CancellationToken::new())
        .await
        .expect("explicit exact replay")
    else {
        panic!("expected resumed finalization");
    };
    let commits = repository.commits();
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0], commits[1]);
    assert_eq!(receipt.commit_digest(), commits[0].commit_digest());
}

#[tokio::test]
async fn continuous_worker_retains_pending_commit_through_shutdown() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::Pending);
    let service = Arc::new(service(repository.clone(), TestClock::repeating(250)));
    let shutdown = CancellationToken::new();
    let task = tokio::spawn({
        let service = service.clone();
        let shutdown = shutdown.clone();
        async move { service.run(shutdown).await }
    });
    timeout(Duration::from_secs(1), async {
        while repository.commits().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("commit dispatch deadline");
    shutdown.cancel();
    repository.set_commit_behavior(CommitBehavior::Succeed);

    timeout(Duration::from_secs(2), task)
        .await
        .expect("exact commit drain deadline")
        .expect("worker task")
        .expect("classified shutdown");
    let commits = repository.commits();
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0], commits[1]);
}

#[tokio::test]
async fn commit_conflict_is_not_retried_or_reclassified() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::Conflict);
    let service = service(repository.clone(), TestClock::new([250]));

    assert!(matches!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect_err("durable conflict is terminal"),
        LogicalRunFinalizationError::Store(LogicalRunFinalizationStoreError::CommitConflict)
    ));
    assert_eq!(repository.commits().len(), 1);
}

#[tokio::test]
async fn mismatched_success_receipt_fails_closed_without_losing_replay_custody() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::MismatchedReceipt);
    let service = service(repository.clone(), TestClock::new([250]));

    let pending = match service.run_once(CancellationToken::new()).await {
        Err(LogicalRunFinalizationError::ReceiptMismatch(pending)) => pending,
        other => panic!("expected a mismatched receipt, got {other:?}"),
    };
    assert_eq!(repository.commits().len(), 1);
    assert_eq!(pending.request(), &repository.commits()[0]);
}

#[tokio::test(start_paused = true)]
async fn stalled_commits_exhaust_the_timeout_budget_with_exact_custody() {
    let repository = Arc::new(SyntheticRepository::ready(claimed(
        worker(3),
        250,
        250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS,
    )));
    repository.set_commit_behavior(CommitBehavior::Pending);
    let service = service(repository.clone(), TestClock::new([250]));
    let started_at = Instant::now();

    let pending = match service.run_once(CancellationToken::new()).await {
        Err(LogicalRunFinalizationError::CommitIndeterminate(pending)) => pending,
        other => panic!("expected indeterminate commit, got {other:?}"),
    };
    let commits = repository.commits();
    assert_eq!(commits.len(), 4);
    assert!(commits.iter().all(|request| request == &commits[0]));
    assert_eq!(pending.request(), &commits[0]);
    assert_eq!(started_at.elapsed(), Duration::from_millis(120_700));
}

#[tokio::test(start_paused = true)]
async fn claim_operation_retries_are_bounded_and_backed_off() {
    let repository = Arc::new(SyntheticRepository::always_transient());
    let service = service(
        repository.clone(),
        TestClock::new([250, 251, 252, 253, 254]),
    );
    let started_at = Instant::now();

    assert!(matches!(
        service
            .run(CancellationToken::new())
            .await
            .expect_err("retry budget is bounded"),
        LogicalRunFinalizationError::Store(LogicalRunFinalizationStoreError::Store(
            StoreError::Operation(_)
        ))
    ));
    assert_eq!(repository.claim_count.load(Ordering::Relaxed), 5);
    assert_eq!(started_at.elapsed(), Duration::from_millis(1_500));
}

#[tokio::test]
async fn invalid_clock_values_fail_before_claim() {
    let negative = Arc::new(SyntheticRepository::idle());
    assert!(matches!(
        service(negative.clone(), TestClock::new([-1]))
            .run_once(CancellationToken::new())
            .await
            .expect_err("negative time"),
        LogicalRunFinalizationError::InvalidTimestamp
    ));
    assert!(negative.claims().is_empty());

    let overflow = Arc::new(SyntheticRepository::idle());
    assert!(matches!(
        service(overflow.clone(), TestClock::new([i64::MAX]))
            .run_once(CancellationToken::new())
            .await
            .expect_err("overflowing claim expiration"),
        LogicalRunFinalizationError::InvalidTimestamp
    ));
    assert!(overflow.claims().is_empty());
}

#[tokio::test]
async fn repository_details_are_not_interpolated_into_public_errors() {
    let repository = Arc::new(SyntheticRepository::corrupt());
    let error = service(repository, TestClock::new([250]))
        .run_once(CancellationToken::new())
        .await
        .expect_err("corrupt repository evidence must fail");

    assert_eq!(
        error.to_string(),
        "logical run-finalization storage operation failed"
    );
    assert!(!error.to_string().contains("sentinel-secret"));
}

#[derive(Debug)]
enum ClaimBehavior {
    Idle,
    Ready(Box<ClaimedLogicalRunFinalization>),
    Pending,
    AlwaysTransient,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitBehavior {
    Succeed,
    Reject,
    Conflict,
    OperationThenSucceed,
    Pending,
    MismatchedReceipt,
}

#[derive(Debug)]
struct SyntheticRepository {
    behavior: ClaimBehavior,
    claim_count: AtomicUsize,
    claim_requests: Mutex<Vec<ClaimLogicalRunFinalization>>,
    commit_requests: Mutex<Vec<CommitLogicalRunFinalization>>,
    commit_behavior: Mutex<CommitBehavior>,
}

impl SyntheticRepository {
    fn idle() -> Self {
        Self::new(ClaimBehavior::Idle)
    }

    fn ready(claimed: ClaimedLogicalRunFinalization) -> Self {
        Self::new(ClaimBehavior::Ready(Box::new(claimed)))
    }

    fn pending() -> Self {
        Self::new(ClaimBehavior::Pending)
    }

    fn always_transient() -> Self {
        Self::new(ClaimBehavior::AlwaysTransient)
    }

    fn corrupt() -> Self {
        Self::new(ClaimBehavior::Corrupt)
    }

    fn new(behavior: ClaimBehavior) -> Self {
        Self {
            behavior,
            claim_count: AtomicUsize::new(0),
            claim_requests: Mutex::new(Vec::new()),
            commit_requests: Mutex::new(Vec::new()),
            commit_behavior: Mutex::new(CommitBehavior::Succeed),
        }
    }

    fn claims(&self) -> Vec<ClaimLogicalRunFinalization> {
        self.claim_requests.lock().expect("claims").clone()
    }

    fn commits(&self) -> Vec<CommitLogicalRunFinalization> {
        self.commit_requests.lock().expect("commits").clone()
    }

    fn set_commit_behavior(&self, behavior: CommitBehavior) {
        *self.commit_behavior.lock().expect("commit behavior") = behavior;
    }
}

#[async_trait]
impl LogicalRunFinalizationRepository for SyntheticRepository {
    async fn claim_logical_run_finalization(
        &self,
        request: ClaimLogicalRunFinalization,
    ) -> Result<Option<ClaimedLogicalRunFinalization>, LogicalRunFinalizationStoreError> {
        self.claim_count.fetch_add(1, Ordering::Relaxed);
        self.claim_requests.lock().expect("claims").push(request);
        match &self.behavior {
            ClaimBehavior::Idle => Ok(None),
            ClaimBehavior::Ready(claimed) => Ok(Some(claimed.as_ref().clone())),
            ClaimBehavior::AlwaysTransient => {
                Err(StoreError::operation(std::io::Error::other("synthetic unavailable")).into())
            }
            ClaimBehavior::Corrupt => Err(StoreError::corrupt_data("sentinel-secret").into()),
            ClaimBehavior::Pending => pending().await,
        }
    }

    async fn commit_logical_run_finalization(
        &self,
        request: CommitLogicalRunFinalization,
    ) -> Result<LogicalRunFinalizationReceipt, LogicalRunFinalizationStoreError> {
        let attempt = {
            let mut commits = self.commit_requests.lock().expect("commits");
            commits.push(request.clone());
            commits.len()
        };
        let behavior = *self.commit_behavior.lock().expect("commit behavior");
        match behavior {
            CommitBehavior::Succeed => Ok(LogicalRunFinalizationReceipt::new(&request, false)),
            CommitBehavior::Reject => Err(LogicalRunFinalizationStoreError::ClaimRejected),
            CommitBehavior::Conflict => Err(LogicalRunFinalizationStoreError::CommitConflict),
            CommitBehavior::OperationThenSucceed if attempt == 1 => {
                Err(StoreError::operation(std::io::Error::other("synthetic lost response")).into())
            }
            CommitBehavior::OperationThenSucceed => {
                Ok(LogicalRunFinalizationReceipt::new(&request, true))
            }
            CommitBehavior::Pending => pending().await,
            CommitBehavior::MismatchedReceipt => {
                let other_claim =
                    claimed(worker(3), 250, 250 + LOGICAL_RUN_FINALIZATION_CLAIM_MILLIS);
                let other_request =
                    CommitLogicalRunFinalization::new(&other_claim, UnixMillis::new(251))
                        .expect("different valid commit");
                Ok(LogicalRunFinalizationReceipt::new(&other_request, false))
            }
        }
    }
}

#[derive(Debug)]
struct TestClock {
    values: Mutex<VecDeque<UnixMillis>>,
    repeating: bool,
}

impl TestClock {
    fn new(values: impl IntoIterator<Item = i64>) -> Self {
        Self {
            values: Mutex::new(values.into_iter().map(UnixMillis::new).collect()),
            repeating: false,
        }
    }

    fn repeating(value: i64) -> Self {
        Self {
            values: Mutex::new(VecDeque::from([UnixMillis::new(value)])),
            repeating: true,
        }
    }
}

impl AdmissionClock for TestClock {
    fn now(&self) -> UnixMillis {
        let mut values = self.values.lock().expect("clock");
        let value = values.pop_front().expect("clock value");
        if self.repeating {
            values.push_back(value);
        }
        value
    }
}

fn service(
    repository: Arc<SyntheticRepository>,
    clock: TestClock,
) -> LogicalRunFinalizationService {
    LogicalRunFinalizationService::new(repository, Arc::new(clock), worker(3))
}

fn claimed(
    claim_worker: LogicalRunFinalizationWorkerId,
    claimed_at: i64,
    expires_at: i64,
) -> ClaimedLogicalRunFinalization {
    let descriptor = LogicalRunFinalizationDescriptor::new(
        target(),
        digest(1),
        LogicalRunFinalizationOpenState::Pending,
        1,
        UnixMillis::new(100),
        LogicalRunFinalizationOpenState::Pending,
        1,
        UnixMillis::new(100),
        LogicalRunFinalizationWorkflowStatus::Queued,
        UnixMillis::new(100),
        vec![
            evidence(0, JobConclusion::Success),
            evidence(1, JobConclusion::Failure),
        ],
    )
    .expect("descriptor");
    let fence = LogicalRunFinalizationClaimFence::new(
        descriptor.target().clone(),
        claim_worker,
        LogicalRunFinalizationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
    )
    .expect("claim fence");
    ClaimedLogicalRunFinalization::new(descriptor, fence).expect("claimed descriptor")
}

fn evidence(source_order: u16, conclusion: JobConclusion) -> LogicalRunJobResultEvidence {
    let offset = u8::try_from(source_order).expect("small fixture");
    LogicalRunJobResultEvidence::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(100 + u128::from(source_order)))
            .expect("logical job"),
        WorkflowJobKey::new(format!("job-{source_order}")).expect("job key"),
        source_order,
        digest(10 + offset),
        conclusion,
        matches!(conclusion, JobConclusion::Failure | JobConclusion::TimedOut),
        conclusion == JobConclusion::Cancelled,
        conclusion == JobConclusion::Skipped,
        1,
        digest(20 + offset),
        0,
        digest(30 + offset),
        0,
        digest(40 + offset),
        digest(50 + offset),
        UnixMillis::new(200 + i64::from(source_order)),
    )
    .expect("job evidence")
}

fn target() -> LogicalRunFinalizationTarget {
    LogicalRunFinalizationTarget::new(
        TenantScope::from_authenticated_tenant_id("run-finalization-service").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
    )
    .expect("target")
}

fn worker(value: u128) -> LogicalRunFinalizationWorkerId {
    LogicalRunFinalizationWorkerId::from_uuid(Uuid::from_u128(value)).expect("worker")
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
