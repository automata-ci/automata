mod support;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci_blob::MemoryBlobStore;
use automata_ci_core::UnixMillis;
use automata_ci_store::{
    AdmitLogicalWorkflowRun, AuthenticatedProviderDeliveryClaim, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError, ProviderDeliveryId,
    ProviderProcessingClaimFence, ProviderProcessingInvocationId, ProviderProcessingReceipt,
    ProviderProcessingState, ProviderProcessingWorkerId,
};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, ProviderProcessingClaimSource, WorkflowAdmissionService,
};
use uuid::Uuid;

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;

#[tokio::test]
async fn provider_admission_reads_the_latest_common_fence_at_commit() -> TestResult {
    let repository = Arc::new(RecordingRepository::default());
    let service = WorkflowAdmissionService::with_system_ports(
        Arc::new(MemoryBlobStore::default()),
        repository.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let request = support::push_request("11111111-1111-4111-8111-111111111111");
    let now = system_now();
    let delivery_id =
        ProviderDeliveryId::from_uuid(Uuid::from_u128(42)).expect("provider delivery ID");
    let invocation_id = ProviderProcessingInvocationId::from_uuid(Uuid::from_u128(43))
        .expect("processing invocation");
    let receipt = ProviderProcessingReceipt::new(
        invocation_id,
        delivery_id,
        Some(delivery_id),
        ProviderProcessingState::Claimed,
        2,
        UnixMillis::new(now - 2_000),
    )?;
    let source = Arc::new(CurrentFence {
        fence: ProviderProcessingClaimFence::new(
            invocation_id,
            ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(44)).expect("worker"),
            7,
            UnixMillis::new(now - 1_000),
            UnixMillis::new(now + 60_000),
        )?,
        reads: AtomicUsize::new(0),
    });

    let result = service
        .admit_authenticated_provider_delivery(request, delivery_id, receipt, source.clone())
        .await?;

    assert!(!result.receipt().is_replay());
    assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    assert_eq!(repository.commit_attempts(), 1);
    Ok(())
}

#[derive(Debug)]
struct CurrentFence {
    fence: ProviderProcessingClaimFence,
    reads: AtomicUsize,
}

impl ProviderProcessingClaimSource for CurrentFence {
    fn current_fence(&self) -> ProviderProcessingClaimFence {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.fence
    }
}

#[derive(Debug, Default)]
struct RecordingRepository {
    state: Mutex<RecordingState>,
}

#[derive(Debug, Default)]
struct RecordingState {
    command: Option<AdmitLogicalWorkflowRun>,
    attempts: usize,
}

impl RecordingRepository {
    fn commit_attempts(&self) -> usize {
        self.state
            .lock()
            .expect("recording repository lock")
            .attempts
    }
}

#[async_trait]
impl LogicalWorkflowAdmissionRepository for RecordingRepository {
    async fn admit_logical_workflow(
        &self,
        _command: AdmitLogicalWorkflowRun,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
    }

    async fn admit_authenticated_provider_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedProviderDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        assert_eq!(command.admitted_at(), observed_at);
        assert!(current_claim.authorizes(observed_at));
        let mut state = self.state.lock().expect("recording repository lock");
        state.attempts += 1;
        let replayed = state.command.is_some();
        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            replayed,
        );
        if !replayed {
            state.command = Some(command);
        }
        Ok(receipt)
    }
}

fn system_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_millis(),
    )
    .expect("current time fits i64")
}
