mod support;

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use automata_ci_blob::MemoryBlobStore;
use automata_ci_core::UnixMillis;
use automata_ci_store::{
    AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim, LogicalWorkflowAdmissionReceipt,
    LogicalWorkflowAdmissionRepository, LogicalWorkflowAdmissionStoreError,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId, ProviderDeliveryId,
    WorkflowAdmissionIdempotency,
};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, WorkflowAdmissionError, WorkflowAdmissionFailure,
    WorkflowAdmissionObservation, WorkflowAdmissionObserver, WorkflowAdmissionRequest,
    WorkflowAdmissionService, WorkflowAdmissionStage, WorkflowAdmissionStageOutcome,
};
use uuid::Uuid;

#[tokio::test]
async fn human_projection_is_bound_into_the_logical_admission() {
    let original = support::ci_request(
        "logical-projection",
        WorkflowAdmissionIdempotency::provider_delivery(support::DELIVERY).expect("delivery"),
    );
    let request = WorkflowAdmissionRequest::builder(
        original.tenant().clone(),
        original.repository().clone(),
        original.workflow_path(),
        original.source().clone(),
        original.event().clone(),
        original.plan().clone(),
        original.idempotency().clone(),
    )
    .commit_sha(original.commit_sha())
    .git_ref(original.git_ref())
    .workflow_name(original.workflow_name())
    .actor("octocat")
    .display_title("Make projection durable")
    .commit_subject("Carry exact admission metadata")
    .run_attempt(7)
    .build()
    .expect("projected request");
    let repository = Arc::new(ControllableRepository::default());
    let service = service(repository.clone());

    service.admit(request).await.expect("admission");
    let command = repository.take_command();
    assert_eq!(command.workflow_name(), "CI");
    assert_eq!(command.git_ref(), support::GIT_REF);
    assert_eq!(command.actor(), Some("octocat"));
    assert_eq!(command.display_title(), Some("Make projection durable"));
    assert_eq!(
        command.commit_subject(),
        Some("Carry exact admission metadata")
    );
    assert_eq!(command.run_attempt(), 7);
    assert_eq!(repository.take_delivery_id(), None);
}

#[tokio::test]
async fn authenticated_delivery_uses_the_distinct_store_path_and_digest() {
    let request = support::push_request("logical-provider-evidence");
    let local_repository = Arc::new(ControllableRepository::default());
    service(local_repository.clone())
        .admit(request.clone())
        .await
        .expect("ordinary admission");
    let local_digest = local_repository.take_command().request_digest();
    assert_eq!(local_repository.take_delivery_id(), None);

    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(42)).expect("delivery ID");
    let current_claim = authenticated_claim(delivery_id);
    let provider_repository = Arc::new(ControllableRepository::default());
    service(provider_repository.clone())
        .admit_authenticated_github_delivery(request, current_claim)
        .await
        .expect("authenticated delivery admission");
    let provider_digest = provider_repository.take_command().request_digest();
    assert_eq!(provider_repository.take_delivery_id(), Some(delivery_id));
    assert_ne!(provider_digest, local_digest);
}

#[tokio::test]
async fn provider_only_entrypoint_rejects_operation_admission_before_the_store() {
    let delivery_id = ProviderDeliveryId::from_uuid(Uuid::from_u128(43)).expect("delivery ID");
    let current_claim = authenticated_claim(delivery_id);
    let repository = Arc::new(ControllableRepository::default());
    assert!(matches!(
        service(repository.clone())
            .admit_authenticated_github_delivery(
                support::operation_request("logical-local-absence"),
                current_claim,
            )
            .await
            .expect_err("operation admission cannot claim provider evidence"),
        WorkflowAdmissionError::Internal
    ));
    assert!(repository.command.lock().expect("command lock").is_none());
    assert!(
        repository
            .delivery_ids
            .lock()
            .expect("delivery capture lock")
            .is_empty()
    );
}

#[tokio::test]
async fn observer_distinguishes_new_replay_and_durable_failure() {
    let request = support::operation_request("logical-observer");
    let job_count = request.plan().jobs().len();
    let repository = Arc::new(ControllableRepository::default());
    let observer = Arc::new(RecordingObserver::default());
    let service = service(repository.clone()).with_observer(observer.clone());

    service.admit(request.clone()).await.expect("new admission");
    repository.mode.store(1, Ordering::SeqCst);
    service
        .admit(request.clone())
        .await
        .expect("receipt replay");
    repository.mode.store(2, Ordering::SeqCst);
    assert!(matches!(
        service.admit(request).await.expect_err("durable conflict"),
        WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::IdempotencyConflict)
    ));

    assert_eq!(
        *observer.admissions.lock().expect("admission lock"),
        [
            WorkflowAdmissionObservation::New { jobs: job_count },
            WorkflowAdmissionObservation::Replay,
            WorkflowAdmissionObservation::Failed(WorkflowAdmissionFailure::DurableStore),
        ]
    );
    let stages = observer.stages.lock().expect("stage lock");
    assert_eq!(stages.len(), 15);
    for attempt in stages.chunks_exact(5).take(2) {
        assert_eq!(
            attempt,
            [
                (
                    WorkflowAdmissionStage::Prepare,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Materialize,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Encode,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Publish,
                    WorkflowAdmissionStageOutcome::Success
                ),
                (
                    WorkflowAdmissionStage::Commit,
                    WorkflowAdmissionStageOutcome::Success
                ),
            ]
        );
    }
    assert_eq!(
        &stages[10..],
        [
            (
                WorkflowAdmissionStage::Prepare,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Materialize,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Encode,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Publish,
                WorkflowAdmissionStageOutcome::Success
            ),
            (
                WorkflowAdmissionStage::Commit,
                WorkflowAdmissionStageOutcome::Failure
            ),
        ]
    );
}

fn service(repository: Arc<ControllableRepository>) -> WorkflowAdmissionService {
    WorkflowAdmissionService::with_system_ports(
        Arc::new(MemoryBlobStore::default()),
        repository,
        Arc::new(GithubWorkflowPlanVerifier::new()),
    )
}

#[derive(Debug, Default)]
struct ControllableRepository {
    command: Mutex<Option<AdmitLogicalWorkflowRun>>,
    delivery_ids: Mutex<Vec<Option<ProviderDeliveryId>>>,
    mode: AtomicU8,
}

impl ControllableRepository {
    fn take_command(&self) -> AdmitLogicalWorkflowRun {
        self.command
            .lock()
            .expect("capture lock")
            .take()
            .expect("captured command")
    }

    fn take_delivery_id(&self) -> Option<ProviderDeliveryId> {
        self.delivery_ids
            .lock()
            .expect("delivery capture lock")
            .pop()
            .expect("captured admission path")
    }

    fn record(
        &self,
        command: AdmitLogicalWorkflowRun,
        delivery_id: Option<ProviderDeliveryId>,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        if self.mode.load(Ordering::SeqCst) == 2 {
            return Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict);
        }
        let receipt = LogicalWorkflowAdmissionReceipt::new(
            command.repository().id(),
            command.workflow_id(),
            command.snapshot_id(),
            command.run_id(),
            command.root_invocation_id(),
            1,
            self.mode.load(Ordering::SeqCst) == 1,
        );
        *self.command.lock().expect("capture lock") = Some(command);
        self.delivery_ids
            .lock()
            .expect("delivery capture lock")
            .push(delivery_id);
        Ok(receipt)
    }
}

impl LogicalWorkflowAdmissionRepository for ControllableRepository {
    fn admit_logical_workflow<'life0, 'async_trait>(
        &'life0 self,
        command: AdmitLogicalWorkflowRun,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        LogicalWorkflowAdmissionReceipt,
                        LogicalWorkflowAdmissionStoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.record(command, None) })
    }

    fn admit_authenticated_github_delivery<'life0, 'async_trait>(
        &'life0 self,
        command: AdmitLogicalWorkflowRun,
        current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        LogicalWorkflowAdmissionReceipt,
                        LogicalWorkflowAdmissionStoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            assert_eq!(command.admitted_at(), observed_at);
            self.record(command, Some(current_claim.claim().delivery_id()))
        })
    }
}

fn authenticated_claim(delivery_id: ProviderDeliveryId) -> AuthenticatedGithubDeliveryClaim {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_millis(),
    )
    .expect("current time fits i64");
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(900)).expect("claim owner");
    let claim =
        ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 1).expect("claim fence");
    AuthenticatedGithubDeliveryClaim::new(
        claim,
        1,
        UnixMillis::new(now - 60_000),
        UnixMillis::new(now + 60_000),
    )
    .expect("authenticated claim")
}

#[derive(Debug, Default)]
struct RecordingObserver {
    stages: Mutex<Vec<(WorkflowAdmissionStage, WorkflowAdmissionStageOutcome)>>,
    admissions: Mutex<Vec<WorkflowAdmissionObservation>>,
}

impl WorkflowAdmissionObserver for RecordingObserver {
    fn observe_stage(
        &self,
        stage: WorkflowAdmissionStage,
        outcome: WorkflowAdmissionStageOutcome,
        _duration: Duration,
    ) {
        self.stages
            .lock()
            .expect("stage lock")
            .push((stage, outcome));
    }

    fn observe_admission(&self, outcome: WorkflowAdmissionObservation, _duration: Duration) {
        self.admissions
            .lock()
            .expect("admission lock")
            .push(outcome);
    }
}
