mod support;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use automata_ci_blob::{
    BlobDescriptor, BlobKey, ImmutableBlobStore as _, MediaType, MemoryBlobStore,
};
use automata_ci_blob_s3::{S3AtRestEncryption, S3BlobStoreConfig, StaticS3Credentials};
use automata_ci_core::UnixMillis;
use automata_ci_store::{
    AdmitLogicalWorkflowRun, AuthenticatedGithubDeliveryClaim, AuthenticatedProviderDeliveryClaim,
    LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionRepository,
    LogicalWorkflowAdmissionStoreError, ProviderDeliveryClaimFence, ProviderDeliveryId,
    ProviderProcessingClaimFence, ProviderProcessingInvocationId, ProviderProcessingReceipt,
    ProviderProcessingState, ProviderProcessingWorkerId,
};
use automata_ci_workflow_service::{
    GithubWorkflowPlanVerifier, ProviderProcessingClaimSource, WorkflowAdmissionError,
    WorkflowAdmissionService,
};
use url::Url;
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

fn required_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|error| panic!("{name} is required: {error}"))
}

#[tokio::test]
#[ignore = "requires an explicitly configured S3-compatible test service"]
async fn authenticated_admission_publishes_exact_evidence_to_rustfs_before_commit() -> TestResult {
    let config = S3BlobStoreConfig::loopback_development(
        Url::parse(&required_environment("AUTOMATA_TEST_S3_ENDPOINT"))?,
        "us-east-1",
        required_environment("AUTOMATA_TEST_S3_BUCKET"),
        Some("workflow-logical-admission-live-v2".to_owned()),
        Duration::from_secs(30),
    )?
    .with_at_rest_encryption(S3AtRestEncryption::aws_kms(required_environment(
        "AUTOMATA_TEST_S3_KMS_KEY_ID",
    ))?);
    let blobs = Arc::new(config.connect(StaticS3Credentials::new(
        required_environment("AUTOMATA_TEST_S3_ACCESS_KEY"),
        required_environment("AUTOMATA_TEST_S3_SECRET_KEY"),
        None,
    )?)?);
    let repository = Arc::new(RecordingRepository::default());
    let service = WorkflowAdmissionService::with_system_ports(
        blobs.clone(),
        repository.clone(),
        Arc::new(GithubWorkflowPlanVerifier::new()),
    );
    let tenant = format!("logical-admission-{}", Uuid::new_v4().simple());
    let request = support::push_request(&tenant);
    let claim = authenticated_claim();

    let (left, right) = tokio::join!(
        service.admit_authenticated_github_delivery(request.clone(), claim),
        service.admit_authenticated_github_delivery(request.clone(), claim)
    );
    let left = left?.receipt();
    let right = right?.receipt();
    assert_eq!(left.run_id(), right.run_id());
    assert_eq!(left.root_invocation_id(), right.root_invocation_id());
    assert_ne!(left.is_replay(), right.is_replay());

    let command = repository.command();
    let mut evidence = vec![command.source(), command.event(), command.plan()];
    if let Some(base_context) = command.base_context() {
        evidence.push(base_context);
    }
    assert_eq!(evidence.len(), 4);
    for object in evidence {
        let descriptor = BlobDescriptor::new(
            BlobKey::new(object.object_key().as_str())?,
            object.digest(),
            object.encoded_size(),
            MediaType::new(object.media_type())?,
        );
        let verified = blobs.get_verified(&descriptor, descriptor.size()).await?;
        assert_eq!(verified.descriptor(), &descriptor);
    }

    assert!(matches!(
        service
            .admit_authenticated_github_delivery(support::changed_event_request(&request), claim,)
            .await
            .expect_err("changed evidence under one delivery must conflict"),
        WorkflowAdmissionError::Store(LogicalWorkflowAdmissionStoreError::IdempotencyConflict)
    ));
    assert_eq!(repository.commit_attempts(), 3);
    Ok(())
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
    fn command(&self) -> AdmitLogicalWorkflowRun {
        self.state
            .lock()
            .expect("recording repository lock")
            .command
            .clone()
            .expect("authenticated command")
    }

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

    async fn admit_authenticated_github_delivery(
        &self,
        command: AdmitLogicalWorkflowRun,
        _current_claim: AuthenticatedGithubDeliveryClaim,
        observed_at: UnixMillis,
    ) -> Result<LogicalWorkflowAdmissionReceipt, LogicalWorkflowAdmissionStoreError> {
        assert_eq!(command.admitted_at(), observed_at);
        let mut state = self.state.lock().expect("recording repository lock");
        state.attempts += 1;
        let replayed = if let Some(previous) = &state.command {
            if previous.idempotency() != command.idempotency()
                || previous.request_digest() != command.request_digest()
            {
                return Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict);
            }
            true
        } else {
            false
        };
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

fn authenticated_claim() -> AuthenticatedGithubDeliveryClaim {
    let now = system_now();
    let delivery_id =
        ProviderDeliveryId::from_uuid(Uuid::from_u128(42)).expect("provider delivery ID");
    let owner = ProviderProcessingWorkerId::from_uuid(Uuid::from_u128(900))
        .expect("provider delivery owner");
    let claim = ProviderDeliveryClaimFence::from_durable_parts(delivery_id, owner, 1)
        .expect("provider delivery fence");
    AuthenticatedGithubDeliveryClaim::new(
        claim,
        1,
        UnixMillis::new(now - 60_000),
        UnixMillis::new(now + 60_000),
    )
    .expect("live authenticated provider claim")
}
