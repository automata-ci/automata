use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use automata_ci_blob::{BlobKey, BlobPayload, ImmutableBlobStore as _, MediaType, MemoryBlobStore};
use automata_ci_core::{
    AttemptId, CompiledValueTemplate, JobConclusion, JobContentReference, JobExecutionContext,
    JobId, JobInstanceIdentity, JobIr, JobIrEnvelope, JobResult, JobSecretExposure, JobSource,
    Located, LogicalJobKind, LogicalJobTemplate, LogicalRunStepTemplate, LogicalRunnerTemplate,
    LogicalStepKind, LogicalStepTemplate, OperationId, PlanSourceLocation, PlanSourceOrigin,
    PlanSourceSpan, RunId, RunValueTemplates, RunnerRequirements, RuntimeBoolean, SemanticStep,
    Sha256Digest, ShellTemplate, StepId, StepIr, StepJobTemplate, UnixMillis, ValueTemplate,
    WorkflowEventProvenance, WorkflowId, WorkflowJobKey, WorkflowPlan, WorkflowSourceProvenance,
    WorkflowStepKey,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_store::{
    AdmissionObject, ClaimLogicalInstanceResult, ClaimLogicalJobResult,
    ClaimNextLogicalInstanceResult, ClaimNextLogicalJobResult, ClaimedLogicalInstanceResult,
    ClaimedLogicalJobResult, CommitLogicalInstanceResult, CommitLogicalJobResult,
    LogicalActivationObject, LogicalInstanceResultClaimFence,
    LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultClaimOutcome,
    LogicalInstanceResultDescriptor, LogicalInstanceResultGeneration,
    LogicalInstanceResultQuarantineKind, LogicalInstanceResultQuarantineOutcome,
    LogicalInstanceResultReceipt, LogicalInstanceResultRepository, LogicalInstanceResultStoreError,
    LogicalInstanceResultTarget, LogicalInstanceResultWorkerId, LogicalInstanceTerminalOrdinal,
    LogicalJobResultClaimFence, LogicalJobResultClaimNextOutcome, LogicalJobResultClaimOutcome,
    LogicalJobResultDescriptor, LogicalJobResultGeneration, LogicalJobResultQuarantineKind,
    LogicalJobResultQuarantineOutcome, LogicalJobResultReceipt, LogicalJobResultRepository,
    LogicalJobResultStoreError, LogicalJobResultTarget, LogicalJobResultWorkerId,
    LogicalServerCancellationTerminal, LogicalTerminalResultObject, LogicalWorkflowInstanceId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, ObjectKey, QuarantineLogicalInstanceResult,
    QuarantineLogicalJobResult, TenantScope,
};
use automata_ci_workflow_service::{
    AdmissionClock, LogicalResultProjectionOutcome, LogicalResultProjectionService,
};
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug)]
struct FixedClock;

impl AdmissionClock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(1_000)
    }
}
#[derive(Debug, Default)]
struct IdleInstanceResults {
    claims: AtomicUsize,
}

#[async_trait]
impl LogicalInstanceResultRepository for IdleInstanceResults {
    async fn claim_next_logical_instance_result(
        &self,
        _request: ClaimNextLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultStoreError> {
        self.claims.fetch_add(1, Ordering::Relaxed);
        Ok(LogicalInstanceResultClaimNextOutcome::Idle)
    }

    async fn claim_logical_instance_result(
        &self,
        _request: ClaimLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
        unreachable!("the autonomous service never guesses a target")
    }

    async fn commit_logical_instance_result(
        &self,
        _request: CommitLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError> {
        unreachable!("idle repositories cannot commit")
    }

    async fn quarantine_logical_instance_result(
        &self,
        _request: QuarantineLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultStoreError> {
        unreachable!("idle repositories cannot quarantine")
    }
}

#[derive(Debug)]
struct QuarantineThenStopInstanceResults {
    claims: AtomicUsize,
    shutdown: CancellationToken,
}

#[async_trait]
impl LogicalInstanceResultRepository for QuarantineThenStopInstanceResults {
    async fn claim_next_logical_instance_result(
        &self,
        _request: ClaimNextLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultStoreError> {
        if self.claims.fetch_add(1, Ordering::Relaxed) == 0 {
            Ok(LogicalInstanceResultClaimNextOutcome::Quarantined)
        } else {
            self.shutdown.cancel();
            Ok(LogicalInstanceResultClaimNextOutcome::Idle)
        }
    }

    async fn claim_logical_instance_result(
        &self,
        _request: ClaimLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
        unreachable!("the autonomous service never guesses a target")
    }

    async fn commit_logical_instance_result(
        &self,
        _request: CommitLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError> {
        unreachable!("pre-claim quarantine cannot commit")
    }

    async fn quarantine_logical_instance_result(
        &self,
        _request: QuarantineLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultStoreError> {
        unreachable!("pre-claim quarantine is already durable")
    }
}

#[derive(Debug, Default)]
struct IdleJobResults {
    claims: AtomicUsize,
}

#[async_trait]
impl LogicalJobResultRepository for IdleJobResults {
    async fn claim_next_logical_job_result(
        &self,
        _request: ClaimNextLogicalJobResult,
    ) -> Result<LogicalJobResultClaimNextOutcome, LogicalJobResultStoreError> {
        self.claims.fetch_add(1, Ordering::Relaxed);
        Ok(LogicalJobResultClaimNextOutcome::Idle)
    }

    async fn claim_logical_job_result(
        &self,
        _request: ClaimLogicalJobResult,
    ) -> Result<LogicalJobResultClaimOutcome, LogicalJobResultStoreError> {
        unreachable!("the autonomous service never guesses a target")
    }

    async fn commit_logical_job_result(
        &self,
        _request: CommitLogicalJobResult,
    ) -> Result<LogicalJobResultReceipt, LogicalJobResultStoreError> {
        unreachable!("idle repositories cannot commit")
    }

    async fn quarantine_logical_job_result(
        &self,
        _request: QuarantineLogicalJobResult,
    ) -> Result<LogicalJobResultQuarantineOutcome, LogicalJobResultStoreError> {
        unreachable!("idle repositories cannot quarantine")
    }
}

#[tokio::test]
async fn idle_poll_checks_both_global_queues_without_target_guessing() {
    let instances = Arc::new(IdleInstanceResults::default());
    let jobs = Arc::new(IdleJobResults::default());
    let service = service(instances.clone(), jobs.clone());

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("idle poll"),
        LogicalResultProjectionOutcome::Idle
    );
    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("alternating idle poll"),
        LogicalResultProjectionOutcome::Idle
    );
    assert_eq!(instances.claims.load(Ordering::Relaxed), 2);
    assert_eq!(jobs.claims.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn cancellation_prevents_new_claims_and_stops_supervision_normally() {
    let instances = Arc::new(IdleInstanceResults::default());
    let jobs = Arc::new(IdleJobResults::default());
    let service = service(instances.clone(), jobs.clone());
    let shutdown = CancellationToken::new();
    shutdown.cancel();

    service.run(shutdown).await.expect("normal shutdown");
    assert_eq!(instances.claims.load(Ordering::Relaxed), 0);
    assert_eq!(jobs.claims.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn supervision_continues_after_durable_quarantine() {
    let shutdown = CancellationToken::new();
    let instances = Arc::new(QuarantineThenStopInstanceResults {
        claims: AtomicUsize::new(0),
        shutdown: shutdown.clone(),
    });
    let jobs = Arc::new(IdleJobResults::default());
    let service = LogicalResultProjectionService::new(
        Arc::new(MemoryBlobStore::default()),
        instances.clone(),
        jobs.clone(),
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    );

    service
        .run(shutdown)
        .await
        .expect("quarantine is observable work, not a fatal supervisor error");
    assert_eq!(instances.claims.load(Ordering::Relaxed), 2);
    assert_eq!(jobs.claims.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn ready_job_loads_exact_plan_and_commits_terminal_projection() {
    let plan = workflow_plan();
    let encoded_plan = serde_json::to_vec(&plan).expect("canonical plan");
    let blob_key = BlobKey::new("plans/result-projection.json").expect("blob key");
    let media_type =
        MediaType::new("application/vnd.automata.workflow-plan+json").expect("media type");
    let payload = BlobPayload::from_bytes(
        blob_key.clone(),
        media_type.clone(),
        encoded_plan.clone().into(),
    );
    let blobs = MemoryBlobStore::default();
    blobs
        .put_if_absent(payload.clone())
        .await
        .expect("seed exact plan");
    let descriptor = job_descriptor(
        AdmissionObject::new(
            payload.descriptor().digest(),
            ObjectKey::new(blob_key.as_str()).expect("store key"),
            payload.descriptor().size(),
            media_type.as_str(),
        )
        .expect("plan object"),
    );
    let jobs = Arc::new(ProjectingJobResults {
        descriptor: descriptor.clone(),
        committed: Mutex::new(None),
        quarantined: Mutex::new(Vec::new()),
    });
    let service = LogicalResultProjectionService::new(
        Arc::new(blobs),
        Arc::new(IdleInstanceResults::default()),
        jobs.clone(),
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    );

    let outcome = service
        .run_once(CancellationToken::new())
        .await
        .expect("project ready job");
    let LogicalResultProjectionOutcome::Job(receipt) = outcome else {
        panic!("ready logical job must be committed");
    };
    assert_eq!(
        receipt.logical_job_id(),
        descriptor.target().logical_job_id()
    );
    assert_eq!(receipt.effective_conclusion(), JobConclusion::Skipped);
    assert!(jobs.committed.lock().expect("commit lock").is_some());
}

#[tokio::test]
async fn terminal_attempt_loads_exact_result_and_job_ir_before_commit() {
    let (descriptor, result_payload, job_ir_payload) = instance_descriptor();
    let blobs = MemoryBlobStore::default();
    blobs
        .put_if_absent(result_payload)
        .await
        .expect("seed exact result");
    blobs
        .put_if_absent(job_ir_payload)
        .await
        .expect("seed exact JobIR");
    let instances = Arc::new(ProjectingInstanceResults {
        descriptor: descriptor.clone(),
        committed: Mutex::new(None),
        quarantined: Mutex::new(Vec::new()),
    });
    let service = LogicalResultProjectionService::new(
        Arc::new(blobs),
        instances.clone(),
        Arc::new(IdleJobResults::default()),
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    );

    let outcome = service
        .run_once(CancellationToken::new())
        .await
        .expect("project terminal attempt");
    let LogicalResultProjectionOutcome::Instance(receipt) = outcome else {
        panic!("terminal attempt must be committed");
    };
    assert_eq!(receipt.instance_id(), descriptor.instance_id());
    assert_eq!(receipt.effective_conclusion(), JobConclusion::Success);
    assert!(instances.committed.lock().expect("commit lock").is_some());
}

#[tokio::test]
async fn server_cancellation_loads_only_job_ir_and_commits_zero_output_evidence() {
    let (descriptor, job_ir_payload) = server_cancellation_descriptor();
    let blobs = MemoryBlobStore::default();
    blobs
        .put_if_absent(job_ir_payload)
        .await
        .expect("seed exact JobIR only");
    let instances = Arc::new(ProjectingInstanceResults {
        descriptor: descriptor.clone(),
        committed: Mutex::new(None),
        quarantined: Mutex::new(Vec::new()),
    });
    let service = LogicalResultProjectionService::new(
        Arc::new(blobs),
        instances.clone(),
        Arc::new(IdleJobResults::default()),
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    );

    let outcome = service
        .run_once(CancellationToken::new())
        .await
        .expect("project server cancellation");
    let LogicalResultProjectionOutcome::Instance(receipt) = outcome else {
        panic!("server cancellation must be committed without a result blob");
    };
    assert_eq!(receipt.instance_id(), descriptor.instance_id());
    assert_eq!(receipt.raw_conclusion(), JobConclusion::Cancelled);
    assert_eq!(receipt.effective_conclusion(), JobConclusion::Cancelled);
    assert_eq!(receipt.secret_exposure(), JobSecretExposure::Secretless);
    assert_eq!(receipt.output_count(), 0);
    assert!(instances.committed.lock().expect("commit lock").is_some());
    assert!(
        instances
            .quarantined
            .lock()
            .expect("quarantine lock")
            .is_empty()
    );
}

#[tokio::test]
async fn missing_terminal_object_is_quarantined_without_a_commit() {
    let (descriptor, _result_payload, job_ir_payload) = instance_descriptor();
    let blobs = MemoryBlobStore::default();
    blobs
        .put_if_absent(job_ir_payload)
        .await
        .expect("seed exact JobIR");
    let instances = Arc::new(ProjectingInstanceResults {
        descriptor,
        committed: Mutex::new(None),
        quarantined: Mutex::new(Vec::new()),
    });
    let service = LogicalResultProjectionService::new(
        Arc::new(blobs),
        instances.clone(),
        Arc::new(IdleJobResults::default()),
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    );

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("quarantine permanent missing object"),
        LogicalResultProjectionOutcome::InstanceQuarantined
    );
    assert!(instances.committed.lock().expect("commit lock").is_none());
    assert_eq!(
        *instances.quarantined.lock().expect("quarantine lock"),
        vec![LogicalInstanceResultQuarantineKind::ObjectEvidence]
    );
}

#[tokio::test]
async fn malformed_workflow_plan_is_quarantined_without_a_commit() {
    let blob_key = BlobKey::new("plans/invalid-result-projection.json").expect("blob key");
    let media_type =
        MediaType::new("application/vnd.automata.workflow-plan+json").expect("media type");
    let payload = BlobPayload::from_bytes(
        blob_key.clone(),
        media_type.clone(),
        Bytes::from_static(b"{"),
    );
    let blobs = MemoryBlobStore::default();
    blobs
        .put_if_absent(payload.clone())
        .await
        .expect("seed malformed plan");
    let jobs = Arc::new(ProjectingJobResults {
        descriptor: job_descriptor(
            AdmissionObject::new(
                payload.descriptor().digest(),
                ObjectKey::new(blob_key.as_str()).expect("store key"),
                payload.descriptor().size(),
                media_type.as_str(),
            )
            .expect("plan object"),
        ),
        committed: Mutex::new(None),
        quarantined: Mutex::new(Vec::new()),
    });
    let service = LogicalResultProjectionService::new(
        Arc::new(blobs),
        Arc::new(IdleInstanceResults::default()),
        jobs.clone(),
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    );

    assert_eq!(
        service
            .run_once(CancellationToken::new())
            .await
            .expect("quarantine malformed plan"),
        LogicalResultProjectionOutcome::JobQuarantined
    );
    assert!(jobs.committed.lock().expect("commit lock").is_none());
    assert_eq!(
        *jobs.quarantined.lock().expect("quarantine lock"),
        vec![LogicalJobResultQuarantineKind::PayloadEvidence]
    );
}

#[derive(Debug)]
struct ProjectingInstanceResults {
    descriptor: LogicalInstanceResultDescriptor,
    committed: Mutex<Option<Sha256Digest>>,
    quarantined: Mutex<Vec<LogicalInstanceResultQuarantineKind>>,
}

#[async_trait]
impl LogicalInstanceResultRepository for ProjectingInstanceResults {
    async fn claim_next_logical_instance_result(
        &self,
        request: ClaimNextLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimNextOutcome, LogicalInstanceResultStoreError> {
        let claim = LogicalInstanceResultClaimFence::new(
            self.descriptor.target().clone(),
            request.owner(),
            LogicalInstanceResultGeneration::new(1).expect("generation"),
            self.descriptor.descriptor_digest(),
            request.observed_at(),
            request.expires_at(),
        )
        .expect("matching claim");
        Ok(LogicalInstanceResultClaimNextOutcome::Claimed(
            ClaimedLogicalInstanceResult::new(self.descriptor.clone(), claim, false)
                .expect("claimed descriptor"),
        ))
    }

    async fn claim_logical_instance_result(
        &self,
        _request: ClaimLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultClaimOutcome, LogicalInstanceResultStoreError> {
        unreachable!("the autonomous service never guesses a target")
    }

    async fn commit_logical_instance_result(
        &self,
        request: CommitLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultReceipt, LogicalInstanceResultStoreError> {
        *self.committed.lock().expect("commit lock") = Some(request.commit_digest());
        Ok(LogicalInstanceResultReceipt::new(
            &request,
            &self.descriptor,
            false,
        ))
    }

    async fn quarantine_logical_instance_result(
        &self,
        request: QuarantineLogicalInstanceResult,
    ) -> Result<LogicalInstanceResultQuarantineOutcome, LogicalInstanceResultStoreError> {
        self.quarantined
            .lock()
            .expect("quarantine lock")
            .push(request.kind());
        Ok(LogicalInstanceResultQuarantineOutcome::Quarantined)
    }
}

#[derive(Debug)]
struct ProjectingJobResults {
    descriptor: LogicalJobResultDescriptor,
    committed: Mutex<Option<Sha256Digest>>,
    quarantined: Mutex<Vec<LogicalJobResultQuarantineKind>>,
}

#[async_trait]
impl LogicalJobResultRepository for ProjectingJobResults {
    async fn claim_next_logical_job_result(
        &self,
        request: ClaimNextLogicalJobResult,
    ) -> Result<LogicalJobResultClaimNextOutcome, LogicalJobResultStoreError> {
        let claim = LogicalJobResultClaimFence::new(
            self.descriptor.target().clone(),
            request.owner(),
            LogicalJobResultGeneration::new(1).expect("generation"),
            self.descriptor.descriptor_digest(),
            request.observed_at(),
            request.expires_at(),
        )
        .expect("matching claim");
        Ok(LogicalJobResultClaimNextOutcome::Claimed(
            ClaimedLogicalJobResult::new(self.descriptor.clone(), claim, false)
                .expect("claimed descriptor"),
        ))
    }

    async fn claim_logical_job_result(
        &self,
        _request: ClaimLogicalJobResult,
    ) -> Result<LogicalJobResultClaimOutcome, LogicalJobResultStoreError> {
        unreachable!("the autonomous service never guesses a target")
    }

    async fn commit_logical_job_result(
        &self,
        request: CommitLogicalJobResult,
    ) -> Result<LogicalJobResultReceipt, LogicalJobResultStoreError> {
        *self.committed.lock().expect("commit lock") = Some(request.commit_digest());
        Ok(LogicalJobResultReceipt::new(
            &request,
            &self.descriptor,
            false,
        ))
    }

    async fn quarantine_logical_job_result(
        &self,
        request: QuarantineLogicalJobResult,
    ) -> Result<LogicalJobResultQuarantineOutcome, LogicalJobResultStoreError> {
        self.quarantined
            .lock()
            .expect("quarantine lock")
            .push(request.kind());
        Ok(LogicalJobResultQuarantineOutcome::Quarantined)
    }
}

fn service(
    instances: Arc<IdleInstanceResults>,
    jobs: Arc<IdleJobResults>,
) -> LogicalResultProjectionService {
    LogicalResultProjectionService::new(
        Arc::new(MemoryBlobStore::default()),
        instances,
        jobs,
        Arc::new(FixedClock),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(1)).expect("instance worker"),
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(2)).expect("job worker"),
        ProtocolLimits::default(),
    )
}

fn job_descriptor(plan: AdmissionObject) -> LogicalJobResultDescriptor {
    let target = LogicalJobResultTarget::new(
        TenantScope::from_authenticated_tenant_id("result-projection").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(20)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(21)).expect("invocation"),
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(22)).expect("logical job"),
    )
    .expect("target");
    LogicalJobResultDescriptor::new(
        target,
        WorkflowJobKey::new("build").expect("logical key"),
        0,
        plan,
        Sha256Digest::from_bytes([0x44; 32]),
        false,
        0,
        Vec::new(),
        Vec::new(),
        UnixMillis::new(900),
    )
    .expect("ready descriptor")
}

#[allow(clippy::too_many_lines)] // Keeps one exact descriptor and both canonical blobs together.
fn instance_descriptor() -> (LogicalInstanceResultDescriptor, BlobPayload, BlobPayload) {
    let run_id = RunId::from_uuid(Uuid::from_u128(30));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(31)).expect("invocation");
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(32)).expect("logical job");
    let instance_id = LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(33)).expect("instance");
    let job_id = JobId::from_uuid(Uuid::from_u128(34));
    let attempt_id = AttemptId::from_uuid(Uuid::from_u128(35));
    let logical_key = WorkflowJobKey::new("build").expect("logical key");
    let matrix_digest = Sha256Digest::from_bytes([0x33; 32]);
    let identity =
        JobInstanceIdentity::new(logical_key.as_str(), 0, 1, matrix_digest).expect("identity");
    let step = StepIr::new_literal_name(
        StepId::new("run").expect("step ID"),
        "Run",
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("true").expect("command"),
            ShellTemplate::default_shell(),
        )),
    )
    .expect("step");
    let envelope = JobIrEnvelope::new(
        WorkflowId::from_uuid(Uuid::from_u128(36)),
        JobSource::new(
            "github",
            "example/project",
            "0123456789abcdef",
            ".github/workflows/ci.yml",
            "push",
        ),
        JobExecutionContext::new(
            "CI",
            "refs/heads/main",
            "/srv/work/repository",
            JobContentReference::new(
                "events/push.json",
                Sha256Digest::from_bytes([0x11; 32]),
                10,
                "application/json",
            ),
            JobContentReference::new(
                "contexts/job.pb",
                Sha256Digest::from_bytes([0x12; 32]),
                10,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
        ),
        JobIr::new(
            job_id,
            run_id,
            "Build",
            RunnerRequirements::default(),
            identity,
            false,
            vec![step],
        ),
    );
    let encoded_job_ir =
        encode_job_ir(&envelope, &ProtocolLimits::default()).expect("canonical JobIR");
    let job_ir_payload = BlobPayload::from_bytes(
        BlobKey::new("job-ir/build.pb").expect("JobIR blob key"),
        MediaType::new("application/vnd.automata.job-ir.protobuf").expect("JobIR media type"),
        encoded_job_ir.into(),
    );
    let result = JobResult::new(
        attempt_id,
        JobConclusion::Success,
        JobSecretExposure::Secretless,
        UnixMillis::new(900),
    )
    .with_outputs(BTreeMap::new());
    let encoded_result = serde_json::to_vec(&result).expect("canonical result");
    let result_payload = BlobPayload::from_bytes(
        BlobKey::new("results/build.json").expect("result blob key"),
        MediaType::new("application/vnd.automata.job-result+json").expect("result media type"),
        encoded_result.into(),
    );
    let target = LogicalInstanceResultTarget::new(
        TenantScope::from_authenticated_tenant_id("result-projection").expect("tenant"),
        attempt_id,
    )
    .expect("target");
    let descriptor = LogicalInstanceResultDescriptor::new(
        target,
        run_id,
        invocation_id,
        logical_job_id,
        instance_id,
        job_id,
        logical_key,
        0,
        1,
        matrix_digest,
        LogicalInstanceTerminalOrdinal::new(1).expect("terminal ordinal"),
        LogicalTerminalResultObject::new(
            result_payload.descriptor().digest(),
            ObjectKey::new(result_payload.descriptor().key().as_str()).expect("result key"),
            result_payload.descriptor().size(),
            automata_ci_core::CORE_SCHEMA_VERSION,
        )
        .expect("terminal result object"),
        LogicalActivationObject::job_ir(
            job_ir_payload.descriptor().digest(),
            ObjectKey::new(job_ir_payload.descriptor().key().as_str()).expect("JobIR key"),
            job_ir_payload.descriptor().size(),
        )
        .expect("JobIR object"),
        JobSecretExposure::Secretless,
        JobConclusion::Success,
        UnixMillis::new(900),
        UnixMillis::new(910),
    )
    .expect("terminal descriptor");
    (descriptor, result_payload, job_ir_payload)
}

fn server_cancellation_descriptor() -> (LogicalInstanceResultDescriptor, BlobPayload) {
    let (runner, _result_payload, job_ir_payload) = instance_descriptor();
    let descriptor = LogicalInstanceResultDescriptor::new_server_cancellation(
        runner.target().clone(),
        runner.run_id(),
        runner.invocation_id(),
        runner.logical_job_id(),
        runner.instance_id(),
        runner.job_id(),
        runner.logical_key().clone(),
        runner.matrix_index(),
        runner.matrix_total(),
        runner.matrix_digest(),
        runner.terminal_ordinal(),
        LogicalServerCancellationTerminal::new(
            OperationId::new(),
            Sha256Digest::from_bytes([0xC7; 32]),
        ),
        runner.job_ir().clone(),
        JobSecretExposure::ReadableSecret,
        runner.result_completed_at(),
        runner.result_committed_at(),
    )
    .expect("server cancellation descriptor");
    (descriptor, job_ir_payload)
}

fn workflow_plan() -> WorkflowPlan {
    let span = span();
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![Located::new(
            CompiledValueTemplate::Literal("linux".to_owned()),
            span.clone(),
        )],
        span.clone(),
    );
    let step = LogicalStepTemplate::builder(
        Located::new(
            WorkflowStepKey::new("position/00000000").expect("step key"),
            span.clone(),
        ),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            Located::new(
                CompiledValueTemplate::Literal("true".to_owned()),
                span.clone(),
            ),
            None,
            None,
        ))),
        span.clone(),
    )
    .build()
    .expect("step");
    let job = LogicalJobTemplate::builder(
        Located::new(WorkflowJobKey::new("build").expect("job key"), span.clone()),
        0,
        LogicalJobKind::Steps(StepJobTemplate::new(runner, vec![step], span.clone())),
        span.clone(),
    )
    .build()
    .expect("job");
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "result-projection.yml",
            PlanSourceOrigin::Memory {
                name: "result-projection.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        vec![job],
        span,
    )
    .build()
    .expect("workflow plan")
}

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "result-projection.yml",
        PlanSourceLocation::new(0, 1, 1).expect("location"),
        PlanSourceLocation::new(1, 1, 2).expect("location"),
    )
    .expect("span")
}
