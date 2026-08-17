use std::collections::BTreeMap;

use automata_ci_core::{
    AttemptId, JobConclusion, JobContentReference, JobExecutionContext, JobInstanceIdentity, JobIr,
    JobIrEnvelope, JobOutputDefinition, JobResult, JobResultOutput, JobSecretExposure, JobSource,
    OperationId, OutputSensitivity, RunId, RunValueTemplates, RunnerRequirements, RuntimeBoolean,
    SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr, UnixMillis, ValueTemplate,
    WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    ClaimNextLogicalInstanceResult, ClaimedLogicalInstanceResult, CommitLogicalInstanceResult,
    LogicalActivationObject, LogicalInstanceResultClaimFence, LogicalInstanceResultDescriptor,
    LogicalInstanceResultGeneration, LogicalInstanceResultQuarantineKind,
    LogicalInstanceResultSelectionId, LogicalInstanceResultTarget, LogicalInstanceResultValueError,
    LogicalInstanceResultWorkerId, LogicalInstanceTerminalOrdinal,
    LogicalServerCancellationTerminal, LogicalTerminalResultObject, LogicalWorkflowInstanceId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, ObjectKey, QuarantineLogicalInstanceResult,
    TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[test]
fn claim_next_requires_stable_non_nil_identity_and_bounded_interval() {
    assert!(LogicalInstanceResultSelectionId::from_uuid(Uuid::nil()).is_err());
    let selection =
        LogicalInstanceResultSelectionId::from_uuid(Uuid::from_u128(90)).expect("selection");
    let worker = LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(91)).expect("worker");
    let request = ClaimNextLogicalInstanceResult::new(
        selection,
        worker,
        UnixMillis::new(10),
        UnixMillis::new(20),
    )
    .expect("bounded selection");
    assert_eq!(request.selection_id(), selection);
    assert_eq!(request.owner(), worker);
    assert!(
        ClaimNextLogicalInstanceResult::new(
            selection,
            worker,
            UnixMillis::new(10),
            UnixMillis::new(10),
        )
        .is_err()
    );
}

#[test]
fn exact_current_blobs_map_coe_and_preserve_only_classified_outputs() {
    let fixture = fixture(JobConclusion::Failure, true, valid_outputs());
    let commit = CommitLogicalInstanceResult::new(
        &fixture.claimed,
        &fixture.result_bytes,
        &fixture.result,
        &fixture.job_ir_bytes,
        &fixture.envelope,
        UnixMillis::new(140),
    )
    .expect("exact current instance result");

    assert_eq!(commit.raw_conclusion(), JobConclusion::Failure);
    assert_eq!(commit.effective_conclusion(), JobConclusion::Success);
    assert!(commit.continue_on_error());
    assert_eq!(commit.secret_exposure(), JobSecretExposure::Secretless);
    assert_eq!(commit.outputs().len(), 3);
    assert_eq!(commit.outputs()[0].name(), "artifact");
    assert_eq!(commit.outputs()[0].public_value(), Some("bundle-42"));
    assert_eq!(commit.outputs()[1].name(), "masked");
    assert_eq!(
        commit.outputs()[1].sensitivity(),
        OutputSensitivity::SecretDerived
    );
    assert_eq!(commit.outputs()[1].public_value(), None);
    assert_eq!(commit.outputs()[2].name(), "secret");
    assert_eq!(commit.outputs()[2].public_value(), None);
    assert!(!format!("{:?}", commit.outputs()).contains("bundle-42"));
}

#[test]
fn readable_secret_results_preserve_individually_public_outputs() {
    let fixture = fixture_with_exposure(
        JobConclusion::Success,
        false,
        valid_outputs(),
        JobSecretExposure::ReadableSecret,
        JobSecretExposure::ReadableSecret,
    );
    let commit = CommitLogicalInstanceResult::new(
        &fixture.claimed,
        &fixture.result_bytes,
        &fixture.result,
        &fixture.job_ir_bytes,
        &fixture.envelope,
        UnixMillis::new(140),
    )
    .expect("value-classified readable-secret result");

    assert_eq!(commit.secret_exposure(), JobSecretExposure::ReadableSecret);
    assert_eq!(commit.outputs()[0].name(), "artifact");
    assert_eq!(commit.outputs()[0].sensitivity(), OutputSensitivity::Public);
    assert_eq!(commit.outputs()[0].public_value(), Some("bundle-42"));
}

#[test]
fn output_names_and_static_sensitivity_are_bound_to_decoded_job_ir() {
    let mut undeclared = valid_outputs();
    undeclared.insert(
        "other".to_owned(),
        JobResultOutput::public("value").expect("bounded public output"),
    );
    let undeclared_fixture = fixture(JobConclusion::Success, false, undeclared);
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &undeclared_fixture.claimed,
            &undeclared_fixture.result_bytes,
            &undeclared_fixture.result,
            &undeclared_fixture.job_ir_bytes,
            &undeclared_fixture.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::InvalidOutputSet)
    ));

    let mut downgraded = valid_outputs();
    downgraded.insert(
        "secret".to_owned(),
        JobResultOutput::public("must-not-persist").expect("bounded public output"),
    );
    let downgraded_fixture = fixture(JobConclusion::Success, false, downgraded);
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &downgraded_fixture.claimed,
            &downgraded_fixture.result_bytes,
            &downgraded_fixture.result,
            &downgraded_fixture.job_ir_bytes,
            &downgraded_fixture.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::InvalidOutputSet)
    ));
}

#[test]
fn object_identity_and_live_fence_fail_closed() {
    let fixture = fixture(JobConclusion::Success, false, valid_outputs());
    let mut changed_result = fixture.result_bytes.clone();
    changed_result[0] ^= 1;
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &fixture.claimed,
            &changed_result,
            &fixture.result,
            &fixture.job_ir_bytes,
            &fixture.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::ResultBlobMismatch)
    ));

    let mut changed_job_ir = fixture.job_ir_bytes.clone();
    changed_job_ir[0] ^= 1;
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &fixture.claimed,
            &fixture.result_bytes,
            &fixture.result,
            &changed_job_ir,
            &fixture.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::JobIrBlobMismatch)
    ));
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &fixture.claimed,
            &fixture.result_bytes,
            &fixture.result,
            &fixture.job_ir_bytes,
            &fixture.envelope,
            UnixMillis::new(200),
        ),
        Err(LogicalInstanceResultValueError::CommitOutsideClaim)
    ));
}

#[test]
fn terminal_exposure_cannot_escape_the_admitted_safety_boundary() {
    let outputs = BTreeMap::from([
        ("artifact".to_owned(), JobResultOutput::secret_derived()),
        ("masked".to_owned(), JobResultOutput::secret_derived()),
        ("secret".to_owned(), JobResultOutput::secret_derived()),
    ]);
    let fixture = fixture_with_exposure(
        JobConclusion::Success,
        false,
        outputs,
        JobSecretExposure::ReadableSecret,
        JobSecretExposure::Secretless,
    );
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &fixture.claimed,
            &fixture.result_bytes,
            &fixture.result,
            &fixture.job_ir_bytes,
            &fixture.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::SecretExposureDisagreesWithAdmission)
    ));

    let underreported = fixture_with_exposure(
        JobConclusion::Success,
        false,
        valid_outputs(),
        JobSecretExposure::Secretless,
        JobSecretExposure::ReadableSecret,
    );
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &underreported.claimed,
            &underreported.result_bytes,
            &underreported.result,
            &underreported.job_ir_bytes,
            &underreported.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::SecretExposureDisagreesWithAdmission)
    ));
}

#[test]
fn queued_server_cancellation_uses_job_ir_semantics_without_runner_evidence() {
    let fixture = fixture_with_exposure(
        JobConclusion::Cancelled,
        true,
        BTreeMap::from([
            ("artifact".to_owned(), JobResultOutput::secret_derived()),
            ("masked".to_owned(), JobResultOutput::secret_derived()),
            ("secret".to_owned(), JobResultOutput::secret_derived()),
        ]),
        JobSecretExposure::ReadableSecret,
        JobSecretExposure::ReadableSecret,
    );
    let runner_descriptor = fixture.claimed.descriptor();
    let operation_id = OperationId::new();
    let authority_digest = Sha256Digest::from_bytes([0x73; 32]);
    let descriptor = LogicalInstanceResultDescriptor::new_server_cancellation(
        runner_descriptor.target().clone(),
        runner_descriptor.run_id(),
        runner_descriptor.invocation_id(),
        runner_descriptor.logical_job_id(),
        runner_descriptor.instance_id(),
        runner_descriptor.job_id(),
        runner_descriptor.logical_key().clone(),
        runner_descriptor.matrix_index(),
        runner_descriptor.matrix_total(),
        runner_descriptor.matrix_digest(),
        runner_descriptor.terminal_ordinal(),
        LogicalServerCancellationTerminal::new(operation_id, authority_digest),
        runner_descriptor.job_ir().clone(),
        runner_descriptor.maximum_secret_exposure(),
        runner_descriptor.result_completed_at(),
        runner_descriptor.result_committed_at(),
    )
    .expect("server cancellation descriptor");
    let claim = LogicalInstanceResultClaimFence::new(
        descriptor.target().clone(),
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(81)).expect("worker"),
        LogicalInstanceResultGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(120),
        UnixMillis::new(200),
    )
    .expect("claim");
    let claimed =
        ClaimedLogicalInstanceResult::new(descriptor, claim, false).expect("claimed cancellation");

    assert!(claimed.descriptor().terminal_result().is_none());
    let cancellation = claimed
        .descriptor()
        .server_cancellation()
        .expect("server cancellation authority");
    assert_eq!(cancellation.operation_id(), operation_id);
    assert_eq!(cancellation.digest(), authority_digest);
    assert!(matches!(
        CommitLogicalInstanceResult::new(
            &claimed,
            &fixture.result_bytes,
            &fixture.result,
            &fixture.job_ir_bytes,
            &fixture.envelope,
            UnixMillis::new(140),
        ),
        Err(LogicalInstanceResultValueError::TerminalAuthorityMismatch)
    ));

    let commit = CommitLogicalInstanceResult::new_server_cancellation(
        &claimed,
        &fixture.job_ir_bytes,
        &fixture.envelope,
        UnixMillis::new(140),
    )
    .expect("server cancellation projection");
    assert_eq!(commit.raw_conclusion(), JobConclusion::Cancelled);
    assert_eq!(commit.effective_conclusion(), JobConclusion::Cancelled);
    assert!(commit.continue_on_error());
    assert_eq!(commit.secret_exposure(), JobSecretExposure::Secretless);
    assert!(commit.outputs().is_empty());
}

#[test]
fn quarantine_classification_preserves_the_exact_claimed_target() {
    let fixture = fixture(JobConclusion::Success, false, valid_outputs());
    let quarantine = QuarantineLogicalInstanceResult::new(
        &fixture.claimed,
        LogicalInstanceResultQuarantineKind::PayloadEvidence,
    );

    assert_eq!(quarantine.descriptor(), fixture.claimed.descriptor());
    assert_eq!(quarantine.claim(), fixture.claimed.claim());
    assert_eq!(
        quarantine.kind(),
        LogicalInstanceResultQuarantineKind::PayloadEvidence
    );
}

fn valid_outputs() -> BTreeMap<String, JobResultOutput> {
    BTreeMap::from([
        (
            "artifact".to_owned(),
            JobResultOutput::public("bundle-42").expect("bounded public output"),
        ),
        ("masked".to_owned(), JobResultOutput::secret_derived()),
        ("secret".to_owned(), JobResultOutput::secret_derived()),
    ])
}

struct Fixture {
    claimed: ClaimedLogicalInstanceResult,
    result: JobResult,
    result_bytes: Vec<u8>,
    envelope: JobIrEnvelope,
    job_ir_bytes: Vec<u8>,
}

fn fixture(
    conclusion: JobConclusion,
    continue_on_error: bool,
    outputs: BTreeMap<String, JobResultOutput>,
) -> Fixture {
    fixture_with_exposure(
        conclusion,
        continue_on_error,
        outputs,
        JobSecretExposure::Secretless,
        JobSecretExposure::Secretless,
    )
}

#[allow(clippy::too_many_lines)] // One fixture binds both complete current object graphs.
fn fixture_with_exposure(
    conclusion: JobConclusion,
    continue_on_error: bool,
    outputs: BTreeMap<String, JobResultOutput>,
    secret_exposure: JobSecretExposure,
    maximum_secret_exposure: JobSecretExposure,
) -> Fixture {
    let tenant = TenantScope::from_authenticated_tenant_id("result-test").expect("tenant");
    let run_id = RunId::from_uuid(Uuid::from_u128(1));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation");
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("logical job");
    let instance_id = LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(4)).expect("instance");
    let job_id = automata_ci_core::JobId::from_uuid(Uuid::from_u128(5));
    let attempt_id = AttemptId::from_uuid(Uuid::from_u128(6));
    let target = LogicalInstanceResultTarget::new(tenant, attempt_id).expect("target");
    let logical_key = WorkflowJobKey::new("build").expect("logical key");
    let identity = JobInstanceIdentity::new(
        logical_key.as_str(),
        0,
        1,
        Sha256Digest::from_bytes([0x33; 32]),
    )
    .expect("instance identity");
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
    let definitions = [
        ("artifact", OutputSensitivity::Public),
        ("masked", OutputSensitivity::Public),
        ("secret", OutputSensitivity::SecretDerived),
    ]
    .into_iter()
    .map(|(name, sensitivity)| {
        JobOutputDefinition::new(
            name,
            ValueTemplate::literal("value").expect("template"),
            sensitivity,
        )
        .expect("output definition")
    });
    let job = JobIr::new(
        job_id,
        run_id,
        "Build",
        RunnerRequirements::default(),
        identity,
        continue_on_error,
        vec![step],
    )
    .with_output_definitions(definitions);
    let execution = JobExecutionContext::new(
        "CI",
        "refs/heads/main",
        "/srv/work/repository",
        JobContentReference::new(
            "events/push.pb",
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
    );
    let envelope = JobIrEnvelope::new(
        WorkflowId::from_uuid(Uuid::from_u128(7)),
        JobSource::new(
            "github",
            "example/project",
            automata_ci_core::GitObjectId::from_provider_hex(
                "0123456789abcdef0123456789abcdef01234567",
            )
            .expect("revision"),
            ".ci/workflows/ci.yml",
            "push",
        ),
        execution,
        job,
    );
    envelope.validate().expect("current JobIR");
    let job_ir_bytes = serde_json::to_vec(&envelope).expect("encoded JobIR");
    let job_ir_object = LogicalActivationObject::job_ir(
        Sha256Digest::from_bytes(Sha256::digest(&job_ir_bytes).into()),
        ObjectKey::new("job-ir/build.pb").expect("JobIR key"),
        u64::try_from(job_ir_bytes.len()).expect("JobIR size"),
    )
    .expect("JobIR object");

    let result = JobResult::new(
        attempt_id,
        conclusion,
        secret_exposure,
        UnixMillis::new(100),
    )
    .with_outputs(outputs);
    result.validate().expect("current terminal result");
    let result_bytes = serde_json::to_vec(&result).expect("encoded result");
    let terminal_result = LogicalTerminalResultObject::new(
        Sha256Digest::from_bytes(Sha256::digest(&result_bytes).into()),
        ObjectKey::new("results/build.json").expect("result key"),
        u64::try_from(result_bytes.len()).expect("result size"),
        automata_ci_core::CORE_SCHEMA_VERSION,
    )
    .expect("terminal result object");
    let descriptor = LogicalInstanceResultDescriptor::new(
        target.clone(),
        run_id,
        invocation_id,
        logical_job_id,
        instance_id,
        job_id,
        logical_key,
        0,
        1,
        Sha256Digest::from_bytes([0x33; 32]),
        LogicalInstanceTerminalOrdinal::new(1).expect("terminal ordinal"),
        terminal_result,
        job_ir_object,
        maximum_secret_exposure,
        conclusion,
        UnixMillis::new(100),
        UnixMillis::new(110),
    )
    .expect("descriptor");
    let claim = LogicalInstanceResultClaimFence::new(
        target,
        LogicalInstanceResultWorkerId::from_uuid(Uuid::from_u128(8)).expect("worker"),
        LogicalInstanceResultGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(120),
        UnixMillis::new(200),
    )
    .expect("claim");
    let claimed =
        ClaimedLogicalInstanceResult::new(descriptor, claim, false).expect("claimed descriptor");
    Fixture {
        claimed,
        result,
        result_bytes,
        envelope,
        job_ir_bytes,
    }
}
