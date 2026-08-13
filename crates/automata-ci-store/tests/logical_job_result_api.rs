use automata_ci_core::{
    CompiledValueTemplate, Located, LogicalJobKind, LogicalJobOutputDefinition,
    LogicalJobOutputSource, LogicalJobTemplate, LogicalOutputMergePolicy, LogicalRunStepTemplate,
    LogicalRunnerTemplate, LogicalStepKind, LogicalStepTemplate, MatrixAxis, MatrixAxisValues,
    MatrixPatchSet, MatrixTemplate, MatrixValue, MatrixValueTemplate, OutputSensitivity,
    PlanSourceLocation, PlanSourceOrigin, PlanSourceSpan, RunId, Sha256Digest, StepJobTemplate,
    UnixMillis, WorkflowEventProvenance, WorkflowJobKey, WorkflowOutputKey, WorkflowPlan,
    WorkflowSourceProvenance, WorkflowStepKey, WorkflowStrategyTemplate,
};
use automata_ci_store::{
    AdmissionObject, ClaimNextLogicalJobResult, ClaimedLogicalJobResult, CommitLogicalJobResult,
    LogicalInstanceTerminalOrdinal, LogicalJobInstanceOutput, LogicalJobInstanceResultEvidence,
    LogicalJobPrerequisiteEvidence, LogicalJobResultClaimFence, LogicalJobResultDescriptor,
    LogicalJobResultGeneration, LogicalJobResultSelectionId, LogicalJobResultTarget,
    LogicalJobResultValueError, LogicalJobResultWorkerId, LogicalWorkflowInstanceId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, ObjectKey, TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[test]
fn claim_next_requires_stable_non_nil_identity_and_bounded_interval() {
    assert!(LogicalJobResultSelectionId::from_uuid(Uuid::nil()).is_err());
    let selection = LogicalJobResultSelectionId::from_uuid(Uuid::from_u128(90)).expect("selection");
    let worker = LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(91)).expect("worker");
    let request =
        ClaimNextLogicalJobResult::new(selection, worker, UnixMillis::new(10), UnixMillis::new(20))
            .expect("bounded selection");
    assert_eq!(request.selection_id(), selection);
    assert_eq!(request.owner(), worker);
    assert!(ClaimNextLogicalJobResult::new(
        selection,
        worker,
        UnixMillis::new(10),
        UnixMillis::new(10),
    )
    .is_err());
}

#[test]
fn last_success_uses_raw_success_then_server_ordinal_and_matrix_tie_break() {
    let plan = matrix_plan(LogicalOutputMergePolicy::LastSuccessfulCompletion, 3);
    let instances = vec![
        instance(0, 9, automata_ci_core::JobConclusion::Success, "older"),
        instance(
            1,
            10,
            automata_ci_core::JobConclusion::Success,
            "same-ordinal-lower-index",
        ),
        instance(
            2,
            10,
            automata_ci_core::JobConclusion::Success,
            "same-ordinal-higher-index",
        ),
    ];
    let prerequisite = LogicalJobPrerequisiteEvidence::new(
        logical_job_id(80),
        WorkflowJobKey::new("prepare").expect("prerequisite key"),
        0,
        digest(0x80),
        digest(0x81),
        automata_ci_core::JobConclusion::Success,
        true,
        false,
        true,
        UnixMillis::new(120),
    )
    .expect("prerequisite evidence");
    let fixture = fixture(plan, instances, vec![prerequisite], true);
    let commit = CommitLogicalJobResult::new(
        &fixture.claimed,
        &fixture.plan_bytes,
        &fixture.plan,
        UnixMillis::new(140),
    )
    .expect("logical aggregate");

    assert_eq!(
        commit.effective_conclusion(),
        automata_ci_core::JobConclusion::Success
    );
    assert!(commit.closure_has_failure());
    assert!(commit.closure_has_skipped());
    assert!(!commit.closure_has_cancelled());
    assert_eq!(commit.outputs().len(), 3);
    assert_eq!(commit.outputs()[0].name().as_str(), "artifact");
    assert_eq!(
        commit.outputs()[0].public_value(),
        Some("same-ordinal-higher-index")
    );
    assert_eq!(commit.outputs()[1].name().as_str(), "missing");
    assert_eq!(commit.outputs()[1].public_value(), Some(""));
    assert_eq!(commit.outputs()[2].name().as_str(), "private");
    assert_eq!(
        commit.outputs()[2].sensitivity(),
        OutputSensitivity::SecretDerived
    );
    assert_eq!(commit.outputs()[2].public_value(), None);
    assert!(!format!("{:?}", commit.outputs()).contains("higher-index"));
}

#[test]
fn last_success_ignores_continue_on_error_effective_success() {
    let plan = matrix_plan(LogicalOutputMergePolicy::LastSuccessfulCompletion, 2);
    let mut failed = instance(
        1,
        100,
        automata_ci_core::JobConclusion::Failure,
        "must-not-win",
    );
    failed = LogicalJobInstanceResultEvidence::new(
        failed.instance_id(),
        failed.matrix_index(),
        failed.terminal_ordinal(),
        failed.descriptor_digest(),
        failed.commit_digest(),
        automata_ci_core::JobConclusion::Failure,
        automata_ci_core::JobConclusion::Success,
        failed.outputs().to_vec(),
        failed.finalized_at(),
    )
    .expect("continue-on-error evidence");
    let fixture = fixture(
        plan,
        vec![
            instance(
                0,
                1,
                automata_ci_core::JobConclusion::Success,
                "raw-success",
            ),
            failed,
        ],
        Vec::new(),
        true,
    );
    let commit = CommitLogicalJobResult::new(
        &fixture.claimed,
        &fixture.plan_bytes,
        &fixture.plan,
        UnixMillis::new(140),
    )
    .expect("logical aggregate");
    assert_eq!(commit.outputs()[0].public_value(), Some("raw-success"));
}

#[test]
fn single_instance_merge_rejects_a_matrix_and_noncanonical_plan_fails_closed() {
    let plan = matrix_plan(LogicalOutputMergePolicy::SingleInstance, 2);
    let fixture = fixture(
        plan,
        vec![
            instance(0, 1, automata_ci_core::JobConclusion::Success, "first"),
            instance(1, 2, automata_ci_core::JobConclusion::Success, "second"),
        ],
        Vec::new(),
        true,
    );
    assert!(matches!(
        CommitLogicalJobResult::new(
            &fixture.claimed,
            &fixture.plan_bytes,
            &fixture.plan,
            UnixMillis::new(140),
        ),
        Err(LogicalJobResultValueError::InvalidOutputMerge)
    ));

    let mut changed = fixture.plan_bytes.clone();
    changed.push(b' ');
    assert!(matches!(
        CommitLogicalJobResult::new(
            &fixture.claimed,
            &changed,
            &fixture.plan,
            UnixMillis::new(140),
        ),
        Err(LogicalJobResultValueError::PlanBlobMismatch)
    ));
}

#[test]
fn zero_instance_result_is_skipped_and_publishes_every_declared_output() {
    let plan = matrix_plan(LogicalOutputMergePolicy::LastSuccessfulCompletion, 2);
    let fixture = fixture(plan, Vec::new(), Vec::new(), false);
    let commit = CommitLogicalJobResult::new(
        &fixture.claimed,
        &fixture.plan_bytes,
        &fixture.plan,
        UnixMillis::new(140),
    )
    .expect("zero-instance aggregate");
    assert_eq!(
        commit.effective_conclusion(),
        automata_ci_core::JobConclusion::Skipped
    );
    assert!(commit.closure_has_skipped());
    assert_eq!(commit.outputs().len(), 3);
    assert_eq!(commit.outputs()[0].public_value(), Some(""));
    assert_eq!(commit.outputs()[1].public_value(), Some(""));
    assert_eq!(commit.outputs()[2].public_value(), None);
}

#[test]
fn commit_rejects_prerequisites_that_disagree_with_the_exact_plan() {
    let plan = matrix_plan(LogicalOutputMergePolicy::LastSuccessfulCompletion, 1);
    let prerequisite = LogicalJobPrerequisiteEvidence::new(
        logical_job_id(81),
        WorkflowJobKey::new("unrelated").expect("prerequisite key"),
        0,
        digest(0x82),
        digest(0x83),
        automata_ci_core::JobConclusion::Success,
        false,
        false,
        false,
        UnixMillis::new(120),
    )
    .expect("prerequisite evidence");
    let fixture = fixture(
        plan,
        vec![instance(
            0,
            1,
            automata_ci_core::JobConclusion::Success,
            "value",
        )],
        vec![prerequisite],
        true,
    );

    assert!(matches!(
        CommitLogicalJobResult::new(
            &fixture.claimed,
            &fixture.plan_bytes,
            &fixture.plan,
            UnixMillis::new(140),
        ),
        Err(LogicalJobResultValueError::PlanJobMismatch)
    ));
}

struct Fixture {
    plan: WorkflowPlan,
    plan_bytes: Vec<u8>,
    claimed: ClaimedLogicalJobResult,
}

fn fixture(
    plan: WorkflowPlan,
    instances: Vec<LogicalJobInstanceResultEvidence>,
    mut prerequisites: Vec<LogicalJobPrerequisiteEvidence>,
    condition_matched: bool,
) -> Fixture {
    if prerequisites.is_empty() {
        prerequisites.push(
            LogicalJobPrerequisiteEvidence::new(
                logical_job_id(80),
                WorkflowJobKey::new("prepare").expect("prerequisite key"),
                0,
                digest(0x80),
                digest(0x81),
                automata_ci_core::JobConclusion::Success,
                false,
                false,
                false,
                UnixMillis::new(120),
            )
            .expect("prerequisite evidence"),
        );
    }
    let plan_bytes = serde_json::to_vec(&plan).expect("canonical plan");
    let target = LogicalJobResultTarget::new(
        TenantScope::from_authenticated_tenant_id("logical-result-test").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
        logical_job_id(3),
    )
    .expect("target");
    let instance_count = u32::try_from(instances.len()).expect("bounded instances");
    let descriptor = LogicalJobResultDescriptor::new(
        target.clone(),
        WorkflowJobKey::new("build").expect("job key"),
        1,
        AdmissionObject::new(
            Sha256Digest::from_bytes(Sha256::digest(&plan_bytes).into()),
            ObjectKey::new("plans/workflow-v1.json").expect("plan key"),
            u64::try_from(plan_bytes.len()).expect("plan size"),
            "application/vnd.automata.workflow-plan+json",
        )
        .expect("plan object"),
        digest(0x55),
        condition_matched,
        instance_count,
        instances,
        prerequisites,
        UnixMillis::new(100),
    )
    .expect("descriptor");
    let claim = LogicalJobResultClaimFence::new(
        target,
        LogicalJobResultWorkerId::from_uuid(Uuid::from_u128(4)).expect("worker"),
        LogicalJobResultGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(130),
        UnixMillis::new(200),
    )
    .expect("claim");
    let claimed = ClaimedLogicalJobResult::new(descriptor, claim, false).expect("claimed result");
    Fixture {
        plan,
        plan_bytes,
        claimed,
    }
}

fn instance(
    matrix_index: u32,
    ordinal: u64,
    raw: automata_ci_core::JobConclusion,
    value: &str,
) -> LogicalJobInstanceResultEvidence {
    LogicalJobInstanceResultEvidence::new(
        LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(100 + u128::from(matrix_index)))
            .expect("instance"),
        matrix_index,
        LogicalInstanceTerminalOrdinal::new(ordinal).expect("terminal ordinal"),
        digest(u8::try_from(10 + matrix_index).expect("digest byte")),
        digest(u8::try_from(30 + matrix_index).expect("digest byte")),
        raw,
        raw,
        vec![
            LogicalJobInstanceOutput::new(
                WorkflowOutputKey::new("artifact").expect("output key"),
                OutputSensitivity::Public,
                Some(value.to_owned()),
            )
            .expect("public output"),
            LogicalJobInstanceOutput::new(
                WorkflowOutputKey::new("private").expect("output key"),
                OutputSensitivity::SecretDerived,
                None,
            )
            .expect("secret output"),
        ],
        UnixMillis::new(110 + i64::from(matrix_index)),
    )
    .expect("instance evidence")
}

fn matrix_plan(merge: LogicalOutputMergePolicy, matrix_size: usize) -> WorkflowPlan {
    let runner = LogicalRunnerTemplate::new(
        None,
        vec![located(CompiledValueTemplate::Literal("linux".to_owned()))],
        span(),
    );
    let step = LogicalStepTemplate::builder(
        located(WorkflowStepKey::new("position/00000000").expect("step key")),
        LogicalStepKind::Run(Box::new(LogicalRunStepTemplate::new(
            located(CompiledValueTemplate::Literal("true".to_owned())),
            None,
            None,
        ))),
        span(),
    )
    .build()
    .expect("step");
    let matrix = MatrixTemplate::new(
        vec![MatrixAxis::new(
            located("shard".to_owned()),
            MatrixAxisValues::Static(
                (0..matrix_size)
                    .map(|index| {
                        located(MatrixValueTemplate::Literal(MatrixValue::Number(
                            index.to_string(),
                        )))
                    })
                    .collect(),
            ),
            span(),
        )],
        MatrixPatchSet::Static(Vec::new()),
        MatrixPatchSet::Static(Vec::new()),
        span(),
    );
    let strategy = WorkflowStrategyTemplate::new(None, None, matrix, 8, span());
    let outputs = [
        ("artifact", merge, OutputSensitivity::Public),
        ("missing", merge, OutputSensitivity::Public),
        ("private", merge, OutputSensitivity::SecretDerived),
    ]
    .into_iter()
    .map(|(name, merge, sensitivity)| {
        LogicalJobOutputDefinition::new(
            located(WorkflowOutputKey::new(name).expect("output key")),
            LogicalJobOutputSource::Template(located(CompiledValueTemplate::Literal(
                "value".to_owned(),
            ))),
            merge,
            sensitivity,
            span(),
        )
    })
    .collect();
    let prepare = LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("prepare").expect("job key")),
        0,
        LogicalJobKind::Steps(StepJobTemplate::new(
            runner.clone(),
            vec![step.clone()],
            span(),
        )),
        span(),
    )
    .build()
    .expect("prepare job");
    let build = LogicalJobTemplate::builder(
        located(WorkflowJobKey::new("build").expect("job key")),
        1,
        LogicalJobKind::Steps(StepJobTemplate::new(runner, vec![step], span())),
        span(),
    )
    .needs(vec![located(
        WorkflowJobKey::new("prepare").expect("need key"),
    )])
    .strategy(Some(strategy))
    .outputs(outputs)
    .build()
    .expect("build job");
    WorkflowPlan::logical_builder(
        WorkflowSourceProvenance::new(
            "github",
            "logical-result.yml",
            PlanSourceOrigin::Memory {
                name: "logical-result.yml".to_owned(),
            },
        ),
        WorkflowEventProvenance::new("github", "workflow_dispatch"),
        vec![prepare, build],
        span(),
    )
    .build()
    .expect("workflow plan")
}

fn logical_job_id(value: u128) -> LogicalWorkflowJobId {
    LogicalWorkflowJobId::from_uuid(Uuid::from_u128(value)).expect("logical job ID")
}

fn digest(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
}

fn span() -> PlanSourceSpan {
    PlanSourceSpan::new(
        "logical-result.yml",
        PlanSourceLocation::new(0, 1, 1).expect("location"),
        PlanSourceLocation::new(1, 1, 2).expect("location"),
    )
    .expect("span")
}

fn located<T>(value: T) -> Located<T> {
    Located::new(value, span())
}
