use automata_ci_core::{
    JobConclusion, OutputSensitivity, RunId, RunIdAlias, Sha256Digest, UnixMillis, WorkflowId,
    WorkflowJobKey, WorkflowOutputKey,
};
use automata_ci_store::{
    AdmissionObject, BindLogicalActivationPreparation, ClaimedLogicalActivationPreparation,
    ConsumedLogicalJobOrchestrationAuthority, ConsumedSelectedLogicalJobOrchestration,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE,
    LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE, LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    LogicalActivationAggregateStatus, LogicalActivationBaseContextKind,
    LogicalActivationExecutionContext, LogicalActivationPreparationClaimFence,
    LogicalActivationPreparationDescriptor, LogicalActivationPreparationGeneration,
    LogicalActivationPreparationTarget, LogicalActivationPreparationValueError,
    LogicalActivationPreparationWorkspace, LogicalActivationPrerequisiteEvidence,
    LogicalActivationPrerequisiteOutput, LogicalActivationWorkerId,
    LogicalJobOrchestrationAuthorityKind, LogicalWorkSelectionGeneration, LogicalWorkSelectionId,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS,
    ObjectKey, PinnedWorkflowRuntimePolicy, RenewLogicalActivationPreparation, RepositoryId,
    SelectedLogicalJobOrchestration, TenantScope, WorkflowRuntimePolicy, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyRevision,
};
use uuid::Uuid;

const RUNTIME_POLICY: &[u8] = br#"{
  "workspace":{"derivation":1,"root":"/__w","schema":1},
  "mappings":[{
    "container_features":["automata.core/job-containers@v1"],
    "architecture":"x86_64","operating_system":"linux",
    "environment_profile":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111","id":"automata.example/ubuntu-24-04"},
    "selector":"Ubuntu-24.04"
  }],"permissions":{"provider_default":{"contents":"read"},"read_all":{"contents":"read"},"write_all":{"contents":"write"}},"resources":{"defaults":{"requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"limits":{"cpu_millis":1000,"memory_bytes":1073741824,"ephemeral_disk_bytes":0,"gpu_count":0}},"minimum_requests":{"cpu_millis":100,"memory_bytes":268435456,"ephemeral_disk_bytes":0,"gpu_count":0},"maximum_limits":{"cpu_millis":4000,"memory_bytes":8589934592,"ephemeral_disk_bytes":0,"gpu_count":0}},"schema":1
}"#;

fn object(key: &str, digest: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        128,
        media_type,
    )
    .expect("object descriptor")
}

fn target(logical_job_id: u128) -> LogicalActivationPreparationTarget {
    LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(logical_job_id)).expect("job"),
    )
    .expect("target")
}

fn runtime_policy(
    target: &LogicalActivationPreparationTarget,
) -> (AdmissionObject, PinnedWorkflowRuntimePolicy) {
    let policy = WorkflowRuntimePolicy::decode_configuration(RUNTIME_POLICY).expect("policy");
    let canonical = policy.canonical_bytes().expect("canonical policy");
    let object_digest = policy.canonical_digest();
    let runner_policy = AdmissionObject::new(
        object_digest,
        ObjectKey::new(format!("github/runner-policy/v1/{object_digest}.json"))
            .expect("runner-policy key"),
        u64::try_from(canonical.len()).expect("runner-policy size"),
        GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
    )
    .expect("runner-policy object");
    let pin = WorkflowRuntimePolicyPin::new(
        target.tenant().clone(),
        RepositoryId::from_uuid(Uuid::from_u128(5)),
        WorkflowRuntimePolicyRevision::new(1).expect("policy revision"),
        policy.digest(),
    );
    let pinned = PinnedWorkflowRuntimePolicy::new(target.run_id(), pin, policy)
        .expect("pinned runtime policy");
    (runner_policy, pinned)
}

fn execution() -> LogicalActivationExecutionContext {
    LogicalActivationExecutionContext::new(
        WorkflowId::from_uuid(Uuid::from_u128(4)),
        "Checks".to_owned(),
        "refs/heads/main".to_owned(),
        "push".to_owned(),
        Some("octocat".to_owned()),
        RunIdAlias::new(11).expect("run ID alias"),
        7,
        1,
    )
    .expect("execution")
}

fn prerequisite(
    id: u128,
    key: &str,
    order: u16,
    conclusion: JobConclusion,
    closure: (bool, bool, bool),
    output: LogicalActivationPrerequisiteOutput,
) -> LogicalActivationPrerequisiteEvidence {
    LogicalActivationPrerequisiteEvidence::new(
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(id)).expect("prerequisite"),
        WorkflowJobKey::new(key).expect("key"),
        order,
        Sha256Digest::from_bytes([u8::try_from(id).unwrap_or(1); 32]),
        Sha256Digest::from_bytes([11; 32]),
        Sha256Digest::from_bytes([12; 32]),
        conclusion,
        closure.0,
        closure.1,
        closure.2,
        vec![output],
        UnixMillis::new(20 + i64::from(order)),
    )
    .expect("prerequisite evidence")
}

fn descriptor(
    logical_job_id: u128,
    prerequisites: Vec<LogicalActivationPrerequisiteEvidence>,
) -> LogicalActivationPreparationDescriptor {
    let target = target(logical_job_id);
    let (runner_policy, runtime_policy) = runtime_policy(&target);
    LogicalActivationPreparationDescriptor::new(
        target,
        WorkflowJobKey::new("deploy").expect("key"),
        3,
        execution(),
        automata_ci_core::JobAuthorityProfile::Standard,
        runner_policy,
        runtime_policy,
        object(
            "plans/current.json",
            21,
            LOGICAL_ACTIVATION_PREPARATION_PLAN_MEDIA_TYPE,
        ),
        object(
            "events/current.json",
            22,
            LOGICAL_ACTIVATION_PREPARATION_EVENT_MEDIA_TYPE,
        ),
        LogicalActivationBaseContextKind::Admission,
        object(
            "contexts/base.pb",
            23,
            LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
        ),
        prerequisites,
        UnixMillis::new(10),
    )
    .expect("descriptor")
}

#[test]
fn aggregate_status_uses_transitive_precedence_and_secret_outputs_are_value_free() {
    let public = LogicalActivationPrerequisiteOutput::new(
        WorkflowOutputKey::new("endpoint").expect("output"),
        OutputSensitivity::Public,
        Some(String::new()),
    )
    .expect("public output");
    let secret = LogicalActivationPrerequisiteOutput::new(
        WorkflowOutputKey::new("token").expect("output"),
        OutputSensitivity::SecretDerived,
        None,
    )
    .expect("secret marker");
    let descriptor = descriptor(
        3,
        vec![
            prerequisite(
                10,
                "build",
                0,
                JobConclusion::Success,
                (false, true, false),
                public,
            ),
            prerequisite(
                11,
                "test",
                1,
                JobConclusion::Success,
                (true, false, false),
                secret,
            ),
        ],
    );
    assert_eq!(
        descriptor.status(),
        LogicalActivationAggregateStatus::Failure
    );
    assert_eq!(
        descriptor.prerequisites()[1].outputs()[0].public_value(),
        None
    );
    assert!(!format!("{:?}", descriptor.prerequisites()[1].outputs()[0]).contains("token-value"));
}

#[test]
fn workspace_is_descriptor_bound_and_cannot_change_under_the_same_fence() {
    let first = descriptor(3, Vec::new());
    let changed = descriptor(30, Vec::new());
    assert_ne!(first.workspace(), changed.workspace());
    assert_ne!(first.descriptor_digest(), changed.descriptor_digest());
    let fence = LogicalActivationPreparationClaimFence::new_for_selection(
        first.target().clone(),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(20)).expect("worker"),
        LogicalActivationPreparationGeneration::new(1).expect("generation"),
        first.descriptor_digest(),
        UnixMillis::new(30),
        UnixMillis::new(100),
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(21)).expect("selection"),
    )
    .expect("fence");
    let base = first.base_context().clone();
    let needs = object(
        "contexts/needs.pb",
        32,
        LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    );
    assert!(matches!(
        BindLogicalActivationPreparation::new(changed, fence, base, needs, UnixMillis::new(40),),
        Err(LogicalActivationPreparationValueError::ClaimDescriptorMismatch)
    ));
}

#[test]
fn binding_accepts_only_the_exact_admission_base_context() {
    let descriptor = descriptor(3, Vec::new());
    let fence = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(20)).expect("worker"),
        LogicalActivationPreparationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(30),
        UnixMillis::new(100),
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(21)).expect("selection"),
    )
    .expect("fence");
    let prerequisite_context = object(
        "contexts/needs.pb",
        32,
        LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    );
    let changed_base = object(
        "contexts/changed-base.pb",
        33,
        LOGICAL_ACTIVATION_RUNTIME_CONTEXT_MEDIA_TYPE,
    );

    assert!(matches!(
        BindLogicalActivationPreparation::new(
            descriptor.clone(),
            fence.clone(),
            changed_base,
            prerequisite_context.clone(),
            UnixMillis::new(40),
        ),
        Err(LogicalActivationPreparationValueError::InvalidContextObject)
    ));
    let binding = BindLogicalActivationPreparation::new(
        descriptor.clone(),
        fence,
        descriptor.base_context().clone(),
        prerequisite_context,
        UnixMillis::new(40),
    )
    .expect("exact admission context binding");
    assert_eq!(binding.base_context(), descriptor.base_context());
}

#[test]
fn workspace_validation_rejects_relative_traversal_and_padding() {
    for value in [
        "relative/path",
        "/work/../escape",
        "/work/job ",
        "C:\\work\\..\\escape",
        "C:\\work/../escape",
    ] {
        assert!(LogicalActivationPreparationWorkspace::new(value).is_err());
    }
    assert!(LogicalActivationPreparationWorkspace::new("C:\\work\\job").is_ok());
}

#[test]
fn renewal_duration_has_a_distinct_achievable_handoff_budget() {
    let descriptor = descriptor(3, Vec::new());
    let fence = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(20)).expect("worker"),
        LogicalActivationPreparationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(30),
        UnixMillis::new(10_000),
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(21)).expect("selection"),
    )
    .expect("fence");
    assert!(
        RenewLogicalActivationPreparation::new(
            fence.clone(),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS,
        )
        .is_ok()
    );
    assert!(matches!(
        RenewLogicalActivationPreparation::new(fence, MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS - 1,),
        Err(LogicalActivationPreparationValueError::InvalidRenewalInterval)
    ));
}

#[test]
fn external_repository_fake_can_rehydrate_a_consumed_preparation() {
    let descriptor = descriptor(3, Vec::new());
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(21)).expect("selection");
    let owner = LogicalActivationWorkerId::from_uuid(Uuid::from_u128(20)).expect("worker");
    let claimed_at = UnixMillis::new(30);
    let expires_at = UnixMillis::new(5_000);
    let selected = SelectedLogicalJobOrchestration::new(
        selection_id,
        descriptor.target().clone(),
        owner,
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        LogicalJobOrchestrationAuthorityKind::Preparation,
        descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
    )
    .expect("selected preparation");
    let fence = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        owner,
        LogicalActivationPreparationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
        selection_id,
    )
    .expect("selection-origin fence");
    let claimed = ClaimedLogicalActivationPreparation::new(descriptor.clone(), fence, false)
        .expect("claimed preparation");
    let consumed = ConsumedSelectedLogicalJobOrchestration::new(
        selected.clone(),
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed),
        UnixMillis::new(100),
    )
    .expect("consumed preparation");
    assert_eq!(consumed.selected().selection_id(), selection_id);

    let unproved_later_fence = LogicalActivationPreparationClaimFence::new_for_selection(
        descriptor.target().clone(),
        owner,
        LogicalActivationPreparationGeneration::new(2).expect("later generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(40),
        UnixMillis::new(6_000),
        selection_id,
    )
    .expect("synthetic later fence");
    let unproved_later =
        ClaimedLogicalActivationPreparation::new(descriptor, unproved_later_fence, false)
            .expect("synthetic later preparation");
    assert!(
        ConsumedSelectedLogicalJobOrchestration::new(
            selected,
            ConsumedLogicalJobOrchestrationAuthority::Preparation(unproved_later),
            UnixMillis::new(100),
        )
        .is_err()
    );
}
