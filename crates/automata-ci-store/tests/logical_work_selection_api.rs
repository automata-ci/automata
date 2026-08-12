use automata_ci_core::{
    JobAuthorityProfile, RunId, RunIdAlias, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AdmissionObject, ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimedLogicalInstanceMaterialization, ClaimedLogicalJobActivation,
    ConsumeSelectedLogicalInstanceMaterialization, ConsumeSelectedLogicalJobOrchestration,
    ConsumedLogicalJobOrchestrationAuthority, ConsumedSelectedLogicalInstanceMaterialization,
    ConsumedSelectedLogicalJobOrchestration, LogicalActivationClaimFence,
    LogicalActivationExecutionContext, LogicalActivationGeneration, LogicalActivationObject,
    LogicalActivationPreparationTarget, LogicalActivationWorkerId,
    LogicalInstanceMaterializationDescriptor, LogicalInstanceMaterializationTarget,
    LogicalJobOrchestrationAuthorityKind, LogicalMaterializationClaimFence,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkQuarantineKind,
    LogicalWorkSelectionGeneration, LogicalWorkSelectionId, LogicalWorkSelectionRepository,
    LogicalWorkSelectionValueError, LogicalWorkflowInstanceId, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, LogicalWorkflowJobKind, MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS,
    MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS, ObjectKey, QuarantineLogicalInstanceMaterialization,
    QuarantineLogicalJobOrchestration, RepositoryId, SelectedLogicalInstanceMaterialization,
    SelectedLogicalJobOrchestration, TenantScope, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyRevision,
};
use uuid::Uuid;

fn runtime_policy(tenant: &TenantScope) -> WorkflowRuntimePolicyPin {
    WorkflowRuntimePolicyPin::new(
        tenant.clone(),
        RepositoryId::from_uuid(Uuid::from_u128(6)),
        WorkflowRuntimePolicyRevision::new(1).expect("runtime-policy revision"),
        Sha256Digest::from_bytes([0x11; 32]),
    )
}

fn object(key: &str, digest: u8) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(key).expect("object key"),
        128,
        "application/vnd.automata.test+json",
    )
    .expect("admission object")
}

fn execution() -> LogicalActivationExecutionContext {
    LogicalActivationExecutionContext::new(
        WorkflowId::from_uuid(Uuid::from_u128(7)),
        "Checks".to_owned(),
        "refs/heads/main".to_owned(),
        Some("octocat".to_owned()),
        RunIdAlias::new(11).expect("run ID alias"),
        1,
        1,
    )
    .expect("execution context")
}

#[test]
fn request_minimum_is_strictly_larger_than_the_handoff_budget() {
    const {
        assert!(
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS > MIN_LOGICAL_WORK_SELECTION_HANDOFF_MILLIS
        );
    }
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(1)).expect("selection");
    let activation_owner =
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(2)).expect("activation owner");
    let materialization_owner = LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(3))
        .expect("materialization owner");

    assert!(
        ClaimNextLogicalJobOrchestration::new(
            selection_id,
            activation_owner,
            UnixMillis::new(10),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
        )
        .is_ok()
    );
    assert!(
        ClaimNextLogicalInstanceMaterialization::new(
            selection_id,
            materialization_owner,
            UnixMillis::new(10),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
        )
        .is_ok()
    );
    assert!(matches!(
        ClaimNextLogicalJobOrchestration::new(
            selection_id,
            activation_owner,
            UnixMillis::new(10),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS - 1,
        ),
        Err(LogicalWorkSelectionValueError::InvalidRequest)
    ));
    assert!(matches!(
        ClaimNextLogicalInstanceMaterialization::new(
            selection_id,
            materialization_owner,
            UnixMillis::new(10),
            MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS - 1,
        ),
        Err(LogicalWorkSelectionValueError::InvalidRequest)
    ));
}

#[test]
fn selector_ids_and_observations_reject_reserved_or_negative_values() {
    assert!(matches!(
        LogicalWorkSelectionId::from_uuid(Uuid::nil()),
        Err(LogicalWorkSelectionValueError::NilSelectionId)
    ));
    let result = ClaimNextLogicalJobOrchestration::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(1)).expect("selection"),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(2)).expect("owner"),
        UnixMillis::new(-1),
        MIN_LOGICAL_WORK_SELECTION_REQUEST_MILLIS,
    );
    assert!(matches!(
        result,
        Err(LogicalWorkSelectionValueError::InvalidRequest)
    ));
}

#[test]
fn public_orchestration_values_accept_only_exact_base_authority() {
    let tenant = TenantScope::from_authenticated_tenant_id("selection-api").expect("tenant");
    let run_id = RunId::from_uuid(Uuid::from_u128(8));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(9)).expect("invocation");
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(10)).expect("logical job");
    let target = LogicalActivationPreparationTarget::new(
        tenant.clone(),
        run_id,
        invocation_id,
        logical_job_id,
    )
    .expect("target");
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(11)).expect("selection");
    let owner = LogicalActivationWorkerId::from_uuid(Uuid::from_u128(12)).expect("owner");
    let input_digest = Sha256Digest::from_bytes([0x22; 32]);
    let selected = SelectedLogicalJobOrchestration::new(
        selection_id,
        target,
        owner,
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        LogicalJobOrchestrationAuthorityKind::Activation,
        input_digest,
        UnixMillis::new(100),
        UnixMillis::new(5_000),
    )
    .expect("selected orchestration");
    let policy = runtime_policy(&tenant);
    let base_fence = LogicalActivationClaimFence::new_for_selection(
        tenant.clone(),
        run_id,
        invocation_id,
        logical_job_id,
        owner,
        policy.clone(),
        LogicalActivationGeneration::new(1).expect("base generation"),
        input_digest,
        UnixMillis::new(100),
        UnixMillis::new(5_000),
        selection_id,
    )
    .expect("base fence");
    let base = claimed_activation(base_fence);
    let consumed = ConsumedSelectedLogicalJobOrchestration::new(
        selected.clone(),
        ConsumedLogicalJobOrchestrationAuthority::Activation(base),
        UnixMillis::new(200),
    )
    .expect("exact base authority");

    let later_fence = LogicalActivationClaimFence::new_for_selection(
        tenant,
        run_id,
        invocation_id,
        logical_job_id,
        owner,
        policy,
        LogicalActivationGeneration::new(2).expect("later generation"),
        input_digest,
        UnixMillis::new(200),
        UnixMillis::new(6_000),
        selection_id,
    )
    .expect("later fence");
    assert!(
        ConsumedSelectedLogicalJobOrchestration::new(
            selected.clone(),
            ConsumedLogicalJobOrchestrationAuthority::Activation(claimed_activation(later_fence)),
            UnixMillis::new(300),
        )
        .is_err()
    );

    let consume = ConsumeSelectedLogicalJobOrchestration::new(selected.clone());
    assert_eq!(consume.selected(), &selected);
    let quarantine = QuarantineLogicalJobOrchestration::new(
        consumed,
        LogicalWorkQuarantineKind::RelationalEvidence,
    );
    assert_eq!(quarantine.selected(), &selected);
}

fn claimed_activation(fence: LogicalActivationClaimFence) -> ClaimedLogicalJobActivation {
    ClaimedLogicalJobActivation::new(
        fence,
        WorkflowJobKey::new("test").expect("logical key"),
        0,
        LogicalWorkflowJobKind::Steps,
        execution(),
        object("plans/current.json", 0x31),
        object("events/current.json", 0x32),
        false,
    )
    .expect("claimed activation")
}

#[test]
fn public_materialization_values_accept_only_exact_base_authority() {
    let tenant = TenantScope::from_authenticated_tenant_id("selection-api").expect("tenant");
    let run_id = RunId::from_uuid(Uuid::from_u128(20));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(21)).expect("invocation");
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(22)).expect("logical job");
    let target = LogicalInstanceMaterializationTarget::new(
        tenant.clone(),
        run_id,
        invocation_id,
        logical_job_id,
        LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(23)).expect("instance"),
    )
    .expect("target");
    let policy = runtime_policy(&tenant);
    let descriptor = LogicalInstanceMaterializationDescriptor::new(
        target,
        WorkflowJobKey::new("test").expect("logical key"),
        0,
        1,
        Sha256Digest::from_bytes([0x41; 32]),
        "/__w/test".to_owned(),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes([0x42; 32]),
            ObjectKey::new("jobs/current.pb").expect("job object key"),
            128,
        )
        .expect("job object"),
        LogicalActivationObject::runtime_context(
            Sha256Digest::from_bytes([0x43; 32]),
            ObjectKey::new("contexts/current.pb").expect("runtime object key"),
            128,
        )
        .expect("runtime object"),
        object("events/current.json", 0x44),
        execution(),
        JobAuthorityProfile::Standard,
        policy.clone(),
    )
    .expect("materialization descriptor");
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(24)).expect("selection");
    let owner = LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(25)).expect("owner");
    let selected = SelectedLogicalInstanceMaterialization::new(
        selection_id,
        descriptor.target().clone(),
        owner,
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        descriptor.descriptor_digest(),
        UnixMillis::new(100),
        UnixMillis::new(5_000),
    )
    .expect("selected materialization");
    let base = claimed_materialization(
        &descriptor,
        owner,
        policy.clone(),
        selection_id,
        1,
        100,
        5_000,
    );
    let consumed = ConsumedSelectedLogicalInstanceMaterialization::new(
        selected.clone(),
        base,
        UnixMillis::new(200),
    )
    .expect("exact base authority");
    let later = claimed_materialization(&descriptor, owner, policy, selection_id, 2, 200, 6_000);
    assert!(
        ConsumedSelectedLogicalInstanceMaterialization::new(
            selected.clone(),
            later,
            UnixMillis::new(300),
        )
        .is_err()
    );

    let consume = ConsumeSelectedLogicalInstanceMaterialization::new(selected.clone());
    assert_eq!(consume.selected(), &selected);
    let quarantine = QuarantineLogicalInstanceMaterialization::new(
        consumed,
        LogicalWorkQuarantineKind::PayloadEvidence,
    );
    assert_eq!(quarantine.selected(), &selected);
}

#[allow(clippy::too_many_arguments)]
fn claimed_materialization(
    descriptor: &LogicalInstanceMaterializationDescriptor,
    owner: LogicalMaterializationWorkerId,
    policy: WorkflowRuntimePolicyPin,
    selection_id: LogicalWorkSelectionId,
    generation: u64,
    claimed_at: i64,
    expires_at: i64,
) -> ClaimedLogicalInstanceMaterialization {
    let fence = LogicalMaterializationClaimFence::new_for_selection(
        descriptor.target().clone(),
        owner,
        LogicalMaterializationGeneration::new(generation).expect("generation"),
        descriptor.descriptor_digest(),
        policy,
        descriptor.expected_job_id(),
        descriptor.expected_attempt_id(),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
        selection_id,
    )
    .expect("materialization fence");
    ClaimedLogicalInstanceMaterialization::new(descriptor.clone(), fence, false)
        .expect("claimed materialization")
}

#[test]
fn repository_port_is_object_safe() {
    fn accepts_repository_object(_: Option<&dyn LogicalWorkSelectionRepository>) {}
    accepts_repository_object(None);
}
