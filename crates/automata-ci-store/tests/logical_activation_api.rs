use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    ClaimLogicalJobActivation, LogicalActivationClaimFence, LogicalActivationGeneration,
    LogicalActivationObject, LogicalActivationValueError, LogicalActivationWorkerId,
    LogicalWorkSelectionId, LogicalWorkflowInvocationId, LogicalWorkflowJobId, MAX_JOB_IR_BYTES,
    MAX_LOGICAL_ACTIVATED_INSTANCES, MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS,
    MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS, ObjectKey, RenewLogicalJobActivation, RepositoryId,
    TenantScope, WorkflowRuntimePolicyPin, WorkflowRuntimePolicyRevision,
};
use uuid::Uuid;

fn runtime_policy(tenant: &TenantScope) -> WorkflowRuntimePolicyPin {
    WorkflowRuntimePolicyPin::new(
        tenant.clone(),
        RepositoryId::from_uuid(Uuid::from_u128(10)),
        WorkflowRuntimePolicyRevision::new(1).expect("runtime-policy revision"),
        Sha256Digest::from_bytes([9; 32]),
    )
}

fn claim(
    observed_at: i64,
    expires_at: i64,
) -> Result<ClaimLogicalJobActivation, LogicalActivationValueError> {
    let tenant = TenantScope::from_authenticated_tenant_id("activation-tenant").expect("tenant");
    ClaimLogicalJobActivation::new(
        tenant.clone(),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("logical job"),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(4)).expect("worker"),
        runtime_policy(&tenant),
        Sha256Digest::from_bytes([5; 32]),
        UnixMillis::new(observed_at),
        UnixMillis::new(expires_at),
    )
}

#[test]
fn current_activation_values_are_bounded_and_exact() {
    let request =
        claim(1_000, 1_000 + MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS).expect("maximum claim interval");
    assert_eq!(request.run_id().as_uuid(), Uuid::from_u128(1));
    assert_eq!(request.input_digest(), Sha256Digest::from_bytes([5; 32]));
    assert_eq!(MAX_LOGICAL_ACTIVATED_INSTANCES, 256);

    let job_ir = LogicalActivationObject::job_ir(
        Sha256Digest::from_bytes([6; 32]),
        ObjectKey::new("activation/job-ir.pb").expect("object key"),
        MAX_JOB_IR_BYTES,
    )
    .expect("maximum JobIR object");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes([7; 32]),
        ObjectKey::new("activation/runtime-context.pb").expect("object key"),
        512,
    )
    .expect("runtime context object");
    assert_eq!(
        job_ir.media_type(),
        "application/vnd.automata.job-ir.protobuf"
    );
    assert_eq!(
        runtime.media_type(),
        "application/vnd.automata.job-runtime-context.protobuf"
    );
}

#[test]
fn invalid_claims_and_objects_fail_before_repository_io() {
    assert!(matches!(
        LogicalActivationWorkerId::from_uuid(Uuid::nil()),
        Err(LogicalActivationValueError::NilUuid(
            "logical activation worker ID"
        ))
    ));
    assert!(matches!(
        LogicalActivationGeneration::new(0),
        Err(LogicalActivationValueError::InvalidGeneration)
    ));
    assert!(matches!(
        claim(1_000, 1_000),
        Err(LogicalActivationValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        claim(1_000, 1_001 + MAX_LOGICAL_ACTIVATION_CLAIM_MILLIS),
        Err(LogicalActivationValueError::InvalidClaimInterval)
    ));
    assert!(matches!(
        claim(-1, 1_000),
        Err(LogicalActivationValueError::NegativeTimestamp(
            "activation claim observation"
        ))
    ));
    assert!(matches!(
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes([8; 32]),
            ObjectKey::new("activation/empty.pb").expect("object key"),
            0,
        ),
        Err(LogicalActivationValueError::InvalidObjectSize)
    ));

    let tenant = TenantScope::from_authenticated_tenant_id("activation-tenant").expect("tenant");
    let fence = LogicalActivationClaimFence::new_for_selection(
        tenant.clone(),
        RunId::from_uuid(Uuid::from_u128(1)),
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation"),
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("logical job"),
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(4)).expect("worker"),
        runtime_policy(&tenant),
        LogicalActivationGeneration::new(1).expect("generation"),
        Sha256Digest::from_bytes([5; 32]),
        UnixMillis::new(1_000),
        UnixMillis::new(1_200),
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(5)).expect("selection"),
    )
    .expect("fence");
    assert!(
        RenewLogicalJobActivation::new(fence.clone(), MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS)
            .is_ok()
    );
    assert!(matches!(
        RenewLogicalJobActivation::new(fence, MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS - 1),
        Err(LogicalActivationValueError::InvalidRenewalInterval)
    ));
}
