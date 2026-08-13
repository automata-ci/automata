use std::collections::BTreeMap;

use automata_ci_core::{
    AttemptId, ContextValue, JobAuthorityProfile, JobContentReference, JobExecutionContext,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobPermissionRequest, JobRuntimeContext, JobSource,
    RunId, RunValueTemplates, RunnerRequirements, RuntimeBoolean, SemanticStep, Sha256Digest,
    ShellTemplate, StepId, StepIr, StrategyContext, UnixMillis, ValueTemplate, WorkflowId,
    WorkflowJobKey,
};
use automata_ci_store::{
    AdmissionObject, ClaimedLogicalInstanceMaterialization, CommitLogicalInstanceMaterialization,
    ConsumedSelectedLogicalInstanceMaterialization, LogicalActivationExecutionContext,
    LogicalActivationObject, LogicalInstanceMaterializationDescriptor,
    LogicalInstanceMaterializationTarget, LogicalMaterializationClaimFence,
    LogicalMaterializationGeneration, LogicalMaterializationValueError,
    LogicalMaterializationWorkerId, LogicalWorkSelectionGeneration, LogicalWorkSelectionId,
    LogicalWorkflowInstanceId, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS, ObjectKey, RenewLogicalInstanceMaterialization,
    RepositoryId, SelectedLogicalInstanceMaterialization, TenantScope, WorkflowRuntimePolicyPin,
    WorkflowRuntimePolicyRevision,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[test]
fn decoded_v5_commit_binds_exact_blob_identity_and_execution_references() {
    let fixture = fixture(0, 2, [0x44; 32]);
    let claim = claim(&fixture.descriptor, 10, 100);
    let claimed =
        ClaimedLogicalInstanceMaterialization::new(fixture.descriptor.clone(), claim, false)
            .expect("claimed descriptor");

    let commit = CommitLogicalInstanceMaterialization::new(
        &claimed,
        &fixture.encoded,
        &fixture.envelope,
        &fixture.runtime_encoded,
        &fixture.runtime_context,
        UnixMillis::new(20),
    )
    .expect("exact decoded JobIR commit");
    assert_eq!(
        commit.claim().expected_job_id(),
        fixture.envelope.job().job_id()
    );
    assert_eq!(
        commit.claim().expected_attempt_id(),
        fixture.expected_attempt_id
    );
    assert_eq!(commit.requirements(), fixture.envelope.job().requirements());
    assert_eq!(commit.authority_profile(), JobAuthorityProfile::Standard);
    assert_eq!(fixture.envelope.schema_version(), 1);

    let mut changed = fixture.encoded.clone();
    changed[0] ^= 0x01;
    assert!(matches!(
        CommitLogicalInstanceMaterialization::new(
            &claimed,
            &changed,
            &fixture.envelope,
            &fixture.runtime_encoded,
            &fixture.runtime_context,
            UnixMillis::new(20),
        ),
        Err(LogicalMaterializationValueError::JobIrBlobMismatch)
    ));

    let mut changed_runtime = fixture.runtime_encoded.clone();
    changed_runtime[0] ^= 0x01;
    assert!(matches!(
        CommitLogicalInstanceMaterialization::new(
            &claimed,
            &fixture.encoded,
            &fixture.envelope,
            &changed_runtime,
            &fixture.runtime_context,
            UnixMillis::new(20),
        ),
        Err(LogicalMaterializationValueError::RuntimeContextBlobMismatch)
    ));
}

#[test]
fn decoded_commit_retains_the_validated_credential_free_authority_profile() {
    let fixture =
        fixture_with_authority_profile(0, 1, [0x45; 32], JobAuthorityProfile::CredentialFree);
    let claim = claim(&fixture.descriptor, 10, 100);
    let claimed =
        ClaimedLogicalInstanceMaterialization::new(fixture.descriptor.clone(), claim, false)
            .expect("claimed descriptor");
    let commit = CommitLogicalInstanceMaterialization::new(
        &claimed,
        &fixture.encoded,
        &fixture.envelope,
        &fixture.runtime_encoded,
        &fixture.runtime_context,
        UnixMillis::new(20),
    )
    .expect("credential-free commit");
    assert_eq!(
        commit.authority_profile(),
        JobAuthorityProfile::CredentialFree
    );
}

#[test]
fn decoded_job_authority_profile_cannot_be_substituted_for_durable_publication() {
    let fixture =
        fixture_with_authority_profile(0, 1, [0x46; 32], JobAuthorityProfile::CredentialFree);
    let durable_standard = LogicalInstanceMaterializationDescriptor::new(
        fixture.descriptor.target().clone(),
        fixture.descriptor.logical_key().clone(),
        fixture.descriptor.matrix_index(),
        fixture.descriptor.matrix_total(),
        fixture.descriptor.matrix_digest(),
        fixture.descriptor.workspace().to_owned(),
        fixture.descriptor.job_ir().clone(),
        fixture.descriptor.runtime_context().clone(),
        fixture.descriptor.event().clone(),
        fixture.descriptor.execution().clone(),
        JobAuthorityProfile::Standard,
        fixture.descriptor.runtime_policy().clone(),
    )
    .expect("opposite durable descriptor");
    let claimed = ClaimedLogicalInstanceMaterialization::new(
        durable_standard.clone(),
        claim(&durable_standard, 10, 100),
        false,
    )
    .expect("claimed opposite descriptor");

    assert!(matches!(
        CommitLogicalInstanceMaterialization::new(
            &claimed,
            &fixture.encoded,
            &fixture.envelope,
            &fixture.runtime_encoded,
            &fixture.runtime_context,
            UnixMillis::new(20),
        ),
        Err(LogicalMaterializationValueError::JobIrIdentityMismatch)
    ));
}

#[test]
fn duplicate_matrix_values_still_derive_distinct_concrete_identities() {
    let first = fixture(0, 2, [0x55; 32]);
    let second = fixture(1, 2, [0x55; 32]);
    assert_eq!(
        first.descriptor.matrix_digest(),
        second.descriptor.matrix_digest()
    );
    assert_ne!(
        first.descriptor.expected_job_id(),
        second.descriptor.expected_job_id()
    );
    assert_ne!(
        first.descriptor.expected_attempt_id(),
        second.descriptor.expected_attempt_id()
    );
    assert_ne!(first.descriptor.job_key(), second.descriptor.job_key());
}

#[test]
fn decoded_job_must_match_runtime_event_workspace_and_matrix_identity() {
    let fixture = fixture(0, 1, [0x66; 32]);
    let claimed = ClaimedLogicalInstanceMaterialization::new(
        fixture.descriptor.clone(),
        claim(&fixture.descriptor, 10, 100),
        false,
    )
    .expect("claimed descriptor");
    let wrong_execution = JobExecutionContext::new(
        "CI",
        "refs/heads/main",
        "/srv/other",
        content_reference(fixture.descriptor.event()),
        activation_reference(fixture.descriptor.runtime_context()),
    )
    .with_actor("octocat")
    .with_run_id_alias(automata_ci_core::RunIdAlias::new(11).expect("run ID alias"))
    .with_run_number(7)
    .with_run_attempt(1);
    let wrong = JobIrEnvelope::new(
        fixture.envelope.workflow_id(),
        fixture.envelope.source().clone(),
        wrong_execution,
        fixture.envelope.job().clone(),
    );
    assert!(matches!(
        CommitLogicalInstanceMaterialization::new(
            &claimed,
            &fixture.encoded,
            &wrong,
            &fixture.runtime_encoded,
            &fixture.runtime_context,
            UnixMillis::new(20),
        ),
        Err(LogicalMaterializationValueError::JobIrIdentityMismatch)
    ));
}

#[test]
fn claims_are_bounded_and_commit_requires_a_live_fence() {
    let fixture = fixture(0, 1, [0x77; 32]);
    let claim = claim(&fixture.descriptor, 10, 20);
    let claimed =
        ClaimedLogicalInstanceMaterialization::new(fixture.descriptor.clone(), claim, false)
            .expect("claimed descriptor");
    assert!(matches!(
        CommitLogicalInstanceMaterialization::new(
            &claimed,
            &fixture.encoded,
            &fixture.envelope,
            &fixture.runtime_encoded,
            &fixture.runtime_context,
            UnixMillis::new(20),
        ),
        Err(LogicalMaterializationValueError::CommitOutsideClaim)
    ));
}

struct Fixture {
    descriptor: LogicalInstanceMaterializationDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
    expected_attempt_id: AttemptId,
}

fn fixture(matrix_index: u32, matrix_total: u32, matrix_digest: [u8; 32]) -> Fixture {
    fixture_with_authority_profile(
        matrix_index,
        matrix_total,
        matrix_digest,
        JobAuthorityProfile::Standard,
    )
}

#[allow(clippy::too_many_lines)] // Synthetic current envelopes require every bound field.
fn fixture_with_authority_profile(
    matrix_index: u32,
    matrix_total: u32,
    matrix_digest: [u8; 32],
    authority_profile: JobAuthorityProfile,
) -> Fixture {
    let tenant = TenantScope::from_authenticated_tenant_id("test-tenant").expect("tenant");
    let run_id = RunId::from_uuid(Uuid::from_u128(1));
    let invocation_id =
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(2)).expect("invocation");
    let logical_job_id = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(3)).expect("logical job");
    let instance_id =
        LogicalWorkflowInstanceId::from_uuid(Uuid::from_u128(100 + u128::from(matrix_index)))
            .expect("instance");
    let runtime_policy = WorkflowRuntimePolicyPin::new(
        tenant.clone(),
        RepositoryId::from_uuid(Uuid::from_u128(5)),
        WorkflowRuntimePolicyRevision::new(1).expect("runtime-policy revision"),
        Sha256Digest::from_bytes([0x22; 32]),
    );
    let target = LogicalInstanceMaterializationTarget::new(
        tenant,
        run_id,
        invocation_id,
        logical_job_id,
        instance_id,
    )
    .expect("target");
    let logical_key = WorkflowJobKey::new("build").expect("logical key");
    let event = AdmissionObject::new(
        Sha256Digest::from_bytes([0x11; 32]),
        ObjectKey::new("events/push.json").expect("event key"),
        128,
        "application/json",
    )
    .expect("event");
    let empty = ContextValue::object(BTreeMap::new()).expect("empty context");
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, matrix_index, matrix_total, matrix_total).expect("strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("runtime context");
    let runtime_encoded =
        serde_json::to_vec(&runtime_context).expect("synthetic encoded runtime context");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new(format!("contexts/{matrix_index}.pb")).expect("context key"),
        u64::try_from(runtime_encoded.len()).expect("runtime size"),
    )
    .expect("runtime context");
    let execution = LogicalActivationExecutionContext::new(
        WorkflowId::from_uuid(Uuid::from_u128(4)),
        "CI".to_owned(),
        "refs/heads/main".to_owned(),
        "push".to_owned(),
        Some("octocat".to_owned()),
        automata_ci_core::RunIdAlias::new(11).expect("run ID alias"),
        7,
        1,
    )
    .expect("execution");

    let placeholder = LogicalInstanceMaterializationDescriptor::new(
        target.clone(),
        logical_key.clone(),
        matrix_index,
        matrix_total,
        Sha256Digest::from_bytes(matrix_digest),
        "/srv/work/repository".to_owned(),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes([0x33; 32]),
            ObjectKey::new(format!("job-ir/{matrix_index}.pb")).expect("job key"),
            1,
        )
        .expect("JobIR"),
        runtime.clone(),
        event.clone(),
        execution.clone(),
        authority_profile,
        runtime_policy.clone(),
    )
    .expect("placeholder descriptor");
    let identity = JobInstanceIdentity::new(
        logical_key.as_str(),
        matrix_index,
        matrix_total,
        Sha256Digest::from_bytes(matrix_digest),
    )
    .expect("matrix identity");
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
    let mut job = JobIr::new(
        placeholder.expected_job_id(),
        run_id,
        format!("Build {matrix_index}"),
        RunnerRequirements::default(),
        identity,
        false,
        vec![step],
    )
    .with_authority_profile(authority_profile);
    if authority_profile == JobAuthorityProfile::CredentialFree {
        job = job.with_permission_request(JobPermissionRequest::mapping([]));
    }
    let job_execution = JobExecutionContext::new(
        execution.workflow_name(),
        execution.git_ref(),
        placeholder.workspace(),
        content_reference(&event),
        activation_reference(&runtime),
    )
    .with_actor(execution.actor().expect("actor"))
    .with_run_id_alias(execution.run_id_alias())
    .with_run_number(execution.run_number())
    .with_run_attempt(execution.run_attempt());
    let envelope = JobIrEnvelope::new(
        execution.workflow_id(),
        JobSource::new(
            "github",
            "example/repository",
            "0123456789abcdef",
            ".ci/workflows/ci.yml",
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("current envelope");
    let encoded = serde_json::to_vec(&envelope).expect("synthetic encoded JobIR");
    let descriptor = LogicalInstanceMaterializationDescriptor::new(
        target,
        logical_key,
        matrix_index,
        matrix_total,
        Sha256Digest::from_bytes(matrix_digest),
        "/srv/work/repository".to_owned(),
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new(format!("job-ir/{matrix_index}.pb")).expect("job key"),
            u64::try_from(encoded.len()).expect("encoded size"),
        )
        .expect("JobIR"),
        runtime,
        event,
        execution,
        authority_profile,
        runtime_policy,
    )
    .expect("descriptor");
    assert_eq!(descriptor.expected_job_id(), envelope.job().job_id());
    let expected_attempt_id = descriptor.expected_attempt_id();
    Fixture {
        descriptor,
        envelope,
        encoded,
        runtime_context,
        runtime_encoded,
        expected_attempt_id,
    }
}

fn claim(
    descriptor: &LogicalInstanceMaterializationDescriptor,
    claimed_at: i64,
    expires_at: i64,
) -> LogicalMaterializationClaimFence {
    LogicalMaterializationClaimFence::new_for_selection(
        descriptor.target().clone(),
        LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(9)).expect("worker"),
        LogicalMaterializationGeneration::new(1).expect("generation"),
        descriptor.descriptor_digest(),
        descriptor.runtime_policy().clone(),
        descriptor.expected_job_id(),
        descriptor.expected_attempt_id(),
        UnixMillis::new(claimed_at),
        UnixMillis::new(expires_at),
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(10)).expect("selection"),
    )
    .expect("claim")
}

#[test]
fn renewal_duration_has_a_distinct_achievable_handoff_budget() {
    let fixture = fixture(0, 1, [0x77; 32]);
    let fence = claim(&fixture.descriptor, 10, 10_000);
    assert!(
        RenewLogicalInstanceMaterialization::new(
            fence.clone(),
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS,
        )
        .is_ok()
    );
    assert!(matches!(
        RenewLogicalInstanceMaterialization::new(
            fence,
            MIN_LOGICAL_WORK_RENEWAL_REQUEST_MILLIS - 1,
        ),
        Err(LogicalMaterializationValueError::InvalidRenewalInterval)
    ));
}

#[test]
fn external_repository_fake_can_rehydrate_a_consumed_materialization() {
    let fixture = fixture(0, 1, [0x78; 32]);
    let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::from_u128(21)).expect("selection");
    let owner = LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(9)).expect("worker");
    let claimed_at = UnixMillis::new(10);
    let expires_at = UnixMillis::new(5_000);
    let selected = SelectedLogicalInstanceMaterialization::new(
        selection_id,
        fixture.descriptor.target().clone(),
        owner,
        LogicalWorkSelectionGeneration::new(1).expect("selection generation"),
        fixture.descriptor.descriptor_digest(),
        claimed_at,
        expires_at,
    )
    .expect("selected materialization");
    let fence = LogicalMaterializationClaimFence::new_for_selection(
        fixture.descriptor.target().clone(),
        owner,
        LogicalMaterializationGeneration::new(1).expect("generation"),
        fixture.descriptor.descriptor_digest(),
        fixture.descriptor.runtime_policy().clone(),
        fixture.descriptor.expected_job_id(),
        fixture.descriptor.expected_attempt_id(),
        claimed_at,
        expires_at,
        selection_id,
    )
    .expect("selection-origin fence");
    let claimed =
        ClaimedLogicalInstanceMaterialization::new(fixture.descriptor.clone(), fence, false)
            .expect("claimed materialization");
    let consumed = ConsumedSelectedLogicalInstanceMaterialization::new(
        selected.clone(),
        claimed,
        UnixMillis::new(100),
    )
    .expect("consumed materialization");
    assert_eq!(consumed.selected().selection_id(), selection_id);

    let unproved_later_fence = LogicalMaterializationClaimFence::new_for_selection(
        fixture.descriptor.target().clone(),
        owner,
        LogicalMaterializationGeneration::new(2).expect("later generation"),
        fixture.descriptor.descriptor_digest(),
        fixture.descriptor.runtime_policy().clone(),
        fixture.descriptor.expected_job_id(),
        fixture.descriptor.expected_attempt_id(),
        UnixMillis::new(20),
        UnixMillis::new(6_000),
        selection_id,
    )
    .expect("synthetic later fence");
    let unproved_later =
        ClaimedLogicalInstanceMaterialization::new(fixture.descriptor, unproved_later_fence, false)
            .expect("synthetic later materialization");
    assert!(
        ConsumedSelectedLogicalInstanceMaterialization::new(
            selected,
            unproved_later,
            UnixMillis::new(100),
        )
        .is_err()
    );
}

fn content_reference(object: &AdmissionObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}

fn activation_reference(object: &LogicalActivationObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}
