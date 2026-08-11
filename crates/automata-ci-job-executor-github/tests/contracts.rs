mod support;

use std::collections::{BTreeMap, BTreeSet};

use automata_ci_core::{
    ActionReference, AttemptId, JobIrEnvelope, RuntimeBoolean, SemanticStep, Sha256Digest, StepId,
    StepIr, ValueTemplate,
};
use automata_ci_job_executor_github::{
    ActionPreparationPort, DeterministicOperationIds, ExecutionClock, ExecutionOperationIds,
    GithubContextPort, GithubToolchain, OperationPurpose, PreparedAction, PreparedActionError,
    RepositoryCredentialPort, SandboxEnvironmentCatalog, SecretPort,
};
use automata_ci_runner_runtime::JobExecutor;
use bytes::Bytes;
use static_assertions::assert_obj_safe;

use support::{Fixture, envelope, prepared_node24_action, run_step};

assert_obj_safe!(ActionPreparationPort);
assert_obj_safe!(RepositoryCredentialPort);
assert_obj_safe!(SecretPort);
assert_obj_safe!(GithubContextPort);
assert_obj_safe!(SandboxEnvironmentCatalog);
assert_obj_safe!(GithubToolchain);
assert_obj_safe!(ExecutionOperationIds);
assert_obj_safe!(ExecutionClock);

#[test]
fn artifact_hash_operation_ids_preserve_full_composite_phase_coordinates() {
    const COMPOSITE_PHASE_BASE: u32 = 1 << 24;

    let ids = DeterministicOperationIds;
    let attempt = AttemptId::new();
    let coordinates = [
        (0, 0),
        (1, 0),
        (COMPOSITE_PHASE_BASE, 0),
        (COMPOSITE_PHASE_BASE, 499),
        (COMPOSITE_PHASE_BASE + 1, 0),
        (u32::MAX, 499),
    ];
    let derived = coordinates
        .map(|(phase, file_index)| ids.artifact_hash_operation_id(attempt, phase, file_index));

    assert_eq!(BTreeSet::from(derived).len(), coordinates.len());
    assert_eq!(
        ids.artifact_hash_operation_id(attempt, COMPOSITE_PHASE_BASE, 499),
        ids.artifact_hash_operation_id(attempt, COMPOSITE_PHASE_BASE, 499),
        "identical composite coordinates must retry with the same operation ID"
    );
    assert_ne!(
        ids.artifact_hash_operation_id(attempt, COMPOSITE_PHASE_BASE, 0),
        ids.operation_id(
            attempt,
            OperationPurpose::ExecutePhase,
            COMPOSITE_PHASE_BASE
        ),
        "artifact hashes must remain separated from the established operation-ID domain"
    );
    assert_ne!(
        ids.artifact_hash_operation_id(attempt, COMPOSITE_PHASE_BASE, 0),
        ids.artifact_hash_operation_id(AttemptId::new(), COMPOSITE_PHASE_BASE, 0),
        "attempt identity must participate in derivation"
    );
}

#[test]
fn safe_local_actions_admit_while_container_actions_fail_closed() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let local = envelope(vec![StepIr::new(
        StepId::new("local").expect("valid step"),
        ValueTemplate::literal("Local").expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Local {
                path: "./action".to_owned(),
            },
            BTreeMap::new(),
        ),
    )]);
    fixture
        .executor
        .admit(&local)
        .expect("contained checked-out action is supported");

    let container = envelope(vec![StepIr::new(
        StepId::new("container").expect("valid step"),
        ValueTemplate::literal("Container").expect("step name template"),
        RuntimeBoolean::literal(false),
        SemanticStep::action(
            ActionReference::Container {
                image: "docker://alpine:3".to_owned(),
            },
            BTreeMap::new(),
        ),
    )]);
    assert!(fixture.executor.admit(&container).is_err());
}

#[test]
fn admitted_workspace_must_be_a_per_job_descendant_of_the_selected_environment_root() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    for workspace in ["/__w", "/__w-other/automata", "/runner/_work/automata"] {
        let mut encoded = serde_json::to_value(envelope(vec![run_step("run", "Run", "true")]))
            .expect("encode JobIR");
        encoded["execution"]["workspace"] = serde_json::json!(workspace);
        let job: JobIrEnvelope = serde_json::from_value(encoded).expect("structural JobIR");

        assert!(
            fixture.executor.admit(&job).is_err(),
            "workspace {workspace} must fail closed"
        );
    }
}

#[test]
fn exact_profile_with_resolved_self_hosted_routing_reaches_executor_admission() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let mut encoded =
        serde_json::to_value(envelope(vec![run_step("run", "Run", "true")])).expect("encode JobIR");
    encoded["job"]["requirements"]["labels"] = serde_json::json!(["self-hosted", "linux", "x64"]);
    encoded["job"]["requirements"]["eligible_groups"] = serde_json::json!(["trusted-builders"]);
    let job: JobIrEnvelope = serde_json::from_value(encoded).expect("routed JobIR");

    fixture
        .executor
        .admit(&job)
        .expect("exact profile selects immutable launch material");
}

#[test]
fn prepared_action_contract_recomputes_content_identity() {
    let valid = prepared_node24_action();
    let error = PreparedAction::with_definition(
        Sha256Digest::from_bytes([0; 32]),
        Bytes::from_static(b"different-content"),
        valid.subpath(),
        valid.definition().clone(),
    )
    .expect_err("mismatched digest must fail closed");
    assert_eq!(error, PreparedActionError::DigestMismatch);
}
