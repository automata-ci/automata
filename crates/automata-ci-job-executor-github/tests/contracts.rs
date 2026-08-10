mod support;

use std::collections::BTreeMap;

use automata_ci_core::{
    ActionReference, JobIrEnvelope, RuntimeBoolean, SemanticStep, Sha256Digest, StepId, StepIr,
    ValueTemplate,
};
use automata_ci_job_executor_github::{
    ActionPreparationPort, ExecutionClock, ExecutionOperationIds, GithubContextPort,
    GithubToolchain, PreparedAction, PreparedActionError, RepositoryCredentialPort,
    SandboxEnvironmentCatalog, SecretPort,
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
