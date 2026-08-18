mod support;

use std::collections::{BTreeMap, BTreeSet};

use automata_ci_core::{
    ActionReference, AttemptId, ExpressionDialect, ExpressionInstruction, ExpressionProgram,
    JobIrEnvelope, RuntimeBoolean, SemanticStep, Sha256Digest, StepId, StepIr, ValueSource,
    ValueTemplate,
};
use automata_ci_job_executor_actions::{
    ActionPreparationPort, ActionsToolchain, DeterministicOperationIds, ExecutionClock,
    ExecutionOperationIds, GithubContextPort, OperationPurpose, PreparedAction,
    PreparedActionError, PreparedBoolean, PreparedCompositeRunStep, PreparedCompositeStepMetadata,
    PreparedCompositeUsesStep, PreparedKeyValue, PreparedValue, RepositoryCredentialPort,
    SandboxEnvironmentCatalog, SecretPort,
};
use automata_ci_runner_runtime::{AdmissionRejection, JobExecutor};
use bytes::Bytes;
use static_assertions::assert_obj_safe;

use support::{
    Fixture, envelope, envelope_with_environment, prepared_node24_action, run_step,
    run_step_with_command_template, run_step_with_named_shell, windows_envelope,
};

assert_obj_safe!(ActionPreparationPort);
assert_obj_safe!(RepositoryCredentialPort);
assert_obj_safe!(SecretPort);
assert_obj_safe!(GithubContextPort);
assert_obj_safe!(SandboxEnvironmentCatalog);
assert_obj_safe!(ActionsToolchain);
assert_obj_safe!(ExecutionOperationIds);
assert_obj_safe!(ExecutionClock);

#[test]
fn shell_seam_has_no_executor_side_effect_or_secret_dependencies() {
    let source = include_str!("../src/shell.rs");
    let production = source
        .split_once("#[cfg(test)]")
        .map_or(source, |(production, _)| production);

    for forbidden in [
        "SecretPort",
        "EnvironmentBuilder",
        "ExecutionEndpoint",
        "CopyToRequest",
        "ExecutionOperationIds",
        "OperationPurpose",
        "ExecutionCancellation",
        "Cancellation",
        "ActionExecutionBudget",
        ".exec(",
    ] {
        assert!(
            !production.contains(forbidden),
            "shell seam must not depend on {forbidden}"
        );
    }
}

#[test]
fn extracted_executor_seams_only_construct_bounded_requests() {
    let seams = vec![
        (
            "action content",
            include_str!("../src/action_content.rs"),
            vec![
                "ExecutionCommand::new",
                "CopyToRequest::new",
                "archive.to_vec()",
            ],
        ),
        (
            "container runtime",
            include_str!("../src/container_runtime.rs"),
            vec![
                "ServicePort::new",
                "ServiceContainerSpec::new",
                "ServiceContainerSpecs::new",
                "ResourceLimits::new",
                "SandboxSpec::new",
                "SandboxLaunch::VirtualMachine",
            ],
        ),
    ];

    for (name, source, required) in seams {
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        for forbidden in [
            "ExecutionCancellation",
            "CancellationBridge",
            "ExecutionEndpoint",
            "SandboxProvider",
            "SecretPort",
            "SecretMasker",
            "EnvironmentBuilder",
            ".exec(",
            ".copy_to(",
            ".create(",
            ".attach(",
        ] {
            assert!(
                !production.contains(forbidden),
                "{name} seam must not depend on {forbidden}"
            );
        }
        for required in required {
            assert!(
                production.contains(required),
                "{name} seam must retain bounded constructor {required}"
            );
        }
    }
}

#[test]
fn extracted_executor_seams_retain_operation_identity_coordinates() {
    let executor = include_str!("../src/executor.rs")
        .split_whitespace()
        .collect::<String>();
    for expected in [
        "letprepare_ordinal=index.checked_add(1).ok_or_else(invalid_job)?;",
        "OperationPurpose::PrepareDirectory,prepare_ordinal",
        "OperationPurpose::CopyActionArchive,index",
        "OperationPurpose::VerifyActionArchive,index",
        "OperationPurpose::ExtractActionArchive,index",
        "OperationPurpose::VerifyActionTree,index",
        "container_runtime::sandbox_spec(&self.config,request,operation_id,generation",
    ] {
        assert!(
            executor.contains(expected),
            "executor must retain operation identity input {expected}"
        );
    }

    let action_content = include_str!("../src/action_content.rs")
        .split_whitespace()
        .collect::<String>();
    for expected in [
        "ExecutionCommand::new(operation_id,",
        "CopyToRequest::new(operation_id,archive_path.clone(),archive.to_vec())",
    ] {
        assert!(
            action_content.contains(expected),
            "action content plan must consume explicit operation identity {expected}"
        );
    }
    assert_eq!(
        action_content
            .matches("ExecutionCommand::new(operation_id,")
            .count(),
        5
    );

    let container_runtime = include_str!("../src/container_runtime.rs")
        .split_whitespace()
        .collect::<String>();
    assert_eq!(
        container_runtime
            .matches("SandboxSpec::new(operation_id,")
            .count(),
        1
    );
}

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
fn static_shell_contracts_are_checked_at_admission_before_provider_work() {
    for (name, step) in [
        (
            "POSIX command mode",
            run_step_with_command_template("unsafe", "Unsafe", "true", "bash -c {0}"),
        ),
        (
            "POSIX cmd",
            run_step_with_named_shell("unsafe", "Unsafe", "true", "cmd"),
        ),
    ] {
        let fixture = Fixture::new(Vec::new(), Vec::new());
        assert_eq!(
            fixture.executor.admit(&envelope(vec![step])),
            Err(AdmissionRejection::InvalidJob),
            "{name} must fail closed during admission"
        );
        assert_eq!(fixture.provider.counts(), (0, 0, 0));
    }

    for (name, step) in [
        (
            "Windows Git Bash",
            run_step_with_named_shell("unsafe", "Unsafe", "true", "bash"),
        ),
        (
            "Windows sh",
            run_step_with_named_shell("unsafe", "Unsafe", "true", "sh"),
        ),
        (
            "Windows cmd command template",
            run_step_with_command_template("unsafe", "Unsafe", "true", "cmd /C {0}"),
        ),
    ] {
        let fixture = Fixture::windows(Vec::new());
        assert_eq!(
            fixture.executor.admit(&windows_envelope(vec![step])),
            Err(AdmissionRejection::InvalidJob),
            "{name} must fail closed during admission"
        );
        assert_eq!(fixture.provider.counts(), (0, 0, 0));
    }
}

#[test]
fn every_advertised_static_shell_contract_passes_admission_on_its_platform() {
    for step in [
        run_step("default", "Default", "true"),
        run_step_with_named_shell("bash", "Bash", "true", "bash"),
        run_step_with_named_shell("sh", "Sh", "true", "sh"),
        run_step_with_named_shell("python", "Python", "true", "python"),
        run_step_with_named_shell("pwsh", "PowerShell Core", "true", "pwsh"),
        run_step_with_command_template(
            "bash-template",
            "Bash template",
            "true",
            "bash --noprofile --norc -e -o pipefail {0}",
        ),
        run_step_with_command_template("sh-template", "Sh template", "true", "sh -e {0}"),
        run_step_with_command_template(
            "python-template",
            "Python template",
            "true",
            "python -u {0}",
        ),
        run_step_with_command_template(
            "pwsh-template",
            "PowerShell template",
            "true",
            "pwsh -File {0}",
        ),
    ] {
        Fixture::new(Vec::new(), Vec::new())
            .executor
            .admit(&envelope(vec![step]))
            .expect("advertised POSIX shell contract");
    }

    for step in [
        run_step("default", "Default", "true"),
        run_step_with_named_shell("python", "Python", "true", "python"),
        run_step_with_named_shell("pwsh", "PowerShell Core", "true", "pwsh"),
        run_step_with_named_shell("powershell", "Windows PowerShell", "true", "powershell"),
        run_step_with_named_shell("cmd", "Command Prompt", "true", "cmd"),
        run_step_with_command_template(
            "python-template",
            "Python template",
            "true",
            "python -u {0}",
        ),
        run_step_with_command_template(
            "pwsh-template",
            "PowerShell template",
            "true",
            "pwsh -File {0}",
        ),
        run_step_with_command_template(
            "powershell-template",
            "Windows PowerShell template",
            "true",
            "powershell -File {0}",
        ),
    ] {
        Fixture::windows(Vec::new())
            .executor
            .admit(&windows_envelope(vec![step]))
            .expect("advertised Windows shell contract");
    }
}

#[test]
fn reserved_planned_environment_names_fail_admission_before_provider_work() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let reserved = [
        "GITHUB_WORKSPACE",
        "RUNNER_OS",
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_STATE",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_ARTIFACTS",
        "GITHUB_ARTIFACTS_LIST",
    ];

    // Workflow and job environment are flattened into the planned job map, so
    // this admission boundary protects both declaration levels.
    for name in reserved {
        let job = envelope_with_environment(
            vec![run_step("run", "Run", "true")],
            BTreeMap::from([(name.to_owned(), ValueSource::Literal("shadow".to_owned()))]),
        );
        assert_eq!(
            fixture.executor.admit(&job),
            Err(AdmissionRejection::InvalidJob),
            "planned {name} must not shadow runner state"
        );
    }

    for name in ["GITHUB_WORKSPACE", "RUNNER_OS", "GITHUB_ENV"] {
        let step = run_step("run", "Run", "true").with_environment(BTreeMap::from([(
            name.to_owned(),
            ValueSource::Literal("shadow".to_owned()),
        )]));
        assert_eq!(
            fixture.executor.admit(&envelope(vec![step])),
            Err(AdmissionRejection::InvalidJob),
            "step {name} must not shadow runner state"
        );
    }

    let allowed = envelope_with_environment(
        vec![
            run_step("run", "Run", "true").with_environment(BTreeMap::from([(
                "CI".to_owned(),
                ValueSource::Literal("step-ci".to_owned()),
            )])),
        ],
        BTreeMap::from([
            (
                "NODE_OPTIONS".to_owned(),
                ValueSource::Literal("--no-warnings".to_owned()),
            ),
            (
                "GITHUB_TOKEN".to_owned(),
                ValueSource::Literal("workflow-mapped-token".to_owned()),
            ),
            (
                "RUNNER_DIGEST".to_owned(),
                ValueSource::Literal("custom-release-value".to_owned()),
            ),
            (
                "github_workspace".to_owned(),
                ValueSource::Literal("case-distinct-on-posix".to_owned()),
            ),
        ]),
    );
    fixture.executor.admit(&allowed).expect(
        "CI, custom prefixed names, declarative NODE_OPTIONS, and POSIX case variants remain valid",
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
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

#[test]
fn oversized_composite_values_preserve_the_public_invalid_step_error() {
    const OVERSIZED_COMPOSITE_VALUES: usize = 1_025;

    let metadata = || {
        PreparedCompositeStepMetadata::new(
            None,
            None,
            ExpressionProgram::new(
                ExpressionDialect::new("github-actions", 1).expect("valid dialect"),
                "success()",
                vec![ExpressionInstruction::Call {
                    name: "success".to_owned(),
                    argument_count: 0,
                }],
            )
            .expect("valid condition"),
            PreparedBoolean::Literal(false),
        )
    };
    let values = || {
        (0..OVERSIZED_COMPOSITE_VALUES)
            .map(|index| {
                PreparedKeyValue::new(
                    format!("value-{index}"),
                    PreparedValue::Literal(String::new()),
                )
                .expect("valid prepared value")
            })
            .collect()
    };
    assert_eq!(
        PreparedCompositeRunStep::new(
            metadata(),
            PreparedValue::Literal("echo".to_owned()),
            PreparedValue::Literal("sh".to_owned()),
            values(),
            None,
        )
        .expect_err("oversized composite run environment must fail"),
        PreparedActionError::InvalidCompositeStep
    );
    assert_eq!(
        PreparedCompositeUsesStep::new(
            metadata(),
            ActionReference::Local {
                path: "action".to_owned(),
            },
            values(),
            Vec::new(),
        )
        .expect_err("oversized composite action inputs must fail"),
        PreparedActionError::InvalidCompositeStep
    );
    assert_eq!(
        PreparedCompositeUsesStep::new(
            metadata(),
            ActionReference::Local {
                path: "action".to_owned(),
            },
            Vec::new(),
            values(),
        )
        .expect_err("oversized composite action environment must fail"),
        PreparedActionError::InvalidCompositeStep
    );
}
