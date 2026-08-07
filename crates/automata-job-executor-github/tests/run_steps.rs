mod support;

use std::{collections::BTreeMap, sync::Arc};

use automata_core::{JobConclusion, SemanticStep, ShellSpec, StepId, StepIr, ValueSource};
use automata_execution::{RootFilesystemPolicy, SandboxPrivilegePolicy};
use automata_github_runtime::CommandFileKind;
use automata_runner_runtime::{
    ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};

use support::{
    Fixture, PhaseResponse, SECRET, envelope_with_environment, envelope_with_job_condition,
    envelope_with_working_directory, environment_map,
};

#[tokio::test]
async fn false_job_condition_skips_without_running_or_adapter_owned_eos() {
    let fixture = Fixture::new(Vec::new(), Vec::new());
    let job = envelope_with_job_condition(Vec::new(), "false");
    let request = fixture.request(job);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("false job condition is a skipped result");

    assert_eq!(result.conclusion(), JobConclusion::Skipped);
    assert!(fixture.events.transitions().is_empty());
    assert!(fixture.events.logs().is_empty());
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}

#[tokio::test]
async fn run_steps_preserve_scripts_and_apply_fresh_command_files_after_exit() {
    let responses = vec![
        PhaseResponse::success()
            .with_stdout(format!(
                "::add-mask::dynamic-secret\n{SECRET} dynamic-secret visible\n"
            ))
            .with_file(CommandFileKind::Environment, b"LATER=from-file\n".to_vec())
            .with_file(CommandFileKind::Path, b"/custom/bin\n".to_vec())
            .with_file(CommandFileKind::Output, b"digest=abc123\n".to_vec()),
        PhaseResponse::success(),
    ];
    let fixture = Fixture::new(Vec::new(), responses);
    let first_script = "printf '%s\\n' \"$TOKEN\"\nprintf '%s\\n' literal-$()\n";
    let second_script = "printf '%s\\n' \"$LATER\"\n";
    let steps = vec![
        StepIr::new(
            StepId::new("first").expect("valid step"),
            "First",
            SemanticStep::run(first_script, ShellSpec::Default),
        ),
        StepIr::new(
            StepId::new("second").expect("valid step"),
            "Second",
            SemanticStep::run(second_script, ShellSpec::Named("bash".to_owned())),
        ),
    ];
    let job = envelope_with_environment(
        steps,
        BTreeMap::from([(
            "TOKEN".to_owned(),
            ValueSource::SecretReference("test-token".to_owned()),
        )]),
    );
    let request = fixture.request(job);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_sandbox_spec(&fixture);

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state.scripts,
        [first_script.as_bytes(), second_script.as_bytes()]
    );
    let bash = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(bash.len(), 2);
    assert!(
        bash.iter()
            .all(|command| command.working_directory().as_str() == "/__w/automata/automata")
    );
    assert_eq!(
        bash[0].argv().arguments(),
        ["-e", bash[0].argv().arguments()[1].as_str()]
    );
    assert!(bash[0].argv().arguments()[1].ends_with("/scripts/step-0.sh"));
    assert_eq!(
        bash[1].argv().arguments()[..4],
        ["--noprofile", "--norc", "-eo", "pipefail"]
    );
    assert!(bash[1].argv().arguments()[4].ends_with("/scripts/step-1.sh"));
    assert!(
        bash.iter()
            .flat_map(|command| command.argv().arguments())
            .all(|argument| !argument.contains(SECRET) && !argument.contains("printf"))
    );
    let second_environment = environment_map(bash[1]);
    assert_eq!(
        second_environment.get("LATER").map(String::as_str),
        Some("from-file")
    );
    assert_eq!(
        second_environment.get("PATH").map(String::as_str),
        Some("/custom/bin:/usr/bin:/bin")
    );
    let event = state
        .files
        .iter()
        .find(|(path, _)| path.ends_with("/event.json"))
        .expect("verified event copied into the attempt sandbox");
    assert_eq!(event.1, b"{}");
    drop(state);

    let logs = fixture
        .events
        .logs()
        .into_iter()
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    let logs = String::from_utf8(logs).expect("UTF-8 logs");
    assert!(!logs.contains(SECRET));
    assert!(!logs.contains("dynamic-secret"));
    assert!(logs.contains("*** *** visible"));
    assert!(!format!("{:?}", fixture.executor).contains(SECRET));
}

fn assert_sandbox_spec(fixture: &Fixture) {
    assert_eq!(fixture.provider.counts(), (1, 1, 0));
    let specs = fixture.provider.specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].root_filesystem(), RootFilesystemPolicy::Writable);
    assert_eq!(specs[0].privilege(), SandboxPrivilegePolicy::Administrator);
    assert_eq!(specs[0].workspace().as_str(), "/__w/automata/automata");
}

#[tokio::test]
async fn step_dot_working_directory_overrides_frontend_style_job_default_to_workspace() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success(); 2]);
    let steps = vec![
        StepIr::new(
            StepId::new("default-ui").expect("valid step"),
            "Default UI",
            SemanticStep::run("true", ShellSpec::Default),
        ),
        StepIr::new(
            StepId::new("repository-root").expect("valid step"),
            "Repository root",
            SemanticStep::Run {
                command: "true".to_owned(),
                shell: ShellSpec::Default,
                working_directory: Some(".".to_owned()),
            },
        ),
    ];
    let request = fixture.request(envelope_with_working_directory(steps, "ui"));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("frontend-style working-directory overrides execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let bash = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(bash.len(), 2);
    assert_eq!(
        bash[0].working_directory().as_str(),
        "/__w/automata/automata/ui"
    );
    assert_eq!(
        bash[1].working_directory().as_str(),
        "/__w/automata/automata"
    );
}

#[tokio::test]
async fn dot_working_directory_normalization_retains_parent_traversal_rejection() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success()]);
    let step = StepIr::new(
        StepId::new("escape").expect("valid step"),
        "Escape",
        SemanticStep::Run {
            command: "true".to_owned(),
            shell: ShellSpec::Default,
            working_directory: Some("./../outside".to_owned()),
        },
    );
    let request = fixture.request(envelope_with_working_directory(vec![step], "ui"));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect_err("parent traversal must remain invalid");

    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
}
