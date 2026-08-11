mod support;

use std::{collections::BTreeMap, sync::Arc};

use automata_ci_core::{
    JobConclusion, JobSecretExposure, StepAnnotationLevel, StepIr, ValueSource,
};
use automata_ci_execution::{RootFilesystemPolicy, SandboxPrivilegePolicy};
use automata_ci_github_runtime::{CommandFileKind, WorkflowCommandPolicy};
use automata_ci_runner_runtime::{
    ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};

use support::{
    Fixture, PhaseResponse, SECRET, credential_free_envelope, envelope_with_environment,
    envelope_with_working_directory, environment_map, run_step, run_step_with_named_shell,
    run_step_with_working_directory,
};

#[tokio::test]
async fn credential_free_execution_has_no_authority_or_secret_and_emits_public_output() {
    let fixture = Fixture::secretless(
        Vec::new(),
        vec![PhaseResponse::success().with_stdout("public output\n")],
    );
    let job = credential_free_envelope(vec![run_step("public", "Public", "true")]);
    job.validate().expect("credential-free job is valid");
    let request = fixture.request(job);
    assert!(request.runtime_authorities().as_slice().is_empty());
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("credential-free job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.secret_exposure(), JobSecretExposure::Secretless);
    assert!(
        fixture
            .events
            .logs()
            .iter()
            .any(|event| event.payload() == b"public output\n"),
        "credential-free user output remains eligible for persistence"
    );
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let command = state.commands.last().expect("run command");
    assert!(
        command
            .environment()
            .values()
            .iter()
            .all(|value| !value.is_secret())
    );
    let environment = environment_map(command);
    for forbidden in [
        "ACTIONS_RESULTS_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GITHUB_TOKEN",
    ] {
        assert!(
            !environment.contains_key(forbidden),
            "unexpected {forbidden}"
        );
    }
}

#[tokio::test]
async fn run_steps_preserve_scripts_and_apply_fresh_command_files_after_exit() {
    let responses = vec![
        PhaseResponse::success()
            .with_stdout(format!(
                "{SECRET} before-dynamic\n::add-mask::dynamic-secret\n{SECRET} dynamic-secret visible\n"
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
        run_step("first", "First", first_script),
        run_step_with_named_shell("second", "Second", second_script, "bash"),
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
    assert!(
        bash[0]
            .environment()
            .values()
            .iter()
            .any(|variable| { variable.name().as_str() == "TOKEN" && variable.is_secret() })
    );
    assert_eq!(
        bash[1].argv().arguments()[..5],
        ["--noprofile", "--norc", "-e", "-o", "pipefail"]
    );
    assert!(bash[1].argv().arguments()[5].ends_with("/scripts/step-1.sh"));
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

    let logs = fixture.events.logs();
    let persisted = logs
        .iter()
        .map(|event| std::str::from_utf8(event.payload()).expect("UTF-8 test output"))
        .collect::<String>();
    assert!(persisted.contains("*** before-dynamic\n"));
    assert!(persisted.contains("*** *** visible\n"));
    assert!(!persisted.contains(SECRET));
    assert!(!persisted.contains("dynamic-secret"));
    assert!(!format!("{:?}", fixture.executor).contains(SECRET));
}

#[tokio::test]
async fn summaries_and_structured_annotations_are_masked_and_retained() {
    let secret = "attachment-secret";
    let response = PhaseResponse::success()
        .with_stdout(format!(
            "::add-mask::{secret}\n::warning file=src/lib.rs,line=7,title=Lint,ignored={secret}::problem {secret}\n"
        ))
        .with_file(
            CommandFileKind::StepSummary,
            format!("## Result\nvalue: {secret}\n").into_bytes(),
        );
    let fixture = Fixture::secretless(Vec::new(), vec![response]);
    let request = fixture.request(support::envelope(vec![run_step("build", "Build", "true")]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    let step = &result.steps()[0];
    assert_eq!(step.summary_markdown(), Some("## Result\nvalue: ***\n"));
    assert_eq!(step.annotations().len(), 1);
    let annotation = &step.annotations()[0];
    assert_eq!(annotation.level(), StepAnnotationLevel::Warning);
    assert_eq!(annotation.message(), "problem ***");
    assert_eq!(
        annotation
            .properties()
            .iter()
            .map(|property| (property.name(), property.value()))
            .collect::<Vec<_>>(),
        [("file", "src/lib.rs"), ("line", "7"), ("title", "Lint")]
    );
    assert!(!format!("{result:?}").contains(secret));
    assert!(
        !serde_json::to_string(&result)
            .expect("serialize")
            .contains(secret)
    );
}

#[tokio::test]
async fn python_and_pwsh_use_exact_script_suffixes_argv_and_powershell_fixup() {
    let fixture = Fixture::secretless(
        Vec::new(),
        vec![PhaseResponse::success(), PhaseResponse::success()],
    );
    let python = "print('python')\n";
    let pwsh = "Write-Output 'powershell'\n";
    let steps = vec![
        run_step_with_named_shell("python", "Python", python, "python"),
        run_step_with_named_shell("pwsh", "PowerShell", pwsh, "pwsh"),
    ];
    let request = fixture.request(support::envelope(steps));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("configured Python and PowerShell Core execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(state.scripts[0], python.as_bytes());
    assert_eq!(
        state.scripts[1],
        b"$ErrorActionPreference = 'stop'\nWrite-Output 'powershell'\n\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }"
    );
    let python_command = state
        .commands
        .iter()
        .find(|command| command.argv().program().as_str() == "/usr/bin/python3")
        .expect("Python command");
    assert_eq!(python_command.argv().arguments().len(), 1);
    assert!(python_command.argv().arguments()[0].ends_with("/scripts/step-0.py"));
    let pwsh_command = state
        .commands
        .iter()
        .find(|command| command.argv().program().as_str() == "/usr/bin/pwsh")
        .expect("PowerShell command");
    assert_eq!(pwsh_command.argv().arguments()[0], "-command");
    assert!(pwsh_command.argv().arguments()[1].starts_with(". '/__automata/attempts/"));
    assert!(pwsh_command.argv().arguments()[1].ends_with("/scripts/step-1.ps1'"));
}

#[tokio::test]
async fn stderr_mask_registration_redacts_a_secret_captured_on_stdout() {
    let secret = "cross-stream-dynamic-secret";
    let response = PhaseResponse::success()
        .with_stdout(format!("{secret}\n"))
        .with_stderr(format!("::add-mask::{secret}\n"));
    let fixture = Fixture::secretless(Vec::new(), vec![response]);
    let request = fixture.request(support::envelope(vec![run_step(
        "masked", "Masked", "true",
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.secret_exposure(), JobSecretExposure::ReadableSecret);
    let logs = fixture.events.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].channel(), automata_ci_core::LogChannel::Stdout);
    assert_eq!(logs[0].payload(), b"***\n");
}

#[tokio::test]
async fn ordered_cross_stream_stop_resume_does_not_apply_a_suppressed_mutation() {
    let token = "resume-token-123";
    let response = PhaseResponse::success()
        .with_stdout(format!("::stop-commands::{token}\n"))
        .with_stderr("::set-env name=BLOCKED::yes\n")
        .with_stdout(format!("::{token}::\n"));
    let fixture = Fixture::secretless(Vec::new(), vec![response, PhaseResponse::success()])
        .with_workflow_command_policy(WorkflowCommandPolicy::new(true, false));
    let request = fixture.request(support::envelope(vec![
        run_step("ordered-first", "Ordered first", "true"),
        run_step("ordered-second", "Ordered second", "true"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let commands = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(commands.len(), 2);
    assert!(!environment_map(commands[1]).contains_key("BLOCKED"));
}

#[tokio::test]
async fn ordered_cross_stream_resume_activates_a_later_stdout_mutation() {
    let token = "resume-token-123";
    let response = PhaseResponse::success()
        .with_stdout(format!("::stop-commands::{token}\n"))
        .with_stderr(format!("::{token}::\n"))
        .with_stdout("::set-env name=ALLOWED::yes\n");
    let fixture = Fixture::secretless(Vec::new(), vec![response, PhaseResponse::success()])
        .with_workflow_command_policy(WorkflowCommandPolicy::new(true, false));
    let request = fixture.request(support::envelope(vec![
        run_step("ordered-first", "Ordered first", "true"),
        run_step("ordered-second", "Ordered second", "true"),
    ]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let commands = state
        .commands
        .iter()
        .filter(|command| command.argv().program().as_str() == "/usr/bin/bash")
        .collect::<Vec<_>>();
    assert_eq!(commands.len(), 2);
    assert_eq!(
        environment_map(commands[1])
            .get("ALLOWED")
            .map(String::as_str),
        Some("yes")
    );
}

#[tokio::test]
async fn long_stop_command_token_is_redacted_without_hiding_adjacent_output() {
    let token = "resume-token-123";
    let response = PhaseResponse::success().with_stdout(format!(
        "::stop-commands::{token}\nordinary output\n{token}\n"
    ));
    let fixture = Fixture::secretless(Vec::new(), vec![response]);
    let request = fixture.request(support::envelope(vec![run_step(
        "stopped", "Stopped", "true",
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(result.secret_exposure(), JobSecretExposure::ReadableSecret);
    let logs = fixture.events.logs();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].payload(), b"ordinary output\n");
    assert_eq!(logs[1].payload(), b"***\n");
}

#[tokio::test]
async fn truncated_output_is_rejected_before_user_bytes_or_command_files_are_consumed() {
    let sentinel = "truncated-output-secret-sentinel";
    let response = PhaseResponse::success()
        .with_stdout(format!("{sentinel}\n"))
        .with_file(
            CommandFileKind::Environment,
            b"MUST_NOT_APPLY=truncated\n".to_vec(),
        )
        .truncated();
    let fixture = Fixture::secretless(Vec::new(), vec![response]);
    let request = fixture.request(support::envelope(vec![run_step(
        "truncated",
        "Truncated",
        "true",
    )]));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect_err("truncated output must fail closed");

    assert_eq!(error.kind(), ExecutorErrorKind::ResourceExhausted);
    let logs = fixture.events.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].channel(), automata_ci_core::LogChannel::System);
    let diagnostic = std::str::from_utf8(logs[0].payload()).expect("system diagnostic is UTF-8");
    assert_eq!(
        diagnostic,
        "command output exceeded the configured capture limit; user output was suppressed\n"
    );
    assert!(!diagnostic.contains(sentinel));
    assert_eq!(
        fixture
            .endpoint_state
            .lock()
            .expect("endpoint lock")
            .copy_from_calls,
        0,
        "command files must not be read after truncated output"
    );
}

#[tokio::test]
async fn failed_step_preserves_status_while_later_failure_and_always_steps_run() {
    let mut failed = PhaseResponse::success();
    failed.termination = automata_ci_execution::ExecutionTermination::Exited(1);
    let fixture = Fixture::new(
        Vec::new(),
        vec![failed, PhaseResponse::success(), PhaseResponse::success()],
    );
    let steps = vec![
        conditioned_run_step("fails", "exit 1", "success()"),
        conditioned_run_step("implicit-success", "exit 99", "success()"),
        conditioned_run_step("on-failure", "true", "failure()"),
        conditioned_run_step("always", "true", "always()"),
    ];
    let request = fixture.request(support::envelope(steps));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect("a failed step remains a terminal job result after cleanup steps");

    assert_eq!(result.conclusion(), JobConclusion::Failure);
    assert_eq!(result.steps().len(), 4);
    assert_eq!(result.steps()[0].outcome(), JobConclusion::Failure);
    assert_eq!(result.steps()[1].conclusion(), JobConclusion::Skipped);
    assert_eq!(result.steps()[2].conclusion(), JobConclusion::Success);
    assert_eq!(result.steps()[3].conclusion(), JobConclusion::Success);

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        state.scripts,
        [b"exit 1".as_slice(), b"true".as_slice(), b"true".as_slice()]
    );
}

fn conditioned_run_step(id: &str, command: &str, condition: &str) -> StepIr {
    let condition = GithubConditionCompiler::default()
        .compile_condition(Some(condition), GithubConditionPhase::Step)
        .expect("valid synthetic step condition");
    run_step(id, id, command).with_condition(condition)
}

fn assert_sandbox_spec(fixture: &Fixture) {
    assert_eq!(fixture.provider.counts(), (1, 1, 0));
    let specs = fixture.provider.specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].root_filesystem(), RootFilesystemPolicy::Writable);
    assert_eq!(specs[0].privilege(), SandboxPrivilegePolicy::Administrator);
    assert_eq!(specs[0].workspace().as_str(), "/__w/automata/automata");
    assert_eq!(specs[0].scratch(), None);
}

#[tokio::test]
async fn step_dot_working_directory_overrides_frontend_style_job_default_to_workspace() {
    let fixture = Fixture::new(Vec::new(), vec![PhaseResponse::success(); 2]);
    let steps = vec![
        run_step("default-ui", "Default UI", "true"),
        run_step_with_working_directory("repository-root", "Repository root", "true", "."),
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
    let step = run_step_with_working_directory("escape", "Escape", "true", "./../outside");
    let request = fixture.request(envelope_with_working_directory(vec![step], "ui"));
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(request, events, ExecutionCancellation::new())
        .await
        .expect_err("parent traversal must remain invalid");

    assert_eq!(error.kind(), ExecutorErrorKind::InvalidJob);
}
