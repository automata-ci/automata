mod support;

use std::{collections::BTreeMap, sync::Arc};

use automata_ci_core::{
    ExpressionProgram, JobConclusion, JobOutputDefinition, OutputSensitivity, ValueSource,
    ValueTemplate,
};
use automata_ci_execution::{NetworkPolicy, RootFilesystemPolicy, SandboxPrivilegePolicy};
use automata_ci_github_runtime::CommandFileKind;
use automata_ci_runner_runtime::{
    AdmissionRejection, ExecutionCancellation, ExecutionEvents, ExecutorErrorKind, JobExecutor,
};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};

use support::{
    Fixture, PhaseResponse, action_step, run_step, run_step_with_named_shell,
    run_step_with_working_directory, windows_envelope, windows_envelope_with_output_definitions,
};

fn output_expression(source: &str) -> ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_value_expression(source, GithubConditionPhase::Step)
        .expect("valid output expression")
}

fn phase_commands(state: &support::EndpointState) -> Vec<&automata_ci_execution::ExecutionCommand> {
    state
        .commands
        .iter()
        .filter(|command| {
            command
                .environment()
                .values()
                .iter()
                .any(|variable| variable.name().as_str() == "GITHUB_ENV")
        })
        .collect()
}

fn environment_value<'command>(
    command: &'command automata_ci_execution::ExecutionCommand,
    name: &str,
) -> Option<&'command str> {
    command
        .environment()
        .values()
        .iter()
        .find(|variable| variable.name().as_str().eq_ignore_ascii_case(name))
        .map(|variable| variable.value().expose())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn windows_default_shell_maps_paths_and_applies_crlf_command_files() {
    let fixture = Fixture::windows(vec![
        PhaseResponse::success()
            .with_file(
                CommandFileKind::Environment,
                b"Mixed=one\r\nMIXED=two\r\n".to_vec(),
            )
            .with_file(CommandFileKind::Path, b"D:\\tools\r\n".to_vec())
            .with_file(CommandFileKind::Output, b"digest=abc123\r\n".to_vec()),
        PhaseResponse::success(),
    ]);
    let second = run_step_with_working_directory(
        "consumer",
        "Consumer",
        "Write-Output $env:FROM_OUTPUT",
        r"subdir",
    )
    .with_environment(BTreeMap::from([(
        "FROM_OUTPUT".to_owned(),
        ValueSource::Expression(output_expression("${{ steps.producer.outputs.digest }}")),
    )]));
    let output = JobOutputDefinition::new(
        "digest",
        ValueTemplate::expression(output_expression("${{ steps.producer.outputs.digest }}"))
            .expect("output template"),
        OutputSensitivity::Public,
    )
    .expect("output definition");
    let job = windows_envelope_with_output_definitions(
        vec![
            run_step("producer", "Producer", "Write-Output 'producer'"),
            second,
        ],
        vec![output],
    );
    fixture.executor.admit(&job).expect("Windows job admits");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("Windows job executes");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(
        result
            .outputs()
            .get("digest")
            .and_then(|value| value.public_value()),
        Some("abc123")
    );

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let commands = phase_commands(&state);
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().all(|command| {
        command
            .argv()
            .program()
            .as_str()
            .eq_ignore_ascii_case(r"C:\Program Files\PowerShell\7\pwsh.exe")
    }));
    assert!(commands[0].argv().arguments()[1].ends_with("\\scripts\\step-0.ps1'"));
    assert!(commands[1].argv().arguments()[1].ends_with("\\scripts\\step-1.ps1'"));
    assert_eq!(
        commands[1].working_directory().as_str(),
        r"D:\a\automata\automata\subdir"
    );
    assert_eq!(environment_value(commands[1], "mixed"), Some("two"));
    assert_eq!(
        commands[1]
            .environment()
            .values()
            .iter()
            .filter(|variable| variable.name().as_str().eq_ignore_ascii_case("mixed"))
            .count(),
        1
    );
    assert_eq!(
        environment_value(commands[1], "FROM_OUTPUT"),
        Some("abc123")
    );
    assert_eq!(
        environment_value(commands[1], "PATH"),
        Some(r"D:\tools;C:\Windows\System32")
    );
    assert!(
        environment_value(commands[1], "GITHUB_ENV")
            .is_some_and(|path| path.contains(r"\commands\phase-4-env"))
    );
    assert_eq!(state.scripts.len(), 2);
    assert!(state.scripts.iter().all(|script| {
        script.starts_with(b"$ErrorActionPreference = 'stop'\n")
            && script.ends_with(
                b"if ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }",
            )
    }));
    drop(state);

    let specs = fixture.provider.specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].workspace().as_str(), r"D:\a\automata\automata");
    assert_eq!(specs[0].network(), NetworkPolicy::Host);
    assert_eq!(specs[0].root_filesystem(), RootFilesystemPolicy::Host);
    assert_eq!(specs[0].privilege(), SandboxPrivilegePolicy::Host);
    assert!(
        specs[0]
            .scratch()
            .is_some_and(|path| path.as_str().starts_with(r"D:\_automata\attempts\"))
    );
}

#[tokio::test]
async fn windows_named_shells_use_platform_argv_and_script_extensions() {
    let fixture = Fixture::windows(vec![PhaseResponse::success(); 4]);
    let job = windows_envelope(vec![
        run_step_with_named_shell("pwsh", "pwsh", "Write-Output pwsh", "pwsh"),
        run_step_with_named_shell(
            "powershell",
            "powershell",
            "Write-Output powershell",
            "powershell",
        ),
        run_step_with_named_shell("cmd", "cmd", "echo cmd", "cmd"),
        run_step_with_named_shell("python", "python", "print('python')", "python"),
    ]);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("configured Windows shells execute");

    assert_eq!(result.conclusion(), JobConclusion::Success);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    let commands = phase_commands(&state);
    assert_eq!(commands.len(), 4);
    assert_eq!(
        commands[0].argv().program().as_str(),
        r"C:\Program Files\PowerShell\7\pwsh.exe"
    );
    assert!(commands[0].argv().arguments()[1].ends_with("step-0.ps1'"));
    assert_eq!(
        commands[1].argv().program().as_str(),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    );
    assert!(commands[1].argv().arguments()[1].ends_with("step-1.ps1'"));
    assert_eq!(
        commands[2].argv().program().as_str(),
        r"C:\Windows\System32\cmd.exe"
    );
    assert_eq!(
        &commands[2].argv().arguments()[..4],
        ["/D", "/E:ON", "/V:OFF", "/C"]
    );
    assert!(commands[2].argv().arguments()[4].ends_with("step-2.cmd"));
    assert_eq!(
        commands[3].argv().program().as_str(),
        r"C:\hostedtoolcache\windows\Python\3.13.0\x64\python.exe"
    );
    assert!(commands[3].argv().arguments()[0].ends_with("step-3.py"));
    assert_eq!(state.scripts[2], b"echo cmd\r\n");
    assert_eq!(state.scripts[3], b"print('python')");
}

#[test]
fn windows_action_steps_are_rejected_during_admission() {
    let fixture = Fixture::windows(Vec::new());
    let job = windows_envelope(vec![action_step("checkout", "actions/checkout")]);

    assert_eq!(
        fixture.executor.admit(&job),
        Err(AdmissionRejection::InvalidJob)
    );
    assert_eq!(fixture.provider.counts(), (0, 0, 0));
}

#[tokio::test]
async fn windows_rejects_unconfigured_bash_shell() {
    let fixture = Fixture::windows(Vec::new());
    let job = windows_envelope(vec![run_step_with_named_shell(
        "bash",
        "bash",
        "echo unsupported",
        "bash",
    )]);
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let error = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect_err("Bash is not implicitly provided by a native Windows profile");

    assert_eq!(error.kind(), ExecutorErrorKind::Unsupported);
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(phase_commands(&state).is_empty());
    assert!(state.scripts.is_empty());
}
