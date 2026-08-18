mod support;

use std::sync::Arc;

use automata_ci_core::JobConclusion;
use automata_ci_runner_runtime::{ExecutionCancellation, ExecutionEvents, JobExecutor};

use support::{
    Fixture, PhaseResponse, action_step, local_action_step, prepared_node24_action,
    prepared_windows_namespace_unsafe_node24_action, windows_envelope,
};

#[tokio::test]
async fn admitted_windows_javascript_action_is_verified_materialized_and_executed() {
    let fixture = Fixture::windows_actions(
        vec![prepared_node24_action()],
        vec![PhaseResponse::success()],
    );
    let job = windows_envelope(vec![action_step("checkout", "actions/example")]);
    fixture.executor.admit(&job).expect("Windows action admits");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("verified Windows action executes");

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        result.conclusion(),
        JobConclusion::Success,
        "{result:?}; commands={:?}",
        state.commands
    );
    let action_commands = state
        .commands
        .iter()
        .filter(|command| {
            let program = command.argv().program().as_str();
            !program.eq_ignore_ascii_case(r"C:\Program Files\PowerShell\7\pwsh.exe")
                || command.argv().arguments().iter().any(|argument| {
                    argument.contains("action directory already exists")
                        || argument.contains("FileAttributes]::ReparsePoint")
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        action_commands
            .iter()
            .map(|command| command.argv().program().as_str())
            .collect::<Vec<_>>(),
        [
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\automata\tools\hash\automata-sha256.exe",
            r"C:\automata\tools\tar\tar.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\automata\externals\node24\node.exe",
            r"C:\automata\externals\node24\node.exe",
        ],
        "directory creation, archive digest, extraction, reparse scan, main, and post are ordered"
    );
    assert!(
        action_commands[0].argv().arguments()[4].contains("action directory already exists"),
        "materialization refuses a stale action directory"
    );
    assert!(
        action_commands[3].argv().arguments()[4].contains("FileAttributes]::ReparsePoint"),
        "the extracted tree is scanned for Windows reparse points"
    );
    assert!(
        action_commands[4].argv().arguments()[0].ends_with(r"\actions\action-0\root\dist\index.js")
    );
}

#[tokio::test]
async fn admitted_windows_local_action_uses_a_reparse_safe_pwsh_probe() {
    let fixture = Fixture::windows_actions(Vec::new(), vec![PhaseResponse::success()]);
    fixture
        .endpoint_state
        .lock()
        .expect("endpoint lock")
        .files
        .insert(
            r"D:\a\automata\automata\local-action\action.yml".to_owned(),
            b"name: Local\nruns:\n  using: node24\n  main: dist/index.js\n".to_vec(),
        );
    let job = windows_envelope(vec![local_action_step("local", "./local-action")]);
    fixture
        .executor
        .admit(&job)
        .expect("Windows local action admits");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("Windows local action executes");

    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert_eq!(
        result.conclusion(),
        JobConclusion::Success,
        "{result:?}; commands={:?}",
        state.commands
    );
    let probe = state
        .commands
        .iter()
        .find(|command| {
            command
                .argv()
                .arguments()
                .iter()
                .any(|argument| argument.contains("automata-local-action-metadata"))
        })
        .expect("local metadata probe");
    assert_eq!(
        probe.argv().program().as_str(),
        r"C:\Program Files\PowerShell\7\pwsh.exe"
    );
    assert!(
        probe
            .argv()
            .arguments()
            .iter()
            .any(|argument| argument.contains("FileAttributes]::ReparsePoint")),
        "the local action directory and tree are checked for reparse points"
    );
    let node = state
        .commands
        .iter()
        .find(|command| {
            command
                .argv()
                .program()
                .as_str()
                .eq_ignore_ascii_case(r"C:\automata\externals\node24\node.exe")
        })
        .expect("local Node action invocation");
    assert_eq!(
        node.argv().arguments()[0],
        r"D:\a\automata\automata\local-action\dist\index.js"
    );
}

#[tokio::test]
async fn admitted_windows_local_composite_executes_its_pwsh_child() {
    let fixture = Fixture::windows_actions(Vec::new(), vec![PhaseResponse::success()]);
    fixture.endpoint_state.lock().expect("endpoint lock").files.insert(
        r"D:\a\automata\automata\local-composite\action.yml".to_owned(),
        b"name: Local composite\nruns:\n  using: composite\n  steps:\n    - id: child\n      shell: pwsh\n      run: Write-Output 'windows-composite'\n"
            .to_vec(),
    );
    let job = windows_envelope(vec![local_action_step(
        "local-composite",
        "./local-composite",
    )]);
    fixture
        .executor
        .admit(&job)
        .expect("Windows local composite admits");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("Windows local composite executes");

    assert_eq!(result.conclusion(), JobConclusion::Success, "{result:?}");
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(
        state.scripts.iter().any(|script| script
            .windows(b"windows-composite".len())
            .any(|window| { window == b"windows-composite" })),
        "the composite child is materialized as a PowerShell script"
    );
    assert!(state.commands.iter().any(|command| {
        command
            .argv()
            .program()
            .as_str()
            .eq_ignore_ascii_case(r"C:\Program Files\PowerShell\7\pwsh.exe")
            && command
                .argv()
                .arguments()
                .iter()
                .any(|argument| argument.ends_with(".ps1'"))
    }));
}

#[tokio::test]
async fn nested_repository_action_is_validated_before_windows_materialization() {
    let fixture = Fixture::windows_actions(
        vec![prepared_windows_namespace_unsafe_node24_action()],
        Vec::new(),
    );
    fixture.endpoint_state.lock().expect("endpoint lock").files.insert(
        r"D:\a\automata\automata\local-parent\action.yml".to_owned(),
        b"name: Local parent\nruns:\n  using: composite\n  steps:\n    - uses: owner/nested@0123456789abcdef0123456789abcdef01234567\n"
            .to_vec(),
    );
    let job = windows_envelope(vec![local_action_step("parent", "./local-parent")]);
    fixture
        .executor
        .admit(&job)
        .expect("Windows local composite admits");
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(fixture.request(job), events, ExecutionCancellation::new())
        .await
        .expect("unsafe nested archive becomes a failed step");

    assert_eq!(result.conclusion(), JobConclusion::Failure, "{result:?}");
    let state = fixture.endpoint_state.lock().expect("endpoint lock");
    assert!(
        state.commands.iter().all(|command| {
            let program = command.argv().program().as_str();
            !program.eq_ignore_ascii_case(r"C:\automata\tools\hash\automata-sha256.exe")
                && !program.eq_ignore_ascii_case(r"C:\automata\tools\tar\tar.exe")
        }),
        "the namespace-unsafe nested archive must fail before hash or extraction: {:?}",
        state.commands
    );
}
