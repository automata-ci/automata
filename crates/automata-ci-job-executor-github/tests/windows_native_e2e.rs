#![cfg(windows)]

mod support;

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use automata_ci_core::{
    ExpressionProgram, JobConclusion, JobOutputDefinition, OutputSensitivity, ValueSource,
    ValueTemplate,
};
use automata_ci_execution::{
    EnvironmentName, EnvironmentValue, EnvironmentVariable, ExecutionEnvironment, TargetPath,
};
use automata_ci_job_executor_github::StaticGithubToolchain;
use automata_ci_runner_runtime::{
    CleanupRequest, ExecutionCancellation, ExecutionEvents, JobExecutor,
};
use automata_ci_workflow_github::{GithubConditionCompiler, GithubConditionPhase};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use support::{
    NativeWindowsFixture, run_step, run_step_with_named_shell,
    windows_envelope_with_output_definitions,
};

struct TemporaryProviderRoot {
    base: PathBuf,
    path: PathBuf,
}

impl TemporaryProviderRoot {
    fn new() -> Self {
        let base = std::env::temp_dir();
        assert!(
            base.is_absolute(),
            "Windows temp directory must be absolute"
        );
        let path = base.join(format!("automata-native-e2e-{}", Uuid::new_v4()));
        fs::create_dir(&path).expect("create unique provider root");
        Self { base, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryProviderRoot {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.starts_with("automata-native-e2e-"));
        if safe_name && self.path.parent() == Some(self.base.as_path()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn target(path: &Path) -> TargetPath {
    TargetPath::windows(
        path.to_str()
            .expect("temporary Windows path is Unicode")
            .trim_end_matches('\\'),
    )
    .expect("valid Windows target path")
}

fn standalone_pwsh_or_windows_powershell(powershell: &Path) -> PathBuf {
    let standalone = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
    if standalone.is_file() {
        return standalone;
    }

    // MSIX PowerShell under WindowsApps already belongs to an application Job
    // Object and cannot safely share the provider's lifetime Job Object with
    // subsequent mixed-shell launches. Hosted CI supplies standalone pwsh;
    // developer machines without it still exercise native PowerShell + cmd.
    powershell.to_path_buf()
}

fn collect_tree(root: &Path, output: &mut Vec<(PathBuf, u64)>) {
    for entry in fs::read_dir(root).expect("read provider tree") {
        let entry = entry.expect("read provider tree entry");
        let metadata = entry.metadata().expect("read provider tree metadata");
        if metadata.is_dir() {
            collect_tree(&entry.path(), output);
        } else {
            output.push((entry.path(), metadata.len()));
        }
    }
}

fn variable(name: &str, value: impl Into<String>) -> EnvironmentVariable {
    EnvironmentVariable::new(
        EnvironmentName::new(name).expect("environment name"),
        EnvironmentValue::new(value).expect("environment value"),
    )
}

fn output_expression(source: &str) -> ExpressionProgram {
    GithubConditionCompiler::default()
        .compile_value_expression(source, GithubConditionPhase::Step)
        .expect("valid output expression")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn native_provider_runs_powershell_then_cmd_with_command_file_propagation() {
    let root = TemporaryProviderRoot::new();
    let profile_root = root.path().join("work");
    let runner_root = root.path().join("scratch");
    let process_temp = root.path().join("temp");
    fs::create_dir(&process_temp).expect("create process temp directory");

    let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    let cmd = std::env::var_os("ComSpec")
        .map_or_else(|| system_root.join(r"System32\cmd.exe"), PathBuf::from);
    let powershell = system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let pwsh = standalone_pwsh_or_windows_powershell(&powershell);
    let toolchain =
        StaticGithubToolchain::windows(target(&pwsh), target(&powershell), target(&cmd))
            .expect("valid native Windows toolchain");
    let defaults = ExecutionEnvironment::new(vec![
        variable("SystemRoot", system_root.to_string_lossy()),
        variable("WINDIR", system_root.to_string_lossy()),
        variable("ComSpec", cmd.to_string_lossy()),
        variable("TEMP", process_temp.to_string_lossy()),
        variable("TMP", process_temp.to_string_lossy()),
        variable("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
    ])
    .expect("valid native process environment");
    let fixture = NativeWindowsFixture::new(
        root.path().to_path_buf(),
        target(&profile_root),
        target(&runner_root),
        defaults,
        toolchain,
    );
    let workspace = profile_root.join(r"automata\automata");
    let home = process_temp.to_string_lossy().into_owned();

    let first = run_step(
        "producer",
        "PowerShell producer",
        r"Write-Output 'native-powershell-log'
Set-Content -LiteralPath (Join-Path (Get-Location) 'powershell-artifact.txt') -Value 'powershell-artifact' -Encoding ascii
'file://powershell-artifact.txt' | Out-File -LiteralPath $env:GITHUB_ARTIFACTS -Encoding ascii -Append
New-Item -ItemType Directory -Force -Path (Join-Path (Get-Location) 'tools') | Out-Null
'FROM_POWERSHELL=ready' | Out-File -LiteralPath $env:GITHUB_ENV -Encoding ascii -Append
'digest=native-output' | Out-File -LiteralPath $env:GITHUB_OUTPUT -Encoding ascii -Append
(Join-Path (Get-Location) 'tools') | Out-File -LiteralPath $env:GITHUB_PATH -Encoding ascii -Append",
    )
    .with_environment(BTreeMap::from([(
        "HOME".to_owned(),
        ValueSource::Literal(home.clone()),
    )]));
    let second = run_step_with_named_shell(
        "consumer",
        "cmd consumer",
        r#"@echo native-cmd-log
@if /I not "%FROM_POWERSHELL%"=="ready" exit /b 31
@if /I not "%FROM_OUTPUT%"=="native-output" exit /b 32
@if not exist "powershell-artifact.txt" exit /b 33
@copy /Y "%GITHUB_ARTIFACTS_LIST%" "artifact-list.json" >nul
@echo cmd-artifact>cmd-artifact.txt"#,
        "cmd",
    )
    .with_environment(BTreeMap::from([
        ("HOME".to_owned(), ValueSource::Literal(home)),
        (
            "FROM_OUTPUT".to_owned(),
            ValueSource::Expression(output_expression("${{ steps.producer.outputs.digest }}")),
        ),
    ]));
    let output = JobOutputDefinition::new(
        "digest",
        ValueTemplate::expression(output_expression("${{ steps.producer.outputs.digest }}"))
            .expect("output template"),
        OutputSensitivity::Public,
    )
    .expect("output definition");
    let job = windows_envelope_with_output_definitions(vec![first, second], vec![output]);
    fixture
        .executor
        .admit(&job)
        .expect("native Windows job admits");
    let request = fixture.request(job);
    let session_id = request.session_id();
    let slot = request.slot();
    let attempt_id = request.lease().attempt_id();
    let guard = request.lease().guard();
    let events: Arc<dyn ExecutionEvents> = fixture.events.clone();

    let result = fixture
        .executor
        .execute(request, events.clone(), ExecutionCancellation::new())
        .await
        .unwrap_or_else(|error| {
            let mut root_entries = Vec::new();
            collect_tree(root.path(), &mut root_entries);
            let logs = fixture
                .events
                .logs()
                .into_iter()
                .flat_map(|event| event.payload().to_vec())
                .collect::<Vec<_>>();
            panic!(
                "native Windows job executes: {error:?}; sandbox={:?}; transitions={:?}; logs={:?}; root_entries={root_entries:?}",
                fixture.events.sandbox(),
                fixture.events.transitions(),
                String::from_utf8_lossy(&logs),
            );
        });

    assert_eq!(result.conclusion(), JobConclusion::Success);
    assert_eq!(
        result
            .outputs()
            .get("digest")
            .and_then(|value| value.public_value()),
        Some("native-output")
    );
    assert_eq!(
        fs::read_to_string(workspace.join("powershell-artifact.txt"))
            .expect("PowerShell artifact")
            .trim(),
        "powershell-artifact"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("cmd-artifact.txt"))
            .expect("cmd artifact")
            .trim(),
        "cmd-artifact"
    );
    let artifact_bytes = fs::read(workspace.join("powershell-artifact.txt"))
        .expect("read declared PowerShell artifact");
    let artifact_digest = format!("{:x}", Sha256::digest(&artifact_bytes));
    let artifact_list: serde_json::Value = serde_json::from_slice(
        &fs::read(workspace.join("artifact-list.json")).expect("copied artifact subject list"),
    )
    .expect("valid artifact subject list");
    assert_eq!(
        artifact_list,
        serde_json::json!({
            "version": 1,
            "subjects": [{
                "name": "powershell-artifact.txt",
                "digest": format!("sha256:{artifact_digest}"),
                "kind": "file"
            }]
        })
    );
    let logs = fixture
        .events
        .logs()
        .into_iter()
        .flat_map(|event| event.payload().to_vec())
        .collect::<Vec<_>>();
    let logs = String::from_utf8_lossy(&logs);
    assert!(logs.contains("native-powershell-log"));
    assert!(logs.contains("native-cmd-log"));

    let sandbox = fixture.events.sandbox().expect("durable sandbox identity");
    fixture
        .executor
        .cleanup(
            CleanupRequest::new(session_id, slot, attempt_id, guard, sandbox),
            events,
            ExecutionCancellation::new(),
        )
        .await
        .expect("native sandbox cleanup succeeds");
    assert!(!workspace.exists(), "workspace removed by provider cleanup");
    assert_eq!(fixture.events.sandbox(), None);
}
