use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, bail, ensure};
use automata_ci_core::{
    CompiledValueTemplate, LogicalJobKind, LogicalStepKind, WorkflowEventProvenance,
};
use automata_ci_workflow_github::{
    CompileWorkflowRequest, GithubWorkflowCompiler, GithubWorkflowFrontend, ParseWorkflowRequest,
    SourceId, SourceOrigin, SourceProvenance, WorkflowFrontend as _,
};

use crate::{
    app::{
        http,
        web::{DemoWebData, demo_router},
    },
    cli::DemoArgs,
    server::Readiness,
};

const MAX_WORKFLOW_BYTES: u64 = 1024 * 1024;

pub(crate) async fn run(args: &DemoArgs) -> Result<()> {
    ensure!(
        args.allow_host_execution,
        "demo workflows inherit the current Windows user token; rerun with --allow-host-execution only for a trusted workflow"
    );
    ensure!(
        args.listen.ip().is_loopback(),
        "demo visualization must bind a literal loopback address"
    );
    #[cfg(windows)]
    {
        let data = Arc::new(DemoWebData::new(
            "Native Windows local evaluation".to_owned(),
            args.workflow.to_string_lossy().replace('\\', "/"),
        ));
        let server = if args.no_visual {
            None
        } else {
            let listener = tokio::net::TcpListener::bind(args.listen)
                .await
                .context("failed to bind demo visualization listener")?;
            let address = listener
                .local_addr()
                .context("failed to inspect demo listener")?;
            let router = http::router_with_readiness_web_data(
                Readiness::all_ready(),
                data.clone(),
                None,
                None,
                DemoWebData::context(),
            )
            .context("failed to initialize demo visualization")?
            .merge(demo_router(data.clone()));
            let url = format!("http://{address}{}", DemoWebData::dashboard_url());
            eprintln!("Visual run page: {url}");
            Some(tokio::spawn(
                async move { axum::serve(listener, router).await },
            ))
        };
        data.start();
        let owned_args = args.clone();
        let execution_data = data.clone();
        let execution =
            tokio::task::spawn_blocking(move || windows::run(&owned_args, &execution_data))
                .await
                .context("native demo execution task failed")?;
        if let Err(error) = &execution {
            data.finish(false, &format!("Demo setup or execution failed: {error}"));
        }
        if server.is_some() {
            eprintln!("Demo finished; inspect the visual run page, then press Ctrl-C to stop it");
            crate::shutdown::wait().await;
        }
        if let Some(server) = server {
            server.abort();
        }
        execution
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        bail!("the native local demo is currently available only on Windows")
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed demo subset is kept as one auditable validation boundary"
)]
fn compile_single_job(workflow_path: &Path, source: &str) -> Result<Vec<DemoStep>> {
    let display_path = workflow_path.to_string_lossy().replace('\\', "/");
    let source_id: Arc<str> = Arc::from(display_path);
    let provenance = SourceProvenance::new(
        SourceId::new(Arc::clone(&source_id)),
        SourceOrigin::Repository {
            repository: Arc::from("local/evaluation"),
            revision: Arc::from("0000000000000000000000000000000000000000"),
            path: source_id,
        },
    );
    let parsed =
        GithubWorkflowFrontend::default().parse(ParseWorkflowRequest::new(provenance, source));
    if !parsed.is_accepted() {
        return Err(diagnostics("workflow parsing failed", parsed.diagnostics()));
    }
    let report = GithubWorkflowCompiler::new().compile(CompileWorkflowRequest::new(
        parsed
            .plan()
            .context("accepted workflow did not retain a source plan")?,
        WorkflowEventProvenance::new("github", "workflow_dispatch")
            .with_delivery_id("local-evaluation")
            .with_commit_sha("0000000000000000000000000000000000000000")
            .with_git_ref("refs/heads/local-evaluation"),
    ));
    if !report.is_accepted() {
        return Err(diagnostics(
            "workflow compilation failed",
            report.diagnostics(),
        ));
    }
    let plan = report
        .plan()
        .context("accepted workflow did not produce a plan")?;
    ensure!(
        plan.jobs().len() == 1,
        "local evaluation currently requires exactly one workflow job"
    );
    ensure!(
        plan.logical().concurrency().is_none(),
        "local evaluation does not support workflow concurrency"
    );
    ensure!(
        plan.logical().environment().entries().is_empty(),
        "local evaluation does not support workflow environment values yet"
    );
    let job = &plan.jobs()[0];
    ensure!(
        job.needs().is_empty(),
        "local evaluation does not schedule job dependencies"
    );
    ensure!(
        job.condition().is_none(),
        "local evaluation does not support job conditions yet"
    );
    ensure!(
        job.strategy().is_none(),
        "local evaluation does not support job strategies yet"
    );
    ensure!(
        job.environment().entries().is_empty(),
        "local evaluation does not support job environment values yet"
    );
    ensure!(
        job.concurrency().is_none(),
        "local evaluation does not support job concurrency"
    );
    ensure!(
        job.deployment().is_none(),
        "local evaluation does not support deployment environments"
    );
    let LogicalJobKind::Steps(step_job) = job.execution() else {
        bail!("local evaluation does not support reusable workflow jobs");
    };
    ensure!(
        step_job.services().is_empty(),
        "local evaluation does not support service containers"
    );
    ensure!(
        step_job.resources().is_none(),
        "local evaluation does not support resource overrides yet"
    );

    step_job
        .steps()
        .iter()
        .enumerate()
        .map(|(index, step)| {
            ensure!(
                step.condition().is_none(),
                "local evaluation does not support step conditions yet"
            );
            ensure!(
                step.environment().entries().is_empty(),
                "local evaluation does not support step environment values yet"
            );
            ensure!(
                step.continue_on_error().is_none(),
                "local evaluation does not support continue-on-error yet"
            );
            ensure!(
                step.timeout().is_none(),
                "local evaluation does not support per-step timeouts yet"
            );
            let LogicalStepKind::Run(run) = step.execution() else {
                bail!("local evaluation rejects every uses: action; use trusted run: steps");
            };
            let script = literal(run.script().value(), "run script")?.to_owned();
            let shell = run
                .shell()
                .map(|value| literal(value.value(), "step shell"))
                .transpose()?
                .unwrap_or("powershell")
                .to_owned();
            ensure!(
                run.working_directory().is_none(),
                "local evaluation does not support step working-directory yet"
            );
            Ok(DemoStep {
                number: index + 1,
                name: step
                    .name()
                    .map(|value| literal(value.value(), "step name"))
                    .transpose()?
                    .unwrap_or("run")
                    .to_owned(),
                script,
                shell,
            })
        })
        .collect()
}

fn literal<'a>(value: &'a CompiledValueTemplate, field: &str) -> Result<&'a str> {
    match value {
        CompiledValueTemplate::Literal(value) => Ok(value),
        CompiledValueTemplate::Expression(_) => {
            bail!("local evaluation requires a literal {field}")
        }
    }
}

fn diagnostics(
    prefix: &str,
    diagnostics: &[automata_ci_workflow_github::Diagnostic],
) -> anyhow::Error {
    let details = diagnostics
        .iter()
        .map(|diagnostic| format!("{}: {}", diagnostic.code(), diagnostic.message()))
        .collect::<Vec<_>>()
        .join("; ");
    anyhow::anyhow!("{prefix}: {details}")
}

#[derive(Debug)]
struct DemoStep {
    number: usize,
    name: String,
    script: String,
    shell: String,
}

#[cfg(windows)]
mod windows {
    use std::{ffi::OsStr, time::Duration};

    use automata_ci_execution::{
        DestroySandbox, EnvironmentName, EnvironmentProfile, EnvironmentProfileId,
        EnvironmentValue, EnvironmentVariable, ExecutionArgv, ExecutionCommand,
        ExecutionEnvironment, ExecutionTermination, NetworkPolicy, NeverCancelled, OperationId,
        ResourceLimits, RootFilesystemPolicy, SandboxEnvironment, SandboxGeneration,
        SandboxPrivilegePolicy, SandboxProvider as _, SandboxSpec, Sha256Digest, TargetPath,
    };
    use automata_ci_sandbox_windows::{WindowsSandboxProvider, WindowsSandboxProviderOptions};

    use super::*;

    const MAX_REPOSITORY_FILES: usize = 4096;
    const MAX_REPOSITORY_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_STEP_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

    #[allow(
        clippy::too_many_lines,
        reason = "native demo setup keeps lifecycle and cleanup ownership visible in one boundary"
    )]
    pub(super) fn run(args: &DemoArgs, visualization: &DemoWebData) -> Result<()> {
        let repository = args
            .repo
            .canonicalize()
            .context("demo repository does not exist")?;
        ensure!(repository.is_dir(), "demo repository must be a directory");
        let workflow = if args.workflow.is_absolute() {
            args.workflow.canonicalize()
        } else {
            repository.join(&args.workflow).canonicalize()
        }
        .context("demo workflow does not exist")?;
        ensure!(
            workflow.starts_with(&repository),
            "demo workflow must be inside the selected repository"
        );
        let metadata = fs::metadata(&workflow).context("could not inspect demo workflow")?;
        ensure!(metadata.is_file(), "demo workflow must be a regular file");
        ensure!(
            metadata.len() <= MAX_WORKFLOW_BYTES,
            "demo workflow exceeds the 1 MiB limit"
        );
        let source = fs::read_to_string(&workflow).context("demo workflow must be UTF-8")?;
        let relative_workflow = workflow
            .strip_prefix(&repository)
            .context("workflow containment changed")?;
        let steps = compile_single_job(relative_workflow, &source)?;
        visualization.set_steps(
            &steps
                .iter()
                .map(|step| (step.number, step.name.clone(), step.shell.clone()))
                .collect::<Vec<_>>(),
        );

        eprintln!("EVALUATION MODE: trusted workflow processes inherit your Windows user token");
        let root = DemoRoot::new()?;
        let provider = WindowsSandboxProvider::open(
            WindowsSandboxProviderOptions::new(root.path.clone())
                .context("invalid demo state root")?,
        )
        .context("could not open the native Windows provider")?;
        let profile_workspace = root.path.join("workspaces");
        let workspace = profile_workspace.join("repository");
        let scratch = root.path.join("scratch");
        let environment = SandboxEnvironment::native(
            EnvironmentProfile::new(
                EnvironmentProfileId::new("automata.demo/windows-native-x86-64-v1")
                    .context("invalid demo profile")?,
                Sha256Digest::from_bytes([0x44; 32]),
            ),
            target(&profile_workspace)?,
            ExecutionEnvironment::empty(),
        )
        .context("invalid demo sandbox environment")?;
        let spec = SandboxSpec::new(
            OperationId::new(),
            SandboxGeneration::new(1).context("invalid demo generation")?,
            environment,
            target(&workspace)?,
            NetworkPolicy::Host,
            RootFilesystemPolicy::Host,
            ResourceLimits::new(2 * 1024 * 1024 * 1024, 4_000, 128)
                .context("invalid demo resource limits")?,
        )
        .with_privilege(SandboxPrivilegePolicy::Host)
        .with_scratch(target(&scratch)?);
        let record = provider
            .create(&spec, &NeverCancelled)
            .context("could not create demo workspace")?;
        let endpoint = provider
            .attach(record.handle(), &NeverCancelled)
            .context("could not attach demo workspace")?;
        let execution = (|| {
            fs::create_dir_all(scratch.join("temp"))
                .context("could not create demo process temp")?;
            fs::create_dir_all(scratch.join("home"))
                .context("could not create demo process home")?;
            copy_repository(&repository, &workspace)?;
            execute_steps(
                endpoint.as_ref(),
                &workspace,
                &scratch,
                &steps,
                visualization,
            )
        })();
        drop(endpoint);
        let cleanup = provider.destroy(
            &DestroySandbox::new(
                OperationId::new(),
                record.handle().clone(),
                record.generation(),
            ),
            &NeverCancelled,
        );
        if let Err(error) = cleanup {
            visualization.finish(false, "Workspace cleanup failed");
            return Err(error).context("demo execution ended but workspace cleanup failed");
        }
        match &execution {
            Ok(()) => visualization.finish(true, "Demo workflow completed successfully"),
            Err(error) => visualization.finish(false, &format!("Demo workflow failed: {error}")),
        }
        execution
    }

    fn execute_steps(
        endpoint: &dyn automata_ci_execution::ExecutionEndpoint,
        workspace: &Path,
        scratch: &Path,
        steps: &[DemoStep],
        visualization: &DemoWebData,
    ) -> Result<()> {
        for step in steps {
            eprintln!("==> step {}: {}", step.number, step.name);
            visualization.step_started(step.number, &step.name);
            let extension = match step.shell.to_ascii_lowercase().as_str() {
                "powershell" | "pwsh" => "ps1",
                "cmd" => "cmd",
                _ => bail!(
                    "unsupported Windows demo shell `{}`; use powershell, pwsh, or cmd",
                    step.shell
                ),
            };
            let script_path =
                workspace.join(format!(".automata-demo-step-{}.{}", step.number, extension));
            fs::write(&script_path, &step.script).context("could not stage demo script")?;
            let (program, arguments) = shell_command(&step.shell, &step.script, &script_path)?;
            let command = ExecutionCommand::new(
                OperationId::new(),
                ExecutionArgv::new(target(&program)?, arguments)
                    .context("invalid demo shell command")?,
                target(workspace)?,
                process_environment(scratch)?,
                Duration::from_mins(30),
                MAX_STEP_OUTPUT_BYTES,
            )
            .context("invalid demo execution request")?;
            let output = endpoint
                .exec(&command, &NeverCancelled)
                .context("native demo step failed to execute")?;
            io::stdout().write_all(output.stdout())?;
            io::stderr().write_all(output.stderr())?;
            visualization.stdout(output.stdout());
            visualization.stderr(output.stderr());
            let exit_code = match output.termination() {
                ExecutionTermination::Exited(code) => code,
                ExecutionTermination::Signalled => -1,
                ExecutionTermination::TimedOut => -2,
                ExecutionTermination::Cancelled => -3,
            };
            visualization.step_finished(step.number, exit_code);
            ensure!(
                !output.was_truncated(),
                "demo step output exceeded the 4 MiB limit"
            );
            ensure!(
                output.termination() == ExecutionTermination::Exited(0),
                "demo step {} exited with {:?}",
                step.number,
                output.termination()
            );
            let _ = fs::remove_file(script_path);
        }
        eprintln!("demo workflow completed successfully");
        Ok(())
    }

    fn shell_command(
        shell: &str,
        source: &str,
        script_path: &Path,
    ) -> Result<(PathBuf, Vec<String>)> {
        let system_root =
            PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot is not set")?);
        ensure!(
            source.encode_utf16().count() <= 16 * 1024,
            "demo scripts are limited to 16384 UTF-16 units"
        );
        match shell.to_ascii_lowercase().as_str() {
            "powershell" => Ok((
                system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-Command".into(),
                    source.to_owned(),
                ],
            )),
            "pwsh" => {
                let program = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
                ensure!(
                    program.is_file(),
                    "standalone PowerShell 7 is not installed at C:\\Program Files\\PowerShell\\7\\pwsh.exe"
                );
                Ok((
                    program,
                    vec![
                        "-NoLogo".into(),
                        "-NoProfile".into(),
                        "-NonInteractive".into(),
                        "-Command".into(),
                        source.to_owned(),
                    ],
                ))
            }
            "cmd" => {
                let script = script_path.to_string_lossy();
                Ok((
                    std::env::var_os("ComSpec")
                        .map_or_else(|| system_root.join(r"System32\cmd.exe"), PathBuf::from),
                    vec![
                        "/D".into(),
                        "/E:ON".into(),
                        "/V:OFF".into(),
                        "/C".into(),
                        script.into_owned(),
                    ],
                ))
            }
            _ => bail!("unsupported Windows demo shell `{shell}`"),
        }
    }

    fn process_environment(scratch: &Path) -> Result<ExecutionEnvironment> {
        let system_root = std::env::var("SystemRoot").context("SystemRoot is not set")?;
        let comspec =
            std::env::var("ComSpec").unwrap_or_else(|_| format!(r"{system_root}\System32\cmd.exe"));
        let temp = scratch.join("temp");
        let mut values = vec![
            ("SystemRoot", system_root.clone()),
            ("WINDIR", system_root),
            ("ComSpec", comspec),
            ("TEMP", temp.to_string_lossy().into_owned()),
            ("TMP", temp.to_string_lossy().into_owned()),
            ("HOME", scratch.join("home").to_string_lossy().into_owned()),
            ("PATHEXT", ".COM;.EXE;.BAT;.CMD".to_owned()),
        ];
        if let Ok(path) = std::env::var("PATH") {
            values.push(("PATH", path));
        }
        ExecutionEnvironment::new(
            values
                .into_iter()
                .map(|(name, value)| {
                    Ok(EnvironmentVariable::new(
                        EnvironmentName::new(name).context("invalid demo environment name")?,
                        EnvironmentValue::new(value).context("invalid demo environment value")?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        )
        .context("invalid demo process environment")
    }

    fn copy_repository(source: &Path, destination: &Path) -> Result<()> {
        let mut files = 0usize;
        let mut bytes = 0u64;
        copy_directory(source, destination, &mut files, &mut bytes)
    }

    fn copy_directory(
        source: &Path,
        destination: &Path,
        files: &mut usize,
        bytes: &mut u64,
    ) -> Result<()> {
        fs::create_dir_all(destination).context("could not create demo repository directory")?;
        for entry in fs::read_dir(source).context("could not read demo repository")? {
            let entry = entry.context("could not read demo repository entry")?;
            let name = entry.file_name();
            if matches!(name.to_str(), Some(".git" | "target" | ".automata")) {
                continue;
            }
            let file_type = entry
                .file_type()
                .context("could not inspect demo repository entry")?;
            ensure!(
                !file_type.is_symlink(),
                "demo repository cannot contain symbolic links or junctions"
            );
            let target = destination.join(&name);
            if file_type.is_dir() {
                copy_directory(&entry.path(), &target, files, bytes)?;
            } else if file_type.is_file() {
                let size = entry
                    .metadata()
                    .context("could not inspect demo repository file")?
                    .len();
                *files = files
                    .checked_add(1)
                    .context("demo repository file count overflow")?;
                *bytes = bytes
                    .checked_add(size)
                    .context("demo repository size overflow")?;
                ensure!(
                    *files <= MAX_REPOSITORY_FILES,
                    "demo repository exceeds the 4096-file limit"
                );
                ensure!(
                    *bytes <= MAX_REPOSITORY_BYTES,
                    "demo repository exceeds the 64 MiB limit"
                );
                fs::copy(entry.path(), target).context("could not copy demo repository file")?;
            } else {
                bail!("demo repository contains an unsupported filesystem entry");
            }
        }
        Ok(())
    }

    fn target(path: &Path) -> Result<TargetPath> {
        TargetPath::windows(path.to_str().context("demo paths must be Unicode")?)
            .context("invalid Windows demo path")
    }

    struct DemoRoot {
        parent: PathBuf,
        path: PathBuf,
    }

    impl DemoRoot {
        fn new() -> Result<Self> {
            let parent = std::env::temp_dir();
            let path = parent.join(format!("automata-demo-{}", OperationId::new()));
            fs::create_dir(&path).context("could not create demo state root")?;
            Ok(Self { parent, path })
        }
    }

    impl Drop for DemoRoot {
        fn drop(&mut self) {
            let safe = self.path.parent() == Some(self.parent.as_path())
                && self
                    .path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with("automata-demo-"));
            if safe {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::compile_single_job;

    #[test]
    fn compiler_accepts_one_literal_run_job() {
        let source = r#"name: Local demo
on: workflow_dispatch
jobs:
  smoke:
    runs-on: windows
    steps:
      - name: First
        shell: powershell
        run: Write-Output 'first'
      - shell: cmd
        run: echo second
"#;

        let steps = compile_single_job(Path::new(".ci/workflows/demo.yml"), source)
            .expect("literal demo workflow");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].name, "First");
        assert_eq!(steps[0].shell, "powershell");
        assert_eq!(steps[1].shell, "cmd");
    }

    #[test]
    fn compiler_rejects_uses_actions_before_execution() {
        let source = r#"name: Local demo
on: workflow_dispatch
jobs:
  smoke:
    runs-on: windows
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
"#;

        let error = compile_single_job(Path::new(".ci/workflows/demo.yml"), source)
            .expect_err("uses actions remain unavailable");
        assert!(error.to_string().contains("rejects every uses: action"));
    }

    #[cfg(windows)]
    #[test]
    fn native_demo_executes_powershell_and_cmd_in_one_disposable_workspace() {
        use std::fs;

        use automata_ci_execution::OperationId;

        use crate::{app::web::DemoWebData, cli::DemoArgs};

        let repository =
            std::env::temp_dir().join(format!("automata-demo-test-{}", OperationId::new()));
        let workflow_dir = repository.join(".ci/workflows");
        fs::create_dir_all(&workflow_dir).expect("create demo test repository");
        fs::write(
            workflow_dir.join("demo.yml"),
            r#"name: Local demo
on: workflow_dispatch
jobs:
  smoke:
    runs-on: windows
    steps:
      - name: Produce
        shell: powershell
        run: Set-Content -LiteralPath result.txt -Value success
      - name: Verify
        shell: cmd
        run: |
          @if not exist result.txt exit /b 9
          @type result.txt
"#,
        )
        .expect("write demo test workflow");

        let visualization =
            DemoWebData::new("Local demo".to_owned(), ".ci/workflows/demo.yml".to_owned());
        visualization.start();
        let result = super::windows::run(
            &DemoArgs {
                repo: repository.clone(),
                workflow: Path::new(".ci/workflows/demo.yml").to_path_buf(),
                listen: "127.0.0.1:8080".parse().expect("loopback listen"),
                no_visual: true,
                allow_host_execution: true,
            },
            &visualization,
        );
        let _ = fs::remove_dir_all(&repository);
        result.expect("native demo workflow executes");
    }
}
