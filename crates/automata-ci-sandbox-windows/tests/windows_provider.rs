#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use automata_ci_execution::{
    Cancellation, CopyFromRequest, CopyToRequest, DestroyDisposition, DestroySandbox,
    EnvironmentName, EnvironmentProfile, EnvironmentProfileId, EnvironmentValue,
    EnvironmentVariable, ExecutionArgv, ExecutionCommand, ExecutionEnvironment, ExecutionErrorKind,
    ExecutionTermination, NetworkPolicy, NeverCancelled, OperationId, ProviderErrorKind,
    ResourceLimits, RootFilesystemPolicy, SandboxCapability, SandboxEnvironment, SandboxGeneration,
    SandboxPrivilegePolicy, SandboxProvider, SandboxRecord, SandboxSpec, SandboxState,
    Sha256Digest, TargetPath,
};
use automata_ci_sandbox_windows::{WindowsSandboxProvider, WindowsSandboxProviderOptions};
use static_assertions::assert_impl_all;

const MIB: u64 = 1024 * 1024;
const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;

assert_impl_all!(WindowsSandboxProvider: Send, Sync, Clone);

#[test]
fn lifecycle_exec_copy_and_exact_replay_work() {
    let fixture = Fixture::new(16);
    let spec = fixture.spec();
    let record = fixture
        .provider
        .create(&spec, &NeverCancelled)
        .expect("create native sandbox");
    assert_eq!(record.state(), SandboxState::Running);
    assert_eq!(
        fixture
            .provider
            .create(&spec, &NeverCancelled)
            .expect("replay exact create"),
        record
    );

    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let payload = fixture.workspace.join("payload.txt");
    let copy_to = CopyToRequest::new(OperationId::new(), target(&payload), b"payload".to_vec())
        .expect("copy-to request");
    endpoint
        .copy_to(&copy_to, &NeverCancelled)
        .expect("copy into workspace");
    endpoint
        .copy_to(&copy_to, &NeverCancelled)
        .expect("replay exact copy into workspace");
    let copy_from =
        CopyFromRequest::new(OperationId::new(), target(&payload), 64).expect("copy-from request");
    assert_eq!(
        endpoint
            .copy_from(&copy_from, &NeverCancelled)
            .expect("copy from workspace"),
        b"payload"
    );
    assert_eq!(
        endpoint
            .copy_from(&copy_from, &NeverCancelled)
            .expect("replay exact copy from workspace"),
        b"payload"
    );

    let output = endpoint
        .exec(
            &fixture.powershell_command(
                "[Console]::Out.Write($env:AUTOMATA_TEST_VALUE); \
                 [Console]::Error.Write('stderr'); exit 7",
                environment(&[("AUTOMATA_TEST_VALUE", "stdout")]),
                Duration::from_secs(15),
            ),
            &NeverCancelled,
        )
        .expect("execute PowerShell in Job Object");
    assert_eq!(output.termination(), ExecutionTermination::Exited(7));
    assert_eq!(output.stdout(), b"stdout");
    assert_eq!(output.stderr(), b"stderr");
    assert!(!output.was_truncated());

    let inspection = fixture
        .provider
        .inspect(record.handle(), &NeverCancelled)
        .expect("inspect running sandbox");
    assert_eq!(inspection.state(), SandboxState::Running);
    assert_eq!(inspection.generation(), record.generation());

    drop(endpoint);
    assert_destroy_replay(&fixture, &record);
}

#[test]
fn provider_restart_recovers_ownership_replay_and_cleanup() {
    let fixture = RestartFixture::new();
    let spec = fixture.spec();
    let record = {
        let provider = fixture.open();
        provider
            .create(&spec, &NeverCancelled)
            .expect("create sandbox with provider A")
    };
    assert!(fixture.workspace.is_dir());
    assert!(fixture.scratch.is_dir());

    let destroy = DestroySandbox::new(
        OperationId::new(),
        record.handle().clone(),
        record.generation(),
    );
    assert_restart_cleanup_and_fresh_reuse(&fixture, &spec, &record, &destroy);
    assert_durable_restart_tombstone(&fixture, &record, &destroy);
}

#[test]
fn endpoint_lease_blocks_reopen_and_cross_generation_path_reuse() {
    let fixture = RestartFixture::new();
    let original_spec = fixture.spec();
    let provider = fixture.open();
    let original = provider
        .create(&original_spec, &NeverCancelled)
        .expect("create original generation");
    let endpoint = provider
        .attach(original.handle(), &NeverCancelled)
        .expect("attach original generation");
    drop(provider);

    let blocked = WindowsSandboxProvider::open(
        WindowsSandboxProviderOptions::new(fixture.root.clone()).expect("provider options"),
    )
    .expect_err("endpoint lease must retain the exclusive provider WAL lock");
    assert_eq!(blocked.kind(), ProviderErrorKind::InvalidConfiguration);

    let old_marker = fixture.workspace.join("old-generation.txt");
    endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::new(),
                target(&old_marker),
                b"old-generation".to_vec(),
            )
            .expect("old-generation copy request"),
            &NeverCancelled,
        )
        .expect("leased endpoint remains bound to the original provider lifetime");
    assert!(old_marker.is_file());
    drop(endpoint);

    let reopened = fixture.open();
    assert_eq!(
        reopened
            .inspect(original.handle(), &NeverCancelled)
            .expect("inspect recovered original generation")
            .state(),
        SandboxState::Absent
    );
    assert!(!old_marker.exists());
    let next_generation =
        SandboxGeneration::new(fixture.generation.get() + 1).expect("next sandbox generation");
    let fresh = reopened
        .create(
            &fixture.spec_for_generation(next_generation),
            &NeverCancelled,
        )
        .expect("create fresh generation after endpoint lease release");
    assert_eq!(fresh.generation(), next_generation);
    assert_ne!(fresh.handle(), original.handle());
    assert_eq!(fresh.state(), SandboxState::Running);
    assert!(!old_marker.exists());
    assert_eq!(
        reopened
            .destroy(
                &DestroySandbox::new(
                    OperationId::new(),
                    fresh.handle().clone(),
                    fresh.generation(),
                ),
                &NeverCancelled,
            )
            .expect("destroy fresh generation"),
        DestroyDisposition::Destroyed
    );
}

fn assert_restart_cleanup_and_fresh_reuse(
    fixture: &RestartFixture,
    spec: &SandboxSpec,
    record: &SandboxRecord,
    destroy: &DestroySandbox,
) {
    let provider = fixture.open();
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());
    let inspection = provider
        .inspect(record.handle(), &NeverCancelled)
        .expect("inspect recovered sandbox");
    assert_eq!(inspection.state(), SandboxState::Absent);
    let replay = provider
        .create(spec, &NeverCancelled)
        .expect("replay recovered create");
    assert_eq!(replay.handle(), record.handle());
    assert_eq!(replay.state(), SandboxState::Absent);
    let attach_error = provider
        .attach(record.handle(), &NeverCancelled)
        .expect_err("recovered sandbox is cleanup-only");
    assert_eq!(attach_error.kind(), ProviderErrorKind::NotFound);
    assert_eq!(
        provider
            .destroy(destroy, &NeverCancelled)
            .expect("destroy recovered sandbox"),
        DestroyDisposition::AlreadyAbsent
    );

    let fresh = provider
        .create(&fixture.spec(), &NeverCancelled)
        .expect("fresh admission nonce reuses reclaimed paths");
    assert_eq!(fresh.state(), SandboxState::Running);
    assert!(fixture.workspace.is_dir());
    assert!(fixture.scratch.is_dir());
    assert_eq!(
        provider
            .destroy(
                &DestroySandbox::new(
                    OperationId::new(),
                    fresh.handle().clone(),
                    fresh.generation(),
                ),
                &NeverCancelled,
            )
            .expect("destroy fresh admission sandbox"),
        DestroyDisposition::Destroyed
    );
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());
}

fn assert_durable_restart_tombstone(
    fixture: &RestartFixture,
    record: &SandboxRecord,
    destroy: &DestroySandbox,
) {
    let provider = fixture.open();
    assert_eq!(
        provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("inspect durable tombstone")
            .state(),
        SandboxState::Absent
    );
    assert_eq!(
        provider
            .destroy(destroy, &NeverCancelled)
            .expect("replay durable destroy"),
        DestroyDisposition::AlreadyAbsent
    );
    let already_absent = DestroySandbox::new(
        OperationId::new(),
        record.handle().clone(),
        record.generation(),
    );
    assert_eq!(
        provider
            .destroy(&already_absent, &NeverCancelled)
            .expect("destroy durable tombstone"),
        DestroyDisposition::AlreadyAbsent
    );
}

struct RestartFixture {
    root: PathBuf,
    profile_workspace: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
    generation: SandboxGeneration,
    _guard: TestRoot,
}

impl RestartFixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "automata-ci-sandbox-windows-restart-{}",
            OperationId::new()
        ));
        Self {
            profile_workspace: root.join("workspaces"),
            workspace: root
                .join("workspaces")
                .join(format!("job-{}", OperationId::new())),
            scratch: root.join(format!("scratch-{}", OperationId::new())),
            generation: SandboxGeneration::new(7).expect("generation"),
            _guard: TestRoot { path: root.clone() },
            root,
        }
    }

    fn open(&self) -> WindowsSandboxProvider {
        WindowsSandboxProvider::open(
            WindowsSandboxProviderOptions::new(self.root.clone()).expect("provider options"),
        )
        .expect("open restart provider")
    }

    fn spec(&self) -> SandboxSpec {
        self.spec_for_generation(self.generation)
    }

    fn spec_for_generation(&self, generation: SandboxGeneration) -> SandboxSpec {
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/windows-native-x86-64-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x57; 32]),
        );
        let environment = SandboxEnvironment::native(
            profile,
            target(&self.profile_workspace),
            ExecutionEnvironment::empty(),
        )
        .expect("native Windows environment");
        SandboxSpec::new(
            OperationId::new(),
            generation,
            environment,
            target(&self.workspace),
            NetworkPolicy::Host,
            RootFilesystemPolicy::Host,
            ResourceLimits::new(512 * MIB, 4_000, 16).expect("resource limits"),
        )
        .with_privilege(SandboxPrivilegePolicy::Host)
        .with_scratch(target(&self.scratch))
    }
}

#[test]
fn host_identity_is_explicit_and_profile_default_secrets_are_rejected() {
    let fixture = Fixture::new(16);
    assert!(
        fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::HostIdentity)
    );
    assert!(
        fixture
            .provider
            .capabilities()
            .supports(SandboxCapability::ProcessLimits)
    );
    let unprivileged = fixture
        .spec()
        .with_privilege(SandboxPrivilegePolicy::Unprivileged);
    let error = fixture
        .provider
        .create(&unprivileged, &NeverCancelled)
        .expect_err("native provider must not claim an unprivileged token");
    assert_eq!(error.kind(), ProviderErrorKind::UnsupportedCapability);

    let profile = EnvironmentProfile::new(
        EnvironmentProfileId::new("automata.dev/windows-native-secret-v1").expect("profile ID"),
        Sha256Digest::from_bytes([0x73; 32]),
    );
    let defaults = ExecutionEnvironment::new(vec![EnvironmentVariable::secret(
        EnvironmentName::new("PROFILE_SECRET").expect("environment name"),
        EnvironmentValue::new("must-not-enter-provider-journal").expect("environment value"),
    )])
    .expect("secret-marked profile environment");
    let environment =
        SandboxEnvironment::native(profile, target(&fixture.profile_workspace), defaults)
            .expect("native Windows environment");
    let secret_spec = SandboxSpec::new(
        OperationId::new(),
        fixture.generation,
        environment,
        target(&fixture.workspace),
        NetworkPolicy::Host,
        RootFilesystemPolicy::Host,
        ResourceLimits::new(512 * MIB, 4_000, fixture.pids).expect("resource limits"),
    )
    .with_privilege(SandboxPrivilegePolicy::Host)
    .with_scratch(target(&fixture.scratch));
    let error = fixture
        .provider
        .create(&secret_spec, &NeverCancelled)
        .expect_err("profile defaults cannot persist secret-derived replay material");
    assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());
}

#[test]
fn direct_cmd_call_executes_a_copied_step_script() {
    let fixture = Fixture::new(16);
    let record = fixture.create();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let preparation = endpoint
        .exec(
            &fixture.powershell_command_at(
                &powershell(),
                "New-Item -ItemType Directory -Force -Path (Join-Path (Get-Location) 'prepared') | Out-Null",
                environment(&[]),
                Duration::from_secs(15),
            ),
            &NeverCancelled,
        )
        .expect("execute preparatory PowerShell command");
    assert_eq!(preparation.termination(), ExecutionTermination::Exited(0));
    let script = fixture.scratch.join("step-0.cmd");
    endpoint
        .copy_to(
            &CopyToRequest::new(
                OperationId::new(),
                target(&script),
                b"@echo off\r\necho cmd-ok\r\n".to_vec(),
            )
            .expect("cmd script copy request"),
            &NeverCancelled,
        )
        .expect("copy cmd script");
    let arguments = ["/D", "/E:ON", "/V:OFF", "/C"]
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once(script.display().to_string()))
        .collect();
    let github_env = fixture.scratch.join("commands").join("phase-0-env");
    let path = env::var("PATH").expect("PATH is defined");
    let home = env::temp_dir();
    let prepared = fixture.workspace.join("prepared");
    let workspace = fixture.workspace.to_str().expect("Unicode workspace");
    let github_env = github_env.to_str().expect("Unicode command file");
    let command = ExecutionCommand::new(
        OperationId::new(),
        ExecutionArgv::new(
            target(&system_root().join("System32").join("cmd.exe")),
            arguments,
        )
        .expect("cmd argv"),
        target(&prepared),
        environment(&[
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_WORKSPACE", workspace),
            ("HOME", home.to_str().expect("Unicode temp")),
            ("PATH", &path),
            ("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
            ("RUNNER_OS", "Windows"),
            ("GITHUB_ENV", github_env),
            ("GITHUB_OUTPUT", github_env),
            ("GITHUB_PATH", github_env),
            ("GITHUB_STATE", github_env),
            ("GITHUB_STEP_SUMMARY", github_env),
        ]),
        Duration::from_secs(15),
        DEFAULT_OUTPUT_LIMIT,
    )
    .expect("cmd execution command");
    let output = endpoint
        .exec(&command, &NeverCancelled)
        .expect("execute cmd step");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    assert_eq!(output.stdout(), b"cmd-ok\r\n");
    drop(endpoint);
    fixture.destroy(&record);
}

fn assert_destroy_replay(fixture: &Fixture, record: &SandboxRecord) {
    let destroy = DestroySandbox::new(
        OperationId::new(),
        record.handle().clone(),
        record.generation(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&destroy, &NeverCancelled)
            .expect("destroy sandbox"),
        DestroyDisposition::Destroyed
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&destroy, &NeverCancelled)
            .expect("replay exact destroy"),
        DestroyDisposition::Destroyed
    );
    assert_eq!(
        fixture
            .provider
            .inspect(record.handle(), &NeverCancelled)
            .expect("inspect tombstone")
            .state(),
        SandboxState::Absent
    );
    let already_absent = DestroySandbox::new(
        OperationId::new(),
        record.handle().clone(),
        record.generation(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&already_absent, &NeverCancelled)
            .expect("destroy exact tombstone"),
        DestroyDisposition::AlreadyAbsent
    );
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());
}

#[test]
fn cancellation_kills_a_descendant_process_tree() {
    let fixture = Fixture::new(16);
    let record = fixture.create();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let pid_file = fixture.scratch.join("cancel-child.pid");
    let cancellation = FlagCancellation::default();
    let cancellation_trigger = cancellation.clone();
    let pid_file_for_trigger = pid_file.clone();
    let trigger = thread::spawn(move || {
        let pid = wait_for_pid(&pid_file_for_trigger, Duration::from_secs(8));
        cancellation_trigger.cancel();
        pid
    });

    let output = endpoint
        .exec(
            &fixture.long_running_descendant_command(&pid_file, Duration::from_secs(20)),
            &cancellation,
        )
        .expect("cancel contained process tree");
    let child_pid = trigger
        .join()
        .expect("cancellation trigger thread")
        .expect("descendant pid was recorded");
    assert_eq!(output.termination(), ExecutionTermination::Cancelled);
    assert_process_exited(child_pid);
    fixture.destroy(&record);
}

#[test]
fn timeout_kills_a_descendant_process_tree() {
    let fixture = Fixture::new(16);
    let record = fixture.create();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let pid_file = fixture.scratch.join("timeout-child.pid");

    let output = endpoint
        .exec(
            &fixture.long_running_descendant_command(&pid_file, Duration::from_secs(3)),
            &NeverCancelled,
        )
        .expect("time out contained process tree");
    let child_pid = wait_for_pid(&pid_file, Duration::from_secs(1))
        .expect("descendant pid was recorded before timeout");
    assert_eq!(output.termination(), ExecutionTermination::TimedOut);
    assert_process_exited(child_pid);
    fixture.destroy(&record);
}

#[test]
fn destroy_interrupts_an_active_process_tree_before_cleanup() {
    let fixture = Fixture::new(16);
    let record = fixture.create();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let pid_file = fixture.scratch.join("destroy-child.pid");
    let command = fixture.long_running_descendant_command(&pid_file, Duration::from_secs(30));
    let execution = thread::spawn(move || endpoint.exec(&command, &NeverCancelled));
    let child_pid =
        wait_for_pid(&pid_file, Duration::from_secs(8)).expect("descendant pid was recorded");

    let started = Instant::now();
    let destroy = DestroySandbox::new(
        OperationId::new(),
        record.handle().clone(),
        record.generation(),
    );
    assert_eq!(
        fixture
            .provider
            .destroy(&destroy, &NeverCancelled)
            .expect("destroy running sandbox"),
        DestroyDisposition::Destroyed
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    let execution_result = execution.join().expect("execution thread");
    match execution_result {
        Ok(output) => assert_ne!(output.termination(), ExecutionTermination::Exited(0)),
        Err(error) => assert_eq!(error.kind(), ExecutionErrorKind::BackendRejected),
    }
    assert_process_exited(child_pid);
    assert!(!fixture.workspace.exists());
    assert!(!fixture.scratch.exists());
}

#[test]
fn active_process_limit_rejects_a_descendant() {
    let fixture = Fixture::new(1);
    let record = fixture.create();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let script = "$ErrorActionPreference = 'Stop'; \
                  try { \
                    $child = Start-Process -FilePath $env:COMSPEC \
                      -ArgumentList '/d','/c','exit 0' -PassThru; \
                    $child.WaitForExit(); [Console]::Out.Write('unexpected') \
                  } catch { [Console]::Out.Write('limited') }";
    let output = endpoint
        .exec(
            &fixture.powershell_command(script, environment(&[]), Duration::from_secs(15)),
            &NeverCancelled,
        )
        .expect("execute process-limit probe");
    assert_eq!(output.termination(), ExecutionTermination::Exited(0));
    assert_eq!(output.stdout(), b"limited");
    fixture.destroy(&record);
}

#[test]
fn preexisting_workspace_and_scratch_are_never_rolled_back() {
    let workspace_fixture = Fixture::new(16);
    fs::create_dir_all(&workspace_fixture.workspace).expect("pre-create workspace");
    let workspace_marker = workspace_fixture.workspace.join("foreign.txt");
    fs::write(&workspace_marker, b"foreign-workspace").expect("write workspace marker");
    let error = workspace_fixture
        .provider
        .create(&workspace_fixture.spec(), &NeverCancelled)
        .expect_err("pre-existing workspace must conflict");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_eq!(
        fs::read(&workspace_marker).expect("foreign workspace marker survives"),
        b"foreign-workspace"
    );
    assert!(!workspace_fixture.scratch.exists());

    let scratch_fixture = Fixture::new(16);
    fs::create_dir_all(&scratch_fixture.scratch).expect("pre-create scratch");
    let scratch_marker = scratch_fixture.scratch.join("foreign.txt");
    fs::write(&scratch_marker, b"foreign-scratch").expect("write scratch marker");
    let error = scratch_fixture
        .provider
        .create(&scratch_fixture.spec(), &NeverCancelled)
        .expect_err("pre-existing scratch must conflict");
    assert_eq!(error.kind(), ProviderErrorKind::Conflict);
    assert_eq!(
        fs::read(&scratch_marker).expect("foreign scratch marker survives"),
        b"foreign-scratch"
    );
    assert!(!scratch_fixture.workspace.exists());
}

#[test]
fn copy_rejects_reparse_escape_and_core_rejects_windows_ads_paths() {
    let fixture = Fixture::new(16);
    let record = fixture.create();
    let endpoint = fixture
        .provider
        .attach(record.handle(), &NeverCancelled)
        .expect("attach exact sandbox");
    let foreign = fixture.root().join("foreign");
    fs::create_dir(&foreign).expect("create foreign directory");
    let foreign_sentinel = foreign.join("sentinel.txt");
    fs::write(&foreign_sentinel, b"foreign-target").expect("write foreign sentinel");
    let link = fixture.workspace.join("escape-link");
    create_directory_reparse(&link, &foreign);
    let request = CopyToRequest::new(
        OperationId::new(),
        target(&link.join("escaped.txt")),
        b"must-not-escape".to_vec(),
    )
    .expect("copy request through reparse point");
    let error = endpoint
        .copy_to(&request, &NeverCancelled)
        .expect_err("reparse point must fail closed");
    assert_eq!(error.kind(), ExecutionErrorKind::OwnershipMismatch);
    assert!(!foreign.join("escaped.txt").exists());

    assert!(
        TargetPath::windows(format!(
            "{}:alternate",
            fixture.workspace.join("payload.txt").display()
        ))
        .is_err(),
        "alternate data streams must fail closed at the core path boundary"
    );

    drop(endpoint);
    fixture.destroy(&record);
    assert!(!link.exists());
    assert_eq!(
        fs::read(&foreign_sentinel).expect("foreign target survives owned-tree cleanup"),
        b"foreign-target"
    );
}

struct Fixture {
    provider: WindowsSandboxProvider,
    profile_workspace: PathBuf,
    workspace: PathBuf,
    scratch: PathBuf,
    generation: SandboxGeneration,
    pids: u32,
    root_guard: TestRoot,
}

impl Fixture {
    fn new(pids: u32) -> Self {
        let root = env::temp_dir().join(format!(
            "automata-ci-sandbox-windows-{}",
            OperationId::new()
        ));
        let options = WindowsSandboxProviderOptions::new(root.clone())
            .expect("absolute ASCII Windows provider root");
        let provider = WindowsSandboxProvider::open(options).expect("open Windows provider");
        let profile_workspace = root.join("workspaces");
        let workspace = profile_workspace.join(format!("job-{}", OperationId::new()));
        let scratch = root.join(format!("scratch-{}", OperationId::new()));
        Self {
            provider,
            profile_workspace,
            workspace,
            scratch,
            generation: SandboxGeneration::new(1).expect("generation"),
            pids,
            root_guard: TestRoot { path: root },
        }
    }

    fn root(&self) -> &Path {
        &self.root_guard.path
    }

    fn spec(&self) -> SandboxSpec {
        let profile = EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.dev/windows-native-x86-64-v1").expect("profile ID"),
            Sha256Digest::from_bytes([0x57; 32]),
        );
        let environment = SandboxEnvironment::native(
            profile,
            target(&self.profile_workspace),
            ExecutionEnvironment::empty(),
        )
        .expect("native Windows environment");
        SandboxSpec::new(
            OperationId::new(),
            self.generation,
            environment,
            target(&self.workspace),
            NetworkPolicy::Host,
            RootFilesystemPolicy::Host,
            ResourceLimits::new(512 * MIB, 4_000, self.pids).expect("resource limits"),
        )
        .with_privilege(SandboxPrivilegePolicy::Host)
        .with_scratch(target(&self.scratch))
    }

    fn create(&self) -> SandboxRecord {
        self.provider
            .create(&self.spec(), &NeverCancelled)
            .expect("create native sandbox")
    }

    fn destroy(&self, record: &SandboxRecord) {
        let request = DestroySandbox::new(
            OperationId::new(),
            record.handle().clone(),
            record.generation(),
        );
        assert_eq!(
            self.provider
                .destroy(&request, &NeverCancelled)
                .expect("destroy native sandbox"),
            DestroyDisposition::Destroyed
        );
    }

    fn powershell_command(
        &self,
        script: &str,
        environment: ExecutionEnvironment,
        timeout: Duration,
    ) -> ExecutionCommand {
        self.powershell_command_at(&powershell(), script, environment, timeout)
    }

    fn powershell_command_at(
        &self,
        program: &Path,
        script: &str,
        environment: ExecutionEnvironment,
        timeout: Duration,
    ) -> ExecutionCommand {
        let arguments = [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        ExecutionCommand::new(
            OperationId::new(),
            ExecutionArgv::new(target(program), arguments).expect("PowerShell argv"),
            target(&self.workspace),
            environment,
            timeout,
            DEFAULT_OUTPUT_LIMIT,
        )
        .expect("PowerShell execution command")
    }

    fn long_running_descendant_command(
        &self,
        pid_file: &Path,
        timeout: Duration,
    ) -> ExecutionCommand {
        let script = "$child = Start-Process -FilePath $env:COMSPEC \
                      -ArgumentList '/d','/c','ping -n 30 127.0.0.1 > nul' \
                      -PassThru -NoNewWindow; \
                      [System.IO.File]::WriteAllText(\
                        $env:AUTOMATA_PID_FILE, [string]$child.Id); \
                      [System.Threading.Thread]::Sleep(30000)";
        self.powershell_command(
            script,
            environment(&[(
                "AUTOMATA_PID_FILE",
                pid_file.to_str().expect("Unicode pid path"),
            )]),
            timeout,
        )
    }
}

struct TestRoot {
    path: PathBuf,
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Default)]
struct FlagCancellation(Arc<AtomicBool>);

impl FlagCancellation {
    fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Cancellation for FlagCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn target(path: &Path) -> TargetPath {
    TargetPath::windows(
        path.to_str()
            .expect("test paths are Unicode")
            .replace('/', "\\"),
    )
    .expect("absolute Windows target path")
}

fn powershell() -> PathBuf {
    system_root()
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

fn system_root() -> PathBuf {
    PathBuf::from(env::var_os("SystemRoot").expect("SystemRoot is defined"))
}

fn environment(extra: &[(&str, &str)]) -> ExecutionEnvironment {
    let system_root = system_root();
    let comspec = system_root.join("System32").join("cmd.exe");
    let temp = env::temp_dir();
    let mut variables = vec![
        variable(
            "SystemRoot",
            system_root.to_str().expect("Unicode SystemRoot"),
        ),
        variable("WINDIR", system_root.to_str().expect("Unicode SystemRoot")),
        variable("COMSPEC", comspec.to_str().expect("Unicode ComSpec")),
        variable("TEMP", temp.to_str().expect("Unicode temp path")),
        variable("TMP", temp.to_str().expect("Unicode temp path")),
    ];
    variables.extend(extra.iter().map(|(name, value)| variable(name, value)));
    ExecutionEnvironment::new(variables).expect("unique Windows environment")
}

fn variable(name: &str, value: &str) -> EnvironmentVariable {
    EnvironmentVariable::new(
        EnvironmentName::new(name).expect("environment name"),
        EnvironmentValue::new(value).expect("environment value"),
    )
}

fn wait_for_pid(path: &Path, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(value) = fs::read_to_string(path)
            && let Ok(pid) = value.trim().parse()
        {
            return Some(pid);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_process_exited(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_is_alive(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(!process_is_alive(pid), "descendant process {pid} survived");
}

fn process_is_alive(pid: u32) -> bool {
    let output = StdCommand::new(system_root().join("System32").join("tasklist.exe"))
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .expect("query Windows process table");
    let expected = format!("\"{pid}\"");
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.split(',')
            .nth(1)
            .is_some_and(|value| value == expected)
    })
}

fn create_directory_reparse(link: &Path, target: &Path) {
    if std::os::windows::fs::symlink_dir(target, link).is_ok() {
        return;
    }
    let status = StdCommand::new(system_root().join("System32").join("cmd.exe"))
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .expect("invoke mklink junction fallback");
    assert!(status.success(), "create directory reparse point");
}
